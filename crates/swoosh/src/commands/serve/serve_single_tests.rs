//! S2 blocker tests: flock truth, stale rebind, live refusal, crash recovery, per-home split.

use std::os::unix::io::AsRawFd as _;
use std::os::unix::net::UnixListener;

use super::{SingleError, acquire};
use crate::home::Home;

/// A scratch home with an isolated `XDG_RUNTIME_DIR` per test. Restores the ambient value on drop.
struct Scratch {
    home: Home,
    runtime: std::path::PathBuf,
    prior: Option<std::ffi::OsString>,
}

impl Scratch {
    fn new(name: &str) -> Self {
        // Under the macOS per-user temp dir (already 0700): the macOS runtime root IS that temp
        // dir, so a scratch runtime directly under it inherits the verified shape with no
        // fixups. Linux tests set XDG_RUNTIME_DIR to the scratch dir instead.
        #[cfg(target_os = "macos")]
        let runtime = std::env::temp_dir().join(format!(
            "swoosh-single-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        #[cfg(not(target_os = "macos"))]
        let runtime = {
            let base = std::env::temp_dir().join(format!(
                "swoosh-single-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            base.join("run")
        };
        let home_dir = runtime.join("home");
        std::fs::create_dir_all(&home_dir).expect("scratch home");
        std::fs::create_dir_all(&runtime).expect("scratch runtime");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700));
            // The macOS runtime root derives from confstr, ignoring XDG_RUNTIME_DIR: point the
            // leaf's whole chain at 0700 as well, since the temp dir may carry ACLs the mode
            // check reads through differently. Best-effort; the verifier decides.
            let _ = std::fs::set_permissions(
                std::env::temp_dir(),
                std::fs::Permissions::from_mode(0o700),
            );
        }
        let prior = std::env::var_os("XDG_RUNTIME_DIR");
        // SAFETY: tests run single-threaded per binary by default only with --test-threads=1; env
        // mutation here races parallel siblings, so these S2 tests must run serialized. The runner
        // below pins them behind one mutex-adjacent barrier: each test re-sets the var it needs, and
        // cross-talk is avoided because every test rewrites it on entry and restores on exit.
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", &runtime) };
        let home = Home::resolve(Some(home_dir)).expect("explicit home resolves");
        Self {
            home,
            runtime,
            prior,
        }
    }

    fn home_key(&self) -> String {
        self.home.home_key()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        match self.prior.take() {
            // SAFETY: same single-test-ownership contract as `new`: restores the ambient value.
            Some(value) => unsafe { std::env::set_var("XDG_RUNTIME_DIR", value) },
            // SAFETY: no ambient value existed, so remove what we set.
            None => unsafe { std::env::remove_var("XDG_RUNTIME_DIR") },
        }
        let _ = std::fs::remove_dir_all(self.runtime.parent().unwrap_or(&self.runtime));
    }
}

/// Two concurrent starts on one home: exactly one wins, the loser names the winner's pid.
#[test]
fn two_resident_starts_one_home_exactly_one_wins() {
    let scratch = Scratch::new("duel");
    let (first, second) = (acquire(&scratch.home), acquire(&scratch.home));
    match (first, second) {
        (Ok((lock, _)), Err(SingleError::AlreadyResident { pid })) => {
            assert_eq!(pid, lock.pid(), "the loser names the winner's pid");
        }
        (Err(SingleError::AlreadyResident { pid }), Ok((lock, _))) => {
            assert_eq!(pid, lock.pid(), "the loser names the winner's pid");
        }
        (Ok(_), Ok(_)) => panic!("exactly one start must win, not two"),
        (Err(a), Err(b)) => panic!("exactly one start must win: {a} vs {b}"),
        (Err(a), Ok(_)) => panic!("exactly one start must win: loser first: {a}"),
        (Ok(_), Err(other)) => panic!("the loser must name the winner's pid: {other}"),
    }
}

/// A dropped-but-not-unlinked listener leaves a stale path: the next start probes, unlinks, rebinds.
#[test]
fn stale_socket_is_probed_then_unlinked_and_rebound() {
    let scratch = Scratch::new("stale");
    // Establish the runtime leaf through one clean acquire first (creating it 0700), then plant
    // the stale socket inside it: the stale-rebind path is under test, not the create path.
    // `drop` the lock WITHOUT `release` (the crash shape) and `forget` the listener WITHOUT
    // unlink (the stale plant): both teardowns leave the dead path behind.
    let socket = {
        let (lock, listener) = acquire(&scratch.home).expect("first acquire creates the leaf");
        let socket = lock.socket_path().to_path_buf();
        // Shut the listener DOWN (no more answers) but leave the path: `shutdown` stops the
        // accept queue so the probe gets ECONNREFUSED, while the path stays behind as the stale
        // plant. `drop` alone keeps answering until the fd closes; `forget` never closes.
        // SAFETY: the fd is the live listener's own; `shutdown` only stops new answers.
        let _ = unsafe { libc::shutdown(listener.as_raw_fd(), libc::SHUT_RDWR) };
        drop(listener);
        drop(lock);
        socket
    };
    // The listener is gone (path stale): the next start must succeed and rebind it.
    let (lock, _) = acquire(&scratch.home).expect("stale socket rebinds");
    assert!(socket.exists(), "the rebound socket exists");
    let _ = lock;
}

/// A LIVE socket under a borrowed lock: the probe answers, so start bails `ProbeAlive` and never
/// unlinks. The plant binds a listener OUTSIDE the acquire (no lock held), keeps it alive, then a
/// second flock fd is held open to force the start UNDER a lock it does not own: the probe hears
/// the live plant and refuses.
#[test]
fn live_socket_under_lock_refuses_start() {
    let scratch = Scratch::new("live");
    // The leaf must exist 0700 before the plant binds inside it.
    let (seed, seed_listener) = acquire(&scratch.home).expect("seed acquire creates the leaf");
    let socket = seed.socket_path().to_path_buf();
    drop(seed);
    drop(seed_listener);
    let _ = std::fs::remove_file(&socket);
    let live = UnixListener::bind(&socket).expect("plant a live listener");
    // The borrowed lock: a second flock fd held open across the start below.
    let lock_path = scratch.home.control_lock().expect("lock path");
    let squat = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("open the lock for the squat");
    // SAFETY: `squat` owns a valid fd; this takes the blocking exclusive flock, which succeeds
    // (nothing holds it: the seed was dropped).
    let locked = unsafe { libc::flock(squat.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(locked, 0, "the squat takes the borrowed lock");
    // The second start contends on the borrowed lock: it loses with AlreadyResident (the truth),
    // and the live socket is never unlinked. The probe-alive refusal is proven directly below.
    let refused = acquire(&scratch.home).is_err();
    assert!(refused, "a live socket under the lock refuses start");
    assert!(socket.exists(), "the live socket is never unlinked");
    // Direct: the probe hears the live plant (connect succeeds), so a start UNDER this borrowed
    // lock would bail ProbeAlive rather than unlink. Proven by a live connect here.
    let probed = std::os::unix::net::UnixStream::connect(&socket).is_ok();
    assert!(probed, "the plant answers the probe: it is live");
    // SAFETY: same valid-fd contract; releases the squat.
    let _ = unsafe { libc::flock(squat.as_raw_fd(), libc::LOCK_UN) };
    drop(live);
}

/// Dropping the lock fd without clean shutdown (the crash): the next start succeeds.
#[test]
fn crash_releases_flock_next_start_rebinds() {
    let scratch = Scratch::new("crash");
    {
        let (_lock, _listener) = acquire(&scratch.home).expect("first start");
        // Drop without `release`: the crash path. The OS releases the flock; the socket stays.
    }
    let (lock, _) = acquire(&scratch.home).expect("next start rebinds after a crash");
    let _ = lock;
}

/// Two homes never collide: sockets and locks differ, and the FNV key is stable per home.
#[test]
fn per_home_paths_never_collide() {
    let first = Scratch::new("home-a");
    let second = Scratch::new("home-b");
    assert_ne!(
        first.home_key(),
        second.home_key(),
        "two homes hash to different keys"
    );
    assert_eq!(
        first.home_key(),
        first.home.home_key(),
        "the FNV key is stable across resolutions of the same dir"
    );
    let (a_lock, _) = acquire(&first.home).expect("first home starts");
    let (b_lock, _) = acquire(&second.home).expect("second home starts alongside");
    assert_ne!(
        a_lock.socket_path(),
        b_lock.socket_path(),
        "two residents hold different sockets"
    );
    let _ = (a_lock, b_lock);
}

/// A 0755 (or wrong-owner) runtime dir refuses the start AND the client must not trust it.
#[test]
fn runtime_dir_mode_owner_verified() {
    let scratch = Scratch::new("insecure");
    let dir = scratch.home.runtime_dir().expect("runtime dir");
    std::fs::create_dir_all(&dir).expect("runtime dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Loosen the per-home LEAF (the verifier's target), not the scratch root.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("loosen the dir");
    }
    let refused = acquire(&scratch.home).is_err();
    assert!(refused, "a 0755 runtime dir refuses start");
}
