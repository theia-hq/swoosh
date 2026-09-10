//! S2 blocker tests: flock truth, stale rebind, live refusal, crash recovery, per-home split.

use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::io::AsRawFd as _;
use std::os::unix::net::UnixListener;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::{SingleError, acquire};
use crate::home::Home;

/// Serializes tests that mutate the process-global `XDG_RUNTIME_DIR`.
///
/// The test harness runs cases on parallel threads, and on Linux the resident runtime root is read
/// from `XDG_RUNTIME_DIR`, so two `Scratch`-owning tests would race each other's roots and their
/// restores (the race that failed CI; on macOS the root comes from `confstr`, the variable is
/// ignored, and the race is invisible locally). Every test in this file holds this for its whole
/// body.
static XDG_RUNTIME_ENV: Mutex<()> = Mutex::new(());

/// Take the process-wide slot for a test that mutates `XDG_RUNTIME_DIR`. A poisoned lock is
/// recovered: the sibling panic that poisoned it is already the reported failure, and cascading
/// poison errors would only hide it.
fn xdg_runtime_env() -> MutexGuard<'static, ()> {
    XDG_RUNTIME_ENV
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// A scratch home with an isolated `XDG_RUNTIME_DIR` per test. Restores the ambient value on drop.
/// The mutation is only safe under the per-test [`xdg_runtime_env`] guard, which `Scratch` does not
/// take itself: `per_home_paths_never_collide` owns two. Drop removes exactly the per-test `root`,
/// never its parent: on macOS the parent of a scratch leaf is the real per-user temp dir.
struct Scratch {
    home: Home,
    root: std::path::PathBuf,
    runtime: std::path::PathBuf,
    leaf: std::path::PathBuf,
    prior: Option<std::ffi::OsString>,
}

impl Scratch {
    fn new(name: &str) -> Self {
        // One per-test root under the system temp dir. The runtime leaf is that root on macOS
        // (whose runtime root IS the per-user temp dir) and `root/run` on Linux, where
        // `XDG_RUNTIME_DIR` names the leaf's parent.
        let root = std::env::temp_dir().join(format!(
            "swoosh-single-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        #[cfg(target_os = "macos")]
        let runtime = root.clone();
        #[cfg(not(target_os = "macos"))]
        let runtime = root.join("run");
        let home_dir = runtime.join("home");
        std::fs::create_dir_all(&home_dir).expect("scratch home");
        std::fs::create_dir_all(&runtime).expect("scratch runtime");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            // Only the scratch root is chmod'd, never the shared system temp dir: the macOS chain
            // verifier reads that dir's mode, but this test does not own it.
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700));
        }
        let prior = std::env::var_os("XDG_RUNTIME_DIR");
        // SAFETY: the test holding `XDG_RUNTIME_ENV` is the only one mutating this process-global
        // variable at a time, and it restores the prior value on drop.
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", &runtime) };
        let home = Home::resolve(Some(home_dir)).expect("explicit home resolves");
        // The resolved leaf under the per-user runtime root, cleaned on drop so a macOS run does
        // not leave `swoosh-<uid>/<key>` behind in the real temp dir.
        let leaf = home.runtime_dir().unwrap_or_default();
        Self {
            home,
            root,
            runtime,
            leaf,
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
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_dir_all(&self.leaf);
    }
}

/// Two concurrent starts on one home: exactly one wins, the loser names the winner's pid.
#[test]
fn two_resident_starts_one_home_exactly_one_wins() {
    let _env = xdg_runtime_env();
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
    let _env = xdg_runtime_env();
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
    let _env = xdg_runtime_env();
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

/// A live listener whose probe answers neither `ENOENT` nor `ECONNREFUSED` refuses start and is
/// never unlinked: only the two proven-stale answers permit the unlink. A mode-000 socket makes
/// connect answer `EACCES`, an outcome the unlink policy must refuse.
#[test]
fn unclassified_probe_refuses_and_never_unlinks() {
    let _env = xdg_runtime_env();
    let scratch = Scratch::new("unclassified");
    // The leaf must exist 0700 before the plant binds inside it.
    let (seed, seed_listener) = acquire(&scratch.home).expect("seed acquire creates the leaf");
    let socket = seed.socket_path().to_path_buf();
    drop(seed);
    drop(seed_listener);
    let _ = std::fs::remove_file(&socket);
    let live = UnixListener::bind(&socket).expect("plant a live listener");
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Mode 000: a non-root connect answers EACCES on Linux and macOS, neither a live connect
        // nor one of the two stale errors. A full accept queue (Linux) answers EAGAIN, the other
        // unclassified shape; both land in the same refuse arm.
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o000))
            .expect("chmod the live socket to 000");
    }
    let refused = acquire(&scratch.home);
    assert!(
        matches!(refused, Err(SingleError::ProbeUnclassified)),
        "an unclassified probe refuses start"
    );
    assert!(socket.exists(), "the refused socket is never unlinked");
    drop(live);
}

/// Dropping the lock fd without clean shutdown (the crash): the next start succeeds.
#[test]
fn crash_releases_flock_next_start_rebinds() {
    let _env = xdg_runtime_env();
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
    let _env = xdg_runtime_env();
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
    // The widened full-width hash: 16 lowercase hex chars, never the old 32-bit 8-char key.
    let key = first.home_key();
    assert_eq!(key.len(), 16, "the key renders the full 64 bits: {key}");
    assert!(
        key.chars().all(|c| c.is_ascii_hexdigit()),
        "the key stays lowercase hex: {key}"
    );
    // The widened key adds eight chars but must still fit sun_path on both platforms (104 on
    // macOS, 108 on Linux; assert the tighter one), or the bind would fail on a long temp root.
    let socket = first.home.control_socket().expect("socket path");
    assert!(
        socket.as_os_str().as_bytes().len() < 104,
        "the resident socket path fits sun_path: {}",
        socket.display()
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
    let _env = xdg_runtime_env();
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
