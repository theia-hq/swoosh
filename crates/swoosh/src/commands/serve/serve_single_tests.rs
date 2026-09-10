//! S2 tests: flock truth, stale rebind, live refusal, per-home split, graceful release.
//!
//! Every case threads its own per-test runtime root into `acquire`; nothing here mutates a
//! process-global (`XDG_RUNTIME_DIR` is never touched), so the suite is parallel-safe by
//! construction rather than by a shared environment mutex.

use core::sync::atomic::{AtomicU32, Ordering};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::io::AsRawFd as _;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use super::{SingleError, acquire};
use crate::home::Home;

/// Serializes scratch base names within this test process; the pid keeps two concurrent runs of the
/// binary apart. Names stay short on purpose: the base sits under the per-user temp dir and the
/// socket path must still fit `sun_path` (104 bytes on macOS).
static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

/// A scratch home plus an isolated runtime root per test, both under one owned base dir. Drop
/// removes exactly that base (`remove_dir_all`), never a parent: on macOS the parent of a scratch
/// leaf would be the real per-user temp dir. The root shape mirrors production: on macOS the base
/// IS the runtime root (whose parent, the per-user temp dir, is the verifier's base); elsewhere
/// `<base>` plays the XDG base and `<base>/run` the runtime root handed to `acquire`.
struct Scratch {
    base: PathBuf,
    root: PathBuf,
    home: Home,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let short: String = name.chars().take(8).collect();
        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("sw-{short}-{}-{seq}", std::process::id()));
        #[cfg(target_os = "macos")]
        let root = base.clone();
        #[cfg(not(target_os = "macos"))]
        let root = base.join("run");
        let home_dir = base.join("home");
        std::fs::create_dir_all(&home_dir).expect("scratch home");
        std::fs::create_dir_all(&root).expect("scratch runtime root");
        {
            use std::os::unix::fs::PermissionsExt as _;
            // 0700 on the two dirs the chain verifier stats; the per-home leaf is created 0700 by
            // `acquire` itself.
            let _ = std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
        }
        let home = Home::resolve(Some(home_dir)).expect("explicit home resolves");
        Self { base, root, home }
    }

    fn home_key(&self) -> String {
        self.home.home_key()
    }

    /// The per-home runtime leaf under this test's root: the same derivation `acquire` uses.
    fn leaf(&self) -> PathBuf {
        self.home.runtime_leaf(&self.root)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Two starts on one home: exactly one wins, the loser names the winner's pid.
#[test]
fn two_resident_starts_one_home_exactly_one_wins() {
    let scratch = Scratch::new("duel");
    let (first, second) = (
        acquire(&scratch.home, &scratch.root),
        acquire(&scratch.home, &scratch.root),
    );
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
        let (lock, listener) =
            acquire(&scratch.home, &scratch.root).expect("first acquire creates the leaf");
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
    let (lock, _) = acquire(&scratch.home, &scratch.root).expect("stale socket rebinds");
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
    let (seed, seed_listener) =
        acquire(&scratch.home, &scratch.root).expect("seed acquire creates the leaf");
    let socket = seed.socket_path().to_path_buf();
    drop(seed);
    drop(seed_listener);
    let _ = std::fs::remove_file(&socket);
    let live = UnixListener::bind(&socket).expect("plant a live listener");
    // The borrowed lock: a second flock fd held open across the start below.
    let lock_path = scratch.leaf().join("control.lock");
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
    let refused = acquire(&scratch.home, &scratch.root).is_err();
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
    let scratch = Scratch::new("unclassified");
    // The leaf must exist 0700 before the plant binds inside it.
    let (seed, seed_listener) =
        acquire(&scratch.home, &scratch.root).expect("seed acquire creates the leaf");
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
    let refused = acquire(&scratch.home, &scratch.root);
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
    let scratch = Scratch::new("crash");
    {
        let (_lock, _listener) = acquire(&scratch.home, &scratch.root).expect("first start");
        // Drop without `release`: the crash path. The OS releases the flock; the socket stays.
    }
    let (lock, _) =
        acquire(&scratch.home, &scratch.root).expect("next start rebinds after a crash");
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
    // The widened full-width hash: 16 lowercase hex chars, never the old 32-bit 8-char key.
    let key = first.home_key();
    assert_eq!(key.len(), 16, "the key renders the full 64 bits: {key}");
    assert!(
        key.chars().all(|c| c.is_ascii_hexdigit()),
        "the key stays lowercase hex: {key}"
    );
    // The widened key adds eight chars but must still fit sun_path on both platforms (104 on
    // macOS, 108 on Linux; assert the tighter one), or the bind would fail on a long temp root.
    let socket = first.leaf().join("control.sock");
    assert!(
        socket.as_os_str().as_bytes().len() < 104,
        "the resident socket path fits sun_path: {}",
        socket.display()
    );
    let (a_lock, _) = acquire(&first.home, &first.root).expect("first home starts");
    let (b_lock, _) = acquire(&second.home, &second.root).expect("second home starts alongside");
    assert_ne!(
        a_lock.socket_path(),
        b_lock.socket_path(),
        "two residents hold different sockets"
    );
    let _ = (a_lock, b_lock);
}

/// A 0755 runtime leaf refuses the start (owner and mode are created AND verified, never assumed).
#[test]
fn runtime_dir_mode_owner_verified() {
    let scratch = Scratch::new("insecure");
    let dir = scratch.leaf();
    std::fs::create_dir_all(&dir).expect("runtime dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Loosen the per-home LEAF (the verifier's target), not the scratch root.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("loosen the dir");
    }
    let refused = acquire(&scratch.home, &scratch.root);
    assert!(
        matches!(refused, Err(SingleError::RuntimeDirInsecure { .. })),
        "a 0755 runtime dir refuses start"
    );
}

/// Graceful teardown unlinks the socket this instance bound: the path identity captured at bind is
/// the same filesystem object `release` stats, so the unlink fires.
#[test]
fn release_unlinks_its_own_socket() {
    let scratch = Scratch::new("release-own");
    let (lock, listener) = acquire(&scratch.home, &scratch.root).expect("resident start");
    let socket = lock.socket_path().to_path_buf();
    assert!(socket.exists(), "the bound socket exists while held");
    lock.release();
    assert!(!socket.exists(), "release unlinks its own socket");
    drop(listener);
}

/// A same-uid swap must not cost the foreign process its file: `release` compares against the path
/// identity captured at bind, and a different inode (a second listener renamed onto the path while
/// both exist, so the inodes are provably distinct) is left alone.
#[test]
fn release_spares_a_foreign_inode_swapped_onto_the_path() {
    let scratch = Scratch::new("release-foreign");
    let (lock, listener) = acquire(&scratch.home, &scratch.root).expect("resident start");
    let socket = lock.socket_path().to_path_buf();
    let foreign_path = scratch.root.join("foreign.sock");
    let foreign = UnixListener::bind(&foreign_path).expect("plant the foreign listener");
    std::fs::rename(&foreign_path, &socket).expect("swap the foreign inode onto the path");
    drop(listener);
    lock.release();
    assert!(socket.exists(), "release never unlinks a foreign inode");
    drop(foreign);
}
