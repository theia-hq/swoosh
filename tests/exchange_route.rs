// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The exchange verbs as the compiled binary runs them beside a running `serve`: `sync` rides it, a reach
//! flag `serve` makes moot refuses `join`, `revoke` and `root restore` before their act, and more
//! `--peer` addresses than one Open carries refuse as usage before anything is written, `serve` running
//! or not. A resident scripted here answers this home's control socket, one connection at a time.

use core::time::Duration;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

use keystore::{KeyFile, Protection};
use swoosh::home::Home;
use swoosh::roster::{Epoch, RosterDoc};
use swoosh::serve::control_codec::{
    DisabledList, OpenRefusal, Request, Response, ServiceMenu, StatusReply,
};
use swoosh::testkit::{STANDING_UNTIL, TestNode, TestRoot};

/// The root this machine is a device of.
const ROOT: u8 = 0x61;
/// This machine.
const DESK: u8 = 0x62;
/// Its other devices.
const NAS: u8 = 0x63;
const PHONE: u8 = 0x64;

/// How long a run may take before the test calls it hung.
const HUNG: Duration = Duration::from_secs(60);

/// A device of `ROOT` holding a list that names `me/nas` and `me/phone`, its key plain: a home `revoke
/// me/phone` would write to.
async fn device(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("sw-exroute-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let mut seed = TestNode::seeded(DESK).seed();
    swoosh::identity::make_machine_dir(&home).unwrap();
    KeyFile::new(home.key())
        .write(&keystore::Secret::take(&mut seed), Protection::Plain)
        .unwrap();
    let root = TestRoot::seeded(ROOT);
    swoosh::config::write_signet(&swoosh::testkit::lock(), &home, root.node_id()).unwrap();
    let until = SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL);
    let badge = root
        .device_badge(TestNode::seeded(DESK).node_id(), until)
        .unwrap();
    swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &badge).unwrap();
    let members = [(DESK, "desk"), (NAS, "nas"), (PHONE, "phone")]
        .into_iter()
        .map(|(seed, label)| {
            root.member(TestNode::seeded(seed).verify_key(), label.parse().unwrap())
                .unwrap()
        })
        .collect();
    let update = root.sign_update(&RosterDoc::new(Epoch(1), members).unwrap());
    swoosh::roster::fold(
        &swoosh::home::HomeWrite::take(&home).await.unwrap(),
        &home,
        &update,
    )
    .await
    .unwrap();
    home
}

/// Every file under `dir`, with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                files.insert(path, bytes);
            }
        }
    }
    files
}

/// One Open the resident answered: its service, the machine it was for, and the addresses it carried.
struct Heard {
    service: String,
    peer: bifrost::NodeId,
    hints: Vec<core::net::SocketAddr>,
}

/// A resident on `home`'s control socket, `serve.lock` held and the socket bound before it returns: it
/// reads one request per connection, one connection at a time, answers a status as this machine's key,
/// as a real one runs, and refuses each Open as busy, until `stop`. Resolves to the Opens it answered.
async fn resident(
    home: &Home,
    stop: tightbeam::tunnel::CancellationToken,
) -> tokio::task::JoinHandle<Vec<Heard>> {
    use std::os::unix::fs::PermissionsExt as _;

    let root = swoosh::home::runtime_root().unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A sibling test's fork holds the last lock's O_CLOEXEC flock copy until its exec: wait, bounded.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let (lock, listener) = loop {
        match swoosh::serve::acquire_single(home, &root).await {
            Err(
                swoosh::serve::SingleError::KeyChanging
                | swoosh::serve::SingleError::AlreadyResident { .. },
            ) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            taken => break taken.unwrap(),
        }
    };
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        let mut heard = Vec::new();
        loop {
            let (mut conn, _) = tokio::select! {
                accepted = listener.accept() => accepted.unwrap(),
                () = stop.cancelled() => break,
            };
            let open = match Request::read(&mut conn).await {
                Ok(Request::Open(open)) => open,
                Ok(asked @ (Request::Status | Request::Whoami)) => {
                    let _ = answer_of(&asked, TestNode::seeded(DESK).node_id())
                        .write(&mut conn)
                        .await;
                    continue;
                }
                Ok(_) | Err(_) => continue,
            };
            // An Open counts only when its reply reaches the client still waiting on it.
            if Response::OpenRefusal(OpenRefusal::Busy)
                .write(&mut conn)
                .await
                .is_ok()
            {
                heard.push(Heard {
                    service: open.service().to_string(),
                    peer: open.peer(),
                    hints: open.hints().as_slice().to_vec(),
                });
            }
        }
        drop(lock);
        heard
    })
}

/// What a `serve` running as `node_id` answers `asked`, a `Whoami` (the probe) or a `Status` (an ask after
/// an Open went unanswered): the same `serve` either way.
fn answer_of(asked: &Request, node_id: bifrost::NodeId) -> Response {
    match asked {
        Request::Whoami => Response::Whoami { node_id },
        _ => Response::Status(status_of(node_id)),
    }
}

/// The status a resident running as `node_id` answers, serving nothing.
fn status_of(node_id: bifrost::NodeId) -> StatusReply {
    StatusReply {
        node_id,
        pid: 1,
        addr: None,
        uptime_secs: 0,
        menu: ServiceMenu {
            catalog: tightbeam::tunnel::ServiceCatalog::decode(&0_u32.to_be_bytes()).unwrap(),
            disabled: DisabledList::Known(Vec::new()),
        },
        warm: Vec::new(),
    }
}

/// Run the compiled binary on `home` with `argv`, nothing on stdin and no reach setting from the
/// environment, polled so the resident on this thread keeps answering: its exit code and stderr.
async fn swoosh(home: &Home, argv: &[&str]) -> (Option<i32>, String) {
    use std::io::Read as _;

    let mut child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home.dir())
        .args(argv)
        .env_remove("SWOOSH_HOME")
        .env_remove("SWOOSH_LOCAL")
        .env_remove("SWOOSH_RELAY")
        .env_remove("SWOOSH_RESOLVER")
        .env_remove("SWOOSH_PEER")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = tokio::time::Instant::now() + HUNG;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if tokio::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{argv:?} hung");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let mut stderr = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr);
    }
    (status, stderr)
}

/// With `serve` answering, `sync` binds nothing: each exchange is an Open there, and the connection that
/// showed `serve` answers is let go first, so a resident that reads one connection at a time is not held.
#[tokio::test]
async fn sync_rides_the_resident_in_the_binary() {
    let home = device("ride").await;
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = resident(&home, stop.clone()).await;
    let (status, stderr) = swoosh(&home, &["sync"]).await;
    stop.cancel();
    let heard = resident.await.unwrap();
    assert_eq!(status, Some(0), "{stderr}");
    assert_eq!(
        heard
            .iter()
            .map(|open| open.service.as_str())
            .collect::<Vec<_>>(),
        vec![swoosh::serve::SYNC_SERVICE; 2],
        "one Open per device: {stderr}"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// With `serve` answering, `sync --peer <key>=<addr>` carries the address on that machine's Open and on
/// no other: the addresses checked where the command line is read reach the Opens.
#[tokio::test]
async fn sync_carries_its_peer_addresses_through_the_resident() {
    let home = device("ride-hints").await;
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = resident(&home, stop.clone()).await;
    let nas = TestNode::seeded(NAS).node_id();
    let hint = format!("{nas}=127.0.0.1:4433");
    let (status, stderr) = swoosh(&home, &["sync", "--peer", &hint]).await;
    stop.cancel();
    let heard = resident.await.unwrap();
    assert_eq!(status, Some(0), "{stderr}");
    assert_eq!(heard.len(), 2, "{stderr}");
    for open in &heard {
        let expected = match open.peer == nas {
            true => vec!["127.0.0.1:4433".parse().unwrap()],
            false => Vec::new(),
        };
        assert_eq!(open.hints, expected, "{}", open.service);
    }
    let _ = std::fs::remove_dir_all(home.dir());
}

/// With `serve` answering, a reach flag refuses `join`, `revoke` and `root restore` before their act:
/// the moot line, exit 1, the home as it was.
#[tokio::test]
async fn a_reach_flag_refuses_a_local_act_before_it_writes() {
    for argv in [
        vec![
            "join",
            "--relay",
            "https://relay.example.com",
            "not-an-invite",
        ],
        vec!["revoke", "--relay", "https://relay.example.com", "me/phone"],
        vec![
            "root",
            "restore",
            "--relay",
            "https://relay.example.com",
            "/nonexistent-copy",
        ],
    ] {
        let home = device(&format!("moot-{}", argv[0])).await;
        let stop = tightbeam::tunnel::CancellationToken::new();
        let resident = resident(&home, stop.clone()).await;
        let before = snapshot(home.dir());
        let (status, stderr) = swoosh(&home, &argv).await;
        let after = snapshot(home.dir());
        stop.cancel();
        let heard = resident.await.unwrap();
        assert_eq!(status, Some(1), "{argv:?}: {stderr}");
        assert!(
            stderr.contains("--relay or SWOOSH_RELAY does not apply while swoosh serve runs here"),
            "{argv:?}: {stderr}"
        );
        assert!(heard.is_empty(), "{argv:?}: no Open");
        assert!(after == before, "{argv:?}: the home is as it was");
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// More `--peer` addresses for one machine than one Open carries are a usage error, exit 2, before
/// anything is written or opened, on every path: `revoke` and `sync` with `serve` running and without,
/// `invite` and `join` without.
#[tokio::test]
async fn crowded_hints_refuse_before_anything_is_written() {
    let crowded: Vec<String> = (0..17)
        .map(|port| {
            format!(
                "{}=127.0.0.1:{}",
                TestNode::seeded(NAS).node_id(),
                4000 + port
            )
        })
        .collect();
    let line = format!(
        "--peer or SWOOSH_PEER gives more than 16 addresses for one key:\n  {}",
        TestNode::seeded(NAS).node_id()
    );
    for (verb, serving) in [
        ("revoke", true),
        ("revoke", false),
        ("sync", true),
        ("sync", false),
        ("invite", false),
        ("join", false),
    ] {
        let home = device(&format!("crowded-{verb}-{serving}")).await;
        let mut argv = vec![verb];
        for hint in &crowded {
            argv.extend(["--peer", hint.as_str()]);
        }
        match verb {
            "revoke" => argv.push("me/phone"),
            "invite" => argv.extend(["tv", "--new-key"]),
            _ => {}
        }
        let stop = tightbeam::tunnel::CancellationToken::new();
        let resident = match serving {
            true => Some(resident(&home, stop.clone()).await),
            false => None,
        };
        let before = snapshot(home.dir());
        let (status, stderr) = swoosh(&home, &argv).await;
        let after = snapshot(home.dir());
        stop.cancel();
        let heard = match resident {
            Some(resident) => resident.await.unwrap(),
            None => Vec::new(),
        };
        assert_eq!(status, Some(2), "{verb} {serving}: {stderr}");
        assert!(stderr.contains(&line), "{verb} {serving}: {stderr}");
        assert!(heard.is_empty(), "{verb} {serving}: no Open");
        assert!(after == before, "{verb} {serving}: the home is as it was");
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// A `--peer` address no machine is reached at is a usage error with its own line, exit 2, before
/// anything is written or opened, `serve` running or not.
#[tokio::test]
async fn an_unusable_hint_refuses_before_anything_is_written() {
    let hint = format!("{}=0.0.0.0:4433", TestNode::seeded(NAS).node_id());
    for (verb, serving) in [
        ("revoke", true),
        ("revoke", false),
        ("sync", true),
        ("sync", false),
    ] {
        let home = device(&format!("unusable-{verb}-{serving}")).await;
        let mut argv = vec![verb, "--peer", hint.as_str()];
        if verb == "revoke" {
            argv.push("me/phone");
        }
        let stop = tightbeam::tunnel::CancellationToken::new();
        let resident = match serving {
            true => Some(resident(&home, stop.clone()).await),
            false => None,
        };
        let before = snapshot(home.dir());
        let (status, stderr) = swoosh(&home, &argv).await;
        let after = snapshot(home.dir());
        stop.cancel();
        let heard = match resident {
            Some(resident) => resident.await.unwrap(),
            None => Vec::new(),
        };
        assert_eq!(status, Some(2), "{verb} {serving}: {stderr}");
        assert!(
            stderr.contains("--peer or SWOOSH_PEER gives an address no machine can be reached at"),
            "{verb} {serving}: {stderr}"
        );
        assert!(heard.is_empty(), "{verb} {serving}: no Open");
        assert!(after == before, "{verb} {serving}: the home is as it was");
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// `home`'s `serve.lock` held and its socket file left with no listener, as a `serve` holds them while
/// this command cannot reach it. Dropping it frees both.
async fn held_unreachable(home: &Home) -> swoosh::serve::InstanceLock {
    use std::os::unix::fs::PermissionsExt as _;

    let root = swoosh::home::runtime_root().unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let (lock, listener) = loop {
        match swoosh::serve::acquire_single(home, &root).await {
            Err(
                swoosh::serve::SingleError::KeyChanging
                | swoosh::serve::SingleError::AlreadyResident { .. },
            ) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            taken => break taken.unwrap(),
        }
    };
    drop(listener);
    lock
}

/// Section 6's second form for `home`, its last line left out on macOS.
fn unreached(home: &Home) -> String {
    let last = match cfg!(target_os = "macos") {
        true => "",
        false => "\n  Otherwise set XDG_RUNTIME_DIR to the value swoosh serve has.",
    };
    format!(
        "error: swoosh serve is running for this home, but this command cannot reach it\n  Nothing \
         answers at {}.\n  If swoosh serve has just started, run this command again.{last}\n",
        home.control_socket().unwrap().display()
    )
}

/// With a reach flag, `join`, `revoke` and `root restore` ask before their act, and a `serve` that holds
/// the lock but cannot be reached refuses there: the out-of-reach line, then that nothing was changed,
/// exit 1, the home as it was.
#[tokio::test]
async fn a_flagged_root_act_refuses_a_held_unreachable_serve_first() {
    for argv in flagged_root_acts() {
        let home = device(&format!("flagged-unreached-{}", argv[0])).await;
        let lock = held_unreachable(&home).await;
        let before = snapshot(home.dir());
        let (status, stderr) = swoosh(&home, &argv).await;
        let after = snapshot(home.dir());
        drop(lock);
        assert_eq!(status, Some(1), "{argv:?}: {stderr}");
        assert_eq!(
            stderr,
            format!("{}  Nothing was changed.\n", unreached(&home)),
            "{argv:?}"
        );
        assert!(after == before, "{argv:?}: the home is as it was");
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// With a reach flag, `join`, `revoke` and `root restore` ask before their act, and a `serve` that holds
/// the lock but never answers, or answers in another version, refuses there: its line, then that nothing
/// was changed, exit 1, the home as it was.
#[tokio::test]
async fn a_flagged_root_act_against_a_stalled_or_skewed_serve_changes_nothing() {
    let stalled = "error: swoosh serve did not answer here\n  Restart it.\n";
    let skewed = "error: swoosh serve on this machine is a different version\n  Restart it with this version.\n";
    for (wrong, line) in [(Wrong::Skewed, skewed), (Wrong::Stalled, stalled)] {
        for argv in flagged_root_acts() {
            let home = device(&format!("flagged-{wrong:?}-{}", argv[0])).await;
            let stop = tightbeam::tunnel::CancellationToken::new();
            let resident = answering_wrongly(&home, wrong, stop.clone()).await;
            let before = snapshot(home.dir());
            let (status, stderr) = swoosh(&home, &argv).await;
            let after = snapshot(home.dir());
            stop.cancel();
            resident.await.unwrap();
            assert_eq!(status, Some(1), "{wrong:?} {argv:?}: {stderr}");
            assert_eq!(
                stderr,
                format!("{line}  Nothing was changed.\n"),
                "{wrong:?} {argv:?}"
            );
            assert!(after == before, "{wrong:?} {argv:?}: the home is as it was");
            let _ = std::fs::remove_dir_all(home.dir());
        }
    }
}

/// How [`answering_wrongly`]'s resident answers.
#[derive(Debug, Clone, Copy)]
enum Wrong {
    /// It takes each connection and never replies.
    Stalled,
    /// It replies in another version of the control wire.
    Skewed,
}

/// A resident on `home`'s control socket, `serve.lock` held, that answers every connection as `wrong`
/// says, until `stop`.
async fn answering_wrongly(
    home: &Home,
    wrong: Wrong,
    stop: tightbeam::tunnel::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    use tokio::io::AsyncWriteExt as _;

    let (lock, listener) = claimed(home).await;
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let (mut conn, _) = tokio::select! {
                accepted = listener.accept() => accepted.unwrap(),
                () = stop.cancelled() => break,
            };
            match wrong {
                Wrong::Stalled => held.push(conn),
                Wrong::Skewed => {
                    let _ = Request::read(&mut conn).await;
                    let _ = conn.write_all(b"SWC9").await;
                }
            }
        }
        drop(held);
        drop(lock);
    })
}

/// `home`'s `serve.lock` taken and its control socket bound, as `serve` takes them.
async fn claimed(home: &Home) -> (swoosh::serve::InstanceLock, tokio::net::UnixListener) {
    use std::os::unix::fs::PermissionsExt as _;

    let root = swoosh::home::runtime_root().unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A sibling test's fork holds the last lock's O_CLOEXEC flock copy until its exec: wait, bounded.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let (lock, listener) = loop {
        match swoosh::serve::acquire_single(home, &root).await {
            Err(
                swoosh::serve::SingleError::KeyChanging
                | swoosh::serve::SingleError::AlreadyResident { .. },
            ) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            taken => break taken.unwrap(),
        }
    };
    listener.set_nonblocking(true).unwrap();
    (lock, tokio::net::UnixListener::from_std(listener).unwrap())
}

/// With a reach flag, `join`, `revoke` and `root restore` whose `serve.lock` cannot be read before their
/// act (`home.lock` held for good beside one a `serve` left) refuse there: the lock error, then that
/// nothing was changed, exit 1, the home as it was.
#[tokio::test]
async fn a_flagged_root_act_refuses_an_unread_lock_first() {
    for argv in flagged_root_acts() {
        let home = device(&format!("flagged-wedged-{}", argv[0])).await;
        // Free and empty, as a stopped `serve` leaves it: an absent one is free without the lock read.
        std::fs::write(home.serve_lock(), b"").unwrap();
        let write = swoosh::home::HomeWrite::take(&home).await.unwrap();
        let before = snapshot(home.dir());
        let (status, stderr) = swoosh(&home, &argv).await;
        let after = snapshot(home.dir());
        drop(write);
        assert_eq!(status, Some(1), "{argv:?}: {stderr}");
        assert_eq!(
            stderr,
            format!(
                "error: could not lock {}: timed out\n  Nothing was changed.\n",
                home.home_lock().display()
            ),
            "{argv:?}"
        );
        assert!(after == before, "{argv:?}: the home is as it was");
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// With a reach flag, `join`, `revoke` and `root restore` ask before their act, and a control socket
/// another process answers refuses there with its own line alone, which already says nothing was sent:
/// exit 1, the home as it was.
#[tokio::test]
async fn a_flagged_root_act_refuses_a_socket_another_process_answers() {
    for argv in flagged_root_acts() {
        let home = device(&format!("flagged-unattributed-{}", argv[0])).await;
        let (lock, listener) = claimed(&home).await;
        std::fs::write(home.serve_lock(), format!("{}\n", std::process::id() + 1)).unwrap();
        let before = snapshot(home.dir());
        let (status, stderr) = swoosh(&home, &argv).await;
        let after = snapshot(home.dir());
        drop((lock, listener));
        assert_eq!(status, Some(1), "{argv:?}: {stderr}");
        assert_eq!(
            stderr,
            format!(
                "error: another process is answering swoosh serve's socket\n  Process {} answers at \
                 {}.\n  Nothing was sent through it.\n",
                std::process::id(),
                home.control_socket().unwrap().display()
            ),
            "{argv:?}"
        );
        assert!(after == before, "{argv:?}: the home is as it was");
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// With a reach flag, `join`, `revoke` and `root restore` ask before their act, and a control socket
/// whose directory is open to others refuses there with its own line alone, which already says nothing
/// was sent: exit 1, the home as it was.
#[tokio::test]
async fn a_flagged_root_act_refuses_a_socket_not_private_to_you() {
    use std::os::unix::fs::PermissionsExt as _;

    for argv in flagged_root_acts() {
        let home = device(&format!("flagged-untrusted-{}", argv[0])).await;
        let (lock, listener) = claimed(&home).await;
        let leaf = home.runtime_dir().unwrap();
        let before = snapshot(home.dir());
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (status, stderr) = swoosh(&home, &argv).await;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o700)).unwrap();
        let after = snapshot(home.dir());
        drop((lock, listener));
        assert_eq!(status, Some(1), "{argv:?}: {stderr}");
        assert_eq!(
            stderr,
            format!(
                "error: swoosh serve's socket is not private to you\n  {} is not yours alone.\n  \
                 Nothing was sent through it.\n",
                leaf.display()
            ),
            "{argv:?}"
        );
        assert!(after == before, "{argv:?}: the home is as it was");
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// `join`, `revoke` and `root restore`, each with a reach flag, so each asks `serve` before its act.
fn flagged_root_acts() -> [Vec<&'static str>; 3] {
    [
        vec![
            "join",
            "--relay",
            "https://relay.example.com",
            "not-an-invite",
        ],
        vec!["revoke", "--relay", "https://relay.example.com", "me/phone"],
        vec![
            "root",
            "restore",
            "--relay",
            "https://relay.example.com",
            "/nonexistent-copy",
        ],
    ]
}

/// A revoke that dials nobody (a device's, with no root kept here) lands whole beside a control socket
/// it could not trust (a 0755 leaf): no probe runs before or after its act, so `serve`'s socket can never
/// stop a local cut. Exit 0, the home changed, no error.
#[tokio::test]
async fn a_local_only_revoke_lands_beside_an_untrusted_socket() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = device("local-revoke").await;
    let lock = held_unreachable(&home).await;
    let leaf = home.runtime_dir().unwrap();
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
    let before = snapshot(home.dir());
    let (status, stderr) = swoosh(&home, &["revoke", "me/phone"]).await;
    let after = snapshot(home.dir());
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(lock);
    assert_eq!(status, Some(0), "{stderr}");
    assert!(!stderr.contains("error:"), "{stderr}");
    assert!(after != before, "the act landed");
    let _ = std::fs::remove_dir_all(home.dir());
}
