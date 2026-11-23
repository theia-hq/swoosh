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
use swoosh::serve::control_codec::{OpenRefusal, Request, Response};
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
/// reads one request per connection, one connection at a time, and refuses each Open as busy, until
/// `stop`. Resolves to the Opens it answered.
async fn resident(
    home: &Home,
    stop: tightbeam::tunnel::CancellationToken,
) -> tokio::task::JoinHandle<Vec<Heard>> {
    use std::os::unix::fs::PermissionsExt as _;

    let root = swoosh::home::runtime_root().unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (lock, listener) = swoosh::serve::acquire_single(home, &root).await.unwrap();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        let mut heard = Vec::new();
        loop {
            let (mut conn, _) = tokio::select! {
                accepted = listener.accept() => accepted.unwrap(),
                () = stop.cancelled() => break,
            };
            // An Open counts only when its reply reaches the client still waiting on it.
            if let Ok(Request::Open(open)) = Request::read(&mut conn).await
                && Response::OpenRefusal(OpenRefusal::Busy)
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
        "--peer or SWOOSH_PEER gives more than 16 addresses for {}",
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
