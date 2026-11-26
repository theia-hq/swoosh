// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The dialing verbs as the compiled binary runs them beside a running `serve`: more `--peer` addresses
//! than one Open carries refuse as usage before `serve` is asked, and an expiring badge warns once,
//! before the first Open, keyed to the key `serve` runs as, with no machine key unlocked. A resident
//! scripted here answers this home's control socket, one connection at a time.

use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bifrost::NodeId;
use keystore::{KeyFile, Protection};
use swoosh::home::Home;
use swoosh::roster::{Epoch, RosterDoc};
use swoosh::serve::control_codec::{
    DisabledList, MAX_FRAME, OpenRefusal, PeerEntry, Request, Response, ServiceMenu, StatusReply,
};
use swoosh::testkit::{TestNode, TestRoot};

/// The root this machine is a device of.
const ROOT: u8 = 0x81;
/// This machine.
const DESK: u8 = 0x82;
/// Its other device, the one every verb here dials.
const NAS: u8 = 0x83;
/// The key the scripted `serve` says it runs as: this machine's, as a real one's is.
const RESIDENT: u8 = DESK;

/// The passphrase this machine's key is sealed under; nothing here is ever asked it.
const PASS: &str = "correct horse battery staple";

/// How long a run may take before the test calls it hung.
const HUNG: Duration = Duration::from_secs(60);

/// A device of `ROOT` listing `me/nas`, its key sealed, its badge ending `days` from now and its last
/// exchange just now, so a dial makes no exchange.
async fn device(tag: &str, days: u64) -> Home {
    device_keyed(tag, days, true).await
}

/// [`device`], its key sealed or plain.
async fn device_keyed(tag: &str, days: u64, sealed: bool) -> Home {
    let dir = std::env::temp_dir().join(format!("sw-dialroute-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let mut seed = TestNode::seeded(DESK).seed();
    swoosh::identity::make_machine_dir(&home).unwrap();
    let passphrase =
        keystore::Passphrase::try_from(zeroize::Zeroizing::new(PASS.to_owned())).unwrap();
    let protection = match sealed {
        true => Protection::Passphrase(&passphrase),
        false => Protection::Plain,
    };
    KeyFile::new(home.key())
        .write(&keystore::Secret::take(&mut seed), protection)
        .unwrap();
    let root = TestRoot::seeded(ROOT);
    swoosh::config::write_signet(&swoosh::testkit::lock(), &home, root.node_id()).unwrap();
    let until = SystemTime::now() + Duration::from_secs(days * 24 * 3600);
    let badge = root
        .device_badge(TestNode::seeded(DESK).node_id(), until)
        .unwrap();
    swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &badge).unwrap();
    let members = [(DESK, "desk"), (NAS, "nas")]
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
    // Again after the fold, which stores the list's own standing for this machine.
    swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &badge).unwrap();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::write(home.synced(), format!("{now}\n")).unwrap();
    home
}

/// A file to send.
fn a_file(home: &Home) -> String {
    let file = home.dir().with_extension("note");
    std::fs::write(&file, b"hello").unwrap();
    file.to_str().unwrap().to_owned()
}

/// What the scripted resident saw.
#[derive(Default)]
struct Seen {
    /// Every connection it accepted.
    connects: AtomicUsize,
    /// The statuses it answered before the first Open: a run asking whether `serve` answers, and as what.
    probes: AtomicUsize,
    /// The connections that closed before a request.
    bare: AtomicUsize,
    /// The services of the Opens it heard, in order.
    opens: Mutex<Vec<String>>,
    /// The addresses each Open carried, in order.
    hints: Mutex<Vec<Vec<core::net::SocketAddr>>>,
}

/// `home`'s `serve.lock` and control socket, taken as a `serve` takes them, its listener on this runtime.
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

/// A resident on `home`'s control socket, `serve.lock` held and the socket bound before it returns: it
/// reads one request per connection, one at a time, answers status as [`RESIDENT`] and refuses each Open
/// as busy, until `stop`.
async fn resident(
    home: &Home,
    seen: Arc<Seen>,
    stop: tightbeam::tunnel::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    resident_of(
        home,
        status_of(TestNode::seeded(RESIDENT).node_id()),
        seen,
        stop,
    )
    .await
}

/// [`resident`], answering a status with `status`: one past the frame drops the connection with no
/// reply, as a `serve` whose encoder refuses it does.
async fn resident_of(
    home: &Home,
    status: StatusReply,
    seen: Arc<Seen>,
    stop: tightbeam::tunnel::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let (lock, listener) = claimed(home).await;
    tokio::spawn(async move {
        loop {
            let (mut conn, _) = tokio::select! {
                accepted = listener.accept() => accepted.unwrap(),
                () = stop.cancelled() => break,
            };
            seen.connects.fetch_add(1, Ordering::SeqCst);
            match Request::read(&mut conn).await {
                Ok(asked @ (Request::Status | Request::Whoami)) => {
                    if seen.opens.lock().unwrap().is_empty() {
                        seen.probes.fetch_add(1, Ordering::SeqCst);
                    }
                    let answer = match asked {
                        Request::Whoami => Response::Whoami {
                            node_id: status.node_id,
                        },
                        _ => Response::Status(status.clone()),
                    };
                    let _ = answer.write(&mut conn).await;
                }
                Ok(Request::Open(open)) => {
                    seen.opens.lock().unwrap().push(open.service().to_string());
                    seen.hints
                        .lock()
                        .unwrap()
                        .push(open.hints().as_slice().to_vec());
                    let _ = Response::OpenRefusal(OpenRefusal::Busy)
                        .write(&mut conn)
                        .await;
                }
                Ok(_) => {}
                Err(_) => {
                    seen.bare.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        drop(lock);
    })
}

fn status_of(node_id: NodeId) -> StatusReply {
    StatusReply {
        node_id,
        pid: 1,
        reach: swoosh::testkit::loopback_reach(),
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
    swoosh_with(home, argv, |_| {}).await
}

/// [`swoosh`] with `XDG_RUNTIME_DIR` set to `xdg`, or unset with `None`.
#[cfg(target_os = "linux")]
async fn swoosh_in(home: &Home, argv: &[&str], xdg: Option<&str>) -> (Option<i32>, String) {
    swoosh_with(home, argv, |command| match xdg {
        Some(value) => {
            command.env("XDG_RUNTIME_DIR", value);
        }
        None => {
            command.env_remove("XDG_RUNTIME_DIR");
        }
    })
    .await
}

/// [`swoosh`], its command first shaped by `shape`.
async fn swoosh_with(
    home: &Home,
    argv: &[&str],
    shape: impl FnOnce(&mut std::process::Command),
) -> (Option<i32>, String) {
    use std::io::BufRead as _;

    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_swoosh"));
    shape(&mut command);
    let mut child = command
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
    // Read on a thread of its own, so a full pipe never holds the run.
    let stderr = std::io::BufReader::new(child.stderr.take().unwrap());
    let reader = std::thread::spawn(move || {
        let mut read = String::new();
        for line in stderr.lines() {
            read.push_str(&line.unwrap());
            read.push('\n');
        }
        read
    });
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
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    (status, reader.join().unwrap())
}

/// The dialing verbs, each to `me/nas`: the bridge and the stop among them.
fn dialing(file: &str) -> [Vec<&str>; 6] {
    [
        vec!["ping", "me/nas", "-c", "1"],
        vec!["speed", "me/nas", "-n", "1024"],
        vec!["status", "me/nas"],
        vec!["send", file, "me/nas"],
        vec!["forward", "me/nas", "ssh", "-"],
        vec!["stop", "me/nas"],
    ]
}

/// More `--peer` addresses for one key than one Open carries refuse each dialing verb as usage, exit 2,
/// before `serve` is asked: no connection reaches its socket, running or not.
#[tokio::test]
async fn crowded_hints_refuse_a_dialing_verb_first() {
    let nas = TestNode::seeded(NAS).node_id();
    let crowded: Vec<String> = (0..17)
        .map(|port| format!("{nas}=127.0.0.1:{}", 4000 + port))
        .collect();
    let line = format!("--peer or SWOOSH_PEER gives more than 16 addresses for one key:\n  {nas}");
    for serving in [true, false] {
        let home = device(&format!("crowded-{serving}"), 60).await;
        let file = a_file(&home);
        let port = ["forward", "me/nas", "ssh", "5432"].to_vec();
        let proxy = ["proxy", "me/nas", "http://example.com/x"].to_vec();
        for verb in dialing(&file).into_iter().chain([port, proxy]) {
            let mut argv = verb.clone();
            for hint in &crowded {
                argv.extend(["--peer", hint.as_str()]);
            }
            let seen = Arc::new(Seen::default());
            let stop = tightbeam::tunnel::CancellationToken::new();
            let resident = match serving {
                true => Some(resident(&home, Arc::clone(&seen), stop.clone()).await),
                false => None,
            };
            let (status, stderr) = swoosh(&home, &argv).await;
            stop.cancel();
            if let Some(resident) = resident {
                resident.await.unwrap();
            }
            assert_eq!(status, Some(2), "{} {serving}: {stderr}", verb[0]);
            assert!(stderr.contains(&line), "{} {serving}: {stderr}", verb[0]);
            // The verb's own usage line, never the root's: the arm finds the verb word as typed.
            let usage = match verb[0] {
                "ping" => "Usage: swoosh ping [OPTIONS] <machine>",
                "speed" => "Usage: swoosh speed [OPTIONS] <machine>",
                "status" => "Usage: swoosh status [OPTIONS] [machine]",
                "send" => "Usage: swoosh send [OPTIONS] <path>... <machine>",
                "forward" => {
                    "Usage: swoosh forward [OPTIONS] <machine> <service> <port | unix:<path> | ->"
                }
                "proxy" => "Usage: swoosh proxy [OPTIONS] <machine> <url>",
                "stop" => "Usage: swoosh stop [OPTIONS] [me/<name>]",
                other => panic!("{other}: not a dialing verb"),
            };
            assert!(stderr.contains(usage), "{} {serving}: {stderr}", verb[0]);
            assert_eq!(
                seen.connects.load(Ordering::SeqCst),
                0,
                "{} {serving}: no connect",
                verb[0]
            );
        }
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// Through `serve`, the bridge's Open carries the `--peer` addresses typed for its machine, which the
/// `ProxyCommand` line `swoosh ssh` writes passes on.
#[tokio::test]
async fn the_bridge_carries_its_peer_hints_through_serve() {
    let hint = format!("{}=127.0.0.1:4000", TestNode::seeded(NAS).node_id());
    let home = device("bridge-hints", 60).await;
    let seen = Arc::new(Seen::default());
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = resident(&home, Arc::clone(&seen), stop.clone()).await;
    let (status, stderr) = swoosh(&home, &["forward", "me/nas", "ssh", "-", "--peer", &hint]).await;
    stop.cancel();
    resident.await.unwrap();
    assert_eq!(status, Some(1), "{stderr}");
    let addr: core::net::SocketAddr = "127.0.0.1:4000".parse().unwrap();
    assert_eq!(*seen.hints.lock().unwrap(), [vec![addr]], "{stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Through `serve`, a badge inside the warning window warns once on stderr, naming the key `serve` runs as
/// in its remedy, with no machine key read: the key file is gone, so a read would fail the run. Outside the
/// window there is no line. (Its order against the first Open is pinned in-process, where one log holds
/// both.)
#[tokio::test]
async fn an_expiring_badge_warns_once_through_serve() {
    let warning = "swoosh: this device's membership badge expires in";
    let remedy = format!(
        "renew it where your root is kept: swoosh invite <name> {}.",
        TestNode::seeded(RESIDENT).node_id()
    );
    for (days, warns) in [(3, true), (60, false)] {
        let home = device(&format!("warn-{days}"), days).await;
        std::fs::remove_file(home.key()).unwrap();
        let file = a_file(&home);
        for argv in dialing(&file) {
            let seen = Arc::new(Seen::default());
            let stop = tightbeam::tunnel::CancellationToken::new();
            let resident = resident(&home, Arc::clone(&seen), stop.clone()).await;
            let (status, stderr) = swoosh(&home, &argv).await;
            stop.cancel();
            resident.await.unwrap();
            let verb = argv[0];
            assert_eq!(status, Some(1), "{verb}: {stderr}");
            assert!(
                !seen.opens.lock().unwrap().is_empty(),
                "{verb}: the run opened through serve: {stderr}"
            );
            assert!(!stderr.contains("key"), "{verb}: no key read: {stderr}");
            assert!(
                stderr.contains("too many connections open through swoosh serve"),
                "{verb}: the Open's own line: {stderr}"
            );
            if !warns {
                assert!(!stderr.contains(warning), "{verb}: {stderr}");
                continue;
            }
            assert_eq!(stderr.matches(warning).count(), 1, "{verb}: {stderr}");
            assert!(stderr.contains(&remedy), "{verb}: {stderr}");
        }
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// By own bind, with no `serve` here, the run's one resolve before its bind warns once, and its opens
/// say nothing more.
#[tokio::test]
async fn an_expiring_badge_warns_once_by_own_bind() {
    let warning = "swoosh: this device's membership badge expires in";
    let home = device_keyed("warn-own", 3, false).await;
    let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1", "--local"]).await;
    assert_eq!(status, Some(1), "{stderr}");
    assert_eq!(stderr.matches(warning).count(), 1, "{stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Through `serve`, a reach flag it makes moot refuses each dialing verb first: the moot line, exit 1,
/// with no Open, no exchange and no warning for a badge inside its window.
#[tokio::test]
async fn a_reach_flag_refuses_a_dialing_verb_before_anything() {
    let warning = "swoosh: this device's membership badge expires in";
    let home = device("moot", 3).await;
    let file = a_file(&home);
    for mut argv in dialing(&file) {
        argv.push("--local");
        let seen = Arc::new(Seen::default());
        let stop = tightbeam::tunnel::CancellationToken::new();
        let resident = resident(&home, Arc::clone(&seen), stop.clone()).await;
        let (status, stderr) = swoosh(&home, &argv).await;
        stop.cancel();
        resident.await.unwrap();
        let verb = argv[0];
        assert_eq!(status, Some(1), "{verb}: {stderr}");
        assert!(
            stderr.starts_with(
                "error: --local or SWOOSH_LOCAL does not apply while swoosh serve runs here"
            ),
            "{verb}: {stderr}"
        );
        assert!(!stderr.contains(warning), "{verb}: {stderr}");
        assert!(seen.opens.lock().unwrap().is_empty(), "{verb}: no Open");
    }
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Through `serve`, `stop me/nas` on a machine whose key is sealed asks no passphrase: its Open is the
/// one `serve` answers, here refused busy, and its line is that refusal's. An own bind would ask for the
/// key's passphrase on a closed stdin and fail on that instead.
#[tokio::test]
async fn stop_through_serve_asks_no_passphrase() {
    let home = device("stop-sealed", 60).await;
    let seen = Arc::new(Seen::default());
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = resident(&home, Arc::clone(&seen), stop.clone()).await;
    let (status, stderr) = swoosh(&home, &["stop", "me/nas"]).await;
    stop.cancel();
    resident.await.unwrap();
    assert_eq!(status, Some(1), "{stderr}");
    assert_eq!(*seen.opens.lock().unwrap(), ["control.serve"], "{stderr}");
    assert!(!stderr.contains("passphrase"), "{stderr}");
    assert!(
        stderr.starts_with("error: too many connections open through swoosh serve on this machine"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A run through `serve` asks it whether it answers once, with one `Whoami` before its first Open,
/// whatever the verb: every dialing verb, every `forward` end, and an exchange verb. No connection it
/// makes carries nothing.
#[tokio::test]
async fn a_run_through_serve_probes_it_once() {
    let home = device("probes-once", 60).await;
    let file = a_file(&home);
    let more = [
        vec!["forward", "me/nas", "ssh", "5432"],
        vec!["forward", "me/nas", "ssh", "unix:/x"],
        vec!["proxy", "me/nas", "http://example.com/x"],
        vec!["sync"],
    ];
    for argv in dialing(&file).into_iter().chain(more) {
        let seen = Arc::new(Seen::default());
        let stop = tightbeam::tunnel::CancellationToken::new();
        let resident = resident(&home, Arc::clone(&seen), stop.clone()).await;
        let (_, stderr) = swoosh(&home, &argv).await;
        stop.cancel();
        resident.await.unwrap();
        assert_eq!(seen.probes.load(Ordering::SeqCst), 1, "{argv:?}: {stderr}");
        assert_eq!(seen.bare.load(Ordering::SeqCst), 0, "{argv:?}: {stderr}");
    }
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A `serve` whose status is past the frame, its catalog and 64 warm peers filling it, still answers the
/// probe with its key alone, so the verb rides it.
#[tokio::test]
async fn whoami_ignores_menu() {
    let home = device("whoami-menu", 60).await;
    let mut catalog = 32_u32.to_be_bytes().to_vec();
    for index in 0..32_u8 {
        catalog.extend_from_slice(&200_u16.to_be_bytes());
        catalog.push(b'a' + index % 26);
        catalog.extend_from_slice(&[b'x'; 199]);
        catalog.push(0);
    }
    let mut status = status_of(TestNode::seeded(RESIDENT).node_id());
    status.menu.catalog = tightbeam::tunnel::ServiceCatalog::decode(&catalog).unwrap();
    status.warm = (0..64_u8)
        .map(|seed| PeerEntry {
            peer: TestNode::seeded(seed).node_id(),
            idle_secs: 0,
        })
        .collect();
    assert!(
        status
            .encode()
            .is_ok_and(|payload| payload.len() > MAX_FRAME),
        "the status is past the frame"
    );
    let seen = Arc::new(Seen::default());
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = resident_of(&home, status, Arc::clone(&seen), stop.clone()).await;
    let (_, stderr) = swoosh(&home, &["stop", "me/nas"]).await;
    stop.cancel();
    resident.await.unwrap();
    assert_eq!(seen.probes.load(Ordering::SeqCst), 1, "{stderr}");
    assert_eq!(
        seen.opens.lock().unwrap().len(),
        1,
        "it rode serve: {stderr}"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// With a resident answering, `stop`, `proxy` and `forward` to a `unix:` end bind nothing beside it, so
/// they end without the sealed machine key's passphrase asked: `stop` and `proxy` Open there, and a `unix:` end refuses on its own line with
/// no Open, since its body refuses it on either path.
#[tokio::test]
async fn a_verb_binds_no_endpoint_while_serve_runs() {
    let home = device("no-endpoint", 60).await;
    for argv in [
        vec!["stop", "me/nas"],
        vec!["forward", "me/nas", "ssh", "unix:/x"],
        vec!["proxy", "me/nas", "http://example.com/x"],
    ] {
        let seen = Arc::new(Seen::default());
        let stop = tightbeam::tunnel::CancellationToken::new();
        let resident = resident(&home, Arc::clone(&seen), stop.clone()).await;
        let (status, stderr) = swoosh(&home, &argv).await;
        stop.cancel();
        resident.await.unwrap();
        assert_eq!(status, Some(1), "{argv:?}: {stderr}");
        assert!(!stderr.contains("passphrase"), "{argv:?}: {stderr}");
        let opens = seen.opens.lock().unwrap().clone();
        match argv[0] {
            "forward" => {
                assert_eq!(
                    stderr,
                    "error: a unix:<path> local end is not built yet: use a port, or - for stdout\n"
                );
                assert!(opens.is_empty(), "{opens:?}");
            }
            _ => {
                assert!(!opens.is_empty(), "{argv:?}: {stderr}");
                assert!(
                    stderr.starts_with("error: too many connections open through swoosh serve"),
                    "{argv:?}: {stderr}"
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(home.dir());
}

/// With a resident answering, `ping` typed with an `anyone` link binds a throwaway key of its own and
/// never asks `serve`: the resident sees no connection, and the run ends on its own bind's line.
#[tokio::test]
async fn an_anyone_link_binds_its_own_key_while_serve_runs() {
    let issuer = TestRoot::seeded(0x91);
    let link = issuer
        .slip(
            &swoosh::reach::PING_SERVICE.parse().unwrap(),
            SystemTime::now() + Duration::from_secs(3600),
        )
        .unwrap()
        .seal()
        .unwrap()
        .link()
        .unwrap();
    let link = swoosh::link::Link::from(link).to_string();
    // A port nothing answers on, so the own bind's dial fails here without asking the internet.
    let hint = format!("{}=127.0.0.1:9", issuer.node_id());
    let home = device("anyone", 60).await;
    let seen = Arc::new(Seen::default());
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = resident(&home, Arc::clone(&seen), stop.clone()).await;
    let argv = ["ping", &link, "-c", "1", "--local", "--peer", &hint];
    let (status, stderr) = swoosh(&home, &argv).await;
    stop.cancel();
    resident.await.unwrap();
    assert_eq!(seen.connects.load(Ordering::SeqCst), 0, "{stderr}");
    assert_eq!(status, Some(1), "{stderr}");
    // The `--local` teaching line is the own bind's: through `serve` the flag is refused first.
    assert!(stderr.starts_with("error: could not reach "), "{stderr}");
    assert!(
        stderr.contains("With --local or SWOOSH_LOCAL, swoosh looks for it on this network,"),
        "{stderr}"
    );
    assert!(!stderr.contains("swoosh serve"), "{stderr}");
    assert!(!stderr.contains("passphrase"), "{stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Section 7's line for `home`: process `pid` answers at its control socket.
fn unattributed(home: &Home, pid: u32) -> String {
    format!(
        "error: another process is answering swoosh serve's socket\n  Process {pid} answers at {}.\n  \
         Nothing was sent through it.\n",
        home.control_socket().unwrap().display()
    )
}

/// A control socket whose listener is not the process its home's `serve.lock` records: the line naming
/// the process that answered, never the mode or owner line, exit 1, no own bind, so the sealed machine
/// key is never asked for, and no request written.
#[tokio::test]
async fn a_socket_answered_by_another_pid_is_untrusted() {
    let home = device("another-pid", 60).await;
    let seen = Arc::new(Seen::default());
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = resident(&home, Arc::clone(&seen), stop.clone()).await;
    // The lock stays held; only the process it names is another.
    std::fs::write(home.serve_lock(), format!("{}\n", std::process::id() + 1)).unwrap();
    let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
    stop.cancel();
    resident.await.unwrap();
    assert_eq!(status, Some(1), "{stderr}");
    assert_eq!(stderr, unattributed(&home, std::process::id()));
    assert_eq!(seen.probes.load(Ordering::SeqCst), 0, "nothing was asked");
    assert!(seen.opens.lock().unwrap().is_empty(), "{stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A listener on this home's control socket with no `serve` behind it: `serve.lock` free and recording
/// nothing, or absent. What answers is named, exit 1, and the run neither goes through it nor binds its
/// own beside it.
#[tokio::test]
async fn a_squatted_socket_with_no_serve_record_is_an_error() {
    use std::os::unix::fs::PermissionsExt as _;

    for record in [None, Some("")] {
        let home = device("squatted", 60).await;
        if let Some(record) = record {
            std::fs::write(home.serve_lock(), record).unwrap();
        }
        let root = swoosh::home::runtime_root().unwrap();
        let leaf = home.runtime_dir().unwrap();
        std::fs::create_dir_all(&leaf).unwrap();
        for dir in [&root, &leaf] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let squatter =
            std::os::unix::net::UnixListener::bind(home.control_socket().unwrap()).unwrap();
        let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
        drop(squatter);
        let _ = std::fs::remove_dir_all(&leaf);
        assert_eq!(status, Some(1), "{record:?}: {stderr}");
        assert_eq!(
            stderr,
            unattributed(&home, std::process::id()),
            "{record:?}"
        );
        assert!(!asked_the_passphrase(&stderr), "{record:?}: {stderr}");
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// A control socket in a leaf that is not this user's alone (here mode 0755) is never connected to: the
/// line naming the leaf, exit 1, with no own bind, so the sealed machine key is never asked for.
#[tokio::test]
async fn an_untrusted_socket_reads_no_key() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = device("untrusted", 60).await;
    let seen = Arc::new(Seen::default());
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = resident(&home, Arc::clone(&seen), stop.clone()).await;
    let leaf = home.runtime_dir().unwrap();
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o700)).unwrap();
    stop.cancel();
    resident.await.unwrap();
    assert_eq!(status, Some(1), "{stderr}");
    assert_eq!(
        stderr,
        format!(
            "error: swoosh serve's socket is not private to you\n  {} is not yours alone.\n  Nothing \
             was sent through it.\n",
            leaf.display()
        )
    );
    assert!(!asked_the_passphrase(&stderr), "{stderr}");
    assert_eq!(seen.connects.load(Ordering::SeqCst), 0, "never connected");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `serve` answers the run's one probe, its `Whoami`, then stops before the first Open: the run ends on
/// the line for `serve` stopped, exit 1, and never falls back to a bind of its own. A connect landing
/// between the probe's reply and the lock's release would read a freed lock instead; the run's file reads
/// make that window microseconds against milliseconds, so the row runs several times to catch it should
/// it widen.
#[tokio::test]
async fn serve_gone_after_the_probe_is_the_stopped_line() {
    let home = device("gone-after-probe", 60).await;
    for run in 0..5 {
        let (lock, listener) = claimed(&home).await;
        let resident = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let probe = matches!(Request::read(&mut conn).await, Ok(Request::Whoami));
            if probe {
                let _ = Response::Whoami {
                    node_id: TestNode::seeded(RESIDENT).node_id(),
                }
                .write(&mut conn)
                .await;
            }
            // The lock first: freeing it removes the socket, so no later connect finds a listener.
            drop(lock);
            drop(listener);
            probe
        });
        let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
        assert!(
            resident.await.unwrap(),
            "run {run}: the first connection carried the probe's Whoami"
        );
        assert_eq!(status, Some(1), "run {run}: {stderr}");
        assert!(
            stderr
                .starts_with("error: swoosh serve stopped here and ended the connection to me/nas"),
            "run {run}: {stderr}"
        );
        assert!(!stderr.contains("passphrase"), "run {run}: {stderr}");
    }
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Through `serve`, `forward` to a `unix:` end with a reach flag ends on the `unix:` line, not the
/// flag's: the end is why it cannot run, whatever the flag. Exit 1, no Open, no passphrase asked.
#[tokio::test]
async fn a_unix_end_refuses_before_a_reach_flag_through_serve() {
    let home = device("unix-moot", 60).await;
    let seen = Arc::new(Seen::default());
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = resident(&home, Arc::clone(&seen), stop.clone()).await;
    let argv = ["forward", "me/nas", "ssh", "unix:/x", "--local"];
    let (status, stderr) = swoosh(&home, &argv).await;
    stop.cancel();
    resident.await.unwrap();
    assert_eq!(status, Some(1), "{stderr}");
    assert_eq!(
        stderr,
        "error: a unix:<path> local end is not built yet: use a port, or - for stdout\n"
    );
    assert!(seen.opens.lock().unwrap().is_empty(), "{stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `home`'s `serve.lock`, held as a `serve` or a key replacement holds it, recording this process when
/// `serving`, with no runtime leaf or socket made: a `serve` this command's runtime root does not show.
async fn held(home: &Home, serving: bool) -> swoosh::home::ServeLock {
    let write = swoosh::home::HomeWrite::take(home).await.unwrap();
    // A sibling test's fork holds the last lock's O_CLOEXEC flock copy until its exec: wait, bounded.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let lock = loop {
        match swoosh::home::ServeLock::take(&write, home) {
            Err(swoosh::home::ServeLockError::Held) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            taken => break taken.unwrap(),
        }
    };
    if serving {
        lock.record(&write, None).unwrap();
    }
    lock
}

/// The own bind's sign on a sealed key: it asks for the passphrase, which no command through `serve` or
/// refused before its bind ever does.
fn asked_the_passphrase(stderr: &str) -> bool {
    stderr.contains("passphrase")
}

/// `serve.lock` free, whatever it records (here this live process's pid, of this user), and no socket:
/// no `serve` runs, so the run binds its own.
#[tokio::test]
async fn a_free_serve_lock_binds_its_own_whatever_it_records() {
    let home = device("free-lock", 60).await;
    std::fs::write(home.serve_lock(), format!("{}\n", std::process::id())).unwrap();
    let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
    assert_eq!(status, Some(1), "{stderr}");
    assert!(asked_the_passphrase(&stderr), "own bind: {stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Section 6's second form for `home`: `serve` holds the lock but nothing answers where this command
/// looked. Its last line is left out on macOS, where no variable sets the root.
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

/// `serve.lock` held by a `serve` whose runtime root is not this command's, so no leaf is under it: the
/// line for a `serve` out of reach, exit 1, nothing bound and no passphrase asked.
#[tokio::test]
async fn a_held_serve_lock_with_another_runtime_dir_is_an_error() {
    let home = device("other-root", 60).await;
    let lock = held(&home, true).await;
    let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
    drop(lock);
    assert_eq!(status, Some(1), "{stderr}");
    assert_eq!(stderr, unreached(&home));
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A socket file no listener holds while `serve.lock` stays held: the connect is refused, as a live
/// macOS `serve` with a full accept queue refuses it, and that is a `serve` out of reach, not none.
#[tokio::test]
async fn a_held_lock_behind_a_refused_connect_is_an_error() {
    let home = device("refused-held", 60).await;
    let (lock, listener) = claimed(&home).await;
    drop(listener);
    let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
    drop(lock);
    assert_eq!(status, Some(1), "{stderr}");
    assert_eq!(stderr, unreached(&home));
    assert!(!asked_the_passphrase(&stderr), "{stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// The case behind it, on macOS: a live `serve` whose accept queue is full refuses a connect with
/// `ECONNREFUSED`, as a socket with no listener does. It still holds the lock, so the run names it out of
/// reach rather than binding beside it.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn a_full_accept_queue_is_not_no_serve() {
    let home = device("full-queue", 60).await;
    let (lock, listener) = claimed(&home).await;
    let socket = home.control_socket().unwrap();
    // Connect without accepting until the kernel refuses one: the queue is full. Bounded, so a kernel that
    // queues without limit fails the row rather than exhausting descriptors.
    let mut queued = Vec::new();
    let full = loop {
        match std::os::unix::net::UnixStream::connect(&socket) {
            Ok(stream) if queued.len() < 4096 => queued.push(stream),
            Ok(_) => break false,
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(libc::ECONNREFUSED), "{error}");
                break true;
            }
        }
    };
    assert!(full, "the accept queue never filled");
    let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
    drop(queued);
    drop(listener);
    drop(lock);
    assert_eq!(status, Some(1), "{stderr}");
    assert_eq!(stderr, unreached(&home));
    assert!(!asked_the_passphrase(&stderr), "{stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `serve.lock` held with nothing recorded, as a key replacement holds it, and no socket: its own line,
/// never the out-of-reach one and never an own bind.
#[tokio::test]
async fn a_key_replacement_under_way_is_its_own_line() {
    let home = device("replacing", 60).await;
    let lock = held(&home, false).await;
    let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
    drop(lock);
    assert_eq!(status, Some(1), "{stderr}");
    assert_eq!(
        stderr,
        "error: this machine's key is being replaced\n  Run this command again when that has \
         finished.\n"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `home.lock` held by another process for good, beside a `serve.lock` a `serve` once left, and no
/// socket: the run's lock read ends within its bound on an error, exit 1, and binds nothing, so one stuck
/// holder cannot wedge every command here.
#[tokio::test]
async fn a_home_lock_held_for_good_binds_nothing() {
    let home = device("wedged", 60).await;
    // Free and empty, as a stopped `serve` leaves it: an absent one is free without the lock read.
    std::fs::write(home.serve_lock(), b"").unwrap();
    let write = swoosh::home::HomeWrite::take(&home).await.unwrap();
    let started = std::time::Instant::now();
    let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
    let took = started.elapsed();
    drop(write);
    assert_eq!(status, Some(1), "{stderr}");
    assert!(
        stderr.starts_with(&format!(
            "error: could not lock {}",
            home.home_lock().display()
        )),
        "{stderr}"
    );
    assert!(!asked_the_passphrase(&stderr), "{stderr}");
    assert!(took < Duration::from_secs(20), "bounded: {took:?}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// How a [`probed`] resident answers a `Whoami`.
#[derive(Clone, Copy)]
enum Answers {
    /// As a `serve` of another control version: its magic, and nothing more.
    Skew,
    /// Never: the connection is held open with no reply, as a stalled `serve` holds it.
    Silent,
}

/// A resident on `home`'s control socket, `serve.lock` held and the socket bound before it returns, that
/// answers a `Whoami` as `answers` says and counts each Open it hears in `opens`, until `stop`.
async fn probed(
    home: &Home,
    answers: Answers,
    opens: Arc<AtomicUsize>,
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
            match Request::read(&mut conn).await {
                Ok(Request::Whoami) => match answers {
                    Answers::Skew => {
                        let _ = conn.write_all(b"SWC9").await;
                    }
                    Answers::Silent => held.push(conn),
                },
                Ok(Request::Open(_)) => {
                    opens.fetch_add(1, Ordering::SeqCst);
                }
                Ok(_) | Err(_) => {}
            }
        }
        drop(held);
        drop(lock);
    })
}

/// A `serve` of another version at the probe: the skew line, exit 1, with no Open sent, no passphrase
/// asked and nothing bound.
#[tokio::test]
async fn skew_at_the_probe_makes_no_bind() {
    let home = device("skew-probe", 60).await;
    let opens = Arc::new(AtomicUsize::new(0));
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = probed(&home, Answers::Skew, Arc::clone(&opens), stop.clone()).await;
    let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
    stop.cancel();
    resident.await.unwrap();
    assert_eq!(status, Some(1), "{stderr}");
    assert_eq!(
        stderr,
        "error: swoosh serve on this machine is a different version\n  Restart it with this version.\n"
    );
    assert_eq!(opens.load(Ordering::SeqCst), 0, "{stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A resident that takes the probe's connection and never replies to its `Whoami`, `serve.lock` held:
/// the line for a stalled `serve`, exit 1, within the client's own bounds (2 s to connect, 5 s for the
/// reply), never a hang and never an own bind.
#[tokio::test]
async fn a_stalled_probe_is_unresponsive() {
    let home = device("stalled-probe", 60).await;
    let opens = Arc::new(AtomicUsize::new(0));
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = probed(&home, Answers::Silent, Arc::clone(&opens), stop.clone()).await;
    let started = std::time::Instant::now();
    let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
    let took = started.elapsed();
    stop.cancel();
    resident.await.unwrap();
    assert_eq!(status, Some(1), "{stderr}");
    assert_eq!(
        stderr,
        "error: swoosh serve did not answer here\n  Restart it.\n"
    );
    assert_eq!(opens.load(Ordering::SeqCst), 0, "{stderr}");
    assert!(took < Duration::from_secs(15), "bounded: {took:?}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A dial to this machine prints its line, exit 2, on both paths, before anything is opened or bound.
/// By own bind with no key file, the check finds no key and mints none: the run dials on, and the home has
/// no key file after. Through `serve`, the key it runs as is this machine's: no Open, and no warning for a
/// badge inside its window first.
#[tokio::test]
async fn the_self_dial_check_mints_no_key() {
    let warning = "swoosh: this device's membership badge expires in";
    let home = device("self-nokey", 3).await;
    std::fs::remove_file(home.key()).unwrap();
    // A port nothing answers on, so the own bind's dial fails here without asking the internet.
    let hint = format!("{}=127.0.0.1:9", TestNode::seeded(NAS).node_id());
    let argv = ["ping", "me/nas", "-c", "1", "--local", "--peer", &hint];
    let (status, stderr) = swoosh(&home, &argv).await;
    assert_eq!(status, Some(1), "{stderr}");
    assert!(stderr.starts_with("error: could not reach "), "{stderr}");
    assert!(!home.key().exists(), "no key minted: {stderr}");

    let seen = Arc::new(Seen::default());
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = resident(&home, Arc::clone(&seen), stop.clone()).await;
    let (status, stderr) = swoosh(&home, &["ping", "me/desk", "-c", "1"]).await;
    stop.cancel();
    resident.await.unwrap();
    assert_eq!(status, Some(2), "{stderr}");
    assert!(
        stderr.starts_with("error: me/desk is this machine\n"),
        "{stderr}"
    );
    assert!(!stderr.contains(warning), "{stderr}");
    assert!(seen.opens.lock().unwrap().is_empty(), "{stderr}");
    assert!(!home.key().exists(), "no key minted: {stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// By own bind, a sealed key file whose header names no key: the check's read surfaces the damaged-key
/// line, exit 1, before any passphrase is asked or anything bound.
#[tokio::test]
async fn the_self_dial_check_surfaces_a_damaged_key() {
    let home = device("self-damaged", 60).await;
    let mut bytes = std::fs::read(home.key()).unwrap();
    // Bytes 10 to 42 are the public key the header claims; all zeros is a small-order point.
    bytes[10..42].fill(0);
    std::fs::write(home.key(), &bytes).unwrap();
    let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
    assert_eq!(status, Some(1), "{stderr}");
    assert!(
        stderr.starts_with(&format!(
            "error: this machine's key file at {} is damaged and holds no usable key",
            home.key().display()
        )),
        "{stderr}"
    );
    assert!(!asked_the_passphrase(&stderr), "{stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A link for this machine's own key that admits anyone takes no check: it dials under a throwaway key,
/// which may reach this machine like any other, so it binds its own and never asks `serve`.
#[tokio::test]
async fn an_anyone_link_to_this_machine_binds_its_own() {
    let this = TestRoot::seeded(DESK);
    assert_eq!(this.node_id(), TestNode::seeded(DESK).node_id());
    let link = this
        .slip(
            &swoosh::reach::PING_SERVICE.parse().unwrap(),
            SystemTime::now() + Duration::from_secs(3600),
        )
        .unwrap()
        .seal()
        .unwrap()
        .link()
        .unwrap();
    let link = swoosh::link::Link::from(link).to_string();
    let hint = format!("{}=127.0.0.1:9", this.node_id());
    let home = device("anyone-self", 60).await;
    let seen = Arc::new(Seen::default());
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = resident(&home, Arc::clone(&seen), stop.clone()).await;
    let argv = ["ping", &link, "-c", "1", "--local", "--peer", &hint];
    let (status, stderr) = swoosh(&home, &argv).await;
    stop.cancel();
    resident.await.unwrap();
    assert_eq!(seen.connects.load(Ordering::SeqCst), 0, "{stderr}");
    assert_eq!(status, Some(1), "{stderr}");
    assert!(stderr.starts_with("error: could not reach "), "{stderr}");
    assert!(!stderr.contains("this machine"), "{stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// By own bind, with this machine's key sealed and no `serve`: a dial to this machine prints its line,
/// exit 2, with no passphrase asked and nothing bound.
#[tokio::test]
async fn the_self_dial_check_asks_no_passphrase() {
    let home = device("self-sealed", 60).await;
    let (status, stderr) = swoosh(&home, &["ping", "me/desk", "-c", "1"]).await;
    assert_eq!(status, Some(2), "{stderr}");
    assert!(
        stderr.starts_with("error: me/desk is this machine\n"),
        "{stderr}"
    );
    assert!(!asked_the_passphrase(&stderr), "{stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// No `XDG_RUNTIME_DIR`, or a relative one, while `serve` holds the lock: the line naming the variable,
/// exit 1, no passphrase asked and nothing bound.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn no_runtime_dir_with_serve_running_is_an_error() {
    let home = device("no-xdg", 60).await;
    let (lock, listener) = claimed(&home).await;
    for (xdg, why) in [
        (None, "is not set here"),
        (Some("run/user/1000"), "is not a full path here"),
    ] {
        let (status, stderr) = swoosh_in(&home, &["ping", "me/nas", "-c", "1"], xdg).await;
        assert_eq!(status, Some(1), "{xdg:?}: {stderr}");
        assert_eq!(
            stderr,
            format!(
                "error: swoosh serve is running for this home, but this command cannot reach it\n  \
                 Commands find it through XDG_RUNTIME_DIR, which {why}.\n  Set XDG_RUNTIME_DIR to the \
                 value swoosh serve has, usually /run/user/$(id -u).\n"
            ),
            "{xdg:?}"
        );
    }
    drop(listener);
    drop(lock);
    let _ = std::fs::remove_dir_all(home.dir());
}
