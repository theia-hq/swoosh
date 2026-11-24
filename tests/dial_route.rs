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
    DisabledList, OpenRefusal, Request, Response, ServiceMenu, StatusReply,
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
    /// The connections that closed before a request: a run asking whether `serve` answers.
    probes: AtomicUsize,
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
    let (lock, listener) = claimed(home).await;
    tokio::spawn(async move {
        loop {
            let (mut conn, _) = tokio::select! {
                accepted = listener.accept() => accepted.unwrap(),
                () = stop.cancelled() => break,
            };
            seen.connects.fetch_add(1, Ordering::SeqCst);
            match Request::read(&mut conn).await {
                Ok(Request::Status) => {
                    let _ = Response::Status(status_of(TestNode::seeded(RESIDENT).node_id()))
                        .write(&mut conn)
                        .await;
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
                    seen.probes.fetch_add(1, Ordering::SeqCst);
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
    use std::io::BufRead as _;

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_swoosh"))
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
    let line = format!("--peer or SWOOSH_PEER gives more than 16 addresses for {nas}");
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
    assert_eq!(*seen.opens.lock().unwrap(), ["control.stop"], "{stderr}");
    assert!(!stderr.contains("passphrase"), "{stderr}");
    assert!(
        stderr.starts_with("error: too many connections open through swoosh serve on this machine"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A run through `serve` asks it whether it answers once, whatever the verb: every dialing verb, every
/// `forward` end, and an exchange verb.
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
    }
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
        stderr.contains("With --local or SWOOSH_LOCAL, swoosh looks on this network only."),
        "{stderr}"
    );
    assert!(!stderr.contains("swoosh serve"), "{stderr}");
    assert!(!stderr.contains("passphrase"), "{stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A control socket whose listener is not the process its home's `serve.lock` records cannot be trusted:
/// the run ends on that error, exit 1, with no own bind, so the sealed machine key is never asked for.
#[tokio::test]
async fn an_untrusted_socket_reads_no_key() {
    let home = device("untrusted", 60).await;
    let seen = Arc::new(Seen::default());
    let stop = tightbeam::tunnel::CancellationToken::new();
    let resident = resident(&home, Arc::clone(&seen), stop.clone()).await;
    // The lock stays held; only the process it names is another.
    std::fs::write(home.serve_lock(), format!("{}\n", std::process::id() + 1)).unwrap();
    let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
    stop.cancel();
    resident.await.unwrap();
    assert_eq!(status, Some(1), "{stderr}");
    assert!(
        stderr.starts_with("error: refusing to trust the control path "),
        "{stderr}"
    );
    assert!(!stderr.contains("passphrase"), "{stderr}");
    assert!(seen.opens.lock().unwrap().is_empty(), "{stderr}");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `serve` answers the run's one probe, then stops before the first Open: the run ends on the line for
/// `serve` stopped, exit 1, and never falls back to a bind of its own. A connect landing between the
/// probe's close and the lock's release would read a freed lock instead; the run's file reads make that
/// window microseconds against milliseconds, so the row runs several times to catch it should it widen.
#[tokio::test]
async fn serve_gone_after_the_probe_is_the_stopped_line() {
    let home = device("gone-after-probe", 60).await;
    for run in 0..5 {
        let (lock, listener) = claimed(&home).await;
        let resident = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let probe = Request::read(&mut conn).await.is_err();
            // The lock first: freeing it removes the socket, so no later connect finds a listener.
            drop(lock);
            drop(listener);
            probe
        });
        let (status, stderr) = swoosh(&home, &["ping", "me/nas", "-c", "1"]).await;
        assert!(
            resident.await.unwrap(),
            "run {run}: the first connection was the probe"
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
