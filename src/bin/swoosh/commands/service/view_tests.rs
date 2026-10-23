use core::sync::atomic::{AtomicU32, Ordering};
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::Arc;

use swoosh::home::Home;
use swoosh::serve::Started;
use swoosh::serve::control_codec::{DisabledList, Request, Response, ServiceMenu, StatusReply};
use swoosh::serve_toml::ServeToml;
use tightbeam::tunnel::ServiceCatalog;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{View, render};
use crate::commands::service::edit::ServiceAddCmd;
use crate::commands::service::toggle::{ServiceToggleCmd, Slot, Way};
use crate::commands::service_state::{ReadMode, ResidentObservation, ServiceState};

// Property map: add -> exact target; off -> fresh file; retarget -> both endpoints;
// down -> defaults/footer; empty -> no defaults; damaged -> no rows; on -> printable names.
static SEQ: AtomicU32 = AtomicU32::new(0);

struct Fixture(Home);

impl Fixture {
    fn new() -> Self {
        Self::named("plain")
    }

    fn named(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "sv-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(Home::resolve(Some(dir)).unwrap())
    }

    async fn list(&self, entries: &[&str], off: &[&str]) {
        let lock = swoosh::home::HomeWrite::take(&self.0).await.unwrap();
        ServeToml::update(&lock, &self.0, |file| {
            file.services = Some(entries.iter().map(|entry| (*entry).to_owned()).collect());
            file.off = off.iter().map(|name| (*name).to_owned()).collect();
        })
        .unwrap();
    }

    fn reply(&self, mode: ReadMode, bytes: Vec<u8>) -> tokio::task::JoinHandle<()> {
        let socket = self.0.control_socket().unwrap();
        let dir = socket.parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = Request::read(&mut stream).await.unwrap();
            assert!(matches!(
                (mode, request),
                (ReadMode::Membership, Request::Status)
                    | (ReadMode::Detail, Request::LocalServiceDetail)
            ));
            stream.write_all(&bytes).await.unwrap();
            // The client must finish the declared frame without waiting for EOF or writing another query.
            let mut extra = [0];
            assert_eq!(stream.read(&mut extra).await.unwrap(), 0);
            assert_eq!(
                listener.into_std().unwrap().accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            std::fs::remove_file(socket).unwrap();
        })
    }

    async fn output(&self, pairs: Option<&[(&str, &str, bool)]>) -> String {
        let server = pairs.map(|pairs| self.reply(ReadMode::Detail, detail(pairs)));
        let mut out = Vec::new();
        View.run_to(&self.0, &mut out).await.unwrap();
        if let Some(server) = server {
            server.await.unwrap();
        }
        String::from_utf8(out).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Ok(socket) = self.0.control_socket() {
            let _ = std::fs::remove_file(&socket);
            let _ = std::fs::remove_dir(socket.parent().unwrap());
        }
        std::fs::remove_dir_all(self.0.dir()).unwrap();
    }
}

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = b"SWC1".to_vec();
    bytes.push(tag);
    bytes.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn detail(pairs: &[(&str, &str, bool)]) -> Vec<u8> {
    let mut body = vec![0];
    body.extend_from_slice(&u16::try_from(pairs.len()).unwrap().to_be_bytes());
    for (name, target, refused) in pairs {
        for text in [name, target] {
            body.extend_from_slice(&u16::try_from(text.len()).unwrap().to_be_bytes());
            body.extend_from_slice(text.as_bytes());
        }
        body.push(u8::from(*refused));
    }
    frame(9, &body)
}

async fn state(entries: &[&str], pairs: &[(&str, &str, bool)]) -> ServiceState {
    let bytes = detail(pairs);
    let Response::LocalServiceDetail(Ok(snapshot)) =
        Response::read(&mut bytes.as_slice()).await.unwrap()
    else {
        panic!("expected a snapshot");
    };
    ServiceState {
        started: Started::Resumed(entries.iter().map(|entry| (*entry).to_owned()).collect()),
        off: Default::default(),
        resident: ResidentObservation::Detail(Some(snapshot)),
    }
}

fn rendered(state: &ServiceState) -> String {
    let mut out = Vec::new();
    render(state, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[tokio::test]
async fn service_prints_the_target_service_add_took() {
    let fixture = Fixture::new();
    fixture.list(&[], &[]).await;
    ServiceAddCmd {
        entries: vec!["web=tcp:localhost:3000".to_owned()],
    }
    .run(&fixture.0)
    .await
    .unwrap();
    assert_eq!(
        fixture
            .output(Some(&[("web", "tcp:localhost:3000", false)]))
            .await,
        "  web  tcp:localhost:3000  on\n"
    );
}

#[tokio::test]
async fn service_marks_off_and_waiting() {
    let fixture = Fixture::new();
    fixture
        .list(
            &[
                "web=tcp:localhost:3000",
                "new=tcp:localhost:4000",
                "off=tcp:localhost:5000",
            ],
            &["web", "off"],
        )
        .await;
    assert_eq!(
        fixture
            .output(Some(&[("web", "tcp:localhost:3000", false)]))
            .await,
        "  web  tcp:localhost:3000  off\n  new  tcp:localhost:4000  from the next start\n  off  tcp:localhost:5000  off, from the next start\n"
    );
}

#[tokio::test]
async fn service_names_a_retargets_next_target() {
    let fixture = Fixture::new();
    fixture.list(&["api=tcp:localhost:9090"], &[]).await;
    for (off, prefix) in [(false, "on,"), (true, "off,")] {
        fixture
            .list(
                &["api=tcp:localhost:9090"],
                if off { &["api"] } else { &[] },
            )
            .await;
        let out = fixture
            .output(Some(&[
                ("api", "tcp:localhost:3000", !off),
                ("removed", "unix:/removed", true),
            ]))
            .await;
        assert_eq!(
            out,
            format!("  api  tcp:localhost:3000  {prefix} tcp:localhost:9090 from the next start\n")
        );
    }
    // Semantically similar endpoint spellings are still different startup/configured bytes.
    let row = state(
        &["api=tcp:LOCALHOST:3000"],
        &[("api", "tcp:localhost:3000", false)],
    )
    .await;
    assert!(rendered(&row).contains("tcp:LOCALHOST:3000 from the next start"));
}

#[tokio::test]
async fn service_with_serve_down_lists_what_a_bare_serve_starts() {
    let fixture = Fixture::new();
    let out = fixture.output(None).await;
    assert!(out.starts_with("  ping  ") && out.contains("\n  speed  "));
    assert!(out.ends_with("\nNot serving now.\nTo start serving:\n  swoosh serve\n"));
    fixture.list(&["web=tcp:localhost:3000"], &["web"]).await;
    assert_eq!(
        fixture.output(None).await,
        "  web  tcp:localhost:3000  off\n\nNot serving now.\nTo start serving:\n  swoosh serve\n"
    );
}

#[tokio::test]
async fn service_on_an_emptied_list_says_serving_nothing() {
    let fixture = Fixture::new();
    fixture.list(&[], &[]).await;
    for pairs in [None, Some([].as_slice())] {
        assert_eq!(
            fixture.output(pairs).await,
            "Serving nothing.\nTo add a service:\n  swoosh service add <service>\n"
        );
    }
}

#[tokio::test]
async fn service_refuses_a_damaged_serve_toml() {
    let fixture = Fixture::named("damaged\n\u{1b}");
    for text in [
        "services = ['web=tcp:x:1', 'web=tcp:x:2']",
        "services = ['--public']",
        "services = ['tcp:x:1']",
        "not toml",
    ] {
        std::fs::write(fixture.0.serve_toml(), text).unwrap();
        let mut out = Vec::new();
        let error = View.run_to(&fixture.0, &mut out).await.unwrap_err();
        assert!(out.is_empty());
        assert!(!format!("{error:#}").contains("damaged\n"));
        assert!(!format!("{error:#}").contains('\u{1b}'));
        assert!(format!("{error:#}").contains(&format!(
            "could not read local service configuration from {}",
            swoosh::escape::EscapedPath(&fixture.0.serve_toml())
        )));
    }
}

#[tokio::test]
async fn the_name_service_prints_is_the_name_service_on_takes() {
    let fixture = Fixture::new();
    let entries = [
        "ping=ping:",
        "speed=speed:",
        "ssh=ssh:",
        "proxy=proxy:https://example.com",
    ];
    fixture
        .list(&entries, &["ping", "speed", "ssh", "proxy"])
        .await;
    let out = fixture.output(None).await;
    for entry in entries {
        let name = entry.split_once('=').unwrap().0;
        assert!(
            out.lines()
                .any(|line| line.split_ascii_whitespace().next() == Some(name))
        );
        ServiceToggleCmd {
            service: Slot::Service(swoosh::names::service(name).unwrap()),
            machine: None,
        }
        .run(&fixture.0, Way::On)
        .await
        .unwrap();
    }
    assert!(ServeToml::read(&fixture.0).unwrap().off.is_empty());
}

#[tokio::test]
async fn acquisition_modes_are_exclusive_and_detail_failure_never_becomes_down() {
    let fixture = Fixture::new();
    let large = format!("web=unix:/{}", "x".repeat(4096));
    fixture.list(&[&large], &[]).await;
    let status = Response::Status(StatusReply {
        node_id: swoosh::testkit::TestNode::seeded(9).node_id(),
        pid: 1,
        addr: None,
        uptime_secs: 0,
        menu: ServiceMenu {
            catalog: ServiceCatalog::decode(b"\x00\x00\x00\x01\x00\x03web\x00").unwrap(),
            disabled: DisabledList::Known(vec![]),
        },
        warm: vec![],
    });
    let mut bytes = Vec::new();
    status.write(&mut bytes).await.unwrap();
    let server = fixture.reply(ReadMode::Membership, bytes);
    let membership = ServiceState::read(&fixture.0, ReadMode::Membership)
        .await
        .unwrap();
    server.await.unwrap();
    assert!(membership.contains_bound("web"));
    let mut out = Vec::new();
    assert!(
        render(&membership, &mut out)
            .unwrap_err()
            .to_string()
            .ends_with("wrong local read mode")
    );
    assert!(out.is_empty());
    // Each optional detail dimension can fail without changing the independent membership read.
    for body in [&[1][..], &[2, 1], &[2, 2], &[2, 3], &[2, 4], &[3]] {
        let server = fixture.reply(ReadMode::Detail, frame(9, body));
        assert!(View.run_to(&fixture.0, &mut out).await.is_err());
        server.await.unwrap();
        assert!(out.is_empty());
    }
    for bytes in [frame(3, &[]), frame(9, &[0, 0])] {
        let server = fixture.reply(ReadMode::Detail, bytes);
        assert!(View.run_to(&fixture.0, &mut out).await.is_err());
        server.await.unwrap();
        assert!(out.is_empty());
    }
}

#[tokio::test]
async fn replacement_residents_cannot_splice_targets_and_membership() {
    let fixture = Fixture::new();
    fixture.list(&["a=tcp:next:1", "b=tcp:next:2"], &[]).await;
    let socket = fixture.0.control_socket().unwrap();
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        socket.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    // Hold A's response until B owns the socket name, making any second acquisition observable.
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let responding = Arc::clone(&barrier);
    let (ready, replaced) = tokio::sync::oneshot::channel();
    let old_socket = PathBuf::clone(&socket);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(matches!(
            Request::read(&mut stream).await.unwrap(),
            Request::LocalServiceDetail
        ));
        drop(listener);
        std::fs::remove_file(old_socket).unwrap();
        ready.send(()).unwrap();
        responding.wait().await;
        stream
            .write_all(&detail(&[("a", "tcp:resident-a:1", false)]))
            .await
            .unwrap();
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    });
    let (a, replacement) = tokio::join!(ServiceState::read(&fixture.0, ReadMode::Detail), async {
        replaced.await.unwrap();
        let replacement = tokio::net::UnixListener::bind(&socket).unwrap();
        barrier.wait().await;
        replacement
    });
    let a = a.unwrap();
    server.await.unwrap();
    // B is installed before A answers. A second acquisition would leave a queued connection to B.
    assert_eq!(
        replacement.into_std().unwrap().accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    std::fs::remove_file(&socket).unwrap();
    let server = fixture.reply(ReadMode::Detail, detail(&[("b", "tcp:resident-b:2", true)]));
    let b = ServiceState::read(&fixture.0, ReadMode::Detail)
        .await
        .unwrap();
    server.await.unwrap();
    assert!(a.contains_bound("a") && !a.contains_bound("b"));
    assert!(b.contains_bound("b") && !b.contains_bound("a"));
    assert!(rendered(&a).contains("tcp:resident-a:1") && !rendered(&a).contains("resident-b"));
    assert!(rendered(&b).contains("tcp:resident-b:2") && !rendered(&b).contains("resident-a"));
}

#[tokio::test]
async fn complete_targets_are_atomic_and_large_rows_do_not_set_padding() {
    for target in [
        format!("unix:/{}", "x".repeat(4080)),
        "unix:/two ordinary spaces".to_owned(),
        "unix:/秘密 a=b".to_owned(),
        "unix:/a\n\r\t\u{1b}\\\u{202e}\u{2800}".to_owned(),
    ] {
        let entry = format!("a={target}");
        let row = state(
            &[&entry, "z=tcp:x:1"],
            &[("a", &target, false), ("z", "tcp:x:1", false)],
        )
        .await;
        let out = rendered(&row);
        assert!(out.contains(&format!("{}", swoosh::escape::EscapedComplete(&target))));
        assert!(!out.contains("..."));
        assert!(out.lines().all(|line| !line.ends_with(' ')));
        if target.len() > 256 || !target.is_ascii() {
            assert!(out.ends_with("  z  tcp:x:1  on\n"));
            assert!(out.starts_with("  a\n    unix:/"));
        }
        // An old and a next target containing spaces must each remain complete spans.
        let row = state(
            &["a=unix:/next target with spaces"],
            &[("a", &target, false)],
        )
        .await;
        assert!(rendered(&row).contains("unix:/next target with spaces"));
    }
}

#[tokio::test]
async fn compact_boundaries_and_independent_maxima_expand_without_splitting() {
    for (size, compact) in [(71, true), (72, false)] {
        let target = "x".repeat(size);
        let entry = format!("a={target}");
        let row = state(&[&entry], &[("a", &target, false)]).await;
        let out = rendered(&row);
        assert_eq!(out.starts_with("  a  "), compact);
        assert!(out.contains(&target));
        assert!(out.lines().all(|line| line.len() <= 80));
    }
    let target = "x".repeat(60);
    let entry = format!("a={target}");
    let row = state(
        &[&entry, "abcdefghijklmnopqrst=tcp:x:1"],
        &[
            ("a", &target, false),
            ("abcdefghijklmnopqrst", "tcp:x:1", false),
        ],
    )
    .await;
    assert_eq!(
        rendered(&row),
        format!("  a\n    {target}\n    on\n  abcdefghijklmnopqrst\n    tcp:x:1\n    on\n")
    );
    let target = "x".repeat(4096);
    let next = format!("unix:/{} with spaces", "y".repeat(120));
    let entry = format!("a={next}");
    let row = state(&[&entry], &[("a", &target, false)]).await;
    assert_eq!(
        rendered(&row),
        format!("  a\n    {target}\n    on,\n    {next}\n    from the next start\n")
    );
}

#[tokio::test]
async fn a_fresh_file_failure_cannot_reuse_an_earlier_observation() {
    let fixture = Fixture::new();
    fixture.list(&["web=tcp:x:1"], &[]).await;
    assert!(
        fixture
            .output(Some(&[("web", "tcp:x:1", false)]))
            .await
            .contains("tcp:x:1")
    );
    std::fs::write(fixture.0.serve_toml(), "services = ['--public']").unwrap();
    let socket = fixture.0.control_socket().unwrap();
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let mut out = Vec::new();
    tokio::select! {
        result = View.run_to(&fixture.0, &mut out) => assert!(result.is_err()),
        _ = listener.accept() => panic!("invalid fresh configuration must fail before resident acquisition"),
    }
    assert!(out.is_empty());
}

#[tokio::test]
async fn file_bounded_targets_remain_complete_beyond_the_optional_wire_limit() {
    let fixture = Fixture::new();
    let target = format!("unix:/{} with spaces", "x".repeat(6000));
    fixture.list(&[&format!("web={target}")], &[]).await;
    for pairs in [None, Some([("web", "tcp:old:1", false)].as_slice())] {
        let out = fixture.output(pairs).await;
        assert!(out.lines().any(|line| line == format!("    {target}")));
        assert!(!out.contains("..."));
    }
    let oversized = format!("services = ['web=unix:/{}']", "x".repeat(65536));
    std::fs::write(fixture.0.serve_toml(), oversized).unwrap();
    let mut out = Vec::new();
    assert!(View.run_to(&fixture.0, &mut out).await.is_err());
    assert!(out.is_empty());
}

#[tokio::test]
async fn rendering_propagates_sink_failure() {
    struct Broken(usize);
    impl io::Write for Broken {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0 == 0 {
                return Err(io::Error::other("broken sink"));
            }
            let count = bytes.len().min(self.0);
            self.0 -= count;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let row = state(&["web=tcp:x:1"], &[("web", "tcp:x:1", false)]).await;
    // Fail inside complete target formatting, not at the initial row indentation.
    assert!(render(&row, &mut Broken(12)).is_err());
}
