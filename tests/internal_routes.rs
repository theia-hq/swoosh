// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The internal routes against the table `status` prints them from.
//!
//! 1. Each row's [`Admits`] is who its bind lets through, over the in-process transport: every route bound
//!    through the same `control::bind_exchanges` and `control::bind_serve` the `swoosh serve` product path
//!    calls, behind the same anchored gate and its live cut. A set of dialers, each holding one standing in
//!    this home, opens every route, and each is admitted exactly where its row says it is.
//! 2. The routes the compiled `swoosh serve` binds are exactly the table's, read from its own catalog over
//!    its control socket: a route bound anywhere in the run outside the table fails here, and so does a row
//!    with no route, so every route the run binds is one the first row checks.
//!
//! Admission is the stream opening, never an answer: `lookup.root` admits keys it then answers with a miss.
//!
//! Over `mem` the proven peer is the transport's synthetic node id, so every row, badge and saved machine
//! here names a dialer by the id the mem transport proves for it; see `gated_send.rs` for the full note.

use core::time::Duration;
use std::sync::Arc;
use std::time::SystemTime;

use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use keystore::{KeyFile, Protection};
use nauthy::Link;
use swoosh::contacts::{ContactsStore, DeviceLabel};
use swoosh::home::Home;
use swoosh::roster::{Epoch, Member, RosterDoc, fold};
use swoosh::serve::control::{self, Admits, INTERNAL};
use swoosh::serve::{BoundTargets, StopSource};
use swoosh::testkit::{STANDING_UNTIL, TestNode, TestRoot};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{CancellationToken, Connector, Router};

/// The root every device here belongs to.
const ROOT: u8 = 0x61;
/// The device that serves the routes.
const NAS: u8 = 0x62;

/// One dialer's standing in the serving home: what it holds, and so what each route should make of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// A live member badge rooted at the pin, and nothing else: not listed, not saved.
    Badged,
    /// A delegate's slip for the route, signed by the root: never a member.
    Slipped,
    /// Listed live in the held update, with no badge presented and saved nowhere else.
    Listed,
    /// Listed in the held update with a standing that has ended.
    Ended,
    /// Listed live in the held update, and revoked here.
    RevokedListed,
    /// Saved as one machine of a person, with no badge, and not listed.
    Saved,
    /// Saved as one machine of a person, and revoked here.
    RevokedSaved,
    /// Saved only as a person's root, never as a machine.
    RootOnly,
    /// Nothing this home holds.
    Stranger,
}

impl Probe {
    const ALL: [Self; 9] = [
        Self::Badged,
        Self::Slipped,
        Self::Listed,
        Self::Ended,
        Self::RevokedListed,
        Self::Saved,
        Self::RevokedSaved,
        Self::RootOnly,
        Self::Stranger,
    ];

    /// Whether a route whose row says `admits` should let this dialer through: the label's claim, written
    /// out per dialer, so a row whose words disagree with its bind fails here.
    fn admitted_by(self, admits: Admits) -> bool {
        match admits {
            // A live member badge, never a slip.
            Admits::Devices => self == Self::Badged,
            // A key the update lists with a standing not ended, not revoked.
            Admits::DevicesByKey => self == Self::Listed,
            // Every key the update lists (`me`), whatever its standing, and every machine saved; never a
            // revoked key, a root alone or a stranger.
            Admits::Saved => matches!(self, Self::Listed | Self::Ended | Self::Saved),
        }
    }
}

/// A spawned child killed and reaped on drop, so a failing test never orphans it.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run `test` on a thread with room for the node's stack, on one local task set.
fn on_a_node<F: core::future::Future<Output = ()>>(test: impl FnOnce() -> F + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(test()));
        })
        .unwrap()
        .join()
        .unwrap();
}

/// A fresh home for the device `seed`: its key, the pin, and a live standing the root signed for it.
fn device_home(tag: &str, seed: u8) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-internal-routes-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let mut secret = TestNode::seeded(seed).seed();
    swoosh::identity::make_machine_dir(&home).unwrap();
    KeyFile::new(home.key())
        .write(&keystore::Secret::take(&mut secret), Protection::Plain)
        .unwrap();
    swoosh::config::write_signet(
        &swoosh::testkit::lock(),
        &home,
        TestRoot::seeded(ROOT).node_id(),
    )
    .unwrap();
    let badge = TestRoot::seeded(ROOT)
        .device_badge(TestNode::seeded(seed).node_id(), live_until())
        .unwrap();
    swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &badge).unwrap();
    home
}

/// The end of every live standing here.
fn live_until() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL)
}

/// A row for `node`, named `label`, whose standing ends at `until` (unix seconds).
fn row(node: NodeId, label: &str, until: u64) -> Member {
    let root = TestRoot::seeded(ROOT);
    let key = node.verify_key().unwrap();
    Member {
        until,
        standing: root
            .member_badge(key, SystemTime::UNIX_EPOCH + Duration::from_secs(until))
            .unwrap()
            .seal()
            .unwrap()
            .link()
            .unwrap(),
        ..root
            .member(key, label.parse::<DeviceLabel>().unwrap())
            .unwrap()
    }
}

/// The dialers, one per [`Probe`], each on its own transport.
struct Dialers(Vec<(Probe, Node<MemTransport, NoDiscovery>)>);

impl Dialers {
    fn new() -> Self {
        Self(
            Probe::ALL
                .into_iter()
                .map(|probe| (probe, Node::new(MemTransport::bind(), NoDiscovery)))
                .collect(),
        )
    }

    fn id(&self, probe: Probe) -> NodeId {
        self.0
            .iter()
            .find(|(held, _)| *held == probe)
            .map(|(_, node)| node.node_id())
            .unwrap()
    }
}

/// Give `nas` every standing the dialers hold: the update listing three of them, the book saving three,
/// and two keys revoked. Written before the routes bind, as the routes read their keys once at bind.
async fn hold(nas: &Home, dialers: &Dialers) {
    let members = vec![
        row(TestNode::seeded(NAS).node_id(), "nas", STANDING_UNTIL),
        row(dialers.id(Probe::Listed), "laptop", STANDING_UNTIL),
        row(dialers.id(Probe::Ended), "old", 1),
        row(dialers.id(Probe::RevokedListed), "lost", STANDING_UNTIL),
    ];
    let doc = RosterDoc::with_revocations(Epoch(1), members, vec![], Vec::new()).unwrap();
    fold(
        &swoosh::home::HomeWrite::take(nas).await.unwrap(),
        nas,
        &TestRoot::seeded(ROOT).sign_update(&doc),
    )
    .await
    .unwrap();

    let mut store = ContactsStore::open(nas).await.unwrap();
    store.contacts_mut().add(
        "bob".parse().unwrap(),
        Some("desk".parse().unwrap()),
        dialers.id(Probe::Saved),
    );
    store.contacts_mut().add(
        "bob".parse().unwrap(),
        Some("phone".parse().unwrap()),
        dialers.id(Probe::RevokedSaved),
    );
    store
        .contacts_mut()
        .set_signet("carol".parse().unwrap(), dialers.id(Probe::RootOnly));
    store.save(&swoosh::testkit::lock()).unwrap();

    swoosh::revoked::add(
        &swoosh::testkit::lock(),
        nas,
        [Probe::RevokedListed, Probe::RevokedSaved]
            .map(|probe| nauthy::Revocation::Key(dialers.id(probe).verify_key().unwrap())),
    )
    .unwrap();
}

/// Bind every internal route on `home`, as `serve` binds them, and run them on `host`.
async fn serve(home: &Home, host: Node<MemTransport, NoDiscovery>) {
    let (gate, cut) = swoosh::gate::anchored(
        home,
        TestNode::seeded(NAS).node_id(),
        BoundTargets::default(),
    )
    .await
    .unwrap();
    let router = swoosh::serve::diagnostics(Router::new(gate), &[]).unwrap();
    let (router, _watched) = control::bind_exchanges(router, home).await.unwrap();
    let cancel = CancellationToken::new();
    let (router, _catalog, _first_round) =
        control::bind_serve(router, cancel.clone(), Arc::new(StopSource::new()), &cut).unwrap();
    let exposer = router.expose().unwrap().with_live_cuts(cut);
    tokio::task::spawn_local(async move { exposer.run(&host, cancel).await });
}

/// What `probe` presents on `route`: on a member route its badge or its slip, as a client presents one; on
/// a proven route nothing, as a client presents nothing there.
fn credential(probe: Probe, id: NodeId, route: &control::Internal) -> Option<Link> {
    if route.admits.is_proven() {
        return None;
    }
    let root = TestRoot::seeded(ROOT);
    match probe {
        // A revoked key presents a badge the root signed too, so its refusal on a member route is the
        // revocation's, never a missing badge.
        Probe::Badged | Probe::RevokedListed | Probe::RevokedSaved => {
            Some(root.device_badge(id, live_until()).unwrap())
        }
        Probe::Slipped => Some(
            root.bound_slip(
                &route.name.parse().unwrap(),
                id.verify_key().unwrap(),
                nauthy::Request::expires_in(Duration::from_secs(300)),
            )
            .unwrap(),
        ),
        _ => None,
    }
}

/// Whether `from` gets a stream on `service` at `host`, presenting `credential`.
async fn opens(
    from: &Node<MemTransport, NoDiscovery>,
    host: NodeId,
    service: &str,
    credential: Option<Link>,
) -> bool {
    let session = Connector::to_node(host, service.parse().unwrap(), credential)
        .open_service(from)
        .await
        .expect("the base connect lands; the node rules per stream");
    session.open_bi().await.is_ok()
}

/// Each internal route admits exactly who its row says: per row, a member badge, a badge-less key the
/// update lists live, a badge-less key saved in the book and a stranger, and at the edges a revoked key the
/// update lists live, a revoked key saved in the book, a listed key whose standing ended, a key saved only
/// as a root, a slip on each member route, and a key listed in the update and saved nowhere else.
#[test]
fn each_internal_row_admits_who_it_says() {
    on_a_node(|| async {
        let nas = device_home("admits", NAS);
        let dialers = Dialers::new();
        hold(&nas, &dialers).await;
        let host = Node::new(MemTransport::bind(), NoDiscovery);
        let host_id = host.node_id();
        serve(&nas, host).await;

        let mut wrong = Vec::new();
        for route in &INTERNAL {
            for (probe, node) in &dialers.0 {
                let presented = credential(*probe, node.node_id(), route);
                let admitted = opens(node, host_id, route.name, presented).await;
                if admitted != probe.admitted_by(route.admits) {
                    wrong.push(format!(
                        "{} ({:?}): {probe:?} admitted {admitted}",
                        route.name, route.admits
                    ));
                }
            }
        }
        assert!(
            wrong.is_empty(),
            "rows that disagree with their bind: {wrong:#?}"
        );
        let _ = std::fs::remove_dir_all(nas.dir());
    });
}

/// The rows of a screen's block titled `title`: the lines under it, up to the blank line.
fn reach_rows<'s>(screen: &'s str, title: &str) -> Vec<&'s str> {
    screen
        .lines()
        .skip_while(|line| *line != title)
        .skip(1)
        .take_while(|line| !line.is_empty())
        .collect()
}

/// Whether `screen` holds the whole block titled `title`: the title, then a blank line after its rows.
fn reach_closed(screen: &str, title: &str) -> bool {
    screen
        .lines()
        .skip_while(|line| *line != title)
        .skip(1)
        .any(str::is_empty)
}

/// The dotted names the compiled `swoosh serve`'s catalog lists, asked over its control socket, are exactly
/// the table's: no route bound outside it, and no row without a route. Its `status`, asked of the same run,
/// prints the banner's `reach` rows.
#[test]
fn a_running_serve_binds_exactly_the_internal_table() {
    use std::io::{BufRead as _, BufReader};
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    use swoosh::node_client::{ControlClient, NodeClient as _};

    let base = std::env::temp_dir().join(format!("sw-internal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (dir, run) = (base.join("home"), base.join("run"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut serve = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_swoosh"))
            .arg("--home")
            .arg(&dir)
            .args(["serve", "--local"])
            .env("XDG_RUNTIME_DIR", &run)
            .env_remove("SWOOSH_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stdout = serve.0.stdout.take().unwrap();
    // Bound the wait; the pipe reader may block, never the deadline owner.
    let (sender, lines) = std::sync::mpsc::sync_channel(16);
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            // Keep draining after readiness, without closing the child's output pipe early.
            let _ = sender.send(line);
        }
    });
    // Ready at the title, which prints only after the bind; then read on to the end of its `reach` block.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut banner = String::new();
    while !banner.contains("swoosh is serving") || !reach_closed(&banner, "reach") {
        let line = lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("serve never became ready before the deadline")
            .expect("read the banner");
        banner.push_str(&line);
        banner.push('\n');
    }
    // `status` reads the same running serve's reach through its own path: the control socket, then its
    // report. Under `--local` it prints every class, as the banner does, so the rows are the same.
    let status = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(&dir)
        .arg("status")
        .env("XDG_RUNTIME_DIR", &run)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let status = String::from_utf8(status.stdout).unwrap();

    let home = Home::resolve(Some(dir)).unwrap();
    // The serve's own runtime root: the per-user temp dir on macOS, `$XDG_RUNTIME_DIR/swoosh` elsewhere.
    #[cfg(target_os = "macos")]
    let root = swoosh::home::runtime_root().unwrap();
    #[cfg(not(target_os = "macos"))]
    let root = run.join("swoosh");
    let socket = home.runtime_leaf(&root).join("control.sock");
    let menu = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            ControlClient::resolve_socket(&home, socket)
                .unwrap()
                .services()
                .await
        });
    // Only the one child spawned here is ever signalled.
    drop(serve);
    let _ = std::fs::remove_dir_all(&base);

    let shown = reach_rows(&banner, "reach");
    assert!(
        shown.iter().any(|row| row.starts_with("  this computer  ")),
        "{banner}"
    );
    assert_eq!(reach_rows(&status, "reach"), shown, "{banner}\n{status}");

    let mut bound: Vec<String> = menu
        .unwrap()
        .catalog
        .entries()
        .map(|entry| entry.name.clone())
        .filter(|name| name.contains('.'))
        .collect();
    bound.sort();
    let mut table: Vec<&str> = INTERNAL.iter().map(|route| route.name).collect();
    table.sort_unstable();
    assert_eq!(bound, table);
}
