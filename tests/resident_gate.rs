// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! BLOCKER-3, end to end over the in-process transport: a running resident's control socket is never a
//! data channel into the gate. A service disabled by writing `<home>/serve.toml`, and a member revoked by
//! writing `<home>/revoked`, are both honored LIVE by the gate on the next stream with ZERO control
//! connections (the resident's `served()` counter stays at zero). Both are file-writes, exactly as
//! `swoosh service disable` and `swoosh revoke` perform them; the socket carries only reads and a
//! stop, so it cannot express either mutation.

use core::time::Duration;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use nauthy::{Cap, Revocation};
use swoosh::home::{Home, HomeWrite};
use swoosh::serve::{Resident, ServiceList};
use swoosh::serve_toml::{LiveServeToml, ServeToml};
use swoosh::testkit::TestRoot;
use tightbeam::tunnel::{self, CancellationToken, Connector, Exposer, Router, ServiceCatalog};

/// The byte the signet's fixed key is seeded with; its ed25519 public half is the signet the family gate
/// trusts.
const SIGNET: u8 = 7;

/// A short scratch home under the temp dir. Drop removes exactly the base it created.
struct Scratch {
    base: PathBuf,
    home: Home,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!("swg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("scratch base");
        let home = Home::resolve(Some(base.clone())).expect("the scratch home resolves");
        Self { base, home }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// The service the gate serves and a test turns off: a name as `service off` stores one.
const GATED: &str = "files";

/// The exposer a resident serves from: one gated read under the service name [`GATED`], the enabled
/// oracle `off` on `<home>/serve.toml`, and the revocations in `<home>/revoked`. Built through the same `resolve_gate` +
/// handler the product path injects.
fn build_exposer(home: &Home, enabled: LiveServeToml) -> Exposer {
    let signet = TestRoot::seeded(SIGNET).node_id();
    let denylist = swoosh::revoked::open(home).expect("the revocations load");
    let gate = tunnel::resolve_gate(Some(signet), denylist).expect("the family gate resolves");
    Router::new(gate)
        .service(
            GATED.parse().expect("a name"),
            ServiceList::new(ServiceCatalog::decode(&0u32.to_be_bytes()).expect("empty catalog")),
        )
        .expect("the gated route binds")
        .expose()
        .expect("the resident exposer assembles")
        .with_enabled(enabled)
}

/// A membership badge the signet signed, bound to the dialer's proven mem id: the shape `swoosh invite`
/// signs for a device, and the cap `swoosh revoke` cuts at its root.
fn signet_badge(bound: NodeId) -> String {
    TestRoot::seeded(SIGNET)
        .device_badge(bound, nauthy::Request::expires_in(Duration::from_secs(300)))
        .expect("mint a member badge")
        .to_string()
}

/// Whether a member reaches the gated read over mem: admitted iff the per-stream handshake succeeds.
async fn reach(host: NodeId, member: &Node<MemTransport, NoDiscovery>, badge: &str) -> bool {
    let connector = Connector::to_node(host, GATED.parse().unwrap(), Some(badge.parse().unwrap()));
    match connector.open_service(member).await {
        Ok(session) => session.open_bi().await.is_ok(),
        Err(_) => false,
    }
}

/// The resident's control listener, running for real on its own socket. Returned with the resident so
/// the test can assert its `served()` counter never moves: if a disable or a revoke reached the gate
/// through the socket, this is the counter that would climb.
fn running_resident(
    off: LiveServeToml,
    base: &Path,
    cancel: &CancellationToken,
) -> (Arc<Resident>, std::os::unix::net::UnixListener) {
    let control =
        std::os::unix::net::UnixListener::bind(base.join("control.sock")).expect("bind the socket");
    let resident = Arc::new(Resident::new(
        NodeId::from_ed25519_secret(&[3u8; 32]),
        None,
        ServiceCatalog::decode(&0u32.to_be_bytes()).expect("empty catalog"),
        off,
        cancel.clone(),
        Arc::default(),
    ));
    (resident, control)
}

/// Turn [`GATED`] off (`true`) or back on in `home`'s `serve.toml`, through the writer `service
/// off|on` uses.
async fn toggle(home: &Home, off: bool) {
    let home_lock = HomeWrite::take(home).await.expect("take home.lock");
    ServeToml::update(&home_lock, home, |file| {
        if off {
            file.off.insert(GATED.to_owned());
        } else {
            file.off.remove(GATED);
        }
    })
    .expect("write serve.toml");
}

/// BLOCKER-3 (disable): with the resident control listener running, writing `<home>/serve.toml` refuses
/// the very next stream, and re-enabling restores it live, both with ZERO control connections. The
/// disable is a file-write; the socket is untouched.
#[tokio::test]
async fn service_disable_is_file_only_with_the_daemon_running() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let scratch = Scratch::new("disable");
            let cancel = CancellationToken::new();
            let off = LiveServeToml::load(&scratch.home).expect("the services off load");
            let (resident, control) = running_resident(off.clone(), &scratch.base, &cancel);
            let control_task = tokio::task::spawn_local({
                let resident = Arc::clone(&resident);
                async move { resident.serve(control).await }
            });

            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let exposer = build_exposer(&scratch.home, off);
            let run = tokio::task::spawn_local({
                let cancel = cancel.clone();
                async move { exposer.run(&host, cancel).await }
            });

            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet_badge(member.node_id());
            assert!(
                reach(host_id, &member, &badge).await,
                "the enabled service admits its member"
            );

            toggle(&scratch.home, true).await;
            // Past the oracle's mtime-watch debounce, so the running gate re-reads the file.
            tokio::time::sleep(Duration::from_millis(250)).await;

            assert!(
                !reach(host_id, &member, &badge).await,
                "the disabled service refuses the next stream"
            );
            assert_eq!(
                resident.served(),
                0,
                "the disable moved zero control connections: it was file-only"
            );

            toggle(&scratch.home, false).await;
            tokio::time::sleep(Duration::from_millis(250)).await;
            assert!(
                reach(host_id, &member, &badge).await,
                "the re-enabled service is restored live"
            );
            assert_eq!(
                resident.served(),
                0,
                "the re-enable moved zero control connections too"
            );

            cancel.cancel();
            control_task
                .await
                .expect("the control task joins")
                .expect("the control arm ends Ok");
            run.await
                .expect("the exposer task joins")
                .expect("the exposer ends Ok");
        })
        .await;
}

/// BLOCKER-3 (revocation twin): with the resident control listener running, revoking the member at its
/// root id refuses the very next stream, monotonically (no re-enable), with ZERO control connections.
/// The revocation is written to `<home>/revoked` through the writer `swoosh revoke` uses, so the running
/// gate's refresh is what honors it.
#[tokio::test]
async fn revoke_while_resident_refuses_next_stream() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let scratch = Scratch::new("revoke");
            let cancel = CancellationToken::new();
            let off = LiveServeToml::load(&scratch.home).expect("the services off load");
            let (resident, control) = running_resident(off.clone(), &scratch.base, &cancel);
            let control_task = tokio::task::spawn_local({
                let resident = Arc::clone(&resident);
                async move { resident.serve(control).await }
            });

            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let exposer = build_exposer(&scratch.home, off);
            let run = tokio::task::spawn_local({
                let cancel = cancel.clone();
                async move { exposer.run(&host, cancel).await }
            });

            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet_badge(member.node_id());
            assert!(
                reach(host_id, &member, &badge).await,
                "the member admits before revocation"
            );

            let cap = Cap::parse(&badge).expect("the badge link parses");
            let home_lock = HomeWrite::take(&scratch.home)
                .await
                .expect("take home.lock");
            swoosh::revoked::add(
                &home_lock,
                &scratch.home,
                cap.root_revocation_id().map(Revocation::Id),
            )
            .expect("revoke the badge at its root");
            drop(home_lock);
            // Past the oracle's mtime-watch debounce, so the running gate re-reads the file.
            tokio::time::sleep(Duration::from_millis(250)).await;

            assert!(
                !reach(host_id, &member, &badge).await,
                "the revoked member is refused on the next stream"
            );
            assert_eq!(
                resident.served(),
                0,
                "the revocation moved zero control connections: it was file-only"
            );
            assert!(
                !reach(host_id, &member, &badge).await,
                "revocation is monotone fail-closed: still refused on a later stream"
            );

            cancel.cancel();
            control_task
                .await
                .expect("the control task joins")
                .expect("the control arm ends Ok");
            run.await
                .expect("the exposer task joins")
                .expect("the exposer ends Ok");
        })
        .await;
}

/// A `serve.toml` deleted while `serve` runs keeps the services it turned off, in the gate and in the
/// status alike: the stream is still refused, and the status the control socket reports still names the
/// service off, because both read the one instance the gate asks.
#[tokio::test]
async fn a_deleted_serve_toml_keeps_the_disabled_set_in_gate_and_status() {
    use swoosh::node_client::NodeClient as _;
    use swoosh::serve::control_codec::DisabledList;

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let scratch = Scratch::new("deleted");
            let cancel = CancellationToken::new();
            let off = LiveServeToml::load(&scratch.home).expect("the services off load");
            let (resident, _control) = running_resident(off.clone(), &scratch.base, &cancel);

            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let exposer = build_exposer(&scratch.home, off);
            let run = tokio::task::spawn_local({
                let cancel = cancel.clone();
                async move { exposer.run(&host, cancel).await }
            });
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet_badge(member.node_id());

            toggle(&scratch.home, true).await;
            tokio::time::sleep(Duration::from_millis(250)).await;
            let reported = || async {
                resident
                    .services()
                    .await
                    .expect("the resident answers")
                    .disabled
            };
            assert!(!reach(host_id, &member, &badge).await, "turned off");
            assert_eq!(
                reported().await,
                DisabledList::Known(vec![GATED.to_owned()])
            );

            std::fs::remove_file(scratch.home.serve_toml()).expect("delete serve.toml");
            tokio::time::sleep(Duration::from_millis(250)).await;
            assert!(
                !reach(host_id, &member, &badge).await,
                "the gate still refuses the service"
            );
            assert_eq!(
                reported().await,
                DisabledList::Known(vec![GATED.to_owned()]),
                "and the status still reports it off"
            );

            cancel.cancel();
            run.await
                .expect("the exposer task joins")
                .expect("the exposer ends Ok");
        })
        .await;
}

/// A `serve.toml` that cannot be read while `serve` runs changes nothing the run holds: damaged, loose
/// (others can write it) or unreadable, the gate still refuses the service turned off, the status still
/// reports it, and the run's one watcher still holds the services, the relay and the resolver it read.
#[tokio::test]
async fn a_read_error_keeps_the_held_settings() {
    use std::os::unix::fs::PermissionsExt as _;

    use swoosh::node_client::NodeClient as _;
    use swoosh::serve::control_codec::DisabledList;

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let scratch = Scratch::new("read-error");
            let home_lock = HomeWrite::take(&scratch.home)
                .await
                .expect("take home.lock");
            ServeToml::update(&home_lock, &scratch.home, |file| {
                file.services = vec![format!("{GATED}=echo:")];
                file.off.insert(GATED.to_owned());
                file.relay = Some("https://relay.example".parse().expect("a relay"));
                file.resolver = Some("https://dns.example/pkarr".parse().expect("a resolver"));
            })
            .expect("write serve.toml");
            drop(home_lock);
            let held = ServeToml::read(&scratch.home).expect("read serve.toml");

            let cancel = CancellationToken::new();
            let watch = LiveServeToml::load(&scratch.home).expect("serve.toml loads");
            let (resident, _control) = running_resident(watch.clone(), &scratch.base, &cancel);
            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let exposer = build_exposer(&scratch.home, watch.clone());
            let run = tokio::task::spawn_local({
                let cancel = cancel.clone();
                async move { exposer.run(&host, cancel).await }
            });
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet_badge(member.node_id());
            let reported = || async {
                resident
                    .services()
                    .await
                    .expect("the resident answers")
                    .disabled
            };

            let path = scratch.home.serve_toml();
            // Each spoils the file in a way the next read refuses; the text it holds would turn the
            // service back on and drop the relay, the resolver and the services if it were read.
            let mode =
                |bits| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(bits));
            for spoiled in ["damaged", "loose", "unreadable"] {
                match spoiled {
                    "damaged" => std::fs::write(&path, "off = 3\n").expect("damage it"),
                    "loose" => {
                        std::fs::write(&path, "").expect("empty it");
                        mode(0o666).expect("loosen it");
                    }
                    _ => mode(0o000).expect("make it unreadable"),
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
                assert!(
                    !reach(host_id, &member, &badge).await,
                    "{spoiled}: the gate still refuses the service"
                );
                assert_eq!(
                    reported().await,
                    DisabledList::Known(vec![GATED.to_owned()]),
                    "{spoiled}: the status still reports it off"
                );
                assert_eq!(watch.held(), held, "{spoiled}: every setting is kept");
            }

            cancel.cancel();
            run.await
                .expect("the exposer task joins")
                .expect("the exposer ends Ok");
        })
        .await;
}

/// Guard: a `revoked` made shorter while `serve` runs never un-revokes live. Two members revoked at their
/// roots are refused by the gate `serve` builds; the file loses a line, and both are still refused, because
/// the running store only ever adds what it reads.
#[tokio::test]
async fn a_shorter_revoked_never_unrevokes_live() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let scratch = Scratch::new("shorter");
            swoosh::config::write_signet(
                &swoosh::testkit::lock(),
                &scratch.home,
                TestRoot::seeded(SIGNET).node_id(),
            )
            .expect("pin the root");
            let own = NodeId::from_ed25519_secret(&[3u8; 32]);
            let (gate, cut) =
                swoosh::gate::anchored(&scratch.home, own, swoosh::serve::BoundTargets::default())
                    .await
                    .expect("the gate serve builds");
            let exposer = Router::new(gate)
                .service(
                    GATED.parse().expect("a name"),
                    ServiceList::new(
                        ServiceCatalog::decode(&0u32.to_be_bytes()).expect("empty catalog"),
                    ),
                )
                .expect("the gated route binds")
                .expose()
                .expect("the exposer assembles")
                .with_live_cuts(cut);
            let cancel = CancellationToken::new();
            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let run = tokio::task::spawn_local({
                let cancel = cancel.clone();
                async move { exposer.run(&host, cancel).await }
            });

            let members: Vec<_> = (0..2)
                .map(|_| {
                    let member = Node::new(MemTransport::bind(), NoDiscovery);
                    let badge = signet_badge(member.node_id());
                    (member, badge)
                })
                .collect();
            for (member, badge) in &members {
                assert!(reach(host_id, member, badge).await, "a member admits");
            }
            let home_lock = HomeWrite::take(&scratch.home)
                .await
                .expect("take home.lock");
            swoosh::revoked::add(
                &home_lock,
                &scratch.home,
                members.iter().flat_map(|(_, badge)| {
                    Cap::parse(badge)
                        .expect("the badge parses")
                        .root_revocation_id()
                        .map(Revocation::Id)
                }),
            )
            .expect("revoke both");
            drop(home_lock);
            tokio::time::sleep(Duration::from_millis(250)).await;
            for (member, badge) in &members {
                assert!(!reach(host_id, member, badge).await, "a revoked member");
            }

            let path = scratch.home.revoked();
            let text = std::fs::read_to_string(&path).expect("read revoked");
            assert_eq!(text.lines().count(), 2, "{text}");
            let first = text.lines().next().expect("a line");
            std::fs::write(&path, format!("{first}\n")).expect("shorten revoked");
            tokio::time::sleep(Duration::from_millis(250)).await;
            for (member, badge) in &members {
                assert!(
                    !reach(host_id, member, badge).await,
                    "still refused once the file lost its line"
                );
            }

            cancel.cancel();
            run.await
                .expect("the exposer task joins")
                .expect("the exposer ends Ok");
        })
        .await;
}
