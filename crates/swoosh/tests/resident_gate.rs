// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! BLOCKER-3, end to end over the in-process transport: a running resident's control socket is never a
//! data channel into the gate. A service disabled by writing `<home>/disabled`, and a member revoked by
//! writing `<home>/revoked`, are both honored LIVE by the gate on the next stream with ZERO control
//! connections (the resident's `served()` counter stays at zero). Both are file-writes, exactly as
//! `swoosh service disable` and `swoosh grant revoke` perform them; the socket carries only reads and a
//! stop, so it cannot express either mutation.

use core::time::Duration;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use nauthy::{Cap, FileDenylist, Identity};
use swoosh::commands::serve::{CONTROL_SERVICES_SERVICE, Resident, ServiceList};
use swoosh::home::Home;
use tightbeam::enabled::FileDisabledList;
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{self, CancellationToken, Connector, Exposer, Router, ServiceCatalog};

/// The signet's fixed secret; its ed25519 public half is the signet the family gate trusts.
const SIGNET_SECRET: [u8; 32] = [7u8; 32];

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

/// The exposer a resident serves from: one gated `control.services` read, the enabled oracle on
/// `<home>/disabled`, and the revocation denylist on `<home>/revoked`. Built through the same
/// `resolve_gate` + handler the product path injects.
async fn build_exposer(home: &Home) -> Exposer {
    let signet = NodeId::from_ed25519_secret(&SIGNET_SECRET);
    let denylist = FileDenylist::load(home.revoked())
        .await
        .expect("the revocation denylist loads");
    let gate = tunnel::resolve_gate(Some(signet), denylist).expect("the family gate resolves");
    let enabled = FileDisabledList::load(home.disabled())
        .await
        .expect("the disabled list loads");
    Router::new(gate)
        .service(
            CONTROL_SERVICES_SERVICE.parse().expect("a name"),
            ServiceList::new(ServiceCatalog::decode(&0u32.to_be_bytes()).expect("empty catalog")),
        )
        .expect("the control.services route binds")
        .expose()
        .expect("the resident exposer assembles")
        .with_enabled(enabled)
}

/// A membership badge the signet signed, bound to the dialer's proven mem id: the shape `swoosh mint`
/// mints for a device, and the cap `swoosh grant revoke` cuts at its root.
fn signet_badge(bound: NodeId) -> String {
    Identity::from_secret(&SIGNET_SECRET)
        .expect("the signet identity")
        .mint_member(
            bound.verify_key(),
            nauthy::Request::expires_in(Duration::from_secs(300)),
        )
        .expect("mint a member badge")
        .seal()
        .expect("seal the badge")
        .link()
        .expect("render the badge link")
        .to_string()
}

/// Whether a member reaches the gated read over mem: admitted iff the per-stream handshake succeeds.
async fn reach(host: NodeId, member: &Node<MemTransport, NoDiscovery>, badge: &str) -> bool {
    let connector = Connector::to_node(
        host,
        CONTROL_SERVICES_SERVICE.parse().unwrap(),
        Some(badge.parse().unwrap()),
    );
    match connector.open_service(member).await {
        Ok(session) => session.open_bi().await.is_ok(),
        Err(_) => false,
    }
}

/// The resident's control listener, running for real on its own socket. Returned with the resident so
/// the test can assert its `served()` counter never moves: if a disable or a revoke reached the gate
/// through the socket, this is the counter that would climb.
fn running_resident(
    home: &Home,
    base: &Path,
    cancel: &CancellationToken,
) -> (Arc<Resident>, std::os::unix::net::UnixListener) {
    let control =
        std::os::unix::net::UnixListener::bind(base.join("control.sock")).expect("bind the socket");
    let resident = Arc::new(Resident::new(
        NodeId::from_ed25519_secret(&[3u8; 32]),
        None,
        ServiceCatalog::decode(&0u32.to_be_bytes()).expect("empty catalog"),
        home.disabled(),
        cancel.clone(),
    ));
    (resident, control)
}

/// BLOCKER-3 (disable): with the resident control listener running, writing `<home>/disabled` refuses
/// the very next stream, and re-enabling restores it live, both with ZERO control connections. The
/// disable is a file-write; the socket is untouched.
#[tokio::test]
async fn service_disable_is_file_only_with_the_daemon_running() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let scratch = Scratch::new("disable");
            let cancel = CancellationToken::new();
            let (resident, control) = running_resident(&scratch.home, &scratch.base, &cancel);
            let control_task = tokio::task::spawn_local({
                let resident = Arc::clone(&resident);
                async move { resident.serve(control).await }
            });

            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let exposer = build_exposer(&scratch.home).await;
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

            std::fs::write(scratch.home.disabled(), "control.services\n")
                .expect("disable the service by file");
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

            std::fs::write(scratch.home.disabled(), "\n").expect("re-enable the service by file");
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
/// The revocation is written to `<home>/revoked` by a separate denylist instance, exactly the file a
/// separate `swoosh grant revoke` process writes, so the running gate's mtime refresh is what honors it.
#[tokio::test]
async fn revoke_while_resident_refuses_next_stream() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let scratch = Scratch::new("revoke");
            let cancel = CancellationToken::new();
            let (resident, control) = running_resident(&scratch.home, &scratch.base, &cancel);
            let control_task = tokio::task::spawn_local({
                let resident = Arc::clone(&resident);
                async move { resident.serve(control).await }
            });

            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let exposer = build_exposer(&scratch.home).await;
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
            let mut denylist = FileDenylist::load(scratch.home.revoked())
                .await
                .expect("load the revocation denylist");
            denylist
                .revoke_root(&cap)
                .await
                .expect("revoke the badge at its root");
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
