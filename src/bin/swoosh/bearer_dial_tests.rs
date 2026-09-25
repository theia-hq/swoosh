// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Which key a link dial binds, through the path the composition root takes: a real verb, clap-parsed,
//! its identity resolved from its home, bound over `quirk+noise` on loopback, and dialed at the gate
//! `serve` runs, whose handler records the key each admitted dialer proved.
//!
//! An `anyone` link admits whoever holds it, so its dial binds a throwaway key: the server never sees
//! this home's key, and revoking that key closes nothing the link opens. A link bound to this machine's
//! key admits only that key, so its dial binds it.

use core::time::Duration;
use std::sync::{Arc, Mutex, PoisonError};

use bifrost::{NoDiscovery, Node, Session as _};
use bifrost_noise::Noise;
use clap::Parser as _;
use nauthy::{Cap, Link, Service, VerifyKey};
use swoosh::contacts::Contacts;
use swoosh::grants::{self, Delegation, GrantKind, GrantRecord, Grants};
use swoosh::home::Home;
use swoosh::identity::Secret;
use swoosh::node_signer::{Bind, NodeSigner};
use swoosh::reaching::{self, BindRole, Reaching as _};
use swoosh::testkit::TestNode;
use swoosh::transport::PeerHint;
use tightbeam::open_policy::Never;
use tightbeam::tunnel::{
    BoxRead, BoxWrite, CancellationToken, Handler, Router, ServeError, Served,
};
use tokio::io::AsyncReadExt as _;

use crate::{Cli, Verb};

/// The machine that serves and signs the links.
const SERVER: u8 = 0x61;
/// The machine that dials, whose home holds this key.
const DESK: u8 = 0x62;
/// The service every link here grants.
const SERVICE: &str = "ssh";

/// A scratch home holding `seed`'s key, removed on drop.
struct Scratch {
    home: Home,
}

impl Scratch {
    async fn new(tag: &str, seed: u8) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "swoosh-bearer-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let home = Home::resolve(Some(dir)).unwrap();
        swoosh::identity::write(&TestNode::seeded(seed).seed(), &home)
            .await
            .unwrap();
        Self { home }
    }

    async fn secret(&self) -> Secret {
        swoosh::identity::load(&self.home).await.unwrap().unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.home.dir());
    }
}

/// The service's handler: it records the key each admitted dialer proved.
struct Recorder(Arc<Mutex<Vec<VerifyKey>>>);

impl Handler for Recorder {
    type Exposure = Never;

    async fn serve(
        &self,
        served: Served<Self>,
        _writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(served.peer());
        Ok(())
    }
}

/// The server: signs `bind`'s link for [`SERVICE`] and records it in its ledger, as `share` does, so its
/// gate admits the link.
async fn share(server: &Scratch, bind: Bind) -> Link {
    let (kind, holder) = match bind {
        Bind::Anyone => (GrantKind::Bearer, grants::ANYONE.to_owned()),
        Bind::Device(key) => (GrantKind::Device, key.to_string()),
        Bind::Fleet(key) => (GrantKind::Fleet, key.to_string()),
    };
    let lifetime = Duration::from_secs(3600);
    let service: Service = SERVICE.parse().unwrap();
    let link = NodeSigner::from(&server.secret().await)
        .mint_slip(&service, bind, lifetime, Delegation::Sealed)
        .unwrap();
    let record = GrantRecord {
        target: service,
        kind,
        delegation: Delegation::Sealed,
        holder,
        root_id: Cap::parse(link.as_str())
            .unwrap()
            .root_revocation_id()
            .unwrap(),
        expiry: nauthy::Request::expires_in(lifetime),
    };
    Grants::at(server.home.links())
        .append(&record)
        .await
        .unwrap();
    link
}

/// Dial `link` from `desk` as `swoosh reach <link> ssh` does, at `server`'s gate. Returns whether the gate
/// admitted the dial and, when it did, the key the server recorded for the dialer.
async fn dial(server: &Scratch, desk: &Scratch, link: &Link) -> Option<VerifyKey> {
    let printed = swoosh::link::Link::from(Link::clone(link)).to_string();
    let Some(command) = Cli::try_parse_from(["swoosh", "reach", printed.as_str(), SERVICE])
        .unwrap()
        .command
    else {
        panic!("reach parses");
    };
    let Verb::Outward(outward) = command.split() else {
        panic!("reach is a reaching verb");
    };

    // The server: `serve`'s gate over its home, one gated route that records who it admitted.
    let host_secret = server.secret().await;
    let host_transport = host_secret
        .with_bytes(bifrost_quirk::Endpoint::bind_with_secret)
        .await
        .unwrap();
    let host_transport = host_secret
        .with_bytes(|seed| Noise::new(host_transport, seed))
        .unwrap();
    let host = Node::new(host_transport, NoDiscovery);
    let (gate, cut) = swoosh::gate::anchored(&server.home, host.node_id())
        .await
        .unwrap();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let exposer = Router::new(gate)
        .service(SERVICE.parse().unwrap(), Recorder(Arc::clone(&recorded)))
        .unwrap()
        .expose()
        .unwrap()
        .with_live_cuts(cut);

    // The dialer: the identity its verb states, resolved from its home and bound as the root binds it.
    let secret = swoosh::identity::resolve(outward.identity(), &desk.home)
        .await
        .unwrap();
    let transport = secret
        .with_bytes(bifrost_quirk::Endpoint::bind_with_secret)
        .await
        .unwrap();
    let transport = secret
        .with_bytes(|seed| Noise::new(transport, seed))
        .unwrap();
    let bind_role = outward.bind_role();
    let hint: PeerHint = format!("{}={}", host.node_id(), host.local_addr().hints[0])
        .parse()
        .unwrap();
    let discovery = PeerHint::discovery(&transport, [hint], &bind_role).discovery;
    let node = Node::new(transport, discovery);
    let BindRole::Dialing(credential) = bind_role else {
        panic!("reach dials");
    };
    let (slot1, slot2) = reaching::resolve(credential, &secret, &desk.home)
        .await
        .unwrap()
        .into_slots();
    let peer = outward.dialed().expect("reach names its peer");
    let connector = peer
        .connector(&Contacts::default(), SERVICE.parse().unwrap(), slot1, slot2)
        .unwrap();

    let cancel = CancellationToken::new();
    let serving = exposer.run(&host, cancel.clone());
    let dialing = async {
        let session = connector.open_service(&node).await.unwrap();
        let admitted = match session.open_bi().await {
            Ok((send, mut recv)) => {
                drop(send);
                let mut rest = Vec::new();
                let _ = recv.read_to_end(&mut rest).await;
                true
            }
            Err(_) => false,
        };
        cancel.cancel();
        admitted
    };
    let (served, admitted) = tokio::join!(serving, async {
        tokio::time::timeout(Duration::from_secs(20), dialing)
            .await
            .expect("the dial ends within the deadline")
    });
    served.unwrap();
    node.close().await;
    host.close().await;
    let recorded = recorded
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    admitted.then(|| {
        recorded
            .first()
            .copied()
            .expect("an admitted dial is recorded")
    })
}

/// The key `seed`'s home dials under when it binds its own key.
fn home_key(seed: u8) -> VerifyKey {
    TestNode::seeded(seed).verify_key()
}

#[tokio::test]
async fn a_bearer_link_dial_binds_a_throwaway_key() {
    let server = Scratch::new("throwaway-server", SERVER).await;
    let desk = Scratch::new("throwaway-desk", DESK).await;
    let link = share(&server, Bind::Anyone).await;

    let recorded = dial(&server, &desk, &link)
        .await
        .expect("the gate admits an anyone link");
    assert_ne!(
        recorded,
        home_key(DESK),
        "the server records a key that is not this home's"
    );
}

#[tokio::test]
async fn a_bearer_link_admits_after_the_dialers_device_key_is_revoked_at_the_server() {
    let server = Scratch::new("revoked-server", SERVER).await;
    let desk = Scratch::new("revoked-desk", DESK).await;
    let link = share(&server, Bind::Anyone).await;
    swoosh::gate::add_revoked_keys(&server.home, &[home_key(DESK)]).unwrap();

    assert!(
        dial(&server, &desk, &link).await.is_some(),
        "revoking this machine's key at the server leaves its anyone link open"
    );
}

#[tokio::test]
async fn a_bound_link_dial_binds_the_home_key() {
    let server = Scratch::new("bound-server", SERVER).await;
    let desk = Scratch::new("bound-desk", DESK).await;
    let link = share(&server, Bind::Device(home_key(DESK))).await;

    let recorded = dial(&server, &desk, &link)
        .await
        .expect("the gate admits a link bound to the key that dials");
    assert_eq!(recorded, home_key(DESK), "admitted as this home's key");
}
