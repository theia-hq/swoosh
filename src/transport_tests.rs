//! What the composed discovery reads off its transport, and what it reports back: the one `advertise`
//! call that starts mDNS is also the one source of the reach a surface reports, so a bind that could
//! publish nothing never reads as a node another host can hear.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use bifrost::{Addr, Error, InProcess, NodeId, Transport};
use bifrost_mem::{MemSession, MemTransport};

use super::{MdnsState, PeerHint};

/// A wildcard bind on a fixed port: the shape the rewrite destroys, since `local_addr` reports it as
/// loopback and a publisher cannot then tell it from a node that deliberately bound `127.0.0.1`.
const WILDCARD: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000);

/// An address accessor read off the transport, with what it handed back.
#[derive(Debug, PartialEq, Eq)]
enum Read {
    /// The dialable hints, which rewrite an unspecified bind to loopback.
    LocalAddr(Vec<SocketAddr>),
    /// The sockets as bound, unspecified IP preserved.
    BoundSockets(Vec<SocketAddr>),
}

/// A transport over mem's sessions that records which address accessor was read and answers
/// [`bound_sockets`](Transport::bound_sockets) with a wildcard bind of its own.
///
/// The two accessors are indistinguishable downstream (the advertisement goes to the network, not to a
/// value the test holds), so recording the read at the source is what proves which one the composition
/// root trusted.
struct Recording {
    inner: MemTransport,
    reads: Arc<Mutex<Vec<Read>>>,
}

impl Transport for Recording {
    type Security = InProcess;
    type Session = MemSession;

    fn node_id(&self) -> NodeId {
        self.inner.node_id()
    }

    fn local_addr(&self) -> Addr {
        let addr = self.inner.local_addr();
        self.record(Read::LocalAddr(addr.hints.clone()));
        addr
    }

    fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.record(Read::BoundSockets(vec![WILDCARD]));
        vec![WILDCARD]
    }

    async fn connect(&self, addr: Addr) -> Result<Self::Session, Error> {
        self.inner.connect(addr).await
    }

    async fn accept(&self) -> Result<Self::Session, Error> {
        self.inner.accept().await
    }

    async fn close(&self) {
        self.inner.close().await;
    }
}

impl Recording {
    /// Note one accessor read. A poisoned lock would only be a panic inside an accessor, which would have
    /// failed the test already.
    fn record(&self, read: Read) {
        self.reads.lock().unwrap().push(read);
    }
}

/// Composing the discovery hands mDNS the transport's bound sockets, and never asks for the hints.
///
/// The advertisement itself may or may not reach the network here (a sandbox blocks multicast, which is
/// the honest degraded path), so the assertion is on what the composition root read, which holds either
/// way.
#[tokio::test]
async fn composing_discovery_advertises_the_bound_sockets() {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let transport = Recording {
        inner: MemTransport::bind(),
        reads: Arc::clone(&reads),
    };

    let _composed = PeerHint::discovery(&transport, []);

    assert_eq!(
        *reads.lock().unwrap(),
        vec![Read::BoundSockets(vec![WILDCARD])],
        "the advertisement must take raw bind truth, not the loopback-rewritten hints"
    );
}

/// A bind with no local addresses to advertise (the in-process transport's shape) cannot be published,
/// so the composed discovery never reports a node another host can hear: it either browses without
/// announcing, or (where the service itself will not start) reads as blocked. A caller that reports
/// discovery reads this state rather than assuming it.
#[tokio::test]
async fn a_bind_without_advertisable_addresses_reports_mdns_unavailable() {
    let transport = MemTransport::bind();
    let composed = PeerHint::discovery(&transport, []);
    assert!(
        matches!(composed.mdns, MdnsState::BrowseOnly(_) | MdnsState::Blocked),
        "no addresses to advertise never reads as advertised, got {:?}",
        composed.mdns
    );
}
