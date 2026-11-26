use core::net::SocketAddr;

use bifrost_mdns::{At, Dialable, MdnsError, Missing, Scope};

use super::{Internet, Lan, Network, Picks, ReachSource};
use crate::transport::MdnsState;

fn at(socket: &str, scope: Scope) -> At {
    At {
        socket: socket.parse().expect("a fixture socket parses"),
        scope,
    }
}

fn addr(socket: &str) -> SocketAddr {
    socket.parse().expect("a fixture socket parses")
}

fn tunnel(link: &str) -> Scope {
    Scope::Tunnel {
        link: link.to_owned(),
    }
}

/// One pick per class, in `Dialable::all()` order, and a v4 replaces a v6 in its class. The fixture is
/// a wifi, ethernet and two-VPN host, shuffled: the order is the expansion's, not the array's. A tunnel
/// lands in `tunnel`, never in `network`, and a class with no v4 shows its v6.
#[test]
fn one_address_per_class_and_v4_leads() {
    let host: Dialable = [
        at("[::1]:51006", Scope::ThisMachine),
        at("[2606:4700::6810:84e5]:51006", Scope::Internet),
        at("100.101.102.103:51006", tunnel("utun4")),
        at("[fd7a:115c:a1e0::1]:51006", Scope::Network),
        at("127.0.0.1:51006", Scope::ThisMachine),
        at("10.0.8.2:51006", tunnel("wg0")),
        at("192.168.1.20:51006", Scope::Network),
        at("192.168.1.21:51006", Scope::Network),
    ]
    .into_iter()
    .collect();

    let picks = Picks::of(&host);

    assert_eq!(
        picks.public(),
        Some(addr("[2606:4700::6810:84e5]:51006")),
        "a class with no v4 shows its v6"
    );
    assert_eq!(
        picks.network(),
        Network::At(addr("192.168.1.20:51006")),
        "the first v4 of the class wins over the v6 the host listed first"
    );
    assert_eq!(
        picks.tunnel(),
        Some(addr("100.101.102.103:51006")),
        "the first tunnel, whatever its link"
    );
    assert_eq!(picks.computer(), Some(addr("127.0.0.1:51006")));
}

/// Only an advertisement another host can dial reads as announced. A loopback record, a browse-only
/// start and a blocked multicast all leave a peer on this network with nothing to find by key.
#[test]
fn mdns_state_reads_as_lan() {
    assert_eq!(
        Lan::of(&MdnsState::OnLan(vec![addr("192.168.1.20:51006")])),
        Lan::Announced
    );
    for degraded in [
        MdnsState::LoopbackOnly,
        MdnsState::BrowseOnly(MdnsError::NoAddrs),
        MdnsState::Blocked,
    ] {
        assert_eq!(Lan::of(&degraded), Lan::ByAddressOnly, "{degraded:?}");
    }
    assert_eq!(Internet::of(true), Internet::Off);
    assert_eq!(Internet::of(false), Internet::On);
}

/// A host whose interfaces could not be read has an unknown network, never none: a screen that read
/// it as none would say offline when the host only could not look. An address in hand is still shown.
#[test]
fn unreadable_interfaces_read_as_unknown() {
    let unread = || Missing::Interfaces(std::io::Error::other("getifaddrs: denied"));
    let loopback_only = Dialable::short([at("127.0.0.1:51006", Scope::ThisMachine)], unread());
    assert_eq!(Picks::of(&loopback_only).network(), Network::Unknown);

    let named = Dialable::short([at("192.168.1.20:51006", Scope::Network)], unread());
    assert_eq!(
        Picks::of(&named).network(),
        Network::At(addr("192.168.1.20:51006"))
    );

    let read: Dialable = [at("127.0.0.1:51006", Scope::ThisMachine)]
        .into_iter()
        .collect();
    assert_eq!(Picks::of(&read).network(), Network::Nothing);
}

/// An entry no peer of its class could dial is never picked: port 0, a multicast or unspecified
/// address, loopback outside `computer`, a non-loopback in `computer`, and a link-local v6, whose scope
/// the reply does not carry. The next entry of the class takes its place.
#[test]
fn an_entry_its_class_cannot_hold_is_skipped() {
    let host: Dialable = [
        at("[fe80::1%4]:51006", Scope::Network),
        at("192.168.1.20:0", Scope::Network),
        at("192.168.1.21:51006", Scope::Network),
        at("127.0.0.1:51006", Scope::Internet),
        at("224.0.0.251:51006", Scope::Internet),
        at("192.168.1.22:51006", Scope::ThisMachine),
    ]
    .into_iter()
    .collect();

    let picks = Picks::of(&host);

    assert_eq!(picks.network(), Network::At(addr("192.168.1.21:51006")));
    assert_eq!(picks.public(), None);
    assert_eq!(picks.computer(), None);
}

/// A v6 pick carries no flow label and no scope id, so the value the bind picked is the value the
/// reply decodes.
#[test]
fn a_v6_pick_drops_flow_and_scope() {
    let socket = SocketAddr::V6(core::net::SocketAddrV6::new(
        "2606:4700::6810:84e5".parse().expect("a v6 address"),
        51006,
        7,
        3,
    ));
    let host: Dialable = [At {
        socket,
        scope: Scope::Internet,
    }]
    .into_iter()
    .collect();
    assert_eq!(
        Picks::of(&host).public(),
        Some(addr("[2606:4700::6810:84e5]:51006"))
    );
}

/// The facts fixed at bind ride along unchanged, and the addresses come from the expansion at the ask.
#[test]
fn a_source_reads_its_bind_facts_and_the_host_now() {
    let source = ReachSource::new(
        vec![addr("192.168.1.20:51006"), addr("127.0.0.1:51006")],
        Internet::Off,
        Lan::ByAddressOnly,
    );
    let reach = source.reachable();
    assert_eq!(reach.internet, Internet::Off);
    assert_eq!(reach.lan, Lan::ByAddressOnly);
    assert_eq!(reach.at.network(), Network::At(addr("192.168.1.20:51006")));
    assert_eq!(reach.at.computer(), Some(addr("127.0.0.1:51006")));
}

/// A host whose interfaces cannot be read, seen by a test: two addresses in hand and the read failed.
fn unread_host(_bound: Vec<SocketAddr>) -> Dialable {
    Dialable::short(
        [
            at("192.168.1.20:51006", Scope::Network),
            at("127.0.0.1:51006", Scope::ThisMachine),
        ],
        Missing::Interfaces(std::io::Error::other("getifaddrs: denied")),
    )
}

/// A log line, captured.
struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// An unread host is logged with its cause and no address: a warn line reaches the journal of a
/// supervised run, and an address there is one the person never chose to show. It warns once when the
/// host becomes unreadable, not on every ask while it stays so.
#[test]
fn an_unread_host_logs_its_cause_and_no_address() {
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = std::sync::Arc::clone(&log);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || LogCapture(std::sync::Arc::clone(&writer)))
        .finish();
    let source =
        ReachSource::new(Vec::new(), Internet::On, Lan::Announced).expanding_with(unread_host);

    let reach = tracing::subscriber::with_default(subscriber, || {
        source.reachable();
        source.reachable()
    });

    assert_eq!(reach.at.network(), Network::At(addr("192.168.1.20:51006")));
    let log = String::from_utf8(log.lock().expect("the capture lock").clone()).expect("utf-8");
    assert!(
        log.contains("could not read this host's addresses") && log.contains("getifaddrs: denied"),
        "the cause is logged: {log:?}"
    );
    assert_eq!(
        log.lines()
            .filter(|line| line.contains("WARN") && line.contains("could not read"))
            .count(),
        1,
        "one warn for the change, not one per ask: {log:?}"
    );
    assert!(
        !log.contains("192.168") && !log.contains("127.0.0.1") && !log.contains("51006"),
        "no address reaches the log: {log:?}"
    );
}
