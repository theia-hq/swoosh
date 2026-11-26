use core::net::SocketAddr;

use bifrost_mdns::{At, Dialable, Missing, Scope};
use rand::{Rng as _, SeedableRng as _};

use crate::serve::reachable::{Internet, Lan, Network, Picks, Reachable};
use crate::serve::socket::{ControlError, DisabledList, ServiceMenu, StatusReply};

fn at(socket: &str, scope: Scope) -> At {
    At {
        socket: socket.parse().expect("a fixture socket parses"),
        scope,
    }
}

fn encoded(reach: &Reachable) -> Vec<u8> {
    let mut out = Vec::new();
    reach.encode_into(&mut out);
    out
}

/// Decode a reach from the start of `bytes`, as the status reply does, and where it stopped. A byte
/// after the reach is the next field's, so refusing it is the status reply's job, not this codec's.
fn decoded(bytes: &[u8]) -> Result<(Reachable, usize), ControlError> {
    let mut cursor = 0;
    let reach = Reachable::decode_at(bytes, &mut cursor)?;
    Ok((reach, cursor))
}

/// Decode `bytes` as one whole reach: the round trips' check that the codec reads exactly what it
/// wrote.
fn round_tripped(bytes: &[u8]) -> Reachable {
    let (reach, read) = decoded(bytes).expect("an encoded reach decodes");
    assert_eq!(
        read,
        bytes.len(),
        "the codec reads exactly what it wrote: {bytes:?}"
    );
    reach
}

/// The reason a refusal carries, so a case that starts failing for another reason goes red.
fn refusal(bytes: &[u8]) -> String {
    match decoded(bytes) {
        Err(ControlError::Protocol(reason)) => reason,
        other => panic!("{bytes:?} is refused as a protocol error: {other:?}"),
    }
}

/// The address each class takes in a fixture, v4 and v6: one a peer of that class could dial.
const V4: [&str; 4] = [
    "203.0.113.7:51006",
    "192.168.1.20:51006",
    "100.101.102.103:51006",
    "127.0.0.1:51006",
];
const V6: [&str; 4] = [
    "[2606:4700::6810:84e5]:51007",
    "[fd7a:115c:a1e0::20]:51007",
    "[fd7a:115c:a1e0::103]:51007",
    "[::1]:51007",
];

fn scope(index: usize) -> Scope {
    match index {
        0 => Scope::Internet,
        1 => Scope::Network,
        2 => Scope::Tunnel {
            link: "utun4".to_owned(),
        },
        _ => Scope::ThisMachine,
    }
}

/// The picks for `mask` (one bit per class) with each class's family from `v6`, and the network
/// unknown when `unread`.
fn picks(mask: u8, v6: u8, unread: bool) -> Picks {
    let entries = (0..4)
        .filter(|index| mask & (1 << index) != 0)
        .map(|index| {
            let table = if v6 & (1 << index) != 0 { V6 } else { V4 };
            at(table[index], scope(index))
        });
    let missing = if unread {
        Missing::Interfaces(std::io::Error::other("denied"))
    } else {
        Missing::Nothing
    };
    Picks::of(&Dialable::short(entries, missing))
}

/// Every presence mask, with v4 and v6 mixes and both states of each fact, decodes to what was
/// encoded. With the network unknown, the mask has no network address, since a known address wins.
#[test]
fn reach_round_trips() {
    let mut seen = 0;
    for mask in 0..16u8 {
        for v6 in [0, 0b1111, 0b0101, 0b1010] {
            for unread in [false, true] {
                for internet in [Internet::On, Internet::Off] {
                    for lan in [Lan::Announced, Lan::ByAddressOnly] {
                        let reach = Reachable {
                            internet,
                            lan,
                            at: picks(mask, v6, unread),
                        };
                        let bytes = encoded(&reach);
                        assert!(bytes.len() <= 79, "the type bounds the reply: {bytes:?}");
                        assert_eq!(round_tripped(&bytes), reach, "{bytes:?}");
                        seen += 1;
                    }
                }
            }
        }
    }
    assert_eq!(seen, 16 * 4 * 2 * 2 * 2);
}

/// Every value `Picks::of` builds encodes and decodes to itself, including from a host that listed a
/// lying entry: the encoder is total, so a status reply never fails on reach.
#[test]
fn every_pick_of_a_host_round_trips() {
    let hosts: [Dialable; 3] = [
        [
            at("127.0.0.1:51006", Scope::Internet),
            at("192.168.1.20:0", Scope::Network),
            at("10.0.0.2:51006", Scope::ThisMachine),
            at(
                "[ff02::fb]:51006",
                Scope::Tunnel {
                    link: "utun4".to_owned(),
                },
            ),
        ]
        .into_iter()
        .collect(),
        Dialable::short(
            [at("[::1]:51006", Scope::ThisMachine)],
            Missing::Interfaces(std::io::Error::other("denied")),
        ),
        Dialable::short([], Missing::Flags),
    ];
    for host in &hosts {
        let reach = Reachable {
            internet: Internet::On,
            lan: Lan::Announced,
            at: Picks::of(host),
        };
        assert_eq!(round_tripped(&encoded(&reach)), reach, "{host:?}");
    }
}

/// The wire form of `slots`: on, announced, `present`, then each address.
fn wire(present: u8, addresses: &[&str]) -> Vec<u8> {
    let mut out = vec![0, 0, present];
    for socket in addresses {
        let socket: SocketAddr = socket.parse().expect("a fixture socket parses");
        match socket {
            SocketAddr::V4(v4) => {
                out.push(4);
                out.extend_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                out.push(6);
                out.extend_from_slice(&v6.ip().octets());
            }
        }
        out.extend_from_slice(&socket.port().to_be_bytes());
    }
    out
}

/// Garble is refused, never read as a reach: an unknown byte value, a high bit, an unknown family, a
/// short read, and every slot that lies about its class, each for its own reason. A lying slot is what
/// a person would paste into `--peer`, so the reply that carries one fails loudly.
#[test]
fn malformed_reach_is_refused() {
    let good = wire(0b1000, &["127.0.0.1:51006"]);
    assert!(decoded(&good).is_ok(), "the baseline decodes");

    const TRUNCATED: &str = "status is truncated";
    const MISFIT: &str = "reach address does not fit its class";
    let mut cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("internet 2", vec![2, 0, 0], "unknown reach internet 0x02"),
        ("lan 2", vec![0, 2, 0], "unknown reach lan 0x02"),
        (
            "high bit",
            vec![0, 0, 0b1000_0000],
            "unknown reach presence 0x80",
        ),
        (
            "bit 5",
            vec![0, 0, 0b10_0000],
            "unknown reach presence 0x20",
        ),
        (
            "family 5",
            {
                let mut bytes = good.clone();
                bytes[3] = 5;
                bytes
            },
            "unknown reach family 0x05",
        ),
        ("short address", good[..good.len() - 1].to_vec(), TRUNCATED),
        ("no presence byte", vec![0, 0], TRUNCATED),
        (
            "network and unknown",
            wire(0b1_0010, &["192.168.1.20:51006"]),
            "reach network is both known and unknown",
        ),
    ];
    for (name, slot, socket) in [
        ("port 0", 0, "203.0.113.7:0"),
        ("unspecified", 1, "0.0.0.0:51006"),
        ("unspecified v6", 0, "[::]:51006"),
        ("multicast", 1, "224.0.0.251:51006"),
        ("multicast v6", 2, "[ff02::fb]:51006"),
        ("broadcast", 1, "255.255.255.255:51006"),
        ("this-network range", 0, "0.1.2.3:51006"),
        ("loopback as public", 0, "127.0.0.1:51006"),
        ("mapped loopback as public", 0, "[::ffff:127.0.0.1]:51006"),
        ("loopback as network", 1, "127.0.0.1:51006"),
        ("loopback as tunnel", 2, "[::1]:51006"),
        ("network as computer", 3, "192.168.1.20:51006"),
        ("link-local v6", 1, "[fe80::1]:51006"),
    ] {
        cases.push((name, wire(1 << slot, &[socket]), MISFIT));
    }
    for (name, bytes, reason) in cases {
        assert_eq!(refusal(&bytes), reason, "{name}: {bytes:?}");
    }
}

/// A byte after a whole status reply is refused by the reply's own decode, the one path a reach
/// reaches a screen through: the reach codec stops where its record ends, and the reply holds the
/// frame to its length.
#[test]
fn a_trailing_byte_after_a_status_is_refused() {
    let status = StatusReply {
        node_id: bifrost::NodeId::from_ed25519_secret(&[9u8; 32]),
        pid: 4242,
        reach: Reachable {
            internet: Internet::On,
            lan: Lan::Announced,
            at: picks(0b1011, 0, false),
        },
        uptime_secs: 3,
        menu: ServiceMenu {
            catalog: tightbeam::tunnel::ServiceCatalog::decode(&0u32.to_be_bytes())
                .expect("an empty catalog decodes"),
            disabled: DisabledList::Known(Vec::new()),
        },
        warm: Vec::new(),
    };
    let mut bytes = status.encode().expect("the status encodes");
    assert_eq!(
        StatusReply::decode(&bytes).ok(),
        Some(status),
        "the baseline decodes"
    );
    bytes.push(0);
    assert!(
        matches!(
            StatusReply::decode(&bytes),
            Err(ControlError::Protocol(reason)) if reason == "status has trailing bytes"
        ),
        "a trailing byte is refused"
    );
}

/// A bind that named a public address beside a wildcard whose interface read failed: the named
/// address is known, the network is unknown, and the reply carries both. The one mix that sets the
/// public bit and the unknown bit together.
#[test]
fn a_named_address_beside_an_unread_wildcard_round_trips() {
    let host = Dialable::short(
        [
            at("203.0.113.7:51006", Scope::Internet),
            at("127.0.0.1:51007", Scope::ThisMachine),
        ],
        Missing::Interfaces(std::io::Error::other("denied")),
    );
    let reach = Reachable {
        internet: Internet::On,
        lan: Lan::ByAddressOnly,
        at: Picks::of(&host),
    };
    assert_eq!(
        reach.at.public(),
        Some("203.0.113.7:51006".parse().expect("a socket"))
    );
    assert_eq!(reach.at.network(), Network::Unknown);
    let bytes = encoded(&reach);
    assert_eq!(
        bytes[2], 0b1_1001,
        "public, computer, and the network unknown"
    );
    assert_eq!(round_tripped(&bytes), reach);
}

/// Every address a decoded reach can hold prints as digits, `a-f`, `.`, `:` and brackets: no byte of
/// the reply reaches a screen as text, so the row needs no escaper. Drawn over many byte strings, most
/// of them shaped like a reply so they decode.
#[test]
fn a_decoded_address_prints_only_address_characters() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5a2a);
    let mut accepted = 0;
    for _ in 0..20_000 {
        let present: u8 = rng.gen_range(0..32);
        let mut bytes = vec![rng.gen_range(0..2), rng.gen_range(0..2), present];
        for _ in 0..(present & 0b1111).count_ones() {
            let v6 = rng.gen_bool(0.5);
            bytes.push(if v6 { 6 } else { 4 });
            let mut ip = vec![0u8; if v6 { 16 } else { 4 }];
            rng.fill(ip.as_mut_slice());
            bytes.extend_from_slice(&ip);
            bytes.extend_from_slice(&rng.r#gen::<u16>().to_be_bytes());
        }
        let Ok((reach, _)) = decoded(&bytes) else {
            continue;
        };
        accepted += 1;
        let network = match reach.at.network() {
            Network::At(socket) => Some(socket),
            Network::Nothing | Network::Unknown => None,
        };
        let addresses = [
            reach.at.public(),
            network,
            reach.at.tunnel(),
            reach.at.computer(),
        ];
        for socket in addresses.into_iter().flatten() {
            let text = socket.to_string();
            assert!(
                text.chars()
                    .all(|c| c.is_ascii_digit() || "abcdef.:[]".contains(c)),
                "{text:?}"
            );
        }
    }
    assert!(
        accepted > 1_000,
        "the draw reaches the accepting path: {accepted}"
    );
}
