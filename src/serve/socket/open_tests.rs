use core::net::SocketAddr;
use core::time::Duration;
use std::time::SystemTime;

use bifrost::{ConnInfo, NodeId, Path, Refusal, RefusalDetail, Relay};
use nauthy::Link;

use super::{
    MAX_ATTACHED, MAX_OPEN_BODY, MAX_OPEN_ERROR, MAX_OPEN_REFUSAL, MalformedOpen, OpenLane,
    OpenRefusal, OpenRequest, PeerRefusal,
};
use crate::credential::LinkExt as _;
use crate::serve::control_codec::{ControlError, Request, Response};
use crate::testkit::{TestNode, TestRoot};

fn peer() -> NodeId {
    TestNode::seeded(0x63).node_id()
}

fn until() -> SystemTime {
    SystemTime::now() + Duration::from_secs(3600)
}

/// A slip the peer issued, so the node it addresses is the request's peer.
fn slip() -> Link {
    TestNode::seeded(0x63)
        .slip(&"ssh".parse().unwrap(), until())
        .unwrap()
        .link()
        .unwrap()
}

/// A well-formed link that addresses another node: a badge rooted elsewhere, for the peer.
fn foreign_slip() -> Link {
    TestRoot::seeded(1).device_badge(peer(), until()).unwrap()
}

/// An Open body spelled field by field, each length written from the bytes given, so a test can put
/// any field at, under or past its bound without the typed encoder's own checks in the way.
fn body(hints: &[&[u8]], service: &[u8], lane: u8, slip: Option<&[u8]>, observe: u8) -> Vec<u8> {
    let mut out = peer().key().to_vec();
    out.push(u8::try_from(hints.len()).unwrap());
    for hint in hints {
        out.push(u8::try_from(hint.len()).unwrap());
        out.extend_from_slice(hint);
    }
    out.push(u8::try_from(service.len()).unwrap());
    out.extend_from_slice(service);
    out.push(lane);
    match slip {
        None => out.push(0),
        Some(slip) => {
            out.push(1);
            out.extend_from_slice(&u16::try_from(slip.len()).unwrap().to_be_bytes());
            out.extend_from_slice(slip);
        }
    }
    out.push(observe);
    out
}

fn minimal() -> Vec<u8> {
    body(&[], b"x", 0, None, 0)
}

fn decode(body: &[u8]) -> Result<OpenRequest, MalformedOpen> {
    OpenRequest::decode(body)
}

#[test]
fn the_minimal_open_body_is_38_bytes_ending_unobserved() {
    // The minimal Main Open: K[32] | no hints | service `x` | Main | no slip | unobserved.
    let mut expected = peer().key().to_vec();
    expected.extend_from_slice(&[0x00, 0x01, 0x78, 0x00, 0x00, 0x00]);
    let request = OpenRequest::new(
        peer(),
        Vec::new(),
        "x".parse().unwrap(),
        OpenLane::Main,
        None,
    )
    .unwrap();
    let encoded = request.encode().unwrap();
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), 0x26);
    assert_eq!(encoded, minimal());
    let decoded = decode(&encoded).unwrap();
    assert_eq!(decoded.peer(), peer());
    assert!(decoded.hints().is_empty());
    assert_eq!(decoded.service().as_str(), "x");
    assert_eq!(decoded.lane(), OpenLane::Main);
    assert!(decoded.slip().is_none());
}

#[test]
fn lanes_are_the_byte_before_slip_presence() {
    for (byte, lane) in [
        (0, OpenLane::Main),
        (1, OpenLane::Bulk),
        (2, OpenLane::Isolated),
    ] {
        let mut bytes = minimal();
        bytes[35] = byte;
        assert_eq!(decode(&bytes).unwrap().lane(), lane);
        let request =
            OpenRequest::new(peer(), Vec::new(), "x".parse().unwrap(), lane, None).unwrap();
        assert_eq!(request.encode().unwrap(), bytes);
    }
    for byte in [3, 0xff] {
        assert_eq!(
            decode(&body(&[], b"x", byte, None, 0)).err(),
            Some(MalformedOpen::Lane)
        );
    }
}

#[test]
fn observation_one_is_malformed_exactly_like_two() {
    // An observed Open (`... 00 01 78 00 00 01`) is not a request this build serves.
    for observe in [1, 2, 0xff] {
        assert_eq!(
            decode(&body(&[], b"x", 0, None, observe)).err(),
            Some(MalformedOpen::Observation)
        );
    }
    // The same answer when every typed field would fail its parse: the byte is read before any field
    // is turned into a value, so a decoder that parses first answers with a field instead.
    let mut bytes = body(&[b"999"], b"no spaces", 2, Some(b"not a link"), 1);
    bytes[..32].copy_from_slice(&invalid_key());
    assert_eq!(decode(&bytes).err(), Some(MalformedOpen::Observation));
}

#[test]
fn hint_count_is_at_most_16() {
    let hint = b"192.0.2.1:7".as_slice();
    assert_eq!(
        decode(&body(&[hint; 16], b"x", 0, None, 0))
            .unwrap()
            .hints()
            .len(),
        16
    );
    assert_eq!(
        decode(&body(&[hint; 17], b"x", 0, None, 0)).err(),
        Some(MalformedOpen::HintCount)
    );
    let addr: SocketAddr = "192.0.2.1:7".parse().unwrap();
    assert_eq!(
        OpenRequest::new(
            peer(),
            vec![addr; 17],
            "x".parse().unwrap(),
            OpenLane::Main,
            None
        )
        .err(),
        Some(MalformedOpen::HintCount)
    );
}

#[test]
fn hint_length_is_1_to_64() {
    // At 1 and 64 the length holds and the text fails as an address; at 0 and 65 the length fails.
    for (len, expected) in [
        (0, MalformedOpen::HintLength),
        (1, MalformedOpen::Hint),
        (64, MalformedOpen::Hint),
        (65, MalformedOpen::HintLength),
    ] {
        let hint = vec![b'9'; len];
        assert_eq!(
            decode(&body(&[&hint], b"x", 0, None, 0)).err(),
            Some(expected),
            "{len}"
        );
    }
}

#[test]
fn service_length_is_1_to_128() {
    assert_eq!(
        decode(&body(&[], b"", 0, None, 0)).err(),
        Some(MalformedOpen::ServiceLength)
    );
    let longest = vec![b's'; 128];
    assert_eq!(
        decode(&body(&[], &longest, 0, None, 0))
            .unwrap()
            .service()
            .as_str()
            .len(),
        128
    );
    assert_eq!(
        decode(&body(&[], &[b's'; 129], 0, None, 0)).err(),
        Some(MalformedOpen::ServiceLength)
    );
    assert_eq!(
        decode(&body(&[], b"no spaces", 0, None, 0)).err(),
        Some(MalformedOpen::Service)
    );
}

#[test]
fn slip_length_is_1_to_14336() {
    for (len, expected) in [
        (0, MalformedOpen::SlipLength),
        (1, MalformedOpen::Slip),
        (14_336, MalformedOpen::Slip),
        (14_337, MalformedOpen::SlipLength),
    ] {
        let slip = vec![b'a'; len];
        assert_eq!(
            decode(&body(&[], b"x", 0, Some(&slip), 0)).err(),
            Some(expected),
            "{len}"
        );
    }
    let mut bytes = minimal();
    bytes[36] = 2;
    assert_eq!(decode(&bytes).err(), Some(MalformedOpen::SlipPresence));
}

#[test]
fn the_structural_maximum_is_15543_bytes_and_one_more_is_trailing() {
    // Every field at its bound: the structure holds, so the first typed field (a hint) is what fails.
    let hint = [b'9'; 64];
    let hint = hint.as_slice();
    let slip = vec![b'a'; 14_336];
    let mut bytes = body(&[hint; 16], &[b's'; 128], 2, Some(&slip), 0);
    assert_eq!(bytes.len(), 15_543);
    assert_eq!(bytes.len(), MAX_OPEN_BODY);
    assert_eq!(decode(&bytes).err(), Some(MalformedOpen::Hint));
    bytes.push(0);
    assert_eq!(decode(&bytes).err(), Some(MalformedOpen::Trailing));
}

#[test]
fn every_short_body_is_truncated_and_a_bad_key_is_refused() {
    let bytes = minimal();
    for end in 0..bytes.len() {
        assert_eq!(
            decode(&bytes[..end]).err(),
            Some(MalformedOpen::Truncated),
            "{end}"
        );
    }
    let mut bytes = minimal();
    bytes[..32].copy_from_slice(&invalid_key());
    assert_eq!(decode(&bytes).err(), Some(MalformedOpen::Peer));
}

/// 32 bytes that are not an Ed25519 key.
fn invalid_key() -> [u8; 32] {
    (0..=u8::MAX)
        .map(|byte| [byte; 32])
        .find(|key| NodeId::try_new(bifrost::CryptoKind::Ed25519, *key).is_err())
        .unwrap()
}

#[test]
fn a_full_open_round_trips_with_hint_order_and_duplicates() {
    let longest: SocketAddr = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535"
        .parse()
        .unwrap();
    let other: SocketAddr = "192.0.2.7:4433".parse().unwrap();
    let mut hints = vec![longest; 14];
    hints.extend([other, longest]);
    let slip = slip();
    let request = OpenRequest::new(
        peer(),
        hints.clone(),
        "s".repeat(128).parse().unwrap(),
        OpenLane::Isolated,
        Some(slip.clone()),
    )
    .unwrap();
    let encoded = request.encode().unwrap();
    // Spelled field by field from the table, so an encoder and decoder agreeing on a wrong layout
    // cannot pass.
    let longest_text = b"[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535".as_slice();
    let mut spelled = vec![longest_text; 14];
    spelled.extend([b"192.0.2.7:4433".as_slice(), longest_text]);
    assert_eq!(
        encoded,
        body(&spelled, &[b's'; 128], 2, Some(slip.as_str().as_bytes()), 0)
    );
    let decoded = decode(&encoded).unwrap();
    assert_eq!(decoded.hints(), hints.as_slice());
    assert_eq!(decoded.lane(), OpenLane::Isolated);
    assert_eq!(decoded.slip().unwrap().as_str(), slip.as_str());
    assert_eq!(decoded.encode().unwrap(), encoded);
    assert!(encoded.len() <= MAX_OPEN_BODY);
}

#[test]
fn a_slip_is_bare_link_text_never_the_person_facing_form() {
    let slip = slip();
    let prefixed = format!("swoosh:{}", slip.as_str());
    assert_eq!(
        decode(&body(&[], b"x", 0, Some(prefixed.as_bytes()), 0)).err(),
        Some(MalformedOpen::Slip)
    );
    assert!(decode(&body(&[], b"x", 0, Some(slip.as_str().as_bytes()), 0)).is_ok());
}

#[test]
fn a_slip_that_addresses_another_node_is_refused_both_ways() {
    assert_eq!(slip().dial_node().unwrap(), peer());
    let foreign = foreign_slip();
    assert_ne!(foreign.dial_node().unwrap(), peer());
    let ssh = || "ssh".parse().unwrap();
    assert_eq!(
        OpenRequest::new(
            peer(),
            Vec::new(),
            ssh(),
            OpenLane::Main,
            Some(foreign.clone())
        )
        .err(),
        Some(MalformedOpen::SlipPeer)
    );
    assert_eq!(
        decode(&body(&[], b"ssh", 0, Some(foreign.as_str().as_bytes()), 0)).err(),
        Some(MalformedOpen::SlipPeer)
    );
    // The peer's own slip is taken on every lane, built or read.
    for lane in [OpenLane::Main, OpenLane::Bulk, OpenLane::Isolated] {
        let built = OpenRequest::new(peer(), Vec::new(), ssh(), lane, Some(slip())).unwrap();
        assert_eq!(decode(&built.encode().unwrap()).unwrap().lane(), lane);
    }
}

#[test]
fn into_slip_hands_over_the_slip_itself() {
    let slip = slip();
    let request = OpenRequest::new(
        peer(),
        Vec::new(),
        "ssh".parse().unwrap(),
        OpenLane::Main,
        Some(slip.clone()),
    )
    .unwrap();
    assert_eq!(request.into_slip().unwrap().as_str(), slip.as_str());
    let bare = OpenRequest::new(
        peer(),
        Vec::new(),
        "ssh".parse().unwrap(),
        OpenLane::Main,
        None,
    )
    .unwrap();
    assert!(bare.into_slip().is_none());
}

#[test]
fn debug_names_no_hint_and_no_slip() {
    let slip = slip();
    let hint: SocketAddr = "192.0.2.7:4433".parse().unwrap();
    let request = OpenRequest::new(
        peer(),
        vec![hint],
        "ssh".parse().unwrap(),
        OpenLane::Main,
        Some(slip.clone()),
    )
    .unwrap();
    // The slip's own text is what follows its root key, which Debug may print as the peer.
    let (_, token) = slip.as_str().split_once('.').unwrap();
    let wrapped: Result<Option<OpenRequest>, ()> = Ok(Some(request));
    for shown in [format!("{wrapped:?}"), format!("{wrapped:#?}")] {
        assert!(!shown.contains(token), "{shown}");
        assert!(!shown.contains(&token[..16]), "{shown}");
        assert!(!shown.contains("192.0.2.7"), "{shown}");
        assert!(!shown.contains("4433"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(shown.contains("ssh"), "{shown}");
    }
}

async fn written(response: &Response) -> Vec<u8> {
    let mut out = Vec::new();
    response.write(&mut out).await.unwrap();
    out
}

async fn read_open(frame: &[u8]) -> Result<Response, ControlError> {
    let mut reader = frame;
    Response::read_open(&mut reader).await
}

fn protocol_reason(result: Result<Response, ControlError>) -> String {
    match result {
        Err(ControlError::Protocol(reason)) => reason,
        other => panic!("expected a protocol error, got {other:?}"),
    }
}

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = b"SWC1".to_vec();
    out.push(tag);
    out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[tokio::test]
async fn attached_unknown_is_the_published_bytes() {
    let response = Response::Attached(ConnInfo::default());
    let bytes = written(&response).await;
    assert_eq!(bytes, b"SWC1\x06\x00\x04\x00\x00\x00\x00");
    assert_eq!(read_open(&bytes).await.unwrap(), response);
}

#[tokio::test]
async fn attached_and_refusal_bodies_are_spelled_by_the_table() {
    // Direct | RTT 1234 us | remote `[2001:db8::1]:7` (15 bytes), with no path reference first.
    let mut attached = vec![0, 1, 1];
    attached.extend_from_slice(&1234u64.to_be_bytes());
    attached.extend_from_slice(&[1, 0, 15]);
    attached.extend_from_slice(b"[2001:db8::1]:7");
    let response = Response::Attached(ConnInfo {
        path: Path::Direct,
        rtt: Some(Duration::from_nanos(1_234_999)),
        remote: Some("[2001:db8::1]:7".parse().unwrap()),
    });
    assert_eq!(written(&response).await, frame(6, &attached));
    // Relayed spells its URL with a u16 length after the class.
    let relayed = Response::Attached(ConnInfo {
        path: Path::Relayed(Relay::from(url::Url::parse("https://r.example/").unwrap())),
        rtt: None,
        remote: None,
    });
    assert_eq!(
        written(&relayed).await,
        frame(6, &relayed_body(b"https://r.example/"))
    );
    // Peer | BadRequest | "no".
    let refusal = Response::OpenRefusal(OpenRefusal::Peer(PeerRefusal::BadRequest(
        RefusalDetail::try_from("no").unwrap(),
    )));
    assert_eq!(written(&refusal).await, frame(7, &[0, 1, 0, 2, b'n', b'o']));
    assert_eq!(
        read_open(&frame(7, &[2, 0, 2, b'n', b'o'])).await.unwrap(),
        Response::OpenRefusal(OpenRefusal::Unreachable(
            RefusalDetail::try_from("no").unwrap()
        ))
    );
}

#[tokio::test]
async fn attached_with_a_path_reference_is_a_protocol_error() {
    // An observed Attached: 01 | epoch[16] | ticket 1 | Unknown.
    let mut body = vec![1];
    body.extend_from_slice(&[0x11; 16]);
    body.extend_from_slice(&1u64.to_be_bytes());
    body.extend_from_slice(&[0, 0, 0]);
    let bytes = frame(6, &body);
    assert_eq!(&bytes[..7], b"SWC1\x06\x00\x1c");
    assert_eq!(
        protocol_reason(read_open(&bytes).await),
        "attached carries an unrequested path reference"
    );
    assert_eq!(
        protocol_reason(read_open(&frame(6, &[2, 0, 0, 0])).await),
        "attached reference presence is invalid"
    );
}

#[tokio::test]
async fn attached_round_trips_every_optional() {
    let relay = Relay::from(url::Url::parse("https://relay.example/").unwrap());
    for info in [
        ConnInfo {
            path: Path::Direct,
            rtt: Some(Duration::from_micros(1234)),
            remote: Some("[2001:db8::1]:7".parse().unwrap()),
        },
        ConnInfo {
            path: Path::Relayed(relay.clone()),
            rtt: None,
            remote: None,
        },
        ConnInfo {
            path: Path::Unknown,
            rtt: Some(Duration::from_micros(u64::MAX)),
            remote: None,
        },
    ] {
        let response = Response::Attached(info);
        assert_eq!(
            read_open(&written(&response).await).await.unwrap(),
            response
        );
    }
    // A round trip past u64 microseconds is refused before a header is written.
    let mut out = Vec::new();
    let too_long = Response::Attached(ConnInfo {
        rtt: Some(Duration::MAX),
        ..ConnInfo::default()
    });
    assert!(too_long.write(&mut out).await.is_err());
    assert!(out.is_empty());
}

fn relayed_body(url: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 2];
    body.extend_from_slice(&u16::try_from(url.len()).unwrap().to_be_bytes());
    body.extend_from_slice(url);
    body.extend_from_slice(&[0, 0]);
    body
}

fn url_of(len: usize) -> Vec<u8> {
    let mut url = b"https://relay.example/".to_vec();
    url.resize(len, b'a');
    url
}

#[tokio::test]
async fn relay_url_length_is_1_to_1024() {
    let edge = read_open(&frame(6, &relayed_body(&url_of(1024))))
        .await
        .unwrap();
    assert!(matches!(
        edge,
        Response::Attached(ConnInfo {
            path: Path::Relayed(_),
            ..
        })
    ));
    for len in [0, 1025] {
        let url = if len == 0 { Vec::new() } else { url_of(len) };
        assert_eq!(
            protocol_reason(read_open(&frame(6, &relayed_body(&url))).await),
            "attached relay url length is out of bounds",
            "{len}"
        );
    }
    // The writer refuses what the reader would, before a header.
    let long = Response::Attached(ConnInfo {
        path: Path::Relayed(Relay::from(
            url::Url::parse(core::str::from_utf8(&url_of(1025)).unwrap()).unwrap(),
        )),
        ..ConnInfo::default()
    });
    let mut out = Vec::new();
    assert!(long.write(&mut out).await.is_err());
    assert!(out.is_empty());
}

#[tokio::test]
async fn remote_length_is_1_to_256() {
    for (len, reason) in [
        (0, "attached remote length is out of bounds"),
        (256, "attached remote is invalid"),
        (257, "attached remote length is out of bounds"),
    ] {
        let mut body = vec![0, 0, 0, 1];
        body.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        body.extend(core::iter::repeat_n(b'9', len));
        assert_eq!(
            protocol_reason(read_open(&frame(6, &body)).await),
            reason,
            "{len}"
        );
    }
}

fn detail(len: usize) -> RefusalDetail {
    RefusalDetail::try_from("d".repeat(len).as_str()).unwrap()
}

#[tokio::test]
async fn every_open_refusal_round_trips_and_the_largest_is_1028_bytes() {
    let refusals = [
        OpenRefusal::Peer(PeerRefusal::NotAdmitted),
        OpenRefusal::Peer(PeerRefusal::BadRequest(detail(0))),
        OpenRefusal::Peer(PeerRefusal::Unavailable(detail(3))),
        OpenRefusal::PeerUnreadable(detail(5)),
        OpenRefusal::Unreachable(detail(1024)),
        OpenRefusal::Timeout,
        OpenRefusal::Broken(detail(1)),
        OpenRefusal::Busy,
        OpenRefusal::StandingEnded,
        OpenRefusal::NotHere,
    ];
    for (class, refusal) in [0, 0, 0, 1, 2, 3, 4, 5, 6, 7].into_iter().zip(refusals) {
        let response = Response::OpenRefusal(refusal);
        let bytes = written(&response).await;
        assert_eq!(bytes[7], class);
        assert_eq!(read_open(&bytes).await.unwrap(), response);
    }
    let largest = Response::OpenRefusal(OpenRefusal::Peer(PeerRefusal::BadRequest(detail(1024))));
    let bytes = written(&largest).await;
    assert_eq!(&bytes[4..7], &[7, 0x04, 0x04]);
    assert_eq!(bytes.len() - 7, MAX_OPEN_REFUSAL);
    assert_eq!(read_open(&bytes).await.unwrap(), largest);
}

#[tokio::test]
async fn open_refusal_grammar_failures_are_protocol_errors() {
    let mut long = vec![2, 0x04, 0x01];
    long.extend_from_slice(&[b'd'; 1025]);
    for (body, reason) in [
        (long.as_slice(), "open refusal detail exceeds 1024 bytes"),
        (&[8], "unknown open refusal class"),
        (&[0, 3], "unknown peer refusal class"),
        (&[5, 0], "open reply has trailing bytes"),
        (&[0, 0, 0], "open reply has trailing bytes"),
        (&[2, 0, 1], "open reply is truncated"),
        (&[2, 0, 1, 0xff], "open refusal detail is not UTF-8"),
        (&[], "open reply is truncated"),
    ] {
        assert_eq!(
            protocol_reason(read_open(&frame(7, body)).await),
            reason,
            "{body:?}"
        );
    }
}

#[test]
fn a_peer_class_is_the_transport_refusal_exactly() {
    assert_eq!(
        Refusal::from(PeerRefusal::NotAdmitted),
        Refusal::NotAdmitted
    );
    assert_eq!(
        Refusal::from(PeerRefusal::BadRequest(detail(2))),
        Refusal::BadRequest { detail: detail(2) }
    );
    let error = bifrost::Error::Refused(PeerRefusal::Unavailable(detail(4)).into());
    assert!(matches!(
        error,
        bifrost::Error::Refused(Refusal::Unavailable { detail }) if detail == self::detail(4)
    ));
}

#[test]
fn each_known_peer_refusal_is_its_own_wire_class() {
    assert_eq!(
        OpenRefusal::from(Refusal::NotAdmitted),
        OpenRefusal::Peer(PeerRefusal::NotAdmitted)
    );
    assert_eq!(
        OpenRefusal::from(Refusal::BadRequest { detail: detail(2) }),
        OpenRefusal::Peer(PeerRefusal::BadRequest(detail(2)))
    );
    assert_eq!(
        OpenRefusal::from(Refusal::Unavailable { detail: detail(4) }),
        OpenRefusal::Peer(PeerRefusal::Unavailable(detail(4)))
    );
}

#[tokio::test]
async fn each_open_reply_is_capped_before_its_body_is_read() {
    // Only the header is supplied: at the ceiling the read waits for a body that never comes, and one
    // past it is refused on the declaration alone.
    for (tag, cap) in [
        (6, MAX_ATTACHED),
        (7, MAX_OPEN_REFUSAL),
        (5, MAX_OPEN_ERROR),
    ] {
        let mut header = b"SWC1".to_vec();
        header.push(tag);
        header.extend_from_slice(&u16::try_from(cap).unwrap().to_be_bytes());
        assert!(
            matches!(read_open(&header).await, Err(ControlError::Io(_))),
            "{tag}"
        );
        let over = cap + 1;
        header.truncate(5);
        header.extend_from_slice(&u16::try_from(over).unwrap().to_be_bytes());
        assert!(
            matches!(read_open(&header).await, Err(ControlError::TooLarge(len)) if len == over),
            "{tag}"
        );
    }
}

#[tokio::test]
async fn an_open_reads_only_attached_refusal_or_error() {
    let error = Response::Error("no".to_owned());
    assert_eq!(read_open(&written(&error).await).await.unwrap(), error);
    assert_eq!(
        protocol_reason(read_open(&frame(5, &[0, 3, b'a'])).await),
        "invalid open diagnostic"
    );
    // Path's replies stay unknown here, as do every other operation's.
    for bytes in [
        b"SWC1\x08\x00\x04\x00\x00\x00\x00".as_slice(),
        b"SWC1\x08\x00\x04\x00\x01\x00\x00",
        b"SWC1\x08\x00\x01\x01",
        b"SWC1\x04\x00\x03\x00\x01r",
        b"SWC1\x03\x00\x00",
        b"SWC1\x09\x00\x00",
    ] {
        assert_eq!(
            protocol_reason(read_open(bytes).await),
            "unexpected reply to open"
        );
    }
}

#[tokio::test]
async fn the_generic_reader_still_calls_open_replies_unknown() {
    for tag in [6, 7] {
        let bytes = frame(tag, &[0]);
        let mut reader = bytes.as_slice();
        assert!(matches!(
            Response::read(&mut reader).await,
            Err(ControlError::Protocol(reason)) if reason == format!("unknown response tag {tag:#04x}")
        ));
    }
}

#[tokio::test]
async fn request_tags_4_and_5_stay_unknown_at_any_declared_length() {
    // The serve's parser is unchanged: Open and Path name no operation yet, so the declaration is never
    // read, whatever it says, including an Open declared one past its own cap.
    for header in [
        b"SWC1\x04\x40\x01".as_slice(),
        b"SWC1\x04\x00\x00",
        b"SWC1\x04\x20\x01",
        b"SWC1\x05\x00\x19",
    ] {
        let mut reader = header;
        let mut observed = None;
        let error = Request::read_observed(&mut reader, &mut observed)
            .await
            .unwrap_err();
        assert!(matches!(error, ControlError::Protocol(_)));
        assert_eq!(observed, None);
        assert_eq!(reader.len(), 2);
    }
    // Every known operation is still held to the frame ceiling on its declaration alone.
    for tag in [1, 2, 3, 6] {
        let header = [b'S', b'W', b'C', b'1', tag, 0x20, 0x01];
        let mut reader = header.as_slice();
        assert!(matches!(
            Request::read_observed(&mut reader, &mut None).await,
            Err(ControlError::TooLarge(8193))
        ));
    }
}
