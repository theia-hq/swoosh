use super::{ControlError, Request, RequestKind, Response};
use crate::testkit::{CONTROL_MAGIC, control_frame, control_header};

const OPERATIONS: [(u8, RequestKind, Request); 5] = [
    (1, RequestKind::Services, Request::Services),
    (2, RequestKind::Status, Request::Status),
    (3, RequestKind::Stop, Request::Stop),
    (
        6,
        RequestKind::LocalServiceDetail,
        Request::LocalServiceDetail,
    ),
    (7, RequestKind::Whoami, Request::Whoami),
];

#[tokio::test]
async fn known_tags_return_one_request_and_copy_only_the_operation_context() {
    for (tag, kind, request) in OPERATIONS {
        let frame = control_frame(&[tag, 0, 0, 0xff]);
        let mut reader = frame.as_slice();
        let mut observed = None;
        assert_eq!(
            Request::read_observed(&mut reader, &mut observed)
                .await
                .unwrap(),
            request
        );
        let retained = observed;
        assert_eq!(observed, Some(kind));
        assert_eq!(retained, Some(kind));
        assert_eq!(reader, &[0xff]);
    }
}

#[tokio::test]
async fn truncated_frames_retain_context_only_after_a_known_tag() {
    for (tag, kind, _) in OPERATIONS {
        let frame = control_frame(&[tag, 0, 3, b'a', b'b']);
        // Missing length bytes and missing body bytes must retain the same diagnostic policy.
        for end in [5, 6, 7, 8, 9] {
            let mut reader = &frame[..end];
            let mut observed = None;
            let error = Request::read_observed(&mut reader, &mut observed)
                .await
                .unwrap_err();
            assert!(matches!(error, ControlError::Io(_)));
            assert_eq!(observed, Some(kind));
            let Response::Error(reason) = Response::request_error(error, observed).unwrap() else {
                panic!("a truncated request must produce an error response");
            };
            assert_eq!(
                reason,
                if kind == RequestKind::LocalServiceDetail {
                    "invalid local service detail request"
                } else {
                    "control stream ended"
                }
            );
        }
    }
}

#[tokio::test]
async fn unknown_tags_and_incomplete_headers_do_not_acquire_operation_context() {
    for frame in [
        b"".as_slice(),
        b"SWC",
        &CONTROL_MAGIC,
        b"XWC1\x06\0\0",
        b"SWC9\x06\0\0",
    ] {
        let mut reader = frame;
        let mut observed = None;
        assert!(
            Request::read_observed(&mut reader, &mut observed)
                .await
                .is_err()
        );
        assert_eq!(observed, None);
    }
    for tag in [0, 8, 9, 0xff] {
        let frame = control_header(tag, 0);
        let mut reader = frame.as_slice();
        let mut observed = None;
        let error = Request::read_observed(&mut reader, &mut observed)
            .await
            .unwrap_err();
        assert!(matches!(error, ControlError::Protocol(_)));
        assert_eq!(observed, None);
        assert_eq!(reader, &[0, 0]);
        let Response::Error(reason) = Response::request_error(error, observed).unwrap() else {
            panic!("an unknown tag must produce an error response");
        };
        assert_eq!(
            reason,
            format!("control protocol error: unknown request tag {tag:#04x}")
        );
    }
}

#[tokio::test]
async fn malformed_payload_diagnostics_use_the_recorded_operation() {
    for (tag, kind, _) in OPERATIONS {
        let frame = control_frame(&[tag, 0, 1, b'x']);
        let mut reader = frame.as_slice();
        let mut observed = None;
        let error = Request::read_observed(&mut reader, &mut observed)
            .await
            .unwrap_err();
        assert!(matches!(error, ControlError::Protocol(_)));
        assert_eq!(observed, Some(kind));
        assert!(reader.is_empty());
        let Response::Error(reason) = Response::request_error(error, observed).unwrap() else {
            panic!("a malformed payload must produce an error response");
        };
        assert_eq!(
            reason,
            if kind == RequestKind::LocalServiceDetail {
                "invalid local service detail request"
            } else {
                "control protocol error: unexpected request payload"
            }
        );
    }
}

#[test]
fn observed_request_parses_once_without_cloning_an_owning_request() {
    // Unit requests make a clone invisible at runtime; enforce this ownership invariant in source.
    let source = include_str!("socket.rs");
    let reader = source
        .split_once("pub(super) async fn read_observed")
        .unwrap()
        .1
        .split_once("// Error diagnostics")
        .unwrap()
        .0;
    assert!(reader.contains("observed: &mut Option<RequestKind>"));
    assert_eq!(reader.matches("::from_tag(").count(), 1);
    assert_eq!(reader.matches("Ok(request)").count(), 1);
    assert!(!reader.contains("clone"));
}

/// `Whoami` and its reply cross the wire as they were, the reply exactly one 32-byte key, and a reply
/// tag no build writes is refused.
#[tokio::test]
async fn whoami_reply_roundtrips() {
    let mut asked = Vec::new();
    Request::Whoami.write(&mut asked).await.unwrap();
    assert_eq!(asked, control_header(0x07, 0));
    assert_eq!(
        Request::read(&mut asked.as_slice()).await.unwrap(),
        Request::Whoami
    );

    let node_id = bifrost::NodeId::from_ed25519_secret(&[0x41; 32]);
    let mut answer = Vec::new();
    Response::Whoami { node_id }
        .write(&mut answer)
        .await
        .unwrap();
    assert_eq!(answer[..7], control_header(0x0d, 32));
    assert_eq!(&answer[7..], node_id.key());
    assert_eq!(
        Response::read(&mut answer.as_slice()).await.unwrap(),
        Response::Whoami { node_id }
    );

    // A key one byte short is no reply, and neither is a tag past the last.
    let short = [control_frame(b"\x0d\x00\x1f").as_slice(), &[0; 31]].concat();
    assert!(matches!(
        Response::read(&mut short.as_slice()).await,
        Err(ControlError::Protocol(_))
    ));
    assert!(matches!(
        Response::read(&mut control_frame(b"\x0e\x00\x00").as_slice()).await,
        Err(ControlError::Protocol(reason)) if reason == "unknown response tag 0x0e"
    ));
}

/// Only the three lines that say the socket itself cannot be trusted end a run on it: its path, the
/// process answering it, or a process `serve.lock` does not record. Every other variant belongs to one
/// connection. `rank` names every variant, so a new one fails to build here until `rank` places it;
/// add its row beside it.
#[test]
fn only_the_socket_distrust_variants_distrust_the_socket() {
    use std::path::PathBuf;

    use super::{LocalDetailError, MalformedOpen, WireVersion};

    // Each variant's place in the table, by an exhaustive match: no wildcard, so no variant can hide.
    fn rank(error: &ControlError) -> usize {
        match error {
            ControlError::NoResident => 0,
            ControlError::Untrusted { .. } => 1,
            ControlError::UntrustedPeer { .. } => 2,
            ControlError::Unattributed { .. } => 3,
            ControlError::Timeout { .. } => 4,
            ControlError::Io(_) => 5,
            ControlError::TooLarge(_) => 6,
            ControlError::Foreign => 7,
            ControlError::Version { .. } => 8,
            ControlError::Protocol(_) => 9,
            ControlError::Catalog(_) => 10,
            ControlError::Refused(_) => 11,
            ControlError::Open(_) => 12,
            ControlError::LocalDetail(_) => 13,
        }
    }

    let path = || PathBuf::from("/run/user/1000/swoosh/home/control.sock");
    let rows = [
        (ControlError::NoResident, false),
        (ControlError::Untrusted { path: path() }, true),
        (ControlError::UntrustedPeer { path: path() }, true),
        (
            ControlError::Unattributed {
                path: path(),
                pid: 4242.try_into().unwrap(),
            },
            true,
        ),
        (ControlError::Timeout { phase: "connect" }, false),
        (ControlError::Io(std::io::Error::other("cut")), false),
        (ControlError::TooLarge(1), false),
        (ControlError::Foreign, false),
        (
            ControlError::Version {
                peer: WireVersion([0xff]),
            },
            false,
        ),
        (ControlError::Protocol("bad tag".to_owned()), false),
        (ControlError::Catalog(eyre::eyre!("bad blob")), false),
        (ControlError::Refused("not admitted".to_owned()), false),
        (ControlError::Open(MalformedOpen::Truncated), false),
        (
            ControlError::LocalDetail(LocalDetailError::MissingStartup),
            false,
        ),
    ];
    let mut ranks: Vec<usize> = rows.iter().map(|(error, _)| rank(error)).collect();
    ranks.sort_unstable();
    assert_eq!(
        ranks,
        (0..rows.len()).collect::<Vec<_>>(),
        "each row a distinct variant, ranks without gaps"
    );
    for (error, distrusts) in rows {
        assert_eq!(error.distrusts_socket(), distrusts, "{error:?}");
    }
}

/// The tag this build speaks, pinned once: every other test names it through `CONTROL_MAGIC`, so a
/// change to it is a change here and nowhere else.
#[test]
fn the_control_magic_is_swc3() {
    assert_eq!(CONTROL_MAGIC, *b"SWC3");
}
