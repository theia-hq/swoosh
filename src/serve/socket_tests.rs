use super::{ControlError, Request, RequestKind, Response};

const OPERATIONS: [(u8, RequestKind, Request); 4] = [
    (1, RequestKind::Services, Request::Services),
    (2, RequestKind::Status, Request::Status),
    (3, RequestKind::Stop, Request::Stop),
    (
        6,
        RequestKind::LocalServiceDetail,
        Request::LocalServiceDetail,
    ),
];

#[tokio::test]
async fn known_tags_return_one_request_and_copy_only_the_operation_context() {
    for (tag, kind, request) in OPERATIONS {
        let frame = [b'S', b'W', b'C', b'1', tag, 0, 0, 0xff];
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
        let frame = [b'S', b'W', b'C', b'1', tag, 0, 3, b'a', b'b'];
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
        b"SWC1",
        b"XWC1\x06\0\0",
        b"SWC2\x06\0\0",
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
    for tag in [0, 4, 5, 7, 0xff] {
        let frame = [b'S', b'W', b'C', b'1', tag, 0, 0];
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
        let frame = [b'S', b'W', b'C', b'1', tag, 0, 1, b'x'];
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
    assert_eq!(reader.matches("Ok(kind.into())").count(), 1);
    assert!(!reader.contains("clone"));
}
