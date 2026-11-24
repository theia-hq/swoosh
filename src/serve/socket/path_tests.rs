use core::num::NonZeroU64;

use bifrost::{ConnInfo, Path};
use rand::RngCore;

use super::{Epoch, EpochError, PathAction, PathRef, PathReply, PathRequest, Ticket};
use crate::serve::control_codec::{ControlError, Request, Response};
use crate::serve::socket::RequestKind;

/// `E1`: one, as sixteen big-endian bytes.
fn e1() -> [u8; 16] {
    let mut epoch = [0; 16];
    epoch[15] = 1;
    epoch
}

fn reference(epoch: [u8; 16], ticket: u64) -> PathRef {
    PathRef::new(
        Epoch::from_bytes(epoch).unwrap(),
        Ticket::at(NonZeroU64::new(ticket).unwrap()),
    )
}

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = b"SWC2".to_vec();
    out.push(tag);
    out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A Path body spelled byte by byte: epoch, ticket, action.
fn body(epoch: [u8; 16], ticket: u64, action: u8) -> Vec<u8> {
    let mut out = epoch.to_vec();
    out.extend_from_slice(&ticket.to_be_bytes());
    out.push(action);
    out
}

async fn written_request(request: &Request) -> Vec<u8> {
    let mut out = Vec::new();
    request.write(&mut out).await.unwrap();
    out
}

async fn written(response: &Response) -> Vec<u8> {
    let mut out = Vec::new();
    response.write(&mut out).await.unwrap();
    out
}

/// Read one request off `bytes`, with how many bytes the read left unconsumed.
async fn read_request(bytes: &[u8]) -> (Result<Request, ControlError>, Option<RequestKind>, usize) {
    let mut reader = bytes;
    let mut observed = None;
    let read = Request::read_observed(&mut reader, &mut observed).await;
    (read, observed, reader.len())
}

async fn read_path(bytes: &[u8]) -> Result<Response, ControlError> {
    let mut reader = bytes;
    Response::read_path(&mut reader).await
}

#[tokio::test]
async fn sample_and_finish_are_the_published_bytes() {
    for (action, byte) in [(PathAction::Sample, 0), (PathAction::Finish, 1)] {
        let request = Request::Path(PathRequest {
            reference: reference(e1(), 1),
            action,
        });
        let bytes = written_request(&request).await;
        assert_eq!(&bytes[..7], b"SWC2\x05\x00\x19");
        assert_eq!(&bytes[7..], body(e1(), 1, byte).as_slice());
        let (read, kind, left) = read_request(&bytes).await;
        assert_eq!(read.unwrap(), request);
        assert_eq!(kind, Some(RequestKind::Path));
        assert_eq!(left, 0);
    }
}

#[tokio::test]
async fn the_three_replies_are_the_published_bytes() {
    let unknown = Response::Path(PathReply::Sample(ConnInfo::default()));
    let direct = Response::Path(PathReply::Sample(ConnInfo {
        path: Path::Direct,
        ..ConnInfo::default()
    }));
    let unavailable = Response::Path(PathReply::Unavailable);
    for (response, bytes) in [
        (&unknown, b"SWC2\x08\x00\x04\x00\x00\x00\x00".as_slice()),
        (&direct, b"SWC2\x08\x00\x04\x00\x01\x00\x00"),
        (&unavailable, b"SWC2\x08\x00\x01\x01"),
    ] {
        assert_eq!(written(response).await, bytes);
        assert_eq!(&read_path(bytes).await.unwrap(), response);
    }
    // Unknown is a sample of the connection, never the reading of a missing reference.
    assert_ne!(unknown, unavailable);
}

#[tokio::test]
async fn a_path_reply_takes_nothing_more_or_less_than_its_outcome() {
    for body in [
        b"\x01\x00".as_slice(),
        b"\x00".as_slice(),
        b"\x00\x00\x00",
        b"\x02",
    ] {
        assert!(
            matches!(
                read_path(&frame(8, body)).await,
                Err(ControlError::Protocol(_))
            ),
            "{body:?}"
        );
    }
}

#[tokio::test]
async fn a_path_body_other_than_25_is_refused_unread() {
    for len in [0, 24, 26, 33, 8192] {
        let mut bytes = frame(5, &vec![1; len]);
        let (read, kind, left) = read_request(&bytes).await;
        assert!(matches!(read, Err(ControlError::Protocol(_))), "{len}");
        assert_eq!(kind, Some(RequestKind::Path), "{len}");
        // Not a byte of the declared body was read.
        assert_eq!(left, len, "{len}");
        // The ceiling every request keeps is checked first.
        bytes.truncate(5);
        bytes.extend_from_slice(&8193u16.to_be_bytes());
        let (read, _, _) = read_request(&bytes).await;
        assert!(matches!(read, Err(ControlError::TooLarge(8193))));
    }
}

#[tokio::test]
async fn a_zero_field_or_unknown_action_is_malformed() {
    for body in [
        body([0; 16], 1, 0),
        body(e1(), 0, 0),
        body(e1(), 1, 2),
        body(e1(), 1, 0xff),
    ] {
        let (read, _, _) = read_request(&frame(5, &body)).await;
        match read {
            Err(ControlError::Protocol(reason)) => assert_eq!(reason, "invalid path request"),
            other => panic!("expected the fixed diagnostic, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_path_error_reply_is_held_to_258_declared_bytes() {
    let mut reason = 256u16.to_be_bytes().to_vec();
    reason.extend_from_slice(&[b'x'; 256]);
    assert!(matches!(
        read_path(&frame(5, &reason)).await.unwrap(),
        Response::Error(text) if text.len() == 256
    ));
    let mut over = 257u16.to_be_bytes().to_vec();
    over.extend_from_slice(&[b'x'; 257]);
    assert!(matches!(
        read_path(&frame(5, &over)).await,
        Err(ControlError::TooLarge(259))
    ));
    // A Path reader takes neither Open's replies nor a detail's.
    for tag in [6, 7, 9] {
        assert!(matches!(
            read_path(&frame(tag, &[0])).await,
            Err(ControlError::Protocol(_))
        ));
    }
}

#[tokio::test]
async fn a_malformed_path_is_answered_with_its_fixed_words() {
    let (read, kind, _) = read_request(&frame(5, &body([0; 16], 1, 0))).await;
    let reply = Response::request_error(read.unwrap_err(), kind).unwrap();
    assert_eq!(reply, Response::Error("invalid path request".to_owned()));
}

/// A random source that fails, or fills with one byte.
enum Source {
    Fails,
    Fills(u8),
}

impl RngCore for Source {
    fn next_u32(&mut self) -> u32 {
        unreachable!("the epoch fills bytes")
    }

    fn next_u64(&mut self) -> u64 {
        unreachable!("the epoch fills bytes")
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        unreachable!("the epoch never takes the panicking fill")
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        match self {
            Self::Fails => Err(rand::Error::new(std::io::Error::other("no entropy"))),
            Self::Fills(byte) => {
                dest.fill(*byte);
                Ok(())
            }
        }
    }
}

#[test]
fn an_epoch_is_never_zero_and_never_a_fallback() {
    assert!(matches!(
        Epoch::draw(&mut Source::Fails),
        Err(EpochError::Random(_))
    ));
    assert!(matches!(
        Epoch::draw(&mut Source::Fills(0)),
        Err(EpochError::Zero)
    ));
    assert_eq!(
        Epoch::draw(&mut Source::Fills(7)).unwrap(),
        Epoch::from_bytes([7; 16]).unwrap()
    );
    assert!(Epoch::draw(&mut rand::rngs::OsRng).is_ok());
}

#[test]
fn tickets_run_from_one_and_end_after_max() {
    assert_eq!(
        Ticket::FIRST.next(),
        Some(Ticket::at(NonZeroU64::new(2).unwrap()))
    );
    let last = Ticket::at(NonZeroU64::MAX);
    assert_eq!(last.next(), None);
}
