#![allow(clippy::unwrap_used, clippy::expect_used)]
// `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
#![allow(clippy::std_instead_of_core)]

use std::io::ErrorKind;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

use super::{OpenRead, OpenWrite};
use crate::serve::control_codec::MAX_FRAME;
use crate::testkit::{control_frame, control_header};

const END: [u8; 7] = control_header(0x0b, 0);
const LANDED: [u8; 7] = control_header(0x0c, 0);

/// A Data frame holding `body`.
fn data(body: &[u8]) -> Vec<u8> {
    let mut frame = control_frame(b"\x0a");
    frame.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
    frame.extend(body);
    frame
}

/// A read half over a socket whose far end, the resident's, writes `wire` and closes, on a task of
/// its own, since `wire` can be more than the socket holds.
async fn reading(wire: &[u8]) -> OpenRead {
    let (near, mut far) = UnixStream::pair().unwrap();
    let wire = wire.to_vec();
    tokio::spawn(async move {
        far.write_all(&wire).await.unwrap();
    });
    OpenRead::new(near.into_split().0)
}

/// A write half, and the far end that reads what it writes.
fn writing() -> (OpenWrite, UnixStream) {
    let (near, far) = UnixStream::pair().unwrap();
    (OpenWrite::new(near.into_split().1), far)
}

#[tokio::test]
async fn the_client_read_half_ends_cleanly_only_at_end() {
    let mut wire = data(b"a whole ");
    wire.extend(data(b"download"));
    wire.extend(END);
    let mut read = reading(&wire).await;
    let mut got = Vec::new();
    read.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"a whole download");
}

#[tokio::test]
async fn the_client_read_half_returns_reset_on_eof_before_end() {
    let whole = data(b"cut short");
    // At a frame boundary, inside a body and inside a header.
    for cut in [whole.len(), whole.len() - 3, 4] {
        let mut read = reading(&whole[..cut]).await;
        let mut got = Vec::new();
        let ended = read.read_to_end(&mut got).await.unwrap_err();
        assert_eq!(ended.kind(), ErrorKind::ConnectionReset, "cut at {cut}");
    }
}

#[tokio::test]
async fn an_unknown_tag_from_the_resident_is_an_error_never_data() {
    for bad in [
        control_header(0x03, 0),
        control_header(0x0d, 0),
        control_header(0x0a, 0),
    ] {
        let mut wire = data(b"before");
        wire.extend(bad);
        let mut read = reading(&wire).await;
        let mut got = Vec::new();
        let ended = read.read_to_end(&mut got).await.unwrap_err();
        assert_eq!(ended.kind(), ErrorKind::InvalidData, "{bad:?}");
        assert_eq!(got, b"before");
    }
}

#[tokio::test]
async fn a_declared_frame_length_never_sizes_a_buffer() {
    // 8193 declared with no body behind it: refused at the header, never read toward.
    let mut read = reading(&control_frame(b"\x0a\x20\x01")).await;
    let mut got = Vec::new();
    let ended = read.read_to_end(&mut got).await.unwrap_err();
    assert_eq!(ended.kind(), ErrorKind::InvalidData);
    // A full frame passes whole.
    let mut wire = data(&[5; MAX_FRAME]);
    wire.extend(END);
    let mut read = reading(&wire).await;
    let mut got = Vec::new();
    read.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, [5; MAX_FRAME]);
}

#[tokio::test]
async fn landed_is_heard_before_or_after_the_downloads_end() {
    for wire in [
        [data(b"x"), LANDED.to_vec(), END.to_vec()].concat(),
        [data(b"x"), END.to_vec(), LANDED.to_vec()].concat(),
    ] {
        let mut read = reading(&wire).await;
        let mut got = Vec::new();
        read.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"x");
        read.landed().await.unwrap();
    }
}

#[tokio::test]
async fn a_close_without_landed_is_a_cut_off_upload() {
    let mut read = reading(&[data(b"x"), END.to_vec()].concat()).await;
    let mut got = Vec::new();
    read.read_to_end(&mut got).await.unwrap();
    assert_eq!(
        read.landed().await.unwrap_err().kind(),
        ErrorKind::ConnectionReset
    );
}

#[tokio::test]
async fn data_after_the_downloads_end_is_an_error() {
    let mut read = reading(&[END.to_vec(), data(b"late")].concat()).await;
    let mut got = Vec::new();
    read.read_to_end(&mut got).await.unwrap();
    assert_eq!(
        read.landed().await.unwrap_err().kind(),
        ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn the_client_write_half_shutdown_sends_end() {
    let (mut write, mut far) = writing();
    write.write_all(b"an upload").await.unwrap();
    write.shutdown().await.unwrap();
    let mut got = Vec::new();
    far.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, [data(b"an upload"), END.to_vec()].concat());
}

#[tokio::test]
async fn the_client_write_half_frames_at_the_ceiling() {
    let (mut write, mut far) = writing();
    let mut got = Vec::new();
    let (wrote, read) = tokio::join!(
        async {
            write.write_all(&[3; MAX_FRAME + 1]).await?;
            write.shutdown().await
        },
        far.read_to_end(&mut got)
    );
    wrote.unwrap();
    read.unwrap();
    assert_eq!(
        got,
        [data(&[3; MAX_FRAME]), data(&[3]), END.to_vec()].concat()
    );
}

#[tokio::test]
async fn a_dropped_client_write_half_sends_no_end() {
    for abort in [true, false] {
        let (mut write, mut far) = writing();
        write.write_all(b"half").await.unwrap();
        write.flush().await.unwrap();
        if abort {
            write.abort();
        } else {
            drop(write);
        }
        let mut got = Vec::new();
        far.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, data(b"half"), "no End after a drop");
    }
}
