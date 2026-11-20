#![allow(clippy::unwrap_used, clippy::expect_used)]

use tokio::io::AsyncReadExt as _;

use super::{
    DataLen, FRAME_BUFFER, Frame, FramedWriter, HEADER, MalformedFrame, Toward, UploadCut,
    frame_reader, upload,
};
use crate::serve::control_codec::MAX_FRAME;

/// Header bytes for `tag` declaring `len`.
fn header(tag: u8, len: u16) -> [u8; HEADER] {
    let [high, low] = len.to_be_bytes();
    [b'S', b'W', b'C', b'1', tag, high, low]
}

#[test]
fn the_three_frames_have_their_exact_bytes() {
    let one = DataLen::new(1).unwrap();
    assert_eq!(
        Frame::Data(one).header(),
        [0x53, 0x57, 0x43, 0x31, 0x0a, 0x00, 0x01]
    );
    assert_eq!(
        Frame::End.header(),
        [0x53, 0x57, 0x43, 0x31, 0x0b, 0x00, 0x00]
    );
    assert_eq!(
        Frame::Landed.header(),
        [0x53, 0x57, 0x43, 0x31, 0x0c, 0x00, 0x00]
    );
    let full = DataLen::new(MAX_FRAME).unwrap();
    assert_eq!(Frame::Data(full).header()[4..], [0x0a, 0x20, 0x00]);
}

#[test]
fn a_data_length_is_one_to_the_frame_ceiling() {
    assert_eq!(DataLen::new(0), None);
    assert_eq!(DataLen::new(1).map(DataLen::get), Some(1));
    assert_eq!(DataLen::new(MAX_FRAME).map(DataLen::get), Some(MAX_FRAME));
    assert_eq!(DataLen::new(MAX_FRAME + 1), None);
}

#[test]
fn every_frame_parses_back_to_itself() {
    for frame in [
        Frame::Data(DataLen::new(1).unwrap()),
        Frame::Data(DataLen::new(MAX_FRAME).unwrap()),
        Frame::End,
    ] {
        assert_eq!(Frame::parse(frame.header(), Toward::Peer), Ok(frame));
        assert_eq!(Frame::parse(frame.header(), Toward::Client), Ok(frame));
    }
    assert_eq!(
        Frame::parse(Frame::Landed.header(), Toward::Client),
        Ok(Frame::Landed)
    );
}

#[test]
fn a_malformed_header_is_refused_by_what_broke() {
    let refused = |header, toward| Frame::parse(header, toward).unwrap_err();
    assert_eq!(refused(header(10, 0), Toward::Peer), MalformedFrame::Empty);
    assert_eq!(
        refused(header(10, 8193), Toward::Peer),
        MalformedFrame::TooLong
    );
    assert_eq!(refused(header(11, 1), Toward::Peer), MalformedFrame::Body);
    assert_eq!(refused(header(12, 1), Toward::Client), MalformedFrame::Body);
    // Landed travels toward the client only, and no request or reply tag is a splice frame.
    assert_eq!(refused(header(12, 0), Toward::Peer), MalformedFrame::Tag);
    for tag in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 255] {
        assert_eq!(refused(header(tag, 0), Toward::Peer), MalformedFrame::Tag);
        assert_eq!(refused(header(tag, 0), Toward::Client), MalformedFrame::Tag);
    }
    let mut foreign = header(10, 1);
    foreign[3] = b'2';
    assert_eq!(refused(foreign, Toward::Peer), MalformedFrame::Magic);
    foreign = header(10, 1);
    foreign[0] = b'X';
    assert_eq!(refused(foreign, Toward::Client), MalformedFrame::Magic);
}

/// Run [`upload`] over `wire`, returning how it ended and what reached the peer.
async fn uploaded(wire: &[u8]) -> (Result<(), UploadCut>, Vec<u8>) {
    let mut from_client = frame_reader(wire);
    let mut to_peer = Vec::new();
    let ended = upload(&mut from_client, &mut to_peer).await;
    (ended, to_peer)
}

#[tokio::test]
async fn an_upload_ends_cleanly_only_at_its_end() {
    let mut wire = Vec::new();
    wire.extend(header(10, 3));
    wire.extend(b"abc");
    wire.extend(header(10, 2));
    wire.extend(b"de");
    wire.extend(header(11, 0));
    // Nothing past End is read, so a frame after it never reaches the peer.
    wire.extend(header(10, 1));
    wire.extend(b"z");
    let (ended, got) = uploaded(&wire).await;
    ended.unwrap();
    assert_eq!(got, b"abcde");
}

#[tokio::test]
async fn an_upload_without_its_end_is_cut_off() {
    let mut wire = Vec::new();
    wire.extend(header(10, 3));
    wire.extend(b"abc");
    // At a frame boundary, inside a header and inside a body.
    for cut in [wire.len(), wire.len() - 4, 3] {
        let (ended, _) = uploaded(&wire[..cut]).await;
        assert!(matches!(ended, Err(UploadCut::Cut(_))), "{ended:?}");
    }
}

#[tokio::test]
async fn a_malformed_upload_frame_ends_the_upload_before_its_body() {
    for bad in [header(10, 0), header(10, 8193), header(12, 0), header(3, 0)] {
        let mut wire = Vec::new();
        wire.extend(header(10, 1));
        wire.extend(b"a");
        wire.extend(bad);
        wire.extend([7; 16]);
        let (ended, got) = uploaded(&wire).await;
        assert!(matches!(ended, Err(UploadCut::Malformed(_))), "{ended:?}");
        assert_eq!(got, b"a", "nothing after the malformed header moves");
    }
}

#[tokio::test]
async fn a_full_data_frame_is_read_in_one_buffer() {
    let mut wire = Vec::new();
    wire.extend(header(10, 8192));
    wire.extend([9; MAX_FRAME]);
    wire.extend(header(11, 0));
    let mut from_client = frame_reader(wire.as_slice());
    // The whole frame fits the reader's one buffer, header and body.
    use tokio::io::AsyncBufReadExt as _;
    assert_eq!(from_client.fill_buf().await.unwrap().len(), FRAME_BUFFER);
    let mut to_peer = Vec::new();
    upload(&mut from_client, &mut to_peer).await.unwrap();
    assert_eq!(to_peer, [9; MAX_FRAME]);
}

#[tokio::test]
async fn peer_bytes_that_spell_a_frame_reach_the_client_as_data() {
    let mut framed = FramedWriter::new(Vec::new());
    let spelled = Frame::End.header();
    framed.body()[..HEADER].copy_from_slice(&spelled);
    framed
        .write_data(DataLen::new(HEADER).unwrap())
        .await
        .unwrap();
    framed.write_end().await.unwrap();
    framed.write_landed().await.unwrap();
    let wire = framed.writer;
    let mut reader = wire.as_slice();
    let mut header = [0; HEADER];
    reader.read_exact(&mut header).await.unwrap();
    assert_eq!(
        Frame::parse(header, Toward::Client),
        Ok(Frame::Data(DataLen::new(HEADER).unwrap()))
    );
    let mut body = [0; HEADER];
    reader.read_exact(&mut body).await.unwrap();
    assert_eq!(
        body, spelled,
        "the peer's bytes arrive as a body, never a frame"
    );
    reader.read_exact(&mut header).await.unwrap();
    assert_eq!(Frame::parse(header, Toward::Client), Ok(Frame::End));
    reader.read_exact(&mut header).await.unwrap();
    assert_eq!(Frame::parse(header, Toward::Client), Ok(Frame::Landed));
    assert!(reader.is_empty());
}
