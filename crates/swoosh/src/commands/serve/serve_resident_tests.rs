//! S3 tests: codec round-trips, hostile `StatusReply` decodes, the uid gate and flood cap through
//! the real serve path, the injected slow-loris timeout, the oversized-frame EOF contract, and the
//! stop-Ack ordering.

use core::pin::Pin;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::{Context, Poll};
use std::sync::Arc;

use bifrost::NodeId;
use tightbeam::tunnel::{CancellationToken, ServiceCatalog};
use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::{MAX_CONTROL_CONNS, READ_TIMEOUT, Resident};
use crate::commands::serve::control::ControlError;
use crate::commands::serve::control_codec::{
    DisabledList, MAGIC, MAX_DISABLED_NAMES, MAX_FRAME, MAX_STATUS_STRING, Request, Response,
    ServiceMenu, StatusReply,
};

/// Serializes scratch dir names within this test process; the pid keeps two concurrent runs of the
/// binary apart. Names stay short on purpose: the control socket path must fit `sun_path` (104
/// bytes on macOS).
static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

/// An empty catalog: the codec tests exercise framing, not service content.
fn empty_catalog() -> ServiceCatalog {
    ServiceCatalog::decode(&0u32.to_be_bytes()).expect("an empty catalog decodes")
}

/// A menu over the empty catalog and an empty known disabled list.
fn empty_menu() -> ServiceMenu {
    ServiceMenu {
        catalog: empty_catalog(),
        disabled: DisabledList::Known(Vec::new()),
    }
}

/// A unique short scratch dir for the resident tests.
fn scratch_dir(tag: &str) -> std::path::PathBuf {
    let short: String = tag.chars().take(8).collect();
    let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("swr-{short}-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("resident scratch");
    dir
}

/// A resident over temp state, for driving the accept path directly.
fn test_resident() -> Resident {
    test_resident_with(CancellationToken::new())
}

/// A resident over temp state holding `cancel` (the same token clone the run holds), so a test can
/// observe the shared teardown token.
fn test_resident_with(cancel: CancellationToken) -> Resident {
    let dir = scratch_dir("state");
    Resident::new(
        NodeId::from_ed25519_secret(&[9u8; 32]),
        None,
        empty_catalog(),
        dir.join("disabled"),
        cancel,
    )
}

/// Poll until the resident holds `want` permits, bounded: the accept loop drains slots
/// asynchronously, so a test waits for the drain rather than assuming it.
async fn wait_for_permits(resident: &Resident, want: usize) {
    let deadline = tokio::time::Instant::now() + core::time::Duration::from_secs(5);
    while resident.semaphore().available_permits() != want {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the resident never settled at {want} permits"
        );
        tokio::time::sleep(core::time::Duration::from_millis(5)).await;
    }
}

/// Every request tag round-trips through the frame codec.
#[tokio::test]
async fn requests_round_trip() {
    for request in [Request::Services, Request::Status, Request::Stop] {
        let mut buf = Vec::new();
        request.write(&mut buf).await.expect("request writes");
        assert_eq!(&buf[..4], &MAGIC, "frames carry the SWC1 magic");
        let back = Request::read(&mut &buf[..]).await.expect("request reads");
        assert_eq!(back, request, "a request round-trips");
    }
}

/// Every response shape round-trips, including the public-shape status, both with a known disabled
/// list and with an explicit unknown.
#[tokio::test]
async fn responses_round_trip() {
    let menu = ServiceMenu {
        catalog: empty_catalog(),
        disabled: DisabledList::Known(vec!["speed".to_owned()]),
    };
    let status = StatusReply {
        node_id: NodeId::from_ed25519_secret(&[9u8; 32]),
        pid: 1234,
        addr: None,
        uptime_secs: 7,
        menu,
        warm: Vec::new(),
    };
    let unknown = StatusReply {
        menu: ServiceMenu {
            disabled: DisabledList::Unknown("the disabled file exceeds the read cap".to_owned()),
            ..status.menu.clone()
        },
        ..status.clone()
    };
    for response in [
        Response::Catalog(status.menu.clone()),
        Response::Status(status),
        Response::Status(unknown),
        Response::Ack,
        Response::Refused("gated".to_owned()),
        Response::Error("skew".to_owned()),
    ] {
        let mut buf = Vec::new();
        response.write(&mut buf).await.expect("response writes");
        let back = Response::read(&mut &buf[..]).await.expect("response reads");
        assert_eq!(back, response, "a response round-trips");
    }
}

/// Foreign magic is a loud protocol error typed as such, never a misparse.
#[tokio::test]
async fn version_skew_is_loud() {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"SWC0");
    buf.push(1);
    buf.extend_from_slice(&0u16.to_be_bytes());
    let error = Request::read(&mut &buf[..])
        .await
        .expect_err("SWC0 must fail");
    assert!(
        matches!(error, ControlError::Protocol(ref message) if message.contains("SWC1")),
        "the skew error is a protocol error naming the expected magic: {error}"
    );
}

/// A declared length over the 8 KiB cap refuses the frame before a byte of it is read, typed
/// `TooLarge` with the declared length.
#[tokio::test]
async fn oversized_frame_is_rejected() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&MAGIC);
    buf.push(1);
    buf.extend_from_slice(&((MAX_FRAME + 1) as u16).to_be_bytes());
    let error = Request::read(&mut &buf[..])
        .await
        .expect_err("oversize must fail");
    assert!(
        matches!(error, ControlError::TooLarge(len) if len == MAX_FRAME + 1),
        "the cap error is typed `TooLarge` with the declared length: {error}"
    );
}

/// A minimal decodable status: no address, empty catalog, empty known disabled list.
fn minimal_status() -> StatusReply {
    StatusReply {
        node_id: NodeId::from_ed25519_secret(&[9u8; 32]),
        pid: 4242,
        addr: None,
        uptime_secs: 3,
        menu: empty_menu(),
        warm: Vec::new(),
    }
}

/// The raw status frame prefix up to and including the `has_addr` byte: key, pid, presence.
fn status_prefix(has_addr: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(NodeId::from_ed25519_secret(&[9u8; 32]).key());
    bytes.extend_from_slice(&4242u32.to_be_bytes());
    bytes.push(has_addr);
    bytes
}

/// A raw status frame with no addr, zero uptime, a real empty catalog, and the given disabled
/// section.
fn status_frame_with_disabled(disabled: &[u8]) -> Vec<u8> {
    let mut bytes = status_prefix(0);
    bytes.extend_from_slice(&0u64.to_be_bytes());
    let catalog = empty_catalog().encode();
    bytes.extend_from_slice(&(catalog.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&catalog);
    bytes.extend_from_slice(disabled);
    // The warm-peer section: empty until the cache lands, but present in the layout.
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes
}

/// Every proper prefix of a valid status frame is refused as a typed protocol error: the decoder
/// bounds-checks each field instead of panicking on a truncated hostile frame.
#[test]
fn status_decode_refuses_every_prefix() {
    let full = minimal_status().encode().expect("a minimal status encodes");
    StatusReply::decode(&full).expect("the whole frame decodes");
    for cut in 0..full.len() {
        let error = StatusReply::decode(&full[..cut]).expect_err("a prefix must not decode");
        assert!(
            matches!(error, ControlError::Protocol(_)),
            "cut at {cut} is a protocol error: {error}"
        );
    }
}

/// `has_addr = 2` is not a presence: only 0 and 1 are legal, so the decode refuses.
#[test]
fn status_decode_refuses_an_unknown_addr_presence() {
    let error = StatusReply::decode(&status_prefix(2)).expect_err("presence 2 must refuse");
    assert!(
        matches!(error, ControlError::Protocol(_)),
        "an unknown addr presence is a protocol error: {error}"
    );
}

/// The addr string cap is checked before the bytes are read: a declared 257-byte addr refuses.
#[test]
fn status_decode_refuses_an_over_long_addr() {
    let mut bytes = status_prefix(1);
    bytes.extend_from_slice(&257u16.to_be_bytes());
    let error = StatusReply::decode(&bytes).expect_err("addr over 256 must refuse");
    assert!(
        matches!(error, ControlError::Protocol(_)),
        "an over-long addr is a protocol error: {error}"
    );
}

/// A declared catalog over the frame cap is typed `TooLarge`, never an on-demand allocation.
#[test]
fn status_decode_refuses_an_over_large_catalog() {
    let mut bytes = status_prefix(0);
    bytes.extend_from_slice(&0u64.to_be_bytes());
    bytes.extend_from_slice(&((MAX_FRAME + 1) as u32).to_be_bytes());
    let error = StatusReply::decode(&bytes).expect_err("an oversized catalog must refuse");
    assert!(
        matches!(error, ControlError::TooLarge(len) if len == MAX_FRAME + 1),
        "an over-cap catalog is typed `TooLarge` with its length: {error}"
    );
}

/// One name more than the decode cap refuses: 1025 is over the 1024 cap.
#[test]
fn status_decode_refuses_too_many_disabled_names() {
    let mut disabled = Vec::new();
    disabled.push(0);
    disabled.extend_from_slice(&1025u32.to_be_bytes());
    let error = StatusReply::decode(&status_frame_with_disabled(&disabled))
        .expect_err("1025 disabled names must refuse");
    assert!(
        matches!(error, ControlError::Protocol(_)),
        "too many disabled names is a protocol error: {error}"
    );
}

/// The encoder refuses the same cap its decoder enforces: a menu over the name cap never becomes a
/// frame a conforming client would reject.
#[test]
fn status_encode_refuses_too_many_disabled_names() {
    let mut status = minimal_status();
    status.menu.disabled = DisabledList::Known(
        (0..MAX_DISABLED_NAMES + 1)
            .map(|i| format!("svc{i:04}"))
            .collect(),
    );
    status
        .encode()
        .expect_err("1025 disabled names must refuse at the encoder");
}

/// An unknown disabled presence is a protocol error: only 0 (known) and 1 (unknown) are legal.
#[test]
fn status_decode_refuses_an_unknown_disabled_presence() {
    let error = StatusReply::decode(&status_frame_with_disabled(&[2]))
        .expect_err("disabled presence 2 must refuse");
    assert!(
        matches!(error, ControlError::Protocol(_)),
        "an unknown disabled presence is a protocol error: {error}"
    );
}

/// A trailing byte after a complete status frame refuses: the whole payload is the frame, no slack.
#[test]
fn status_decode_refuses_trailing_bytes() {
    let mut bytes = minimal_status().encode().expect("a minimal status encodes");
    bytes.push(0);
    let error = StatusReply::decode(&bytes).expect_err("trailing bytes must refuse");
    assert!(
        matches!(error, ControlError::Protocol(_)),
        "trailing bytes are a protocol error: {error}"
    );
}

/// A fake peer-credential checker reporting a uid that is never ours (a faked foreign peer, no root
/// needed), shaped as a plain `fn` so it coerces to the checker seam.
fn foreign_uid(_: i32) -> std::io::Result<u32> {
    // SAFETY: `geteuid` takes no arguments and touches no memory.
    Ok(if unsafe { libc::geteuid() } == 0 {
        1
    } else {
        0
    })
}

/// The uid gate on the REAL serve path: a foreign checker gets EOF before a byte is served; the
/// production `real_peer_uid` admits our own uid over a live fd pair and answers a status read.
#[tokio::test]
async fn accepts_own_uid_refuses_foreign_uid() {
    let refused = Arc::new(test_resident());
    let (mut client, server) = tokio::net::UnixStream::pair().expect("socketpair");
    let task = tokio::spawn({
        let this = Arc::clone(&refused);
        async move {
            this.serve_checked_with(server, foreign_uid, READ_TIMEOUT)
                .await;
        }
    });
    // The refusal can close the server end before this write lands, so a broken pipe is itself a
    // refusal outcome here; either way the client must see EOF, never a reply.
    let _ = Request::Status.write(&mut client).await;
    let reply = tokio::time::timeout(READ_TIMEOUT, Response::read(&mut client))
        .await
        .expect("the refusal closes the stream");
    assert!(reply.is_err(), "a foreign uid gets no reply, only EOF");
    task.await.expect("the serve task joins");
    assert_eq!(
        refused.served(),
        0,
        "the uid gate sits before the first byte"
    );

    let admitted = Arc::new(test_resident());
    let (mut client, server) = tokio::net::UnixStream::pair().expect("socketpair");
    let task = tokio::spawn({
        let this = Arc::clone(&admitted);
        async move {
            this.serve_checked_with(server, super::real_peer_uid, READ_TIMEOUT)
                .await;
        }
    });
    Request::Status
        .write(&mut client)
        .await
        .expect("request writes");
    let reply = Response::read(&mut client)
        .await
        .expect("our uid is served");
    assert!(
        matches!(reply, Response::Status(_)),
        "a status reply comes back"
    );
    task.await.expect("the serve task joins");
    assert_eq!(admitted.served(), 1, "the admitted connection was served");
}

/// The accept cap queues instead of dropping: with every slot held by a silent client, a ninth
/// one-shot client stays queued at the listener (neither a reply nor EOF in the bounded window),
/// and freeing one slot admits it. This drives `Resident::serve`, so deleting the slot gate is not
/// silently green.
#[tokio::test]
async fn control_flood_queues_rather_than_drops() {
    let dir = scratch_dir("flood");
    let socket = dir.join("control.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("bind the control socket");
    let cancel = CancellationToken::new();
    let resident = Arc::new(test_resident_with(cancel.clone()));
    let serving = tokio::spawn({
        let this = Arc::clone(&resident);
        async move { this.serve(listener).await }
    });

    // Every slot held by a connected-but-silent client: each serve task parks on the read timeout.
    let mut silent = Vec::new();
    for _ in 0..MAX_CONTROL_CONNS {
        silent.push(
            tokio::net::UnixStream::connect(&socket)
                .await
                .expect("a silent client connects"),
        );
    }
    wait_for_permits(&resident, 0).await;

    // A one-shot client behind the flood writes its request: past the cap it waits at the listener,
    // so the bounded read sees neither a reply nor EOF (the drop shape would end the stream here).
    let mut queued = tokio::net::UnixStream::connect(&socket)
        .await
        .expect("the queued client connects");
    Request::Status
        .write(&mut queued)
        .await
        .expect("queued request writes");
    let mut first_byte = [0u8; 1];
    let early = tokio::time::timeout(
        core::time::Duration::from_millis(100),
        queued.read_exact(&mut first_byte),
    )
    .await;
    assert!(
        early.is_err(),
        "past the cap the request queues, no reply yet"
    );

    // Free one slot: the queued client is admitted and its request answered.
    drop(silent.pop());
    let reply = tokio::time::timeout(
        core::time::Duration::from_secs(5),
        Response::read(&mut queued),
    )
    .await
    .expect("the queued client is served once a slot frees")
    .expect("the queued request gets a reply");
    assert!(
        matches!(reply, Response::Status(_)),
        "the queued request is answered"
    );
    assert_eq!(
        resident.served(),
        (MAX_CONTROL_CONNS + 1) as u64,
        "every admitted connection is counted"
    );

    cancel.cancel();
    serving
        .await
        .expect("the serve task joins")
        .expect("serve ends Ok");
}

/// One byte sent, then silence: the frame never completes, so the injected timeout is the only way
/// the task ends. Deleting the wrapper hangs the join, so this is not a constant against itself.
#[tokio::test]
async fn slow_loris_is_timed_out() {
    let resident = Arc::new(test_resident());
    let (mut client, server) = tokio::net::UnixStream::pair().expect("socketpair");
    let task = tokio::spawn({
        let this = Arc::clone(&resident);
        async move {
            this.serve_checked_with(
                server,
                super::real_peer_uid,
                core::time::Duration::from_millis(50),
            )
            .await;
        }
    });
    client
        .write_all(&MAGIC[..1])
        .await
        .expect("a partial frame writes");
    tokio::time::timeout(core::time::Duration::from_secs(5), task)
        .await
        .expect("the injected timeout reaps the slow client")
        .expect("the serve task joins");
    assert_eq!(
        resident.served(),
        1,
        "the connection was admitted, then reaped"
    );
}

/// EOF is the oversized-frame contract: a request that DECLARES more than the cap is never answered,
/// only closed. This drives `Resident::serve_checked_with`, so changing the serve path to reply
/// `Error` would fail the `read == 0` assertion.
#[tokio::test]
async fn oversized_declared_frame_ends_the_connection() {
    let resident = Arc::new(test_resident());
    let (mut client, server) = tokio::net::UnixStream::pair().expect("socketpair");
    let task = tokio::spawn({
        let this = Arc::clone(&resident);
        async move {
            this.serve_checked_with(server, super::real_peer_uid, READ_TIMEOUT)
                .await;
        }
    });
    let mut frame = Vec::new();
    frame.extend_from_slice(&MAGIC);
    frame.push(1);
    frame.extend_from_slice(&((MAX_FRAME + 1) as u16).to_be_bytes());
    client
        .write_all(&frame)
        .await
        .expect("the oversized header writes");
    let mut sink = [0u8; 1];
    let read = tokio::time::timeout(READ_TIMEOUT, client.read(&mut sink))
        .await
        .expect("the serve path closes an oversized declared frame")
        .expect("the close is a clean read");
    assert_eq!(read, 0, "EOF, never a reply");
    task.await.expect("the serve task joins");
    assert_eq!(
        resident.served(),
        1,
        "the connection was admitted before the codec cap"
    );
}

/// A socket `Stop` is acked on the wire before it fires: the client observes the Ack, the source
/// records the local kind (so the run never files it as a wire stop), and the shared teardown token
/// is cancelled only after the confirm is written.
#[tokio::test]
async fn socket_stop_acks_before_it_fires() {
    use super::StopKind;
    use crate::commands::serve::{Stopped, classify_stop};

    let cancel = CancellationToken::new();
    let resident = Arc::new(test_resident_with(cancel.clone()));
    let (mut client, server) = tokio::net::UnixStream::pair().expect("socketpair");
    let task = tokio::spawn({
        let this = Arc::clone(&resident);
        async move {
            this.serve_checked_with(server, super::real_peer_uid, READ_TIMEOUT)
                .await;
        }
    });
    Request::Stop.write(&mut client).await.expect("stop writes");
    let reply = tokio::time::timeout(READ_TIMEOUT, Response::read(&mut client))
        .await
        .expect("the Ack arrives before any teardown")
        .expect("the Ack reads");
    assert!(matches!(reply, Response::Ack), "a stop is acked");
    task.await.expect("the serve task joins");
    let source = resident.stop_source();
    assert_eq!(
        source.first(),
        Some(StopKind::Socket),
        "the socket kind is recorded"
    );
    assert_eq!(
        classify_stop(source.first()),
        Stopped::Local,
        "the socket stop renders local, never the wire line"
    );
    assert!(cancel.is_cancelled(), "the stop fired after the Ack");
}

/// A writer whose writes never complete: holds the reply in flight so the test can observe whether
/// the stop fired mid-write.
struct PendingWriter;

impl AsyncWrite for PendingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

/// The Ack write precedes the stop: while the reply write is still pending, the cancel has NOT
/// fired; it fires only after the write deadline lets the serve path past the write. Swapping the
/// two lines in `reply_then_fire` fails the mid-write assertion.
#[tokio::test]
async fn stop_fires_only_after_the_ack_write_completes() {
    let cancel = CancellationToken::new();
    let resident = test_resident_with(cancel.clone());
    let mut writer = PendingWriter;
    let write_deadline = core::time::Duration::from_millis(200);
    let reply = resident.reply_then_fire(&mut writer, &Response::Ack, true, write_deadline);
    tokio::pin!(reply);
    let mid_write = tokio::time::timeout(core::time::Duration::from_millis(50), &mut reply).await;
    assert!(mid_write.is_err(), "the reply write is still pending");
    assert!(
        !cancel.is_cancelled(),
        "the stop must not fire while its Ack is still being written"
    );
    tokio::time::timeout(core::time::Duration::from_secs(1), reply)
        .await
        .expect("the write deadline elapses");
    assert!(
        cancel.is_cancelled(),
        "the stop fires once the write path is done"
    );
}

/// M4: an accept error is classified before it retries: listener-broken errnos are fatal (the run
/// ends loudly), fd-pressure errnos take the bounded backoff, and the backoff stays short.
#[test]
fn accept_errors_split_fatal_from_backoff() {
    use super::{ACCEPT_BACKOFF, accept_error_fatal};

    for errno in [libc::EBADF, libc::EFAULT, libc::EINVAL, libc::ENOTSOCK] {
        assert!(
            accept_error_fatal(&std::io::Error::from_raw_os_error(errno)),
            "a broken listener is fatal: errno {errno}"
        );
    }
    for errno in [
        libc::EMFILE,
        libc::ENFILE,
        libc::ENOBUFS,
        libc::ECONNABORTED,
        libc::EAGAIN,
    ] {
        assert!(
            !accept_error_fatal(&std::io::Error::from_raw_os_error(errno)),
            "a recoverable accept error backs off: errno {errno}"
        );
    }
    assert!(
        ACCEPT_BACKOFF <= core::time::Duration::from_millis(250),
        "the backoff stays short and bounded"
    );
}

/// M4 at the call, not the predicate: a recoverable accept error must WAIT one bounded backoff
/// before re-accepting, or the loop spins the serving runtime. The helper is what the accept loop
/// calls on a recoverable error; deleting its `sleep` makes the future complete at once, so the
/// bounded poll here fails. Inducing a real EMFILE/ENOBUFS is process-global and flaky, which is
/// why the wait is split out and driven directly.
#[tokio::test]
async fn recoverable_accept_error_waits_one_bounded_backoff() {
    use super::{ACCEPT_BACKOFF, accept_backoff_wait};

    let early =
        tokio::time::timeout(core::time::Duration::from_millis(10), accept_backoff_wait()).await;
    assert!(
        early.is_err(),
        "a recoverable accept error must wait its backoff, not fall straight through"
    );
    tokio::time::timeout(
        ACCEPT_BACKOFF + core::time::Duration::from_secs(1),
        accept_backoff_wait(),
    )
    .await
    .expect("the backoff is bounded and completes");
}

/// m1/m2: the disabled read is bounded and honest. An absent file means an empty `Known` list; a
/// read failure or an oversized file is an explicit `Unknown` (never a false "nothing disabled");
/// and past the count cap the list truncates rather than write a reply the client refuses.
#[test]
fn disabled_read_is_bounded_and_reports_errors() {
    use super::{DISABLED_BYTES_CAP, DISABLED_NAMES_CAP, read_disabled_names};

    let dir = scratch_dir("disabled");
    assert_eq!(
        read_disabled_names(&dir.join("absent")),
        DisabledList::Known(Vec::new()),
        "an absent file means nothing is disabled"
    );

    let path = dir.join("disabled");
    std::fs::write(&path, "speed\n\n ping \nspeed\n").expect("write disabled");
    assert_eq!(
        read_disabled_names(&path),
        DisabledList::Known(vec![
            "ping".to_owned(),
            "speed".to_owned(),
            "speed".to_owned(),
        ]),
        "names are trimmed, dropped when empty, and sorted"
    );

    // Invalid UTF-8: the read itself fails, so the reply must say unknown, never empty.
    std::fs::write(&path, [0xff, 0xfe, 0xfd]).expect("write invalid utf8");
    assert!(
        matches!(read_disabled_names(&path), DisabledList::Unknown(_)),
        "a read failure is an explicit unknown"
    );

    // Over the byte cap: unknown, never a truncated list that under-reports.
    let oversized = "x\n".repeat((DISABLED_BYTES_CAP as usize / 2) + 1);
    std::fs::write(&path, oversized).expect("write oversized disabled");
    assert!(
        matches!(read_disabled_names(&path), DisabledList::Unknown(_)),
        "an oversized file is an explicit unknown"
    );

    // A name over the reply's own string cap: unknown, never a frame the client refuses to decode.
    let long_name = "n".repeat(MAX_STATUS_STRING + 1);
    std::fs::write(&path, format!("{long_name}\n")).expect("write long disabled name");
    assert!(
        matches!(read_disabled_names(&path), DisabledList::Unknown(_)),
        "a name over the reply cap is an explicit unknown"
    );

    // Over the count cap: the reply truncates to the decode cap instead of writing names a
    // conforming client would refuse to decode.
    let many: String = (0..DISABLED_NAMES_CAP + 8)
        .map(|i| format!("svc{i:05}\n"))
        .collect();
    std::fs::write(&path, many).expect("write many disabled");
    match read_disabled_names(&path) {
        DisabledList::Known(names) => {
            assert_eq!(
                names.len(),
                DISABLED_NAMES_CAP,
                "the reported count is capped"
            );
        }
        DisabledList::Unknown(reason) => panic!("a many-name file above the count cap: {reason}"),
    }
}
