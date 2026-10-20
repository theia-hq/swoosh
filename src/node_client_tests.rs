//! S5 tests: the two backends agree on the control contract, and resolve refuses an untrusted path
//! without ever connecting.

use core::sync::atomic::{AtomicU32, Ordering};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bifrost::NodeId;
use tightbeam::tunnel::{CancellationToken, ServiceCatalog};

use super::{NodeClient as _, UidSocket};
use crate::serve::Resident;
use crate::serve::control_codec::{ControlError, DisabledList, Request, Response};

/// Serializes scratch dir names within this test process; the pid keeps two concurrent runs apart.
/// Names stay short: the control socket path must fit `sun_path` (104 bytes on macOS).
static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

/// A unique per-home runtime leaf with an explicit mode, for driving resolve and a real listener.
fn scratch(tag: &str, mode: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let short: String = tag.chars().take(8).collect();
    let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("swc-{short}-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("control scratch");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode))
        .expect("control scratch mode");
    dir
}

/// An empty catalog: these tests exercise the control contract, not service content.
fn empty_catalog() -> ServiceCatalog {
    ServiceCatalog::decode(&0u32.to_be_bytes()).expect("an empty catalog decodes")
}

/// A resident over temp state holding `cancel`, reading the services off from the home at `home`.
fn test_resident(cancel: CancellationToken, home: &Path) -> Resident {
    let home = crate::home::Home::resolve(Some(home.to_owned())).expect("a scratch home");
    Resident::new(
        NodeId::from_ed25519_secret(&[9u8; 32]),
        None,
        empty_catalog(),
        crate::serve_toml::LiveServeToml::load(&home).expect("the services off load"),
        cancel,
        std::sync::Arc::default(),
    )
}

/// The uid-socket backend and the resident answer the same control contract: byte-equal menus and
/// status replies over a real temp-dir socket, and both accept a stop. A menu with one live disabled
/// entry proves the disabled section rides both paths, not only the happy empty case.
#[tokio::test]
async fn backends_agree() {
    let leaf = scratch("agree", 0o700);
    let socket = leaf.join("control.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("bind the control socket");
    std::fs::write(leaf.join("serve.toml"), "off = [\"speed\"]\n").expect("write serve.toml");

    let cancel = CancellationToken::new();
    let resident = Arc::new(test_resident(cancel.clone(), &leaf));
    let serving = tokio::spawn({
        let this = Arc::clone(&resident);
        async move { this.serve(listener).await }
    });

    let client = UidSocket::resolve_socket(socket).expect("the bound socket resolves");

    let direct = resident.services().await.expect("resident services");
    let over = client.services().await.expect("socket services");
    assert_eq!(direct, over, "the two backends agree on the service menu");
    assert_eq!(
        over.disabled,
        DisabledList::Known(vec!["speed".to_owned()]),
        "the live disabled list rides the socket menu"
    );

    // Both status reads call the same resident, so only the uptime second can differ at a boundary;
    // retry until the two reads land in one second, then assert the whole reply is equal.
    let mut agreed = false;
    for _ in 0..8 {
        let direct = resident.status().await.expect("resident status");
        let over = client.status().await.expect("socket status");
        if direct.uptime_secs == over.uptime_secs {
            assert_eq!(direct, over, "the two backends agree on the status reply");
            agreed = true;
            break;
        }
    }
    assert!(agreed, "the status reads never landed in one uptime second");

    client.stop().await.expect("the socket stop succeeds");
    resident.stop().await.expect("the resident stop succeeds");
    serving
        .await
        .expect("the serve task joins")
        .expect("serve ends Ok");

    let _ = std::fs::remove_dir_all(&leaf);
}

/// One socket `services()` is exactly one control connection: the resident's `served` counter
/// advances by one per call, and the in-process implementation opens no connection at all.
#[tokio::test]
async fn services_is_one_round_trip() {
    let leaf = scratch("round", 0o700);
    let socket = leaf.join("control.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("bind the control socket");
    let resident = Arc::new(test_resident(CancellationToken::new(), &leaf));
    let serving = tokio::spawn({
        let this = Arc::clone(&resident);
        async move { this.serve(listener).await }
    });
    let client = UidSocket::resolve_socket(socket).expect("the bound socket resolves");

    assert_eq!(
        resident.served(),
        0,
        "nothing is served before the first call"
    );
    client.services().await.expect("socket services");
    assert_eq!(
        resident.served(),
        1,
        "one socket services() is one connection"
    );
    resident.services().await.expect("in-process services");
    assert_eq!(
        resident.served(),
        1,
        "the in-process backend opens no connection"
    );
    client.services().await.expect("second socket services");
    assert_eq!(
        resident.served(),
        2,
        "each socket call is exactly one round trip"
    );

    resident.stop().await.expect("stop the resident");
    serving
        .await
        .expect("the serve task joins")
        .expect("serve ends Ok");

    let _ = std::fs::remove_dir_all(&leaf);
}

/// A listener that accepts and then stalls must not park the verb: the client's response-read bound
/// fires and the call returns the typed `Timeout`, never a hang. Paused time makes the five-second
/// bound instant and deterministic.
#[tokio::test(start_paused = true)]
async fn stalled_response_read_times_out() {
    let leaf = scratch("stall", 0o700);
    let socket = leaf.join("control.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("bind the control socket");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let stalled = tokio::spawn(async move {
        let listener = tokio::net::UnixListener::from_std(listener).expect("tokio listener");
        let (_stream, _) = listener.accept().await.expect("accept");
        core::future::pending::<()>().await;
    });

    let client = UidSocket::resolve_socket(socket).expect("the bound socket resolves");
    let error = client
        .services()
        .await
        .expect_err("a stalled resident times out");
    assert!(
        matches!(
            error,
            ControlError::Timeout {
                phase: "response read"
            }
        ),
        "the response-read bound fires, never a hang: {error}"
    );

    stalled.abort();
    let _ = stalled.await;
    let _ = std::fs::remove_dir_all(&leaf);
}

/// A dial that never completes must not park the verb: the connect bound fires and the call returns
/// the typed `Timeout`, never a hang. The injected dial resolves only through the production bound;
/// the outer guard fails the test cleanly (instead of hanging CI) if that bound is deleted.
#[tokio::test(start_paused = true)]
async fn connect_deadline_is_bounded() {
    let leaf = scratch("dial", 0o700);
    let socket = leaf.join("control.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("bind the control socket");
    let client = UidSocket::resolve_socket(socket).expect("the bound socket resolves");
    let error = tokio::time::timeout(
        super::CONNECT_TIMEOUT * 2,
        client.connect_checked_with(
            core::future::pending::<std::io::Result<tokio::net::UnixStream>>(),
            super::real_peer_uid,
        ),
    )
    .await
    .expect("the connect bound fires before the guard")
    .expect_err("a wedged dial times out");
    assert!(
        matches!(error, ControlError::Timeout { phase: "connect" }),
        "the connect bound is the typed connect-phase timeout: {error}"
    );

    drop(listener);
    let _ = std::fs::remove_dir_all(&leaf);
}

/// A request write that cannot drain must not park the verb: a one-byte duplex the peer never reads
/// fills at the first byte, so the write bound fires and the call returns the typed `Timeout`. The
/// outer guard fails the test cleanly if that bound is deleted.
#[tokio::test(start_paused = true)]
async fn request_write_deadline_is_bounded() {
    let (stream, _peer) = tokio::io::duplex(1);
    let error = tokio::time::timeout(
        super::IO_TIMEOUT * 2,
        UidSocket::exchange_on(stream, &Request::Services),
    )
    .await
    .expect("the write bound fires before the guard")
    .expect_err("a wedged write times out");
    assert!(
        matches!(
            error,
            ControlError::Timeout {
                phase: "request write"
            }
        ),
        "the write bound is the typed request-write timeout: {error}"
    );
}

/// A fake peer-credential checker reporting a uid that is never ours: pins the connected-fd uid
/// proof without root. Shaped as a plain `fn` so it coerces to the checker seam.
fn foreign_uid(_: i32) -> std::io::Result<u32> {
    Ok(if super::euid() == 0 { 1 } else { 0 })
}

/// The connected-fd peer-uid proof refuses a peer the checker reports as foreign: the client twin of
/// the server's uid gate, driven through the same kind of injected checker. Deleting the comparison
/// in `connect_checked_with` lets the live stream through and fails this test.
#[tokio::test]
async fn connect_refuses_a_foreign_uid_peer() {
    let leaf = scratch("peer", 0o700);
    let socket = leaf.join("control.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("bind the control socket");
    let client = UidSocket::resolve_socket(socket).expect("the bound socket resolves");

    let error = client
        .connect_checked_with(tokio::net::UnixStream::connect(&client.socket), foreign_uid)
        .await
        .expect_err("a foreign-uid peer must refuse");
    assert!(
        matches!(error, ControlError::Untrusted { ref path } if path == &client.socket),
        "a forged peer is Untrusted naming the socket: {error}"
    );

    drop(listener);
    let _ = std::fs::remove_dir_all(&leaf);
}

/// The production `connect` admits our own uid through the real `getpeereid`/`SO_PEERCRED` checker:
/// a live listener in this process is trusted, so the proof is not a blanket refusal.
#[tokio::test]
async fn connect_admits_our_own_uid() {
    let leaf = scratch("admit", 0o700);
    let socket = leaf.join("control.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("bind the control socket");
    let client = UidSocket::resolve_socket(socket).expect("the bound socket resolves");

    let stream = client.connect().await.expect("our own uid is admitted");
    drop(stream);
    drop(listener);
    let _ = std::fs::remove_dir_all(&leaf);
}

/// Plant a socket inode at `path` that never listened: `socket` + `bind` + close, no `listen`. The
/// path refuses every connect (`ECONNREFUSED`) and cannot be revived: a non-listening socket stays
/// refusing even while a forked child holds an inherited fd. A `UnixListener` bound and dropped
/// would leave the same path but could still answer through a listening fd a sibling test's
/// concurrent `Command` spawn inherited before its own exec closed it.
fn plant_dead_socket(path: &std::path::Path) {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = path.as_os_str().as_bytes();
    // SAFETY: `sockaddr_un` is plain C data (integers plus a byte array); all-zero is a valid
    // initial value and every field the kernel reads is set below.
    let mut addr: libc::sockaddr_un = unsafe { core::mem::zeroed() };
    assert!(
        bytes.len() < addr.sun_path.len(),
        "the scratch socket path fits sun_path"
    );
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in addr.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    // SAFETY: `socket` takes no pointers and returns a fresh fd or -1.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "socket() for the dead plant");
    // SAFETY: `fd` is fresh; `addr` names a fully-initialized `sockaddr_un`.
    let bound = unsafe {
        libc::bind(
            fd,
            core::ptr::addr_of!(addr).cast(),
            core::mem::size_of_val(&addr) as libc::socklen_t,
        )
    };
    assert_eq!(bound, 0, "bind() the dead plant");
    // SAFETY: `fd` is owned by no other handle; closing it leaves the bound path behind as the dead
    // inode the production connect must classify.
    let _ = unsafe { libc::close(fd) };
}

/// A dead socket inode maps `ECONNREFUSED` to the typed `NoResident` miss, never a bare I/O error:
/// the stale-resident shape, on the production connect path. Deleting the errno arm turns this into
/// `Io`.
#[tokio::test]
async fn connect_maps_a_dead_listener_to_no_resident() {
    let leaf = scratch("stale", 0o700);
    let socket = leaf.join("control.sock");
    plant_dead_socket(&socket);
    let client = UidSocket::resolve_socket(socket).expect("the dead socket inode still resolves");

    let error = client.connect().await.expect_err("a dead listener refuses");
    assert!(
        matches!(error, ControlError::NoResident),
        "a refused connect is a typed NoResident: {error}"
    );

    let _ = std::fs::remove_dir_all(&leaf);
}

/// Resolve refuses a path that is not this user's 0700 socket, with zero connects: a loose leaf and a
/// non-socket inode are `Untrusted`; an absent socket is the typed `NoResident` miss.
#[test]
fn resolve_refuses_untrusted_paths() {
    let loose = scratch("loose", 0o755);
    let error =
        UidSocket::resolve_socket(loose.join("control.sock")).expect_err("a 0755 leaf must refuse");
    assert!(
        matches!(error, ControlError::Untrusted { ref path } if path == &loose),
        "a loose leaf is Untrusted naming the dir: {error}"
    );

    let leaf = scratch("inode", 0o700);
    let socket = leaf.join("control.sock");
    std::fs::write(&socket, b"not a socket").expect("write a plain file");
    let error =
        UidSocket::resolve_socket(socket.clone()).expect_err("a non-socket inode must refuse");
    assert!(
        matches!(error, ControlError::Untrusted { ref path } if path == &socket),
        "a non-socket inode is Untrusted naming the path: {error}"
    );

    let leaf = scratch("absent", 0o700);
    let error =
        UidSocket::resolve_socket(leaf.join("control.sock")).expect_err("an absent socket misses");
    assert!(
        matches!(error, ControlError::NoResident),
        "an absent socket is a typed NoResident: {error}"
    );
}

/// A leaf owned by another uid is Untrusted. Root-only: a non-root process cannot chown a dir to a
/// foreign owner, so this stays ignored in the normal CI run.
#[test]
#[ignore = "requires root: the leaf is chowned to a foreign uid"]
fn resolve_refuses_a_foreign_owner_leaf() {
    let leaf = scratch("foreign", 0o700);
    let foreign = if super::euid() == 0 { 1 } else { 0 };
    std::os::unix::fs::chown(&leaf, Some(foreign), None).expect("chown the leaf");
    let error = UidSocket::resolve_socket(leaf.join("control.sock"))
        .expect_err("a foreign-owner leaf must refuse");
    assert!(
        matches!(error, ControlError::Untrusted { .. }),
        "a foreign-owner leaf is Untrusted: {error}"
    );
}

/// The owner comparisons refuse a foreign owner on either half without root: the dir first, then the
/// socket after the dir passes. Each refusal names its half, so deleting either comparison is caught
/// by the named path, and the same tree resolves with our own uid.
#[test]
fn resolve_refuses_a_foreign_owner() {
    let leaf = scratch("owner", 0o700);
    let socket = leaf.join("control.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("bind the control socket");
    let foreign = if super::euid() == 0 { 1 } else { 0 };

    let error = UidSocket::resolve_socket_as(socket.clone(), foreign, super::euid())
        .expect_err("a foreign-owner leaf must refuse");
    assert!(
        matches!(error, ControlError::Untrusted { ref path } if path == &leaf),
        "a foreign-owner leaf is Untrusted naming the dir: {error}"
    );

    let error = UidSocket::resolve_socket_as(socket.clone(), super::euid(), foreign)
        .expect_err("a foreign-owner socket must refuse");
    assert!(
        matches!(error, ControlError::Untrusted { ref path } if path == &socket),
        "a foreign-owner socket is Untrusted naming the socket: {error}"
    );

    UidSocket::resolve_socket(socket).expect("our own tree resolves");

    drop(listener);
    let _ = std::fs::remove_dir_all(&leaf);
}

/// A wire `Refused` maps to the typed `ControlError::Refused`, never a stringified protocol error:
/// a scripted server answers a refusal and the client surfaces it as the refusal it is.
#[tokio::test]
async fn socket_maps_a_refusal_to_the_typed_error() {
    let leaf = scratch("refuse", 0o700);
    let socket = leaf.join("control.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("bind the control socket");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let server = tokio::spawn(async move {
        let listener = tokio::net::UnixListener::from_std(listener).expect("tokio listener");
        let (mut stream, _) = listener.accept().await.expect("accept");
        let _ = Request::read(&mut stream).await;
        Response::Refused("gated".to_owned())
            .write(&mut stream)
            .await
            .expect("the refusal writes");
    });

    let client = UidSocket::resolve_socket(socket).expect("the bound socket resolves");
    let error = client.services().await.expect_err("a refusal is an error");
    assert!(
        matches!(error, ControlError::Refused(ref reason) if reason == "gated"),
        "a wire refusal is the typed Refused with its reason: {error}"
    );
    server.await.expect("the scripted server joins");

    let _ = std::fs::remove_dir_all(&leaf);
}

/// `stop` treats a clean EOF after the written request as success: a server that reads the stop and
/// closes without an Ack still confirms the stop. Deleting the `UnexpectedEof` arm makes this `Io`.
#[tokio::test]
async fn stop_treats_a_clean_eof_as_success() {
    let leaf = scratch("eof", 0o700);
    let socket = leaf.join("control.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("bind the control socket");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let server = tokio::spawn(async move {
        let listener = tokio::net::UnixListener::from_std(listener).expect("tokio listener");
        let (mut stream, _) = listener.accept().await.expect("accept");
        let request = Request::read(&mut stream).await.expect("the stop reads");
        assert_eq!(request, Request::Stop, "the client asked to stop");
        // Drop the stream with no Ack: the client must read the clean EOF as the confirmation.
    });

    let client = UidSocket::resolve_socket(socket).expect("the bound socket resolves");
    client
        .stop()
        .await
        .expect("a clean EOF after the stop is success");
    server.await.expect("the scripted server joins");

    let _ = std::fs::remove_dir_all(&leaf);
}

/// The verb-boundary rendering of the typed control errors: `NoResident` teaches the fix verbatim,
/// a wire `Refused` renders the resident's reason verbatim (never doubled), and a `Protocol`
/// error names the skew fix, so a stale resident is never silently bypassed.
#[test]
fn control_errors_render_through_their_taxonomy() {
    let missing = format!(
        "{:#}",
        super::control_error_report(ControlError::NoResident)
    );
    assert!(
        missing.contains("swoosh serve is not running on this machine"),
        "the missing-serve error says nothing is running: {missing}"
    );

    let refused = format!(
        "{:#}",
        super::control_error_report(ControlError::Refused(
            "not admitted: no member badge or capability for this service was accepted".to_owned()
        ))
    );
    assert!(
        refused.contains("not admitted"),
        "the resident's refusal reason rides through: {refused}"
    );
    assert!(
        !refused.contains("refused (refused)"),
        "the token is never doubled: {refused}"
    );

    let skew = format!(
        "{:#}",
        super::control_error_report(ControlError::Protocol(
            "unknown response tag 0x07".to_owned()
        ))
    );
    assert!(
        skew.contains("different swoosh version") && skew.contains("restart it with this binary"),
        "a protocol error names the skew fix: {skew}"
    );
}

fn detail_frame(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = b"SWC1".to_vec();
    frame.push(tag);
    frame.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

async fn detail_read(
    mut bytes: &[u8],
) -> Result<crate::serve::control_codec::LocalServiceSnapshot, ControlError> {
    Response::read_local_detail(&mut bytes)
        .await?
        .into_local_snapshot()
}

#[tokio::test]
async fn local_detail_success_is_one_request_without_eof_or_second_frame_merge() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let target = "unix:秘密=a=b\n";
    let snapshot = crate::serve::control_codec::LocalServiceSnapshot::capture(
        [("a", target, true)].into_iter(),
    )
    .unwrap();
    let mut frames = Vec::new();
    Response::LocalServiceDetail(Ok(snapshot))
        .write(&mut frames)
        .await
        .unwrap();
    frames.extend_from_slice(&detail_frame(9, &[0, 0, 0]));
    let leaf = scratch("detail", 0o700);
    let path = leaf.join("control.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let client = UidSocket::resolve_socket(PathBuf::clone(&path)).unwrap();
    let server = async {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 7];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"SWC1\x06\0\0");
            stream.write_all(&frames).await.unwrap();
            // Keep the response side open until the client drops, proving no EOF wait or retry.
            // Dropping an unread second frame may reset the Unix stream instead of returning EOF.
            let mut extra = [0];
            match stream.read(&mut extra).await {
                Ok(0) => {}
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
                result => panic!("expected client close without another request, got {result:?}"),
            }
        }
        assert!(
            tokio::time::timeout(core::time::Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    };
    let calls = async {
        let direct = client.local_service_detail().await.unwrap();
        let delegated = super::ControlClient::resolve_socket(path)
            .unwrap()
            .local_service_detail()
            .await
            .unwrap();
        for snapshot in [direct, delegated] {
            assert_eq!(snapshot.len(), 1);
            let pair = snapshot.get("a").unwrap();
            assert_eq!(pair.target().as_str().as_bytes(), target.as_bytes());
            assert!(pair.refused());
        }
    };
    tokio::time::timeout(core::time::Duration::from_secs(2), async {
        tokio::join!(server, calls);
    })
    .await
    .unwrap();
    drop(listener);
    std::fs::remove_dir_all(leaf).unwrap();
}

#[tokio::test]
async fn local_detail_socket_rejects_diagnostic_declarations_without_waiting_for_body() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let leaf = scratch("d-cap", 0o700);
    let path = leaf.join("control.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let client = UidSocket::resolve_socket(path).unwrap();
    let server = async {
        for tag in [4, 5] {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(
                Request::read(&mut stream).await.unwrap(),
                Request::LocalServiceDetail
            );
            stream
                .write_all(&[b'S', b'W', b'C', b'1', tag, 1, 3])
                .await
                .unwrap();
            let mut extra = [0];
            assert_eq!(stream.read(&mut extra).await.unwrap(), 0);
        }
    };
    let calls = async {
        for _ in 0..2 {
            assert!(matches!(client.local_service_detail().await,
                Err(ControlError::Protocol(reason)) if reason == "local service detail diagnostic exceeds 256 bytes"));
        }
    };
    tokio::time::timeout(core::time::Duration::from_secs(1), async {
        tokio::join!(server, calls);
    })
    .await
    .unwrap();
    drop(listener);
    std::fs::remove_dir_all(leaf).unwrap();
}

#[tokio::test]
async fn local_detail_capture_failures_keep_their_structural_types() {
    use crate::serve::control_codec::{LocalDetailError as E, LocalDetailLimit as L};
    for payload in [&[1][..], &[3], &[2, 1], &[2, 2], &[2, 3], &[2, 4]] {
        let error = detail_read(&detail_frame(9, payload)).await.unwrap_err();
        assert!(match (payload, error) {
            ([1], ControlError::LocalDetail(E::MissingStartup)) => true,
            ([3], ControlError::LocalDetail(E::InconsistentState)) => true,
            ([2, n], ControlError::LocalDetail(E::LimitExceeded(limit))) =>
                limit
                    == [L::BoundCount, L::NameBytes, L::TargetBytes, L::PayloadBytes]
                        [usize::from(*n - 1)],
            _ => false,
        });
    }
}

#[tokio::test]
async fn local_detail_diagnostics_are_bounded_exact_utf8_and_not_classified_by_text() {
    use crate::serve::control_codec::LocalDetailError;
    for tag in [4, 5] {
        for reason in [
            "".to_owned(),
            "é".repeat(128),
            "local service detail resources are unavailable".to_owned(),
        ] {
            let mut payload = u16::try_from(reason.len()).unwrap().to_be_bytes().to_vec();
            payload.extend_from_slice(reason.as_bytes());
            let error = detail_read(&detail_frame(tag, &payload)).await.unwrap_err();
            let owned = match error {
                ControlError::Refused(owned) if tag == 4 => owned,
                ControlError::LocalDetail(LocalDetailError::PeerError(owned)) if tag == 5 => owned,
                error => panic!("{error:?}"),
            };
            assert_eq!(owned, reason);
            assert!(owned.capacity() <= 256);
        }
        for payload in [vec![], vec![0], vec![0, 1], vec![0, 1, 255], vec![0, 0, 0]] {
            assert!(matches!(detail_read(&detail_frame(tag, &payload)).await,
                Err(ControlError::Protocol(reason)) if reason == "invalid local service detail diagnostic"));
        }
        let mut payload = vec![1, 1];
        payload.extend_from_slice(&[b'x'; 257]);
        assert!(matches!(detail_read(&detail_frame(tag, &payload)).await,
            Err(ControlError::Protocol(reason)) if reason == "local service detail diagnostic exceeds 256 bytes"));
        // There is no body to read, and allocation at the declared size is forbidden.
        let header = [b'S', b'W', b'C', b'1', tag, 1, 3];
        let result = detail_read(&header).await;
        assert!(
            matches!(result, Err(ControlError::Protocol(reason)) if reason == "local service detail diagnostic exceeds 256 bytes")
        );
    }
    // Narrowing is operation-specific: generic reads retain their larger diagnostic allowance.
    let mut bytes = Vec::new();
    Response::Error("x".repeat(257))
        .write(&mut bytes)
        .await
        .unwrap();
    assert!(
        matches!(Response::read(&mut bytes.as_slice()).await.unwrap(), Response::Error(reason) if reason.len() == 257)
    );
}

#[tokio::test]
async fn local_detail_malformed_unexpected_identity_version_and_eof_never_mean_absent() {
    for tag in [1, 2, 3, 6, 7, 8, 255] {
        assert!(
            matches!(detail_read(&detail_frame(tag, b"private-target/path")).await,
            Err(ControlError::Protocol(reason)) if reason == "unexpected reply to local service detail")
        );
    }
    for payload in [&[][..], &[4], &[2, 5], &[1, 0], &[0, 0, 1]] {
        assert!(matches!(
            detail_read(&detail_frame(9, payload)).await,
            Err(ControlError::Protocol(_))
        ));
    }
    assert!(matches!(
        detail_read(b"BAD1").await,
        Err(ControlError::Foreign)
    ));
    assert!(matches!(
        detail_read(b"SWC2").await,
        Err(ControlError::Version { .. })
    ));
    let valid = detail_frame(9, &[0, 0, 0]);
    for end in 0..valid.len() {
        assert!(
            matches!(detail_read(&valid[..end]).await, Err(ControlError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof)
        );
    }
    assert!(matches!(
        detail_read(b"SWC1\x09\x20\x01").await,
        Err(ControlError::TooLarge(8193))
    ));
}

#[tokio::test(start_paused = true)]
async fn local_detail_write_and_read_deadlines_enclose_the_whole_phase() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let (stream, _peer) = tokio::io::duplex(1);
    let result = tokio::time::timeout(
        super::IO_TIMEOUT * 2,
        UidSocket::exchange_on(stream, &Request::LocalServiceDetail),
    )
    .await
    .unwrap();
    assert!(matches!(
        result,
        Err(ControlError::Timeout {
            phase: "request write"
        })
    ));
    let (stream, mut peer) = tokio::io::duplex(1);
    let writer = tokio::spawn(async move {
        let mut request = [0; 7];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"SWC1\x06\0\0");
        for byte in detail_frame(9, &[0, 0, 0]) {
            if peer.write_all(&[byte]).await.is_err() {
                break;
            }
            tokio::time::sleep(core::time::Duration::from_secs(1)).await;
        }
    });
    let start = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        super::IO_TIMEOUT * 2,
        UidSocket::exchange_on(stream, &Request::LocalServiceDetail),
    )
    .await
    .unwrap();
    assert!(matches!(
        result,
        Err(ControlError::Timeout {
            phase: "response read"
        })
    ));
    assert_eq!(start.elapsed(), super::IO_TIMEOUT);
    writer.abort();
    let _ = writer.await;
}

#[tokio::test]
async fn local_detail_no_resident_is_distinct_from_post_connect_eof() {
    let leaf = scratch("d-miss", 0o700);
    let path = leaf.join("control.sock");
    plant_dead_socket(&path);
    let client = UidSocket::resolve_socket(PathBuf::clone(&path)).unwrap();
    assert!(matches!(
        client.local_service_detail().await,
        Err(ControlError::NoResident)
    ));
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        client.local_service_detail().await,
        Err(ControlError::NoResident)
    ));
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(
            Request::read(&mut stream).await.unwrap(),
            Request::LocalServiceDetail
        );
    };
    let calls = async {
        assert!(
            matches!(client.local_service_detail().await, Err(ControlError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof)
        );
    };
    tokio::time::timeout(core::time::Duration::from_secs(2), async {
        tokio::join!(server, calls);
    })
    .await
    .unwrap();
    drop(listener);
    std::fs::remove_dir_all(leaf).unwrap();
}

#[tokio::test]
async fn local_detail_credential_query_failure_and_symlinks_stay_untrusted() {
    fn failed_credentials(_: i32) -> std::io::Result<u32> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
    let leaf = scratch("d-trust", 0o700);
    let path = leaf.join("control.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let client = UidSocket::resolve_socket(PathBuf::clone(&path)).unwrap();
    assert!(matches!(
        client
            .connect_checked_with(tokio::net::UnixStream::connect(&path), failed_credentials)
            .await,
        Err(ControlError::Untrusted { .. })
    ));
    let alias = leaf.join("alias.sock");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(matches!(
        UidSocket::resolve_socket(alias),
        Err(ControlError::Untrusted { .. })
    ));
    let alias = leaf.with_extension("alias");
    std::os::unix::fs::symlink(&leaf, &alias).unwrap();
    assert!(matches!(
        UidSocket::resolve_socket(alias.join("control.sock")),
        Err(ControlError::Untrusted { .. })
    ));
    std::fs::remove_file(alias).unwrap();
    drop(listener);
    std::fs::remove_dir_all(leaf).unwrap();
}
