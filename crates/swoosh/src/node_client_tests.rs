//! S5 tests: the two backends agree on the control contract, and resolve refuses an untrusted path
//! without ever connecting.

use core::sync::atomic::{AtomicU32, Ordering};
use std::path::PathBuf;
use std::sync::Arc;

use bifrost::NodeId;
use tightbeam::tunnel::{CancellationToken, ServiceCatalog};

use super::{NodeClient as _, UidSocket};
use crate::commands::serve::Resident;
use crate::commands::serve::control_codec::{ControlError, DisabledList, Request, Response};

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

/// A resident over temp state holding `cancel`, with `disabled` as its live disabled path.
fn test_resident(cancel: CancellationToken, disabled: PathBuf) -> Resident {
    Resident::new(
        NodeId::from_ed25519_secret(&[9u8; 32]),
        None,
        empty_catalog(),
        disabled,
        cancel,
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
    let disabled = leaf.join("disabled");
    std::fs::write(&disabled, "speed\n").expect("write the disabled file");

    let cancel = CancellationToken::new();
    let resident = Arc::new(test_resident(cancel.clone(), disabled));
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
    let resident = Arc::new(test_resident(
        CancellationToken::new(),
        leaf.join("disabled"),
    ));
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
