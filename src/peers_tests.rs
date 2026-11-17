//! Cache ownership proofs use the existing scripted gate; only transport scheduling and failure are
//! injected here. Sessions deliberately implement neither Clone nor Send.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::cell::{Cell, RefCell};
use core::future::pending;
use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use core::time::Duration;
use std::rc::Rc;
use std::time::SystemTime;

use bifrost::{
    Addr, Layered, NoDiscovery, Node, NodeId, Path, PathChanges, Session, StaticDiscovery,
    Transport,
};
use bifrost_mdns::MdnsDiscovery;
use futures::poll;
use nauthy::{Link, Service};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::sync::Semaphore;

use super::Lane::{Bulk, Main};
use super::Presents::{Slip, Standing};
use super::{
    BULK_STREAMS, Carry, Class, DIAL_TIMEOUT, DialFailure, Hints, IDLE_EVICTION,
    ISOLATED_CONNECTIONS, Key, MAIN_OPEN_TIMEOUT, MAIN_STREAMS, OPEN_TIMEOUT, OpenError, Peers,
    TooManyHints,
};
use crate::home::Home;
use crate::renewal::{Fetch as _, NodeFetch};
use crate::serve::{RENEWAL_SERVICE, SYNC_SERVICE};
use crate::sync::{Dial as _, NodeDial};
use crate::testkit::{Script, ScriptedPeer, TestNode, TestRoot, TestWrite};

#[tokio::test]
async fn credentialed_exchange_and_none_pickup_use_separate_sessions() {
    let probe = Probe::new((0..5).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let home = scratch("cohorts");
    let peers = Peers::new(&node);
    let dial = NodeDial::new(&peers, &home);
    let fetch = NodeFetch::new(&peers);
    let first = badge(1);
    crate::config::write_badge(&crate::testkit::lock(), &home, &first).unwrap();
    // The gate admits the stream; this deliberately unprovisioned home cannot run the exchange body.
    assert!(dial.exchange(peer()).await.is_err());
    // The gate admits the stream; this deliberately unprovisioned home cannot run the exchange body.
    assert!(dial.exchange(peer()).await.is_err());
    assert_eq!(probe.state.dials.get(), 1);
    assert!(fetch.fetch(peer()).await.unwrap().is_none());
    assert_eq!(probe.state.dials.get(), 2);
    crate::config::write_badge(&crate::testkit::lock(), &home, &badge(2)).unwrap();
    assert!(fetch.fetch(peer()).await.unwrap().is_none());
    assert_eq!(
        probe.state.dials.get(),
        2,
        "NONE survives badge replacement"
    );
    // The gate admits the stream; this deliberately unprovisioned home cannot run the exchange body.
    assert!(dial.exchange(peer()).await.is_err());
    assert_eq!(
        probe.state.dials.get(),
        3,
        "renewal changes the credentialed key"
    );
    let requests = probe.gate.requests();
    assert_eq!(requests.len(), 5, "one handshake per exchange or fetch");
    assert_eq!(requests[0].service, SYNC_SERVICE);
    assert_eq!(requests[0].capability.as_deref(), Some(first.as_str()));
    for request in &requests[2..4] {
        assert_eq!(request.service, RENEWAL_SERVICE);
        assert!(request.capability.is_none() && request.membership.is_none());
    }
    std::fs::remove_dir_all(home.dir()).unwrap();
}

#[tokio::test]
async fn credentialed_key_and_slots_use_one_badge_snapshot() {
    let probe = Probe::new([Script::Lists(vec![])]);
    let gate = Rc::new(Semaphore::new(0));
    *probe.state.dial_gate.borrow_mut() = Some(Rc::clone(&gate));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let home = scratch("snapshot");
    let first = badge(1);
    crate::config::write_badge(&crate::testkit::lock(), &home, &first).unwrap();
    let dial = NodeDial::new(&peers, &home);
    let exchange = dial.exchange(peer());
    tokio::pin!(exchange);
    // Async file reads may yield before the dial barrier. Poll until the transport records the dial,
    // rather than assuming that one poll selected the key.
    while probe.state.dials.get() == 0 {
        assert!(poll!(&mut exchange).is_pending());
        tokio::task::yield_now().await;
    }
    let keys: Vec<_> = peers.entries.borrow().keys().cloned().collect();
    assert_eq!(keys.len(), 1);
    assert!(keys[0].carry == main_carry(Some(first.as_str().to_owned())));
    crate::config::write_badge(&crate::testkit::lock(), &home, &badge(2)).unwrap();
    gate.add_permits(1);
    assert!(
        exchange.await.is_err(),
        "only the unprovisioned exchange body fails"
    );
    assert_eq!(
        probe.gate.requests()[0].capability.as_deref(),
        Some(first.as_str())
    );
    std::fs::remove_dir_all(home.dir()).unwrap();
}

#[tokio::test]
async fn none_fetch_performs_zero_badge_reads() {
    let probe = Probe::new((0..4).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let home = scratch("unreadable-badge");
    let expired = TestRoot::seeded(1)
        .device_badge(peer(), SystemTime::UNIX_EPOCH)
        .unwrap();
    crate::config::write_badge(&crate::testkit::lock(), &home, &expired).unwrap();
    let fetch = NodeFetch::new(&peers);
    assert!(fetch.fetch(peer()).await.unwrap().is_none());
    std::fs::write(home.key_cert(), b"malformed").unwrap();
    assert!(fetch.fetch(peer()).await.unwrap().is_none());
    std::fs::remove_file(home.key_cert()).unwrap();
    std::fs::create_dir(home.key_cert()).unwrap();
    assert!(NodeDial::new(&peers, &home).exchange(peer()).await.is_err());
    assert!(fetch.fetch(peer()).await.unwrap().is_none());
    std::fs::remove_dir(home.key_cert()).unwrap();
    // A read-only FIFO descriptor records whether any reader opened the badge, without ever allowing
    // a blocking read to consume the test runtime. No writer is opened unless a reader was observed.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let path = std::ffi::CString::new(home.key_cert().as_os_str().as_bytes()).unwrap();
        // SAFETY: the NUL-terminated path lives across this call; no pointer is retained.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(
            tokio::time::timeout(OPEN_TIMEOUT, fetch.fetch(peer()))
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
        // No reader was retained by a hidden cache-key lookup.
        let error = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(home.key_cert())
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENXIO));
    }
    assert_eq!(probe.state.dials.get(), 1);
    assert_eq!(probe.gate.requests().len(), 3 + usize::from(cfg!(unix)));
    assert!(
        probe
            .gate
            .requests()
            .iter()
            .all(|r| r.capability.is_none() && r.membership.is_none())
    );
    std::fs::remove_dir_all(home.dir()).unwrap();
}

#[tokio::test]
async fn concurrent_opens_share_the_flight_and_cancelled_waiters_release_their_counts() {
    let probe = Probe::new((0..3).map(|_| Script::Lists(vec![])));
    let gate = Rc::new(Semaphore::new(0));
    *probe.state.dial_gate.borrow_mut() = Some(Rc::clone(&gate));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let mut leader = Box::pin(peers.open(peer(), Hints::NONE, service(), Main, Standing(None)));
    let mut waiter = Box::pin(peers.open(peer(), Hints::NONE, service(), Main, Standing(None)));
    let mut cancelled = Box::pin(peers.open(peer(), Hints::NONE, service(), Main, Standing(None)));
    assert!(poll!(&mut leader).is_pending());
    assert!(poll!(&mut waiter).is_pending());
    assert!(poll!(&mut cancelled).is_pending());
    assert_eq!(probe.state.dials.get(), 1);
    drop(cancelled);
    drop(leader);
    assert_eq!(
        probe.state.pending.get(),
        1,
        "the waiter still owns the flight"
    );
    gate.add_permits(1);
    drop(waiter.await.unwrap());
    assert_eq!(probe.state.pending.get(), 0);
    assert_eq!(
        peers.counts.borrow()[&(peer(), Class::Main)].strong_count(),
        0
    );
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    assert_eq!(probe.state.dials.get(), 1);
    // With no waiter left, even an uncompleted dial is dropped, not kept dormant in the cache.
    let other = TestNode::seeded(9).node_id();
    let mut abandoned = Box::pin(peers.open(other, Hints::NONE, service(), Main, Standing(None)));
    assert!(poll!(&mut abandoned).is_pending());
    drop(abandoned);
    assert_eq!(probe.state.pending.get(), 0);
    assert!(!peers.entries.borrow().keys().any(|key| key.peer == other));
}

#[tokio::test]
async fn credentialed_flights_and_retries_preserve_other_cohorts() {
    let probe = Probe::new((0..4).map(|_| Script::Lists(vec![])));
    let gate = Rc::new(Semaphore::new(0));
    *probe.state.dial_gate.borrow_mut() = Some(Rc::clone(&gate));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let a = badge(1);
    let b = badge(2);
    let a_key = Key {
        peer: peer(),
        carry: main_carry(Some(a.as_str().to_owned())),
    };
    let b_key = Key {
        peer: peer(),
        carry: main_carry(Some(b.as_str().to_owned())),
    };
    let none_key = Key {
        peer: peer(),
        carry: main_carry(None),
    };
    let mut leader = Box::pin(peers.open(
        peer(),
        Hints::NONE,
        service(),
        Main,
        Standing(Some(a.clone())),
    ));
    let mut other = Box::pin(peers.open(peer(), Hints::NONE, service(), Main, Standing(Some(b))));
    let mut waiter = Box::pin(peers.open(
        peer(),
        Hints::NONE,
        service(),
        Main,
        Standing(Some(a.clone())),
    ));
    assert!(poll!(&mut leader).is_pending());
    assert!(poll!(&mut other).is_pending());
    assert!(poll!(&mut waiter).is_pending());
    assert_eq!(probe.state.dials.get(), 2);
    assert_eq!(probe.state.pending.get(), 2);
    assert_eq!(peers.entries.borrow().len(), 2);
    drop(leader);
    assert_eq!(probe.state.pending.get(), 2);
    assert!(matches!(
        peers.entries.borrow().get(&a_key),
        Some(super::Slot::Dialing(_))
    ));
    assert!(matches!(
        peers.entries.borrow().get(&b_key),
        Some(super::Slot::Dialing(_))
    ));
    gate.add_permits(2);
    let (a_stream, b_stream) = tokio::join!(waiter, other);
    let (_a_stream, _b_stream) = (a_stream.unwrap(), b_stream.unwrap());
    assert_eq!(probe.state.dials.get(), 2);
    *probe.state.dial_gate.borrow_mut() = None;
    let _none_stream = peers
        .open(peer(), Hints::NONE, service(), Main, Standing(None))
        .await
        .unwrap();
    let (b_entry, reused) = peers.session(&b_key, &Hints::NONE).await.unwrap();
    assert!(reused);
    let (none_entry, reused) = peers.session(&none_key, &Hints::NONE).await.unwrap();
    assert!(reused);

    // Retrying the older snapshot must replace only its own entry, even while its dial is pending.
    let retry_gate = Rc::new(Semaphore::new(0));
    *probe.state.dial_gate.borrow_mut() = Some(Rc::clone(&retry_gate));
    probe.state.fail_opens.set(1);
    let mut retry = Box::pin(peers.open(peer(), Hints::NONE, service(), Main, Standing(Some(a))));
    assert!(poll!(&mut retry).is_pending());
    assert_eq!(probe.state.dials.get(), 4);
    assert_eq!(probe.state.pending.get(), 1);
    assert_eq!(peers.entries.borrow().len(), 3);
    assert!(matches!(
        peers.entries.borrow().get(&b_key),
        Some(super::Slot::Ready(entry)) if Rc::ptr_eq(entry, &b_entry)
    ));
    assert!(matches!(
        peers.entries.borrow().get(&none_key),
        Some(super::Slot::Ready(entry)) if Rc::ptr_eq(entry, &none_entry)
    ));
    retry_gate.add_permits(1);
    drop(retry.await.unwrap());
    let (current, reused) = peers.session(&b_key, &Hints::NONE).await.unwrap();
    assert!(reused && Rc::ptr_eq(&current, &b_entry));
    let (current, reused) = peers.session(&none_key, &Hints::NONE).await.unwrap();
    assert!(reused && Rc::ptr_eq(&current, &none_entry));
    assert_eq!(probe.state.dials.get(), 4);
    assert_eq!(probe.gate.requests().len(), 4);
}

#[tokio::test]
async fn a_failed_flight_reaches_all_waiters_and_is_not_cached() {
    let probe = Probe::new([Script::Lists(vec![])]);
    let gate = Rc::new(Semaphore::new(0));
    *probe.state.dial_gate.borrow_mut() = Some(Rc::clone(&gate));
    probe.state.fail_dials.set(1);
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let mut asks: Vec<_> = (0..8)
        .map(|_| Box::pin(peers.open(peer(), Hints::NONE, service(), Main, Standing(None))))
        .collect();
    for ask in &mut asks {
        assert!(poll!(ask).is_pending());
    }
    assert_eq!(probe.state.dials.get(), 1);
    gate.add_permits(1);
    let first = asks.pop().unwrap();
    assert!(matches!(first.await, Err(OpenError::Unreachable(_))));
    assert_eq!(asks.len(), 7);
    assert!(peers.entries.borrow().is_empty());
    for ask in asks {
        assert!(matches!(ask.await, Err(OpenError::Unreachable(_))));
    }
    assert!(peers.entries.borrow().is_empty());
    *probe.state.dial_gate.borrow_mut() = None;
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    assert_eq!(probe.state.dials.get(), 2);
}

#[tokio::test]
async fn a_reused_broken_entry_redials_once_but_not_after_a_fresh_failure() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    probe.state.fail_opens.set(1);
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    assert_eq!(probe.state.dials.get(), 2);
    probe.state.fail_opens.set(2);
    assert!(matches!(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await,
        Err(OpenError::Open(bifrost::Error::Closed))
    ));
    assert_eq!(
        probe.state.dials.get(),
        3,
        "a second failure does not start a third attempt"
    );
    let fresh = Probe::new([]);
    fresh.state.fail_opens.set(1);
    let node = Node::new(fresh.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    assert!(matches!(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await,
        Err(OpenError::Open(bifrost::Error::Closed))
    ));
    assert_eq!(fresh.state.dials.get(), 1);
}

#[tokio::test]
async fn refusal_and_wrong_peer_never_retry_or_cache_admission() {
    let refusal = bifrost::Refusal::Unavailable {
        detail: bifrost::RefusalDetail::bounded("off"),
    };
    let probe = Probe::new([Script::Lists(vec![]), Script::Refuse(refusal.clone())]);
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    assert!(
        matches!(peers.open(peer(), Hints::NONE, service(), Main, Standing(None)).await, Err(OpenError::Open(bifrost::Error::Refused(r))) if r == refusal)
    );
    assert_eq!(
        probe.gate.requests().len(),
        2,
        "the second stream checks admission"
    );
    probe.state.wrong_peer.set(true);
    assert!(
        matches!(peers.open(peer(), Hints::NONE, service(), Main, Standing(None)).await,
        Err(OpenError::Open(bifrost::Error::Stream(cause))) if cause.is::<tightbeam::tunnel::WrongPeer>())
    );
    assert_eq!(
        probe.gate.requests().len(),
        2,
        "no credentials reach a wrong peer"
    );
    assert_eq!(probe.state.dials.get(), 1);
}

#[tokio::test]
async fn eviction_checks_entry_identity_and_keeps_the_old_live_stream() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let stream = peers
        .open(peer(), Hints::NONE, service(), Main, Standing(None))
        .await
        .unwrap();
    let key = Key {
        peer: peer(),
        carry: main_carry(None),
    };
    let (old, _) = peers.session(&key, &Hints::NONE).await.unwrap();
    peers.evict(&key, &old);
    let (replacement, _) = peers.session(&key, &Hints::NONE).await.unwrap();
    peers.evict(&key, &old);
    let (current, reused) = peers.session(&key, &Hints::NONE).await.unwrap();
    assert!(reused && Rc::ptr_eq(&replacement, &current));
    assert!(!probe.state.closed.borrow().contains(&old.session.id));
    drop(stream);
    let id = old.session.id;
    drop(old);
    assert!(probe.state.closed.borrow().contains(&id));
}

#[tokio::test(start_paused = true)]
async fn deadlines_evict_stalls_and_cancellation_releases_open_occupancy() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    *probe.state.dial_gate.borrow_mut() = Some(Rc::new(Semaphore::new(0)));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let started = tokio::time::Instant::now();
    assert!(matches!(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await,
        Err(OpenError::Unreachable(DialFailure::TimedOut))
    ));
    assert_eq!(started.elapsed(), DIAL_TIMEOUT);
    // Worded as every verb's own dial words a timeout, so a reach through the owner prints the same line.
    assert_eq!(
        DialFailure::TimedOut.to_string(),
        "timed out after 10s with no response"
    );
    assert!(peers.entries.borrow().is_empty());
    *probe.state.dial_gate.borrow_mut() = None;
    probe.state.stall_open.set(true);
    let started = tokio::time::Instant::now();
    assert!(matches!(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await,
        Err(OpenError::Timeout)
    ));
    assert_eq!(started.elapsed(), MAIN_OPEN_TIMEOUT);
    assert!(peers.entries.borrow().is_empty());
    let mut opening = Box::pin(peers.open(peer(), Hints::NONE, service(), Main, Standing(None)));
    assert!(poll!(&mut opening).is_pending());
    drop(opening);
    assert_eq!(
        peers.counts.borrow()[&(peer(), Class::Main)].strong_count(),
        0
    );
    probe.state.stall_open.set(false);
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
}

#[tokio::test(start_paused = true)]
async fn timeout_without_progress_evicts() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    // A success before this open began is no progress during its wait.
    tokio::time::advance(Duration::from_secs(1)).await;
    probe.state.hold_next.set(1);
    let started = tokio::time::Instant::now();
    assert!(matches!(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await,
        Err(OpenError::Timeout)
    ));
    assert_eq!(started.elapsed(), MAIN_OPEN_TIMEOUT);
    assert!(peers.entries.borrow().is_empty());
    assert_eq!(*probe.state.closed.borrow(), vec![1]);
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    assert_eq!(
        probe.state.dials.get(),
        2,
        "the stalled session is not reused"
    );
}

#[tokio::test(start_paused = true)]
async fn main_stall_times_out_inside_each() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    probe.state.hold_next.set(1);
    let started = tokio::time::Instant::now();
    // The open's own deadline fires inside the caller's bound, so the stall is evicted, not abandoned.
    let asked = tokio::time::timeout(
        crate::sync::EACH,
        peers.open(peer(), Hints::NONE, service(), Main, Standing(None)),
    )
    .await;
    assert!(matches!(asked, Ok(Err(OpenError::Timeout))));
    assert_eq!(started.elapsed(), Duration::from_secs(4));
    assert!(peers.entries.borrow().is_empty());
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    assert_eq!(probe.state.dials.get(), 2);
}

#[tokio::test(start_paused = true)]
async fn cancel_at_any_instant_evicts_nothing() {
    let probe = Probe::new([Script::Lists(vec![])]);
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let key = Key {
        peer: peer(),
        carry: Carry::Home {
            lane: Bulk,
            standing: None,
        },
    };
    // The held open dials the session, so no other open ever ran on it.
    probe.state.hold_next.set(1);
    let mut cancelled = Box::pin(peers.open(peer(), Hints::NONE, service(), Bulk, Standing(None)));
    park(&mut cancelled, &probe, 1).await;
    let (entry, _) = peers.session(&key, &Hints::NONE).await.unwrap();
    let idle = entry.idle_since.get();
    // Past the Main deadline, short of Bulk's: only the drop can end this open.
    tokio::time::advance(Duration::from_secs(6)).await;
    drop(cancelled);
    assert!(
        peers.entries.borrow().contains_key(&key),
        "the session is kept"
    );
    assert_eq!(entry.live.get(), 0);
    assert_eq!(entry.idle_since.get(), idle);
    drop(entry);
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Bulk, Standing(None))
            .await
            .unwrap(),
    );
    assert_eq!(probe.state.dials.get(), 1);
}

#[tokio::test(start_paused = true)]
async fn timeout_with_progress_keeps_session() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    probe.state.hold_next.set(1);
    let started = tokio::time::Instant::now();
    let mut held = Box::pin(peers.open(peer(), Hints::NONE, service(), Main, Standing(None)));
    park(&mut held, &probe, 1).await;
    tokio::time::advance(Duration::from_secs(2)).await;
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    assert!(matches!(held.await, Err(OpenError::Timeout)));
    assert_eq!(started.elapsed(), MAIN_OPEN_TIMEOUT);
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    assert_eq!(
        probe.state.dials.get(),
        1,
        "a host that answered another open keeps its session"
    );
    assert!(probe.state.closed.borrow().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_refused_open_is_not_progress() {
    let refusal = bifrost::Refusal::Unavailable {
        detail: bifrost::RefusalDetail::bounded("off"),
    };
    let probe = Probe::new([Script::Refuse(refusal), Script::Lists(vec![])]);
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    probe.state.hold_next.set(1);
    let started = tokio::time::Instant::now();
    let mut held = Box::pin(peers.open(peer(), Hints::NONE, service(), Main, Standing(None)));
    park(&mut held, &probe, 1).await;
    tokio::time::advance(Duration::from_secs(2)).await;
    // The host answered, but with a refusal: no stream opened, so it shows nothing about the session.
    assert!(matches!(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await,
        Err(OpenError::Open(bifrost::Error::Refused(_)))
    ));
    assert!(matches!(held.await, Err(OpenError::Timeout)));
    assert_eq!(started.elapsed(), MAIN_OPEN_TIMEOUT);
    assert!(
        peers.entries.borrow().is_empty(),
        "the stalled session is evicted"
    );
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    assert_eq!(probe.state.dials.get(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_success_at_the_open_s_start_is_progress() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    // The paused clock stamps that success at exactly the next open's start, which the rule counts.
    probe.state.hold_next.set(1);
    assert!(matches!(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await,
        Err(OpenError::Timeout)
    ));
    assert_eq!(peers.entries.borrow().len(), 1, "the session is kept");
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    assert_eq!(probe.state.dials.get(), 1);
}

#[tokio::test(start_paused = true)]
async fn cancelled_open_keeps_session_and_idle_clock() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    let key = Key {
        peer: peer(),
        carry: main_carry(None),
    };
    let (entry, _) = peers.session(&key, &Hints::NONE).await.unwrap();
    let idle = entry.idle_since.get();
    tokio::time::advance(Duration::from_secs(60)).await;
    probe.state.hold_next.set(1);
    let mut cancelled = Box::pin(peers.open(peer(), Hints::NONE, service(), Main, Standing(None)));
    park(&mut cancelled, &probe, 1).await;
    drop(cancelled);
    assert_eq!(entry.live.get(), 0);
    assert_eq!(
        entry.idle_since.get(),
        idle,
        "an open that never completed did not use the session"
    );
    assert_eq!(
        peers.counts.borrow()[&(peer(), Class::Main)].strong_count(),
        0
    );
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    assert_eq!(probe.state.dials.get(), 1);
    assert!(probe.state.closed.borrow().is_empty());
}

#[tokio::test(start_paused = true)]
async fn slip_main_attaches_beside_stalled_bulk() {
    let probe = Probe::new([Script::Lists(vec![])]);
    // The first session dialed is the slip's Bulk session, and nothing opens on it.
    probe.state.stalled.borrow_mut().push(1);
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let link = badge(1);
    let slip = || Slip {
        slip: link.clone(),
        membership: None,
    };
    let mut pipe = Box::pin(peers.open(peer(), Hints::NONE, service(), Bulk, slip()));
    park(&mut pipe, &probe, 1).await;
    let started = tokio::time::Instant::now();
    let _call = peers
        .open(peer(), Hints::NONE, service(), Main, slip())
        .await
        .unwrap();
    assert_eq!(started.elapsed(), Duration::ZERO, "Main attaches at once");
    assert_eq!(probe.state.dials.get(), 2);
    assert_eq!(
        probe.state.parked.get(),
        1,
        "Main never waited on the Bulk session"
    );
}

#[tokio::test(start_paused = true)]
async fn dead_session_redials_before_open() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    probe.state.dead.borrow_mut().push(1);
    let started = tokio::time::Instant::now();
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(probe.state.dials.get(), 2);
    assert_eq!(
        probe.state.dead_opens.get(),
        0,
        "no stream is asked of a closed session"
    );
    // That dial was the open's one redial: a fresh failure after it is returned, not redialed.
    probe.state.dead.borrow_mut().push(2);
    probe.state.fail_opens.set(1);
    assert!(matches!(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await,
        Err(OpenError::Open(bifrost::Error::Closed))
    ));
    assert_eq!(probe.state.dials.get(), 3);
    assert_eq!(probe.state.dead_opens.get(), 0);
}

#[tokio::test(start_paused = true)]
async fn both_halves_own_one_budget_and_idle_eviction_waits_for_the_last_half() {
    let probe = Probe::new((0..usize::from(MAIN_STREAMS)).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let mut streams = Vec::new();
    for _ in 0..MAIN_STREAMS {
        streams.push(
            peers
                .open(peer(), Hints::NONE, service(), Main, Standing(None))
                .await
                .unwrap(),
        );
    }
    assert!(matches!(
        peers
            .open(
                peer(),
                Hints::NONE,
                service(),
                Main,
                Standing(Some(badge(1)))
            )
            .await,
        Err(OpenError::Busy)
    ));
    let (writer, reader) = streams.pop().unwrap();
    drop(writer);
    assert_eq!(
        peers.counts.borrow()[&(peer(), Class::Main)]
            .upgrade()
            .unwrap()
            .get(),
        MAIN_STREAMS
    );
    drop(reader);
    assert_eq!(
        peers.counts.borrow()[&(peer(), Class::Main)]
            .upgrade()
            .unwrap()
            .get(),
        MAIN_STREAMS - 1
    );
    let (writer, reader) = streams.pop().unwrap();
    drop(reader);
    assert_eq!(
        peers.counts.borrow()[&(peer(), Class::Main)]
            .upgrade()
            .unwrap()
            .get(),
        MAIN_STREAMS - 1
    );
    drop(writer);
    assert_eq!(
        peers.counts.borrow()[&(peer(), Class::Main)]
            .upgrade()
            .unwrap()
            .get(),
        MAIN_STREAMS - 2
    );
    tokio::time::advance(IDLE_EVICTION).await;
    peers.sweep_at(tokio::time::Instant::now());
    assert_eq!(
        peers.entries.borrow().len(),
        1,
        "live streams keep the entry"
    );
    drop(streams);
    tokio::time::advance(IDLE_EVICTION - core::time::Duration::from_secs(1)).await;
    peers.sweep_at(tokio::time::Instant::now());
    assert_eq!(peers.entries.borrow().len(), 1);
    tokio::time::advance(core::time::Duration::from_secs(1)).await;
    peers.sweep_at(tokio::time::Instant::now());
    assert!(peers.entries.borrow().is_empty());
    assert_eq!(*probe.state.closed.borrow(), vec![1]);
}

#[tokio::test]
async fn fan_out_rides_the_bulk_lane() {
    let probe = Probe::new((0..101).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let mut pipes = Vec::new();
    for _ in 0..100 {
        pipes.push(
            peers
                .open(peer(), Hints::NONE, service(), Bulk, Standing(None))
                .await
                .unwrap(),
        );
    }
    assert_eq!(probe.state.dials.get(), 1);
    let _call = peers
        .open(peer(), Hints::NONE, service(), Main, Standing(None))
        .await
        .unwrap();
    assert_eq!(
        probe.state.dials.get(),
        2,
        "Main never rides the Bulk session"
    );
    assert_eq!(peers.entries.borrow().len(), 2);
}

#[tokio::test]
async fn each_lane_caps_its_own_streams_per_peer() {
    let probe = Probe::new((0..usize::from(BULK_STREAMS) + 2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let mut pipes = Vec::new();
    for _ in 0..BULK_STREAMS {
        pipes.push(
            peers
                .open(peer(), Hints::NONE, service(), Bulk, Standing(None))
                .await
                .unwrap(),
        );
    }
    assert!(matches!(
        peers
            .open(
                peer(),
                Hints::NONE,
                service(),
                Bulk,
                Standing(Some(badge(1)))
            )
            .await,
        Err(OpenError::Busy)
    ));
    assert_eq!(
        probe.gate.requests().len(),
        usize::from(BULK_STREAMS),
        "a refused open sends nothing"
    );
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, Standing(None))
            .await
            .unwrap(),
    );
    pipes.pop();
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Bulk, Standing(None))
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn isolated_opens_a_connection_it_never_stores() {
    let probe = Probe::new([]);
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let first = peers.isolated(peer(), Hints::NONE).await.unwrap();
    let second = peers.isolated(peer(), Hints::NONE).await.unwrap();
    assert_eq!(probe.state.dials.get(), 2, "one connection per caller");
    assert!(peers.entries.borrow().is_empty());
    assert_eq!(first.peer(), peer());
    drop(first);
    assert_eq!(*probe.state.closed.borrow(), vec![1]);
    drop(second);
    assert_eq!(*probe.state.closed.borrow(), vec![1, 2]);
}

#[tokio::test]
async fn isolated_opens_cap_at_four_per_peer() {
    let probe = Probe::new([]);
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let mut live = Vec::new();
    for _ in 0..ISOLATED_CONNECTIONS {
        live.push(peers.isolated(peer(), Hints::NONE).await.unwrap());
    }
    assert!(matches!(
        peers.isolated(peer(), Hints::NONE).await,
        Err(OpenError::Busy)
    ));
    assert_eq!(
        probe.state.dials.get(),
        u32::from(ISOLATED_CONNECTIONS),
        "a fifth connection is never dialed"
    );
    live.pop();
    live.push(peers.isolated(peer(), Hints::NONE).await.unwrap());
}

#[tokio::test]
async fn a_cancelled_isolated_dial_frees_its_count() {
    let probe = Probe::new([]);
    let gate = Rc::new(Semaphore::new(0));
    *probe.state.dial_gate.borrow_mut() = Some(Rc::clone(&gate));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let mut dialing = Box::pin(peers.isolated(peer(), Hints::NONE));
    assert!(poll!(&mut dialing).is_pending());
    assert_eq!(
        peers.counts.borrow()[&(peer(), Class::Isolated)]
            .upgrade()
            .unwrap()
            .get(),
        1
    );
    drop(dialing);
    assert_eq!(probe.state.pending.get(), 0);
    assert_eq!(
        peers.counts.borrow()[&(peer(), Class::Isolated)].strong_count(),
        0
    );
    *probe.state.dial_gate.borrow_mut() = None;
    let mut live = Vec::new();
    for _ in 0..ISOLATED_CONNECTIONS {
        live.push(peers.isolated(peer(), Hints::NONE).await.unwrap());
    }
}

#[tokio::test(start_paused = true)]
async fn a_bulk_open_timeout_evicts_only_the_bulk_session() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let _call = peers
        .open(peer(), Hints::NONE, service(), Main, Standing(None))
        .await
        .unwrap();
    let main = Key {
        peer: peer(),
        carry: main_carry(None),
    };
    let (held, _) = peers.session(&main, &Hints::NONE).await.unwrap();
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Bulk, Standing(None))
            .await
            .unwrap(),
    );
    assert_eq!(peers.entries.borrow().len(), 2);
    // The paused clock would otherwise stamp the earlier success at this open's start, as progress.
    tokio::time::advance(Duration::from_secs(1)).await;
    probe.state.stall_open.set(true);
    let started = tokio::time::Instant::now();
    assert!(matches!(
        peers
            .open(peer(), Hints::NONE, service(), Bulk, Standing(None))
            .await,
        Err(OpenError::Timeout)
    ));
    // A literal, so a build that shortens the deadline Bulk uses fails here.
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    let keys: Vec<_> = peers.entries.borrow().keys().cloned().collect();
    assert!(keys == [main.clone()], "only the Bulk session is evicted");
    let (current, reused) = peers.session(&main, &Hints::NONE).await.unwrap();
    assert!(reused && Rc::ptr_eq(&current, &held));
    assert_eq!(*probe.state.closed.borrow(), vec![2]);
}

#[tokio::test(start_paused = true)]
async fn a_slip_open_timeout_evicts_only_the_slip_session() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let _call = peers
        .open(peer(), Hints::NONE, service(), Main, Standing(None))
        .await
        .unwrap();
    let main = Key {
        peer: peer(),
        carry: main_carry(None),
    };
    let (held, _) = peers.session(&main, &Hints::NONE).await.unwrap();
    // One link: a badge minted again carries a new expiry, so it would be another slip.
    let link = badge(1);
    let slip = || Slip {
        slip: link.clone(),
        membership: None,
    };
    drop(
        peers
            .open(peer(), Hints::NONE, service(), Main, slip())
            .await
            .unwrap(),
    );
    assert_eq!(peers.entries.borrow().len(), 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    probe.state.stall_open.set(true);
    let started = tokio::time::Instant::now();
    assert!(matches!(
        peers
            .open(peer(), Hints::NONE, service(), Main, slip())
            .await,
        Err(OpenError::Timeout)
    ));
    assert_eq!(started.elapsed(), MAIN_OPEN_TIMEOUT);
    let keys: Vec<_> = peers.entries.borrow().keys().cloned().collect();
    assert!(keys == [main.clone()], "only the slip session is evicted");
    let (current, reused) = peers.session(&main, &Hints::NONE).await.unwrap();
    assert!(reused && Rc::ptr_eq(&current, &held));
    assert_eq!(*probe.state.closed.borrow(), vec![2]);
}

#[tokio::test]
async fn a_link_forward_rides_one_slip_session_per_lane() {
    let probe = Probe::new((0..61).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let slip = badge(1);
    let presents = || Slip {
        slip: slip.clone(),
        membership: None,
    };
    let mut pipes = Vec::new();
    for _ in 0..60 {
        pipes.push(
            peers
                .open(peer(), Hints::NONE, service(), Bulk, presents())
                .await
                .unwrap(),
        );
    }
    let _call = peers
        .open(peer(), Hints::NONE, service(), Main, presents())
        .await
        .unwrap();
    assert_eq!(
        probe.state.dials.get(),
        2,
        "all 60 pipes ride one session, and Main rides another"
    );
    let digest = *blake3::hash(slip.as_str().as_bytes()).as_bytes();
    let entries = peers.entries.borrow();
    for lane in [Main, Bulk] {
        let key = Key {
            peer: peer(),
            carry: Carry::Slip {
                lane,
                digest,
                membership: None,
            },
        };
        assert!(entries.contains_key(&key));
    }
    assert_eq!(entries.len(), 2);
    drop(entries);
    assert!(
        probe
            .gate
            .requests()
            .iter()
            .all(|request| request.capability.as_deref() == Some(slip.as_str()))
    );
}

#[tokio::test]
async fn a_different_slip_never_shares() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let _a = peers
        .open(
            peer(),
            Hints::NONE,
            service(),
            Bulk,
            Slip {
                slip: badge(1),
                membership: None,
            },
        )
        .await
        .unwrap();
    let _b = peers
        .open(
            peer(),
            Hints::NONE,
            service(),
            Bulk,
            Slip {
                slip: badge(2),
                membership: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(probe.state.dials.get(), 2);
}

#[tokio::test]
async fn a_slip_open_never_rides_the_held_session() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let home = Key {
        peer: peer(),
        carry: main_carry(None),
    };
    let _own = peers
        .open(peer(), Hints::NONE, service(), Main, Standing(None))
        .await
        .unwrap();
    let (held, _) = peers.session(&home, &Hints::NONE).await.unwrap();
    let _slip = peers
        .open(
            peer(),
            Hints::NONE,
            service(),
            Main,
            Slip {
                slip: badge(1),
                membership: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(probe.state.dials.get(), 2);
    let (current, reused) = peers.session(&home, &Hints::NONE).await.unwrap();
    assert!(reused && Rc::ptr_eq(&current, &held));
    assert_eq!(held.live.get(), 1, "the slip's stream is not on it");
}

#[tokio::test]
async fn slips_share_the_peer_bulk_cap() {
    let probe = Probe::new((0..usize::from(BULK_STREAMS)).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let mut pipes = Vec::new();
    for generation in [1, 2] {
        for _ in 0..BULK_STREAMS / 2 {
            pipes.push(
                peers
                    .open(
                        peer(),
                        Hints::NONE,
                        service(),
                        Bulk,
                        Slip {
                            slip: badge(generation),
                            membership: None,
                        },
                    )
                    .await
                    .unwrap(),
            );
        }
    }
    assert!(matches!(
        peers
            .open(
                peer(),
                Hints::NONE,
                service(),
                Bulk,
                Slip {
                    slip: badge(3),
                    membership: None
                }
            )
            .await,
        Err(OpenError::Busy)
    ));
}

#[tokio::test]
async fn structured_borrowers_and_owner_drop_before_node_close() {
    let probe = Probe::new([Script::Lists(vec![])]);
    let node = Node::new(probe.clone(), NoDiscovery);
    {
        let peers = Peers::new(&node);
        let work = async {
            let _stream = peers
                .open(peer(), Hints::NONE, service(), Main, Standing(None))
                .await
                .unwrap();
            pending::<()>().await;
        };
        let mut work = Box::pin(work);
        while probe.gate.requests().is_empty() {
            assert!(poll!(&mut work).is_pending());
            tokio::task::yield_now().await;
        }
        assert!(probe.state.closed.borrow().is_empty());
        drop(work);
        assert_eq!(
            peers.counts.borrow()[&(peer(), Class::Main)].strong_count(),
            0
        );
    }
    assert_eq!(*probe.state.closed.borrow(), vec![1]);
    node.close().await;
    assert!(probe.state.node_closed.get());
}

#[tokio::test]
async fn badge_expiry_does_not_cut_a_live_none_fetch() {
    live_none_survives(StandingEnd::Expiry).await;
}

#[tokio::test]
async fn badge_revocation_does_not_cut_a_live_none_fetch() {
    live_none_survives(StandingEnd::Revocation).await;
}

enum StandingEnd {
    Expiry,
    Revocation,
}

async fn live_none_survives(end: StandingEnd) {
    use std::sync::Arc;

    use bifrost_mem::MemTransport;
    use nauthy::{Denylist, Gate, Revocation};
    use tightbeam::tunnel::{CancellationToken, Router};

    let home = scratch(match end {
        StandingEnd::Expiry => "live-expiry",
        StandingEnd::Revocation => "live-revocation",
    });
    let store = Arc::new(Denylist::load(home.dir().join("denylist")).unwrap());
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let node = Node::new(MemTransport::bind(), NoDiscovery);
    let root = TestRoot::seeded(1);
    let lifetime = match end {
        StandingEnd::Expiry => core::time::Duration::from_secs(2),
        StandingEnd::Revocation => core::time::Duration::from_secs(3600),
    };
    let credential = root
        .device_badge(node.node_id(), SystemTime::now() + lifetime)
        .unwrap();
    let payload = root
        .device_badge(
            node.node_id(),
            SystemTime::now() + core::time::Duration::from_secs(86400),
        )
        .unwrap();
    let started = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let exposer = Router::new(Gate::rooted(root.verify_key(), Arc::clone(&store)))
        .echo(service())
        .unwrap()
        .proven_service(
            RENEWAL_SERVICE.parse().unwrap(),
            HeldRenewal {
                payload: payload.clone(),
                started: Arc::clone(&started),
                release: Arc::clone(&release),
            },
            |_| true,
        )
        .unwrap()
        .expose()
        .unwrap()
        .with_live_cuts(Arc::clone(&store));
    let cancel = CancellationToken::new();
    let exercise = async {
        let peers = Peers::new(&node);
        let fetch = NodeFetch::new(&peers);
        let (mut write, mut read) = peers
            .open(
                host.node_id(),
                Hints::NONE,
                service(),
                Main,
                Standing(Some(credential.clone())),
            )
            .await
            .unwrap();
        write.write_all(b"a").await.unwrap();
        assert_eq!(read.read_u8().await.unwrap(), b'a');
        let mut pickup = Box::pin(fetch.fetch(host.node_id()));
        tokio::select! {
            result = &mut pickup => panic!("the payload must wait for release: {result:?}"),
            permit = started.acquire() => permit.unwrap().forget(),
        }
        if let StandingEnd::Revocation = end {
            let id = credential.cap().revocation_ids().pop().unwrap();
            let locked = store.lock().unwrap();
            store.revoke(&locked, [Revocation::Id(id)]).unwrap();
        }
        // The dependency's grant lease uses SystemTime, not tokio's paused clock. Await its actual cut
        // event under a deadline; no sleep or guessed delay stands in for observing that cut.
        let mut byte = [0];
        assert!(
            matches!(
                tokio::time::timeout(core::time::Duration::from_secs(5), read.read(&mut byte))
                    .await,
                Ok(Ok(0) | Err(_))
            ),
            "the credentialed session must actually be cut"
        );
        release.add_permits(1);
        assert_eq!(
            pickup.await.unwrap().as_ref().map(Link::as_str),
            Some(payload.as_str()),
            "the NONE payload remains live after the badge's lease ends"
        );
        assert!(
            matches!(
                peers
                    .open(
                        host.node_id(),
                        Hints::NONE,
                        service(),
                        Main,
                        Standing(Some(credential))
                    )
                    .await,
                Err(OpenError::Open(bifrost::Error::Refused(
                    bifrost::Refusal::NotAdmitted
                )))
            ),
            "the next credentialed stream still checks admission"
        );
        cancel.cancel();
    };
    let ((), ()) = tokio::join!(exposer.run(&host, cancel.clone()), exercise);
    node.close().await;
    host.close().await;
    std::fs::remove_dir_all(home.dir()).unwrap();
}

/// A full fan-out rides one held session: the transport carries every pipe the Bulk lane admits, so no
/// open waits on stream credit, times out or dials a second session. Real iroh, since the mock has no
/// stream limit.
#[tokio::test]
async fn home_bulk_128_ride_one_session() {
    let (host, node, badge, store, home) = loopback_pair("bulk-128").await;
    let exposer = tightbeam::tunnel::Router::new(nauthy::Gate::rooted(
        TestRoot::seeded(1).verify_key(),
        store,
    ))
    .echo(service())
    .unwrap()
    .expose()
    .unwrap();
    let cancel = tightbeam::tunnel::CancellationToken::new();
    let exercise = async {
        let peers = Peers::new(&node);
        let open = || {
            peers.open(
                host.node_id(),
                Hints::NONE,
                service(),
                Bulk,
                Standing(Some(badge.clone())),
            )
        };
        let key = Key {
            peer: host.node_id(),
            carry: Carry::Home {
                lane: Bulk,
                standing: Some(badge.as_str().to_owned()),
            },
        };
        let mut pipes = Vec::new();
        pipes.push(open().await.unwrap());
        let (held, _) = peers.session(&key, &Hints::NONE).await.unwrap();
        for _ in 1..BULK_STREAMS {
            pipes.push(open().await.unwrap());
        }
        assert_eq!(
            held.live.get(),
            BULK_STREAMS,
            "every pipe rides one session"
        );
        let (current, reused) = peers.session(&key, &Hints::NONE).await.unwrap();
        assert!(reused && Rc::ptr_eq(&current, &held), "no second dial");
        assert_eq!(peers.entries.borrow().len(), 1);
        assert!(matches!(open().await, Err(OpenError::Busy)));
        drop((held, current, pipes));
        cancel.cancel();
    };
    // A transport that stalls an open fails this test rather than hanging the suite.
    let ((), ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(exposer.run(&host, cancel.clone()), exercise)
    })
    .await
    .expect("128 pipes attach well inside 30 s");
    node.close().await;
    host.close().await;
    std::fs::remove_dir_all(home.dir()).unwrap();
}

/// A window stall needs a real QUIC connection, so this test runs iroh on loopback with the real clock
/// and waits out one open deadline. The host writes a stream window into each of 14 Bulk streams the
/// client never reads, which spends the connection's receive window: no new open can be answered.
#[tokio::test]
async fn window_stall_recovers_new_opens() {
    const UNREAD: u16 = 14;
    let (host, node, badge, store, home) = loopback_pair("window-stall").await;
    let flood = Flood::default();
    let exposer = tightbeam::tunnel::Router::new(nauthy::Gate::rooted(
        TestRoot::seeded(1).verify_key(),
        store,
    ))
    .service(service(), flood.clone())
    .unwrap()
    .expose()
    .unwrap();
    let cancel = tightbeam::tunnel::CancellationToken::new();
    let exercise = async {
        let peers = Peers::new(&node);
        let open = || {
            peers.open(
                host.node_id(),
                Hints::NONE,
                service(),
                Bulk,
                Standing(Some(badge.clone())),
            )
        };
        let mut unread = Vec::new();
        for _ in 0..UNREAD {
            unread.push(open().await.unwrap());
        }
        flood
            .settle(UNREAD, CONNECTION_WINDOW - STREAM_WINDOW as u64)
            .await;
        let key = Key {
            peer: host.node_id(),
            carry: Carry::Home {
                lane: Bulk,
                standing: Some(badge.as_str().to_owned()),
            },
        };
        let (stalled, reused) = peers.session(&key, &Hints::NONE).await.unwrap();
        assert!(reused);
        let started = std::time::Instant::now();
        assert!(matches!(open().await, Err(OpenError::Timeout)));
        assert!(started.elapsed() >= OPEN_TIMEOUT);
        assert!(
            !peers.entries.borrow().contains_key(&key),
            "the stalled session is evicted"
        );
        let _fresh = open().await.unwrap();
        let (current, reused) = peers.session(&key, &Hints::NONE).await.unwrap();
        assert!(
            reused && !Rc::ptr_eq(&current, &stalled),
            "the next open rides a fresh session"
        );
        assert_eq!(
            stalled.live.get(),
            UNREAD,
            "the unread streams stay on the old session"
        );
        flood.stop.cancel();
        cancel.cancel();
    };
    let ((), ()) = tokio::join!(exposer.run(&host, cancel.clone()), exercise);
    node.close().await;
    host.close().await;
    std::fs::remove_dir_all(home.dir()).unwrap();
}

#[test]
fn seventeen_hints_do_not_type() {
    assert_eq!(Hints::new([]), Ok(Hints::NONE));
    assert_eq!(Hints::new([A]).unwrap().as_slice(), [A]);
    let sixteen = Hints::new([A; Hints::MAX]).unwrap();
    assert_eq!(sixteen.as_slice(), [A; 16]);
    assert_eq!(Hints::new([A; Hints::MAX + 1]), Err(TooManyHints));
}

#[test]
fn a_mapped_hint_is_held_as_ipv4_in_order_with_repeats() {
    let mapped: SocketAddr = "[::ffff:192.0.2.1]:1".parse().unwrap();
    let scoped: SocketAddr = "[fe80::1%3]:1".parse().unwrap();
    let hints = Hints::new([mapped, scoped, A, mapped]).unwrap();
    assert_eq!(hints.as_slice(), [A, scoped, A, A]);
    // A hint prints only as a count.
    assert_eq!(format!("{hints:?}"), "Hints(4)");
}

#[tokio::test]
async fn per_open_hints_lead_the_runs_addresses() {
    let probe = Probe::new([Script::Lists(vec![])]);
    let node = Node::new(probe.clone(), runs_addresses());
    let peers = Peers::new(&node);
    drop(
        peers
            .open(
                peer(),
                Hints::new([A]).unwrap(),
                service(),
                Main,
                Standing(None),
            )
            .await
            .unwrap(),
    );
    assert_eq!(*probe.state.seen.borrow(), [vec![A, S]]);
}

#[tokio::test]
async fn a_hint_reaches_its_own_isolated_dial() {
    let probe = Probe::new([]);
    let node = Node::new(probe.clone(), runs_addresses());
    let peers = Peers::new(&node);
    let first = peers
        .isolated(peer(), Hints::new([A]).unwrap())
        .await
        .unwrap();
    let second = peers.isolated(peer(), Hints::NONE).await.unwrap();
    assert_eq!(*probe.state.seen.borrow(), [vec![A, S], vec![S]]);
    drop((first, second));
}

#[tokio::test]
async fn another_dials_hint_never_reaches_a_hintless_dial() {
    let (probe, gate, node) = gated(2);
    let peers = Peers::new(&node);
    let mut pipe = Box::pin(peers.open(
        peer(),
        Hints::new([A]).unwrap(),
        service(),
        Bulk,
        Standing(None),
    ));
    let mut call = Box::pin(peers.open(peer(), Hints::NONE, service(), Main, Standing(None)));
    dialing(&mut pipe, &probe, 1).await;
    dialing(&mut call, &probe, 2).await;
    gate.add_permits(2);
    let (pipe, call) = futures::join!(pipe, call);
    drop((pipe.unwrap(), call.unwrap()));
    assert_eq!(*probe.state.seen.borrow(), [vec![A], vec![]]);
}

#[tokio::test]
async fn a_joiner_adds_no_hints_and_causes_no_second_dial() {
    let (probe, gate, node) = gated(2);
    let peers = Peers::new(&node);
    let mut starter = Box::pin(peers.open(
        peer(),
        Hints::new([A]).unwrap(),
        service(),
        Main,
        Standing(None),
    ));
    let mut joiner = Box::pin(peers.open(
        peer(),
        Hints::new([B]).unwrap(),
        service(),
        Main,
        Standing(None),
    ));
    dialing(&mut starter, &probe, 1).await;
    assert!(poll!(&mut joiner).is_pending());
    gate.add_permits(1);
    let (started, joined) = futures::join!(starter, joiner);
    drop((started.unwrap(), joined.unwrap()));
    assert_eq!(*probe.state.seen.borrow(), [vec![A]]);
}

#[tokio::test]
async fn a_reuse_ignores_hints_and_a_redial_carries_the_redialing_callers() {
    let (probe, gate, node) = gated(3);
    let peers = Peers::new(&node);
    gate.add_permits(1);
    drop(
        peers
            .open(
                peer(),
                Hints::new([A]).unwrap(),
                service(),
                Main,
                Standing(None),
            )
            .await
            .unwrap(),
    );
    drop(
        peers
            .open(
                peer(),
                Hints::new([B]).unwrap(),
                service(),
                Main,
                Standing(None),
            )
            .await
            .unwrap(),
    );
    assert_eq!(
        *probe.state.seen.borrow(),
        [vec![A]],
        "a held session dials nothing"
    );
    probe.state.fail_opens.set(1);
    let mut redial = Box::pin(peers.open(
        peer(),
        Hints::new([B]).unwrap(),
        service(),
        Main,
        Standing(None),
    ));
    dialing(&mut redial, &probe, 2).await;
    gate.add_permits(1);
    drop(redial.await.unwrap());
    assert_eq!(*probe.state.seen.borrow(), [vec![A], vec![B]]);
}

/// A probe whose dials wait on the returned gate, under a node with no discovery of its own.
fn gated(opens: usize) -> (Probe, Rc<Semaphore>, Node<Probe, NoDiscovery>) {
    let probe = Probe::new((0..opens).map(|_| Script::Lists(vec![])));
    let gate = Rc::new(Semaphore::new(0));
    *probe.state.dial_gate.borrow_mut() = Some(Rc::clone(&gate));
    let node = Node::new(probe.clone(), NoDiscovery);
    (probe, gate, node)
}

/// The run's discovery as `serve` composes it, with the run's own address [`S`] for `peer()` and mDNS
/// off.
fn runs_addresses() -> crate::transport::Discovery {
    let mut given = StaticDiscovery::new();
    given.insert(peer(), vec![S]);
    Layered::new(given, MdnsDiscovery::disabled())
}

/// Poll `open` until the transport has taken `dials` dials, so the newest one has read its addresses.
async fn dialing<F: Future + Unpin>(open: &mut F, probe: &Probe, dials: u32) {
    while probe.state.dials.get() < dials {
        assert!(poll!(&mut *open).is_pending());
        tokio::task::yield_now().await;
    }
}

// Documentation addresses: two callers' hints and the run's own address for `peer()`.
const A: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 1));
const B: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 1));
const S: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 1));

/// Two iroh nodes on loopback, the client told the host's addresses, and a badge the host's gate admits.
async fn loopback_pair(
    tag: &str,
) -> (
    Node<bifrost_iroh::Endpoint, NoDiscovery>,
    Node<bifrost_iroh::Endpoint, bifrost::StaticDiscovery>,
    Link,
    std::sync::Arc<nauthy::Denylist>,
    Home,
) {
    let home = scratch(tag);
    let store = std::sync::Arc::new(nauthy::Denylist::load(home.dir().join("denylist")).unwrap());
    let host = Node::new(
        bifrost_iroh::Endpoint::bind_local().await.unwrap(),
        NoDiscovery,
    );
    let mut hints = bifrost::StaticDiscovery::new();
    hints.insert(host.node_id(), host.local_addr().hints);
    let node = Node::new(bifrost_iroh::Endpoint::bind_local().await.unwrap(), hints);
    let badge = TestRoot::seeded(1)
        .device_badge(
            node.node_id(),
            SystemTime::now() + Duration::from_secs(3600),
        )
        .unwrap();
    (host, node, badge, store, home)
}

/// A handler that writes one stream window's worth of bytes the client never reads, then holds the
/// stream open until stopped.
#[derive(Clone, Default)]
struct Flood {
    written: std::sync::Arc<core::sync::atomic::AtomicU64>,
    started: std::sync::Arc<core::sync::atomic::AtomicU16>,
    progress: std::sync::Arc<tokio::sync::Notify>,
    stop: tightbeam::tunnel::CancellationToken,
}

// noq's per-stream receive window, the bytes one stream can hold unread.
const STREAM_WINDOW: usize = 1_250_000;
// bifrost-iroh's receive window per connection, which the unread streams spend.
const CONNECTION_WINDOW: u64 = 16 * 1024 * 1024;
// No byte moved for this long means every flood is written or blocked on flow control.
const QUIET: Duration = Duration::from_millis(500);

impl Flood {
    /// Wait until `streams` floods began, at least `floor` bytes were written, and no byte has moved
    /// for [`QUIET`]. The window fills from the host's side, so an open issued before this can be
    /// answered ahead of the stall; the floor keeps a slow machine's pause from passing for a full one.
    async fn settle(&self, streams: u16, floor: u64) {
        use core::sync::atomic::Ordering;
        tokio::time::timeout(Duration::from_secs(30), async {
            // Every wait parks on the next byte or the quiet period, never spinning: a flood stores
            // its notification when no one waits, so no progress is missed between checks.
            loop {
                let quiet = tokio::time::timeout(QUIET, self.progress.notified())
                    .await
                    .is_err();
                if quiet
                    && self.started.load(Ordering::SeqCst) >= streams
                    && self.written.load(Ordering::SeqCst) >= floor
                {
                    break;
                }
            }
        })
        .await
        .unwrap();
    }

    async fn flood(&self, writer: &mut tightbeam::tunnel::BoxWrite) -> std::io::Result<()> {
        use core::sync::atomic::Ordering;
        let chunk = [0u8; 16 * 1024];
        let mut left = STREAM_WINDOW;
        while left > 0 {
            let len = left.min(chunk.len());
            writer.write_all(&chunk[..len]).await?;
            left -= len;
            self.written.fetch_add(len as u64, Ordering::SeqCst);
            self.progress.notify_one();
        }
        writer.flush().await
    }
}

impl tightbeam::tunnel::Handler for Flood {
    type Exposure = tightbeam::open_policy::Never;

    async fn serve(
        &self,
        _served: tightbeam::tunnel::Served<Self>,
        mut writer: tightbeam::tunnel::BoxWrite,
        _reader: tightbeam::tunnel::BoxRead,
    ) -> Result<(), tightbeam::tunnel::ServeError> {
        self.started
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        self.progress.notify_one();
        tokio::select! {
            () = self.stop.cancelled() => {}
            flooded = self.flood(&mut writer) => {
                flooded?;
                self.stop.cancelled().await;
            }
        }
        Ok(())
    }
}

struct HeldRenewal {
    payload: Link,
    started: std::sync::Arc<Semaphore>,
    release: std::sync::Arc<Semaphore>,
}

impl tightbeam::tunnel::Handler for HeldRenewal {
    type Exposure = tightbeam::open_policy::ProvenOnly;

    async fn serve(
        &self,
        _served: tightbeam::tunnel::Served<Self>,
        mut writer: tightbeam::tunnel::BoxWrite,
        _reader: tightbeam::tunnel::BoxRead,
    ) -> Result<(), tightbeam::tunnel::ServeError> {
        let reply = crate::renewal::reply(Some(&self.payload));
        writer.write_all(&reply[..4]).await?;
        self.started.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        writer.write_all(&reply[4..]).await?;
        writer.shutdown().await?;
        Ok(())
    }
}

/// Poll `open` until `parked` opens wait on a held session. Async dials may yield first, so one poll
/// is not assumed to reach the transport.
async fn park<F: Future + Unpin>(open: &mut F, probe: &Probe, parked: u32) {
    while probe.state.parked.get() < parked {
        assert!(poll!(&mut *open).is_pending());
        tokio::task::yield_now().await;
    }
}

fn peer() -> NodeId {
    TestNode::seeded(0x63).node_id()
}
fn service() -> Service {
    SYNC_SERVICE.parse().unwrap()
}
fn badge(generation: u8) -> Link {
    TestRoot::seeded(1)
        .device_badge(
            peer(),
            SystemTime::now() + core::time::Duration::from_secs(86400 * u64::from(generation)),
        )
        .unwrap()
}
fn main_carry(standing: Option<String>) -> Carry {
    Carry::Home {
        lane: Main,
        standing,
    }
}
fn scratch(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-peers-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    crate::config::create_store_dir(&dir).unwrap();
    Home::resolve(Some(dir)).unwrap()
}

#[derive(Clone)]
struct Probe {
    gate: ScriptedPeer,
    state: Rc<State>,
}
#[derive(Default)]
struct State {
    dials: Cell<u32>,
    pending: Cell<u32>,
    fail_dials: Cell<u32>,
    fail_opens: Cell<u32>,
    stall_open: Cell<bool>,
    // Sessions whose every open waits forever, and a count of the next opens on any session that do.
    stalled: RefCell<Vec<u32>>,
    hold_next: Cell<u32>,
    parked: Cell<u32>,
    // Sessions the transport has closed: `wait_closed` is ready and an open fails.
    dead: RefCell<Vec<u32>>,
    dead_opens: Cell<u32>,
    wrong_peer: Cell<bool>,
    dial_gate: RefCell<Option<Rc<Semaphore>>>,
    closed: RefCell<Vec<u32>>,
    node_closed: Cell<bool>,
    // The addresses each dial was handed, in dial order.
    seen: RefCell<Vec<Vec<SocketAddr>>>,
}
impl Probe {
    fn new(script: impl IntoIterator<Item = Script>) -> Self {
        Self {
            gate: ScriptedPeer::new(peer(), script),
            state: Rc::default(),
        }
    }
}
struct ProbeSession {
    inner: ScriptedPeer,
    state: Rc<State>,
    id: u32,
}
struct Pending(Rc<State>);
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.pending.set(self.0.pending.get() - 1);
    }
}
impl Transport for Probe {
    type Session = ProbeSession;
    fn node_id(&self) -> NodeId {
        self.gate.node_id()
    }
    fn local_addr(&self) -> Addr {
        self.gate.local_addr()
    }
    fn bound_sockets(&self) -> Vec<core::net::SocketAddr> {
        vec![]
    }
    async fn connect(&self, addr: Addr) -> Result<Self::Session, bifrost::Error> {
        let id = self.state.dials.get() + 1;
        self.state.dials.set(id);
        self.state.seen.borrow_mut().push(addr.hints.clone());
        self.state.pending.set(self.state.pending.get() + 1);
        let _pending = Pending(Rc::clone(&self.state));
        let gate = self.state.dial_gate.borrow().clone();
        if let Some(gate) = gate {
            gate.acquire().await.unwrap().forget();
        }
        if self.state.fail_dials.get() > 0 {
            self.state.fail_dials.set(self.state.fail_dials.get() - 1);
            return Err(bifrost::Error::Connect("offline".into()));
        }
        Ok(ProbeSession {
            inner: self.gate.connect(addr).await?,
            state: Rc::clone(&self.state),
            id,
        })
    }
    async fn accept(&self) -> Result<Self::Session, bifrost::Error> {
        Err(bifrost::Error::Closed)
    }
    async fn close(&self) {
        assert_eq!(self.state.pending.get(), 0);
        self.state.node_closed.set(true);
    }
}
impl Session for ProbeSession {
    type Write = TestWrite<DuplexStream>;
    type Read = DuplexStream;
    fn peer(&self) -> NodeId {
        if self.state.wrong_peer.get() {
            TestNode::seeded(9).node_id()
        } else {
            self.inner.peer()
        }
    }
    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        if self.state.dead.borrow().contains(&self.id) {
            self.state.dead_opens.set(self.state.dead_opens.get() + 1);
            return Err(bifrost::Error::Closed);
        }
        let held = self.state.hold_next.get() > 0;
        if held {
            self.state.hold_next.set(self.state.hold_next.get() - 1);
        }
        if held || self.state.stall_open.get() || self.state.stalled.borrow().contains(&self.id) {
            self.state.parked.set(self.state.parked.get() + 1);
            pending::<()>().await;
        }
        if self.state.fail_opens.get() > 0 {
            self.state.fail_opens.set(self.state.fail_opens.get() - 1);
            return Err(bifrost::Error::Closed);
        }
        self.inner.open_bi().await
    }
    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        Err(bifrost::Error::Closed)
    }
    async fn wait_closed(&self) {
        if !self.state.dead.borrow().contains(&self.id) {
            pending::<()>().await;
        }
    }
    fn close(&self) {
        self.state.closed.borrow_mut().push(self.id);
        Session::close(&self.inner);
    }
    fn path_changes(&self) -> PathChanges {
        PathChanges::fixed(Path::Unknown)
    }
}
