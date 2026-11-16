//! Cache ownership proofs use the existing scripted gate; only transport scheduling and failure are
//! injected here. Sessions deliberately implement neither Clone nor Send.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::cell::{Cell, RefCell};
use core::future::pending;
use std::io;
use std::rc::Rc;
use std::time::SystemTime;

use bifrost::{Addr, InProcess, NoDiscovery, Node, NodeId, Path, PathChanges, Session, Transport};
use futures::poll;
use nauthy::{Link, Service};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::sync::Semaphore;

use super::{DIAL_TIMEOUT, IDLE_EVICTION, Key, MAIN_STREAMS, OPEN_TIMEOUT, Peers};
use crate::home::Home;
use crate::renewal::{Fetch as _, NodeFetch};
use crate::serve::{RENEWAL_SERVICE, SYNC_SERVICE};
use crate::sync::{Dial as _, NodeDial};
use crate::testkit::{Script, ScriptedPeer, TestNode, TestRoot};

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
    assert_eq!(keys[0].standing.as_deref(), Some(first.as_str()));
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
    let mut leader = Box::pin(peers.open(peer(), service(), None));
    let mut waiter = Box::pin(peers.open(peer(), service(), None));
    let mut cancelled = Box::pin(peers.open(peer(), service(), None));
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
    assert_eq!(peers.counts.borrow()[&peer()].strong_count(), 0);
    drop(peers.open(peer(), service(), None).await.unwrap());
    assert_eq!(probe.state.dials.get(), 1);
    // With no waiter left, even an uncompleted dial is dropped, not kept dormant in the cache.
    let other = TestNode::seeded(9).node_id();
    let mut abandoned = Box::pin(peers.open(other, service(), None));
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
        standing: Some(a.as_str().to_owned()),
    };
    let b_key = Key {
        peer: peer(),
        standing: Some(b.as_str().to_owned()),
    };
    let none_key = Key {
        peer: peer(),
        standing: None,
    };
    let mut leader = Box::pin(peers.open(peer(), service(), Some(a.clone())));
    let mut other = Box::pin(peers.open(peer(), service(), Some(b)));
    let mut waiter = Box::pin(peers.open(peer(), service(), Some(a.clone())));
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
    let _none_stream = peers.open(peer(), service(), None).await.unwrap();
    let (b_entry, reused) = peers.session(&b_key).await.unwrap();
    assert!(reused);
    let (none_entry, reused) = peers.session(&none_key).await.unwrap();
    assert!(reused);

    // Retrying the older snapshot must replace only its own entry, even while its dial is pending.
    let retry_gate = Rc::new(Semaphore::new(0));
    *probe.state.dial_gate.borrow_mut() = Some(Rc::clone(&retry_gate));
    probe.state.fail_opens.set(1);
    let mut retry = Box::pin(peers.open(peer(), service(), Some(a)));
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
    let (current, reused) = peers.session(&b_key).await.unwrap();
    assert!(reused && Rc::ptr_eq(&current, &b_entry));
    let (current, reused) = peers.session(&none_key).await.unwrap();
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
        .map(|_| Box::pin(peers.open(peer(), service(), None)))
        .collect();
    for ask in &mut asks {
        assert!(poll!(ask).is_pending());
    }
    assert_eq!(probe.state.dials.get(), 1);
    gate.add_permits(1);
    let first = asks.pop().unwrap();
    assert!(matches!(first.await, Err(bifrost::Error::Connect(_))));
    assert_eq!(asks.len(), 7);
    assert!(peers.entries.borrow().is_empty());
    for ask in asks {
        assert!(matches!(ask.await, Err(bifrost::Error::Connect(_))));
    }
    assert!(peers.entries.borrow().is_empty());
    *probe.state.dial_gate.borrow_mut() = None;
    drop(peers.open(peer(), service(), None).await.unwrap());
    assert_eq!(probe.state.dials.get(), 2);
}

#[tokio::test]
async fn a_reused_broken_entry_redials_once_but_not_after_a_fresh_failure() {
    let probe = Probe::new((0..2).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    drop(peers.open(peer(), service(), None).await.unwrap());
    probe.state.fail_opens.set(1);
    drop(peers.open(peer(), service(), None).await.unwrap());
    assert_eq!(probe.state.dials.get(), 2);
    probe.state.fail_opens.set(2);
    assert!(matches!(
        peers.open(peer(), service(), None).await,
        Err(bifrost::Error::Closed)
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
        peers.open(peer(), service(), None).await,
        Err(bifrost::Error::Closed)
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
    drop(peers.open(peer(), service(), None).await.unwrap());
    assert!(
        matches!(peers.open(peer(), service(), None).await, Err(bifrost::Error::Refused(r)) if r == refusal)
    );
    assert_eq!(
        probe.gate.requests().len(),
        2,
        "the second stream checks admission"
    );
    probe.state.wrong_peer.set(true);
    assert!(matches!(peers.open(peer(), service(), None).await,
        Err(bifrost::Error::Stream(cause)) if cause.is::<tightbeam::tunnel::WrongPeer>()));
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
    let stream = peers.open(peer(), service(), None).await.unwrap();
    let key = Key {
        peer: peer(),
        standing: None,
    };
    let (old, _) = peers.session(&key).await.unwrap();
    peers.evict(&key, &old);
    let (replacement, _) = peers.session(&key).await.unwrap();
    peers.evict(&key, &old);
    let (current, reused) = peers.session(&key).await.unwrap();
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
        peers.open(peer(), service(), None).await,
        Err(bifrost::Error::Connect(_))
    ));
    assert_eq!(started.elapsed(), DIAL_TIMEOUT);
    assert!(peers.entries.borrow().is_empty());
    *probe.state.dial_gate.borrow_mut() = None;
    probe.state.stall_open.set(true);
    let started = tokio::time::Instant::now();
    assert!(matches!(peers.open(peer(), service(), None).await,
        Err(bifrost::Error::Stream(cause)) if cause.downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut)));
    assert_eq!(started.elapsed(), OPEN_TIMEOUT);
    assert!(peers.entries.borrow().is_empty());
    let mut opening = Box::pin(peers.open(peer(), service(), None));
    assert!(poll!(&mut opening).is_pending());
    drop(opening);
    assert_eq!(peers.counts.borrow()[&peer()].strong_count(), 0);
    probe.state.stall_open.set(false);
    drop(peers.open(peer(), service(), None).await.unwrap());
}

#[tokio::test(start_paused = true)]
async fn a_caller_cancelling_a_stalled_open_evicts_only_its_own_entry() {
    let probe = Probe::new((0..3).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let key = Key {
        peer: peer(),
        standing: None,
    };
    drop(peers.open(peer(), service(), None).await.unwrap());
    // Callers bound an exchange below the open deadline, so only the cancellation can evict here.
    probe.state.stall_open.set(true);
    let started = tokio::time::Instant::now();
    assert!(
        tokio::time::timeout(crate::sync::EACH, peers.open(peer(), service(), None))
            .await
            .is_err()
    );
    assert!(started.elapsed() < OPEN_TIMEOUT);
    assert_eq!(peers.counts.borrow()[&peer()].strong_count(), 0);
    assert_eq!(*probe.state.closed.borrow(), vec![1]);
    probe.state.stall_open.set(false);
    drop(peers.open(peer(), service(), None).await.unwrap());
    assert_eq!(
        probe.state.dials.get(),
        2,
        "the stalled session is not reused"
    );

    // An attempt cancelled after its entry was replaced leaves the replacement cached.
    probe.state.stall_open.set(true);
    let mut stalled = Box::pin(peers.open(peer(), service(), None));
    assert!(poll!(&mut stalled).is_pending());
    probe.state.stall_open.set(false);
    let (stalled_entry, _) = peers.session(&key).await.unwrap();
    peers.evict(&key, &stalled_entry);
    drop(stalled_entry);
    drop(peers.open(peer(), service(), None).await.unwrap());
    let (replacement, _) = peers.session(&key).await.unwrap();
    drop(stalled);
    let (current, reused) = peers.session(&key).await.unwrap();
    assert!(reused && Rc::ptr_eq(&current, &replacement));
    assert_eq!(probe.state.dials.get(), 3);
}

#[tokio::test(start_paused = true)]
async fn both_halves_own_one_budget_and_idle_eviction_waits_for_the_last_half() {
    let probe = Probe::new((0..usize::from(MAIN_STREAMS)).map(|_| Script::Lists(vec![])));
    let node = Node::new(probe.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let mut streams = Vec::new();
    for _ in 0..MAIN_STREAMS {
        streams.push(peers.open(peer(), service(), None).await.unwrap());
    }
    assert!(
        matches!(peers.open(peer(), service(), Some(badge(1))).await,
        Err(bifrost::Error::Stream(cause)) if cause.downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::WouldBlock))
    );
    let (writer, reader) = streams.pop().unwrap();
    drop(writer);
    assert_eq!(
        peers.counts.borrow()[&peer()].upgrade().unwrap().get(),
        MAIN_STREAMS
    );
    drop(reader);
    assert_eq!(
        peers.counts.borrow()[&peer()].upgrade().unwrap().get(),
        MAIN_STREAMS - 1
    );
    let (writer, reader) = streams.pop().unwrap();
    drop(reader);
    assert_eq!(
        peers.counts.borrow()[&peer()].upgrade().unwrap().get(),
        MAIN_STREAMS - 1
    );
    drop(writer);
    assert_eq!(
        peers.counts.borrow()[&peer()].upgrade().unwrap().get(),
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
async fn structured_borrowers_and_owner_drop_before_node_close() {
    let probe = Probe::new([Script::Lists(vec![])]);
    let node = Node::new(probe.clone(), NoDiscovery);
    {
        let peers = Peers::new(&node);
        let work = async {
            let _stream = peers.open(peer(), service(), None).await.unwrap();
            pending::<()>().await;
        };
        let mut work = Box::pin(work);
        while probe.gate.requests().is_empty() {
            assert!(poll!(&mut work).is_pending());
            tokio::task::yield_now().await;
        }
        assert!(probe.state.closed.borrow().is_empty());
        drop(work);
        assert_eq!(peers.counts.borrow()[&peer()].strong_count(), 0);
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
            .open(host.node_id(), service(), Some(credential.clone()))
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
                    .open(host.node_id(), service(), Some(credential))
                    .await,
                Err(bifrost::Error::Refused(bifrost::Refusal::NotAdmitted))
            ),
            "the next credentialed stream still checks admission"
        );
        cancel.cancel();
    };
    let (served, ()) = tokio::join!(exposer.run(&host, cancel.clone()), exercise);
    served.unwrap();
    node.close().await;
    host.close().await;
    std::fs::remove_dir_all(home.dir()).unwrap();
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
    wrong_peer: Cell<bool>,
    dial_gate: RefCell<Option<Rc<Semaphore>>>,
    closed: RefCell<Vec<u32>>,
    node_closed: Cell<bool>,
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
    type Security = InProcess;
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
    type Security = InProcess;
    type Write = DuplexStream;
    type Read = DuplexStream;
    fn peer(&self) -> NodeId {
        if self.state.wrong_peer.get() {
            TestNode::seeded(9).node_id()
        } else {
            self.inner.peer()
        }
    }
    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        if self.state.stall_open.get() {
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
        pending::<()>().await;
    }
    fn close(&self) {
        self.state.closed.borrow_mut().push(self.id);
        Session::close(&self.inner);
    }
    fn path_changes(&self) -> PathChanges {
        PathChanges::fixed(Path::Unknown)
    }
}
