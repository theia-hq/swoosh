use core::num::NonZeroU64;
use core::time::Duration;

use tokio::time::Instant;

use super::{Observations, Observing, TERMINAL_RETENTION, Unobservable};
use crate::serve::control_codec::{Epoch, PathAction, PathRef, PathRequest};
use crate::serve::socket::Ticket;

/// A set whose records carry a name for the connection, so a test reads which one a lookup found.
type Named = Observations<&'static str>;

fn epoch(byte: u8) -> Epoch {
    Epoch::draw(&mut Fill(byte)).unwrap()
}

fn set() -> Named {
    Observations::new(epoch(1), 4).unwrap()
}

fn ask(reference: PathRef, action: PathAction) -> PathRequest {
    PathRequest { reference, action }
}

fn sample(
    set: &Named,
    observing: &Observing<'_, &'static str>,
    now: Instant,
) -> Option<&'static str> {
    set.take(ask(observing.reference(), PathAction::Sample), now)
}

fn finish(set: &Named, reference: PathRef, now: Instant) -> Option<&'static str> {
    set.take(ask(reference, PathAction::Finish), now)
}

#[test]
fn a_reserved_record_answers_only_once_published() {
    let set = set();
    let now = Instant::now();
    let a = set.reserve().unwrap();
    assert_eq!(sample(&set, &a, now), None);
    a.publish("a");
    assert_eq!(sample(&set, &a, now), Some("a"));
}

#[test]
fn tickets_count_from_one_and_a_dropped_reservation_spends_its_own() {
    let set = set();
    let first = set.reserve().unwrap();
    assert_eq!(first.reference().ticket(), Ticket::FIRST);
    drop(first);
    let second = set.reserve().unwrap();
    assert_eq!(
        second.reference().ticket(),
        Ticket::at(NonZeroU64::new(2).unwrap())
    );
    // The dropped one's number answers nothing, now or later.
    second.publish("b");
    let stale = PathRef::new(epoch(1), Ticket::FIRST);
    assert_eq!(finish(&set, stale, Instant::now()), None);
}

#[test]
fn the_last_ticket_is_handed_out_once_then_none() {
    let set = set();
    set.next.set(Some(Ticket::at(NonZeroU64::MAX)));
    let last = set.reserve().unwrap();
    assert_eq!(last.reference().ticket(), Ticket::at(NonZeroU64::MAX));
    drop(last);
    assert!(matches!(set.reserve(), Err(Unobservable)));
    assert!(matches!(set.reserve(), Err(Unobservable)));
}

#[test]
fn records_never_outgrow_the_room_taken_at_the_start() {
    let set: Named = Observations::new(epoch(1), 2).unwrap();
    let _a = set.reserve().unwrap();
    let _b = set.reserve().unwrap();
    assert!(matches!(set.reserve(), Err(Unobservable)));
}

#[test]
fn another_runs_reference_is_unavailable() {
    let set = set();
    let a = set.reserve().unwrap();
    a.publish("a");
    let other = PathRef::new(epoch(2), a.reference().ticket());
    assert_eq!(
        set.take(ask(other, PathAction::Sample), Instant::now()),
        None
    );
    assert_eq!(sample(&set, &a, Instant::now()), Some("a"));
}

#[test]
fn finish_takes_the_connection_once_and_retires_the_reference() {
    let set = set();
    let a = set.reserve().unwrap();
    a.publish("a");
    let now = Instant::now();
    assert_eq!(finish(&set, a.reference(), now), Some("a"));
    assert_eq!(finish(&set, a.reference(), now), None);
    assert_eq!(sample(&set, &a, now), None);
}

#[test]
fn dropping_one_hold_removes_only_its_own_record() {
    let set = set();
    let a = set.reserve().unwrap();
    let b = set.reserve().unwrap();
    let c = set.reserve().unwrap();
    a.publish("a");
    b.publish("b");
    c.publish("c");
    // Removal moves the last record into the gap, so the drop must find its record by ticket.
    drop(a);
    let now = Instant::now();
    assert_eq!(sample(&set, &b, now), Some("b"));
    assert_eq!(sample(&set, &c, now), Some("c"));
    // A finished record's late drop finds nothing of its own and removes nothing else.
    assert_eq!(finish(&set, b.reference(), now), Some("b"));
    drop(b);
    assert_eq!(sample(&set, &c, now), Some("c"));
}

#[test]
fn an_ended_record_expires_at_its_deadline_at_lookup() {
    let set = set();
    let a = set.reserve().unwrap();
    a.publish("a");
    let ended = Instant::now();
    let deadline = ended + TERMINAL_RETENTION;
    assert!(a.end(deadline));
    let just_before = deadline - Duration::from_nanos(1);
    assert_eq!(sample(&set, &a, ended), Some("a"));
    // A sample just before the deadline does not move it.
    assert_eq!(sample(&set, &a, just_before), Some("a"));
    assert_eq!(sample(&set, &a, deadline), None);
    assert_eq!(finish(&set, a.reference(), deadline), None);
    assert_eq!(sample(&set, &a, deadline + TERMINAL_RETENTION), None);
}

#[test]
fn only_a_live_record_enters_retention() {
    let set = set();
    let deadline = Instant::now() + TERMINAL_RETENTION;
    let unpublished = set.reserve().unwrap();
    assert!(!unpublished.end(deadline));
    let finished = set.reserve().unwrap();
    finished.publish("f");
    finish(&set, finished.reference(), Instant::now());
    assert!(!finished.end(deadline));
}

#[tokio::test(start_paused = true)]
async fn retention_lets_go_at_once_when_nothing_is_left_to_observe() {
    let set = set();
    let started = Instant::now();
    // Never published: Attached was not written whole.
    set.reserve().unwrap().retain().await;
    // Finished while the stream ran: the observation is already retired.
    let finished = set.reserve().unwrap();
    finished.publish("f");
    finish(&set, finished.reference(), Instant::now());
    finished.retain().await;
    assert_eq!(Instant::now(), started);
    assert!(set.records.borrow().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_finish_during_retention_lets_go_at_once() {
    let set = set();
    let a = set.reserve().unwrap();
    let reference = a.reference();
    a.publish("a");
    let started = Instant::now();
    let retained = a.retain();
    tokio::pin!(retained);
    // Polled once, so it is in retention and waiting.
    assert!(futures::poll!(retained.as_mut()).is_pending());
    assert_eq!(finish(&set, reference, Instant::now()), Some("a"));
    retained.await;
    assert_eq!(Instant::now(), started);
}

#[tokio::test(start_paused = true)]
async fn an_unfinished_record_is_let_go_at_the_retention_deadline() {
    let set = set();
    let a = set.reserve().unwrap();
    let reference = a.reference();
    a.publish("a");
    let started = Instant::now();
    a.retain().await;
    assert_eq!(Instant::now(), started + TERMINAL_RETENTION);
    assert!(set.records.borrow().is_empty());
    assert_eq!(set.take(ask(reference, PathAction::Sample), started), None);
}

/// A random source that fills with one byte.
struct Fill(u8);

impl rand::RngCore for Fill {
    fn next_u32(&mut self) -> u32 {
        u32::from(self.0)
    }

    fn next_u64(&mut self) -> u64 {
        u64::from(self.0)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(self.0);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        dest.fill(self.0);
        Ok(())
    }
}
