//! The observed Opens a run answers Path for: one record per observed Open, held by that Open's own
//! future through a guard, and nothing else.
//!
//! A record is reserved before Attached and is invisible until the whole Attached is written; from then
//! it names the exact connection the stream rides, through the stream's life and for
//! [`TERMINAL_RETENTION`] after it ends, until a Finish retires it. Every record belongs to an Open that
//! holds one of the run's reach slots, so there are never more of them than there are slots, and none
//! outlives the Open that owns it: no history, no sweeper, no task of its own.

use core::cell::{Cell, RefCell};
use core::pin::pin;
use core::time::Duration;
use std::rc::Rc;

use bifrost::{ConnInfo, Session};
use tokio::sync::Notify;
use tokio::time::Instant;

use super::socket::{Epoch, PathAction, PathRef, PathReply, PathRequest, Ticket};
use crate::peers::{Isolated, SessionEnd};

/// How long a record stays after its stream has ended both ways, for the Finish that reads the
/// connection's final path. Its own policy, not the request deadline's: a Sample never extends it.
pub const TERMINAL_RETENTION: Duration = Duration::from_secs(5);

/// The connection an observed Open's stream rides, kept for Path: a held lane's session, or the Open's
/// own isolated connection. Cloning shares it, so a query can sample it after the record is gone.
pub(crate) enum Carrier<S: Session> {
    /// A held lane's session, shared with other streams and kept in the run's cache.
    Held(SessionEnd<S>),
    /// The Open's own connection, closed once the last holder lets go.
    Isolated(Rc<Isolated<S>>),
}

impl<S: Session> Carrier<S> {
    /// The connection's path report as it reads now: the transport's own synchronous snapshot.
    fn conn_info(&self) -> ConnInfo {
        match self {
            Self::Held(session) => session.conn_info(),
            Self::Isolated(connection) => connection.conn_info(),
        }
    }
}

impl<S: Session> Clone for Carrier<S> {
    fn clone(&self) -> Self {
        match self {
            Self::Held(session) => Self::Held(session.clone()),
            Self::Isolated(connection) => Self::Isolated(Rc::clone(connection)),
        }
    }
}

/// The run's observed Opens: its epoch, the next ticket, and the records Path looks up, each carrying
/// its connection as a `C`, a [`Carrier`] in a run.
///
/// The records sit behind a `RefCell` because every Open, every Path and this set are driven by one
/// task, the control listener's, and each borrow ends before an await.
pub(crate) struct Observations<C> {
    epoch: Epoch,
    /// The ticket the next observed Open takes, or `None` once `u64::MAX` has been handed out.
    next: Cell<Option<Ticket>>,
    records: RefCell<Vec<Record<C>>>,
}

/// One observed Open's record.
struct Record<C> {
    ticket: Ticket,
    phase: Phase<C>,
    /// Woken when a Finish retires the record, so an owner waiting out the retention lets go at once.
    retired: Rc<Notify>,
}

/// Where an observed Open's record stands.
enum Phase<C> {
    /// Reserved, Attached not yet written whole: no query can see it.
    Preparing,
    /// The stream runs on this connection.
    Live(C),
    /// The stream has ended both ways; the connection stays queryable until `deadline`.
    Ended { carrier: C, deadline: Instant },
}

/// Why an observed Open could not be given a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unobservable;

impl<C: Clone> Observations<C> {
    /// The set for a run whose epoch is `epoch`, with room for `capacity` records, the run's reach
    /// slots. The room is taken now, so recording an Open never grows the records; each reservation
    /// allocates only its own wakeup.
    ///
    /// # Errors
    ///
    /// The room cannot be allocated.
    pub(crate) fn new(
        epoch: Epoch,
        capacity: usize,
    ) -> Result<Self, std::collections::TryReserveError> {
        let mut records = Vec::new();
        records.try_reserve_exact(capacity)?;
        Ok(Self {
            epoch,
            next: Cell::new(Some(Ticket::FIRST)),
            records: RefCell::new(records),
        })
    }

    /// Reserve a ticket and a record for an observed Open that holds a reach slot. The ticket is spent
    /// whatever becomes of the Open: a refused or cancelled one never hands its number to another.
    ///
    /// # Errors
    ///
    /// [`Unobservable`] once the run has handed out its last ticket, or should the records have no
    /// room, which the reach slots rule out.
    pub(crate) fn reserve(&self) -> Result<Observing<'_, C>, Unobservable> {
        let ticket = self.next.get().ok_or(Unobservable)?;
        self.next.set(ticket.next());
        let mut records = self.records.borrow_mut();
        // Within the room taken at the start, so the push below never grows the records. The record's
        // wakeup is the one allocation a reservation makes, after the room is checked.
        if records.len() == records.capacity() {
            return Err(Unobservable);
        }
        let retired = Rc::new(Notify::new());
        records.push(Record {
            ticket,
            phase: Phase::Preparing,
            retired: Rc::clone(&retired),
        });
        Ok(Observing {
            set: self,
            ticket,
            retired,
        })
    }

    /// The connection `request` names, as of `now`, retiring the record on a Finish. The borrow ends
    /// here, so the caller reads the connection with nothing held.
    ///
    /// A record past its deadline is Unavailable here even if its owner has not yet woken to remove it:
    /// the deadline is the rule, the owner's timer only the cleanup.
    fn take(&self, request: PathRequest, now: Instant) -> Option<C> {
        let PathRequest { reference, action } = request;
        if reference.epoch() != self.epoch {
            return None;
        }
        let mut records = self.records.borrow_mut();
        let at = records
            .iter()
            .position(|record| record.ticket == reference.ticket())?;
        let carrier = match &records[at].phase {
            Phase::Preparing => return None,
            Phase::Live(carrier) => carrier.clone(),
            Phase::Ended { carrier, deadline } if now < *deadline => carrier.clone(),
            Phase::Ended { .. } => return None,
        };
        if let PathAction::Finish = action {
            records.swap_remove(at).retired.notify_one();
        }
        Some(carrier)
    }
}

impl<S: Session> Observations<Carrier<S>> {
    /// Hand out the last ticket, as a run that has handed out every other would have.
    #[cfg(test)]
    pub(crate) fn spend_tickets(&self) {
        self.next.set(None);
    }

    /// Answer `request` as of `now`: the connection's report, or Unavailable. A Finish retires the
    /// record before the connection is read, so a lost reply never brings it back.
    pub(crate) fn answer(&self, request: PathRequest, now: Instant) -> PathReply {
        match self.take(request, now) {
            Some(carrier) => PathReply::Sample(carrier.conn_info()),
            None => PathReply::Unavailable,
        }
    }
}

/// An observed Open's hold on its record, from reservation until the Open lets go.
///
/// Dropping it removes the record it reserved, by ticket, and only that one: tickets are never reused
/// within a run, so a late drop can never remove another Open's record.
pub(crate) struct Observing<'o, C> {
    set: &'o Observations<C>,
    ticket: Ticket,
    retired: Rc<Notify>,
}

impl<C: Clone> Observing<'_, C> {
    /// The reference Attached carries.
    pub(crate) fn reference(&self) -> PathRef {
        PathRef::new(self.set.epoch, self.ticket)
    }

    /// Make the record queryable on `carrier`. Called in the same poll that saw the whole Attached
    /// written, with no await between: a client that has read its reference can always sample it. A
    /// change of state in place, so it cannot fail or allocate.
    pub(crate) fn publish(&self, carrier: C) {
        let mut records = self.set.records.borrow_mut();
        if let Some(record) = records
            .iter_mut()
            .find(|record| record.ticket == self.ticket)
        {
            record.phase = Phase::Live(carrier);
        }
    }

    /// The stream has ended both ways: keep the record queryable for [`TERMINAL_RETENTION`] from now,
    /// or until a Finish retires it, then let it go. A record never published, or already finished,
    /// lets go at once.
    pub(crate) async fn retain(self) {
        // Interest first, then the check: a Finish between the two still wakes this wait.
        let mut retired = pin!(self.retired.notified());
        retired.as_mut().enable();
        // A deadline past what the clock can hold retires the record rather than keeping it forever.
        let Some(deadline) = Instant::now().checked_add(TERMINAL_RETENTION) else {
            return;
        };
        if !self.end(deadline) {
            return;
        }
        tokio::select! {
            () = retired => {}
            () = tokio::time::sleep_until(deadline) => {}
        }
    }

    /// Move a live record to its retention, ending at `deadline`. False when there is no live record to
    /// keep: never published, or already retired.
    fn end(&self, deadline: Instant) -> bool {
        let mut records = self.set.records.borrow_mut();
        let Some(record) = records
            .iter_mut()
            .find(|record| record.ticket == self.ticket)
        else {
            return false;
        };
        let carrier = match &record.phase {
            Phase::Live(carrier) => carrier.clone(),
            Phase::Preparing | Phase::Ended { .. } => return false,
        };
        record.phase = Phase::Ended { carrier, deadline };
        true
    }
}

impl<C> Drop for Observing<'_, C> {
    fn drop(&mut self) {
        let mut records = self.set.records.borrow_mut();
        if let Some(at) = records
            .iter()
            .position(|record| record.ticket == self.ticket)
        {
            records.swap_remove(at);
        }
    }
}

#[cfg(test)]
#[path = "observing_tests.rs"]
mod tests;
