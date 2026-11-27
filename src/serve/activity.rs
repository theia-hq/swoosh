//! A serving node's activity lines: the one place an engine's fact becomes text.
//!
//! An engine reports what it did as a typed value through a sink the root installs when it constructs
//! the engine, and never prints. This module is that sink and its renderer. It owns the row's shape and
//! the writer it lands on, and every peer-named string on it goes through the shared escaper, cut to the
//! room its line has left ([`peer_cell`]), whichever engine carried it.
//!
//! The renderer runs on a thread of its own, behind a bounded queue. An engine's report call only
//! renders a capped line and offers it to the queue, so a slow or wedged writer (a terminal paused
//! mid-scroll, a full pipe nobody drains) can never hold a transfer's stream open. When the queue is
//! full the line is dropped and counted; the file itself has already landed, and only its line is lost.
//! The renderer then says how many it lost, on the same writer, once that writer is moving again.
//!
//! The root decides whether activity is shown at all by whether it builds an [`Activity`]: a node that
//! builds none installs no sink, and its engines stay silent whatever the environment says.

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::time::SystemTime;
use std::{io, thread};

use nauthy::VerifyKey;
use tightbeam::identity::AsNodeId as _;
use transfer::{Received, ReceivedSink};

use crate::contacts::Contacts;
use crate::escape::{Escaped, LINE_WIDTH, PEER_FLOOR, columns, peer_cell};
use crate::size::Size;

/// How many landed files may wait on a stalled writer before new ones are dropped. Each holds at most
/// [`NAME_KEPT`] scalars of its name, so the queue's memory is bounded however many streams a sender
/// opens, and a burst of small files still fits while the writer catches up.
const ACTIVITY_BACKLOG: usize = 256;

/// Where a file name sits when it takes a line of its own: under the sender, past the clock.
const INDENT: &str = "       ";

/// The room a file name has on a line of its own, the most it ever has.
const NAME_ROOM: usize = LINE_WIDTH - INDENT.len() - 1;

/// How many scalars of a landed file's name are kept for its row: one past the most a row can show,
/// since every scalar fills at least one column, so the row still knows to mark the cut.
const NAME_KEPT: usize = NAME_ROOM + 1;

/// How the renderer reads this home's book, the names a receive row gives senders: read once for each
/// batch of rows it renders, so a contact saved while the node runs is named and a burst of files costs
/// one read. Handed in by the root, so the renderer reads no home of its own, and run on the renderer's
/// thread, so a slow read holds no stream. A book that does not read is an empty one: every sender then
/// prints by its whole key.
pub type Book = Box<dyn Fn() -> Contacts + Send>;

/// How long an idle renderer waits before it looks at the drop count again. A drop is counted just after
/// the queue refuses a line, so a fast writer can drain the queue and go idle between that refusal and
/// the count; this tick is what reports such a drop without waiting for a later file to land.
const DROP_CHECK: Duration = Duration::from_secs(1);

/// A node's activity renderer: the queue its engines' sinks feed and the thread that drains it onto one
/// writer. Build one per node, then hand each reporting engine the sink for its route.
///
/// The renderer thread lives while any sink does: while the process lives it drains what is queued, and
/// it exits once this handle and every sink it issued are dropped. Nothing joins it, because joining a
/// wedged writer would hang the node's teardown, so lines still queued when the process exits are lost.
pub struct Activity {
    lines: SyncSender<Landed>,
    dropped: Arc<AtomicU64>,
}

impl Activity {
    /// Start rendering activity onto `out`, one row per fact, behind a queue of [`ACTIVITY_BACKLOG`]
    /// facts, naming each sender from `book`.
    pub fn spawn(out: impl io::Write + Send + 'static, book: Book) -> io::Result<Self> {
        Self::with_backlog(out, book, ACTIVITY_BACKLOG)
    }

    /// [`spawn`](Self::spawn) with an explicit queue bound, so a test can reach the bound in a few lines.
    fn with_backlog(
        out: impl io::Write + Send + 'static,
        book: Book,
        backlog: usize,
    ) -> io::Result<Self> {
        let (lines, queued) = mpsc::sync_channel(backlog);
        let dropped = Arc::new(AtomicU64::new(0));
        let renderer = Renderer {
            out,
            book,
            dropped: Arc::clone(&dropped),
            reported: 0,
        };
        // A thread, not a runtime task: the write blocks for as long as the writer does, and a blocked
        // write must hold only this thread, never a runtime worker another stream is polled on.
        thread::Builder::new()
            .name("swoosh-activity".to_owned())
            .spawn(move || renderer.drain(&queued))?;
        Ok(Self { lines, dropped })
    }

    /// The sink for one receive route: every file its engine lands renders as one row,
    /// `00:47  me/laptop sent 28.6 MiB: photo.bin`.
    pub fn recv(&self) -> RecvLines {
        RecvLines {
            lines: self.lines.clone(),
            dropped: Arc::clone(&self.dropped),
        }
    }

    /// How many lines the queue has refused since this renderer started.
    #[cfg(test)]
    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// One receive route's sink: the [`ReceivedSink`] the root installs on that route's `Recv` engine.
pub struct RecvLines {
    lines: SyncSender<Landed>,
    dropped: Arc<AtomicU64>,
}

/// A landed file as its row needs it: when it landed, who sent it, how much, and the start of its name.
struct Landed {
    /// Seconds since the epoch.
    at: u64,
    /// The key the gate admitted the stream under.
    from: VerifyKey,
    bytes: u64,
    /// At most [`NAME_KEPT`] scalars of the name it was saved under, as the peer gave it.
    name: String,
}

impl Landed {
    /// The fact `file` reports, stamped now.
    fn of(file: &Received) -> Self {
        let at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        Self {
            at,
            from: file.from,
            bytes: file.bytes,
            name: file
                .path
                .to_string_lossy()
                .chars()
                .take(NAME_KEPT)
                .collect(),
        }
    }

    /// The row, sender first and the peer's file name last, so a name can never print a sender of its
    /// own before the real one: `00:47  me/laptop sent 28.6 MiB: photo.bin`.
    ///
    /// The sender is who the gate admitted the stream as, named by this home's `book`, else its whole key: then
    /// nothing else on the row names the machine, so a short form would leave nothing to compare or copy
    /// (a squatted name shows a stranger's key). A sender that leaves the file less than [`PEER_FLOOR`]
    /// columns, which a whole key always does, breaks the row after the colon, and the file takes a line
    /// of its own under the sender. The file name is escaped and cut
    /// ([`peer_cell`]) to the room its line has left, so no glyph can wrap it onto a forged row.
    fn row(&self, book: &Contacts, clock: &str) -> String {
        let named = self
            .from
            .node_id()
            .ok()
            .and_then(|node| book.saved_at(&node));
        let sender = named.map_or_else(|| self.from.to_string(), |name| name.to_string());
        let head = format!("{clock}  {} sent {}:", Escaped(&sender), Size(self.bytes));
        let room = LINE_WIDTH.saturating_sub(columns(&head) + " ".len() + 1);
        // A whole key is 56 columns, so beside the clock and the smallest size it leaves 5: it always
        // breaks here, by the same floor as a long name.
        if room < PEER_FLOOR {
            return format!("{head}\n{INDENT}{}", peer_cell(&self.name, NAME_ROOM));
        }
        format!("{head} {}", peer_cell(&self.name, room))
    }
}

/// `at` as a row's clock: the local `HH:MM`, or UTC's when the system cannot say the local time.
fn clock(at: u64) -> String {
    match crate::root::local_time(at) {
        Some(local) => format!("{:02}:{:02}", local.tm_hour, local.tm_min),
        None => format!("{:02}:{:02}", at % 86_400 / 3600, at % 3600 / 60),
    }
}

impl ReceivedSink for RecvLines {
    /// Offer the landed fact and return at once: `try_send` never waits, so a full queue costs the row,
    /// never the stream. Stamping it and keeping the start of its name are bounded work; the sender's
    /// name is read on the renderer's thread.
    fn received(&self, file: Received) {
        match self.lines.try_send(Landed::of(&file)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            // The renderer is gone only once the node is tearing down; there is no one left to tell.
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

/// The renderer thread's state: the writer every row lands on, how it reads the book that names senders,
/// and how many drops it has already reported.
struct Renderer<W> {
    out: W,
    book: Book,
    dropped: Arc<AtomicU64>,
    reported: u64,
}

impl<W: io::Write> Renderer<W> {
    /// Write each queued line until every sender is gone. A failed write (a closed pipe) loses that one
    /// line and the loop keeps draining, so a dead writer never pins the queue full.
    ///
    /// Drops are reported when the queue runs empty, on the writer the lost lines were meant for: the
    /// writer is moving again by then, the notice follows the lines that survived, and it is activity,
    /// so `--quiet` withholds it with the rest. It is not a log event, because the default log filter
    /// shows errors only and an operator would never see it. A final check on the way out reports a
    /// drop that no later line followed.
    fn drain(mut self, queued: &Receiver<Landed>) {
        loop {
            let first = match queued.try_recv() {
                Ok(landed) => landed,
                Err(TryRecvError::Empty) => {
                    self.report_drops();
                    match queued.recv_timeout(DROP_CHECK) {
                        Ok(landed) => landed,
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                Err(TryRecvError::Disconnected) => break,
            };
            // What is queued now renders under one read of the book, bounded by the queue's own size.
            let batch: Vec<Landed> = core::iter::once(first)
                .chain(queued.try_iter().take(ACTIVITY_BACKLOG))
                .collect();
            let book = (self.book)();
            for landed in batch {
                let row = landed.row(&book, &clock(landed.at));
                self.write(&row);
            }
        }
        self.report_drops();
    }

    /// Say how many lines were dropped since the last notice, if any were.
    fn report_drops(&mut self) {
        let dropped = self.dropped.load(Ordering::Relaxed);
        if dropped > self.reported {
            let lost = dropped - self.reported;
            let noun = if lost == 1 { "line" } else { "lines" };
            self.write(&format!(
                "warning: {lost} activity {noun} dropped while the output was stalled"
            ));
            self.reported = dropped;
        }
    }

    /// Write one line. A failed write loses the line and nothing else: there is nowhere to report it.
    fn write(&mut self, line: &str) {
        let _ = writeln!(self.out, "{line}").and_then(|()| self.out.flush());
    }
}

#[cfg(test)]
#[path = "activity_tests.rs"]
mod activity_tests;
