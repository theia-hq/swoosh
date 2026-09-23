//! A serving node's activity lines: the one place an engine's fact becomes text.
//!
//! An engine reports what it did as a typed value through a sink the root installs when it constructs
//! the engine, and never prints. This module is that sink and its renderer. It owns the line's shape,
//! the escaping and capping of every peer-named string on it, and the writer it lands on, so a hostile
//! name is neutralised in exactly one place whichever engine carried it.
//!
//! The renderer runs on a thread of its own, behind a bounded queue. An engine's report call only
//! renders a capped line and offers it to the queue, so a slow or wedged writer (a terminal paused
//! mid-scroll, a full pipe nobody drains) can never hold a transfer's stream open. When the queue is
//! full the line is dropped and counted; the file itself has already landed, and only its line is lost.
//! The renderer then says how many it lost, on the same writer, once that writer is moving again.
//!
//! The root decides whether activity is shown at all by whether it builds an [`Activity`]: a node that
//! builds none installs no sink, and its engines stay silent whatever the environment says.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::{io, thread};

use nauthy::Service;
use transfer::{Received, ReceivedSink};

/// How many rendered lines may wait on a stalled writer before new ones are dropped. A line is capped
/// (a service name plus [`MAX_RENDERED_PATH`] characters of escapes), so the queue's memory is bounded
/// however many streams a sender opens, and a burst of small files still fits while the writer catches
/// up.
const ACTIVITY_BACKLOG: usize = 256;

/// The longest a peer-named path renders on a line, in characters. The path is unbounded up to the wire
/// frame, so the render caps what reaches the queue and the writer.
const MAX_RENDERED_PATH: usize = 256;

/// How long an idle renderer waits before it looks at the drop count again. A drop is counted just after
/// the queue refuses a line, so a fast writer can drain the queue and go idle between that refusal and
/// the count; this tick is what reports such a drop without waiting for a later file to land.
const DROP_CHECK: Duration = Duration::from_secs(1);

/// Letters that render as blank space on a terminal. `char::escape_debug` treats them as printable and
/// passes them raw, so a name made only of them would print as an empty path and two such names would
/// look alike. They cannot forge a line or drive a terminal; they are escaped so a name is never
/// invisible.
const BLANK_LETTERS: [char; 5] = ['\u{115f}', '\u{1160}', '\u{3164}', '\u{ffa0}', '\u{2800}'];

/// A node's activity renderer: the queue its engines' sinks feed and the thread that drains it onto one
/// writer. Build one per node, then hand each reporting engine the sink for its route.
///
/// The renderer thread lives while any sink does: while the process lives it drains what is queued, and
/// it exits once this handle and every sink it issued are dropped. Nothing joins it, because joining a
/// wedged writer would hang the node's teardown, so lines still queued when the process exits are lost.
pub struct Activity {
    lines: SyncSender<String>,
    dropped: Arc<AtomicU64>,
}

impl Activity {
    /// Start rendering activity onto `out`, one line per fact, behind a queue of [`ACTIVITY_BACKLOG`]
    /// lines.
    pub fn spawn(out: impl io::Write + Send + 'static) -> io::Result<Self> {
        Self::with_backlog(out, ACTIVITY_BACKLOG)
    }

    /// [`spawn`](Self::spawn) with an explicit queue bound, so a test can reach the bound in a few lines.
    fn with_backlog(out: impl io::Write + Send + 'static, backlog: usize) -> io::Result<Self> {
        let (lines, queued) = mpsc::sync_channel(backlog);
        let dropped = Arc::new(AtomicU64::new(0));
        let renderer = Renderer {
            out,
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

    /// The sink for one receive route: every file its engine lands renders as
    /// `<service>: received <path> (<bytes> bytes)`. The route's own name leads the line, because a node
    /// serving two receive routes would otherwise print the same path for two different directories.
    pub fn recv(&self, service: Service) -> RecvLines {
        RecvLines {
            service,
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
    service: Service,
    lines: SyncSender<String>,
    dropped: Arc<AtomicU64>,
}

impl RecvLines {
    /// Render one landed file as its line. The ONE render site for a received path: the service name is
    /// the operator's own validated route name, and the path is the peer's, so only the path is escaped.
    fn line(&self, file: &Received) -> String {
        format!(
            "{}: received {} ({} bytes)",
            self.service,
            Escaped(&file.path),
            file.bytes
        )
    }
}

impl ReceivedSink for RecvLines {
    /// Offer the rendered line and return at once: `try_send` never waits, so a full queue costs the
    /// line, never the stream. The render before it is bounded work, capped by [`Escaped`].
    fn received(&self, file: Received) {
        match self.lines.try_send(self.line(&file)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            // The renderer is gone only once the node is tearing down; there is no one left to tell.
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

/// The renderer thread's state: the writer every line lands on, and how many drops it has already
/// reported.
struct Renderer<W> {
    out: W,
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
    fn drain(mut self, queued: &Receiver<String>) {
        loop {
            let line = match queued.try_recv() {
                Ok(line) => line,
                Err(TryRecvError::Empty) => {
                    self.report_drops();
                    match queued.recv_timeout(DROP_CHECK) {
                        Ok(line) => line,
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                Err(TryRecvError::Disconnected) => break,
            };
            self.write(&line);
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
                "{lost} activity {noun} dropped while the output was stalled"
            ));
            self.reported = dropped;
        }
    }

    /// Write one line. A failed write loses the line and nothing else: there is nowhere to report it.
    fn write(&mut self, line: &str) {
        let _ = writeln!(self.out, "{line}").and_then(|()| self.out.flush());
    }
}

/// A peer-named path as it may appear on a line: control characters escaped and the length capped. A
/// raw newline forges a line, a carriage return rewrites one, and ESC drives a terminal, so none reaches
/// the writer as-is. `char::escape_debug` escapes C0 and C1 controls, DEL, and the format characters
/// that reorder or hide text (a bidi override, a zero-width space), and leaves printable text alone
/// except grapheme-extended marks, which it also escapes (a combining accent renders as `\u{...}`).
/// [`BLANK_LETTERS`] render as `\u{...}` too.
///
/// Escapes are written whole: when the next complete escape would pass the cap, the render writes the
/// `...` cut marker and stops, so the cut never lands inside a sequence.
struct Escaped<'a>(&'a Path);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut written = 0usize;
        for ch in self.0.to_string_lossy().chars() {
            let blank = BLANK_LETTERS.contains(&ch);
            // The width is the whole escape's, so the cap check below never admits half of one.
            let width = if blank {
                ch.escape_unicode().len()
            } else {
                ch.escape_debug().len()
            };
            if written + width > MAX_RENDERED_PATH {
                return f.write_str("...");
            }
            if blank {
                write!(f, "{}", ch.escape_unicode())?;
            } else {
                write!(f, "{}", ch.escape_debug())?;
            }
            written += width;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "activity_tests.rs"]
mod activity_tests;
