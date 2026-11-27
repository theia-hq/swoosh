//! The activity renderer's guards, asserted on the bytes a writer receives: the sender leads a row and a
//! hostile peer-named path is escaped and cut to its room at the one render site, a stalled writer never blocks the engine's report call,
//! the queue holds exactly its bound while the rest are dropped and counted, and the count reaches the
//! same writer once it moves again.

use core::time::Duration;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::{io, thread};

use transfer::{Received, ReceivedSink as _};

use super::{Activity, Book};
use crate::contacts::Contacts;
use crate::escape::BLANK_LETTERS;

/// Long enough that a green run never waits on it; a red run fails with a message rather than hanging.
const PATIENCE: Duration = Duration::from_secs(5);

/// A writer that records every byte and can hold its first write until the test releases it. Dropping
/// it signals `closed`, which is how a test knows the renderer thread drained and exited.
struct Capture {
    written: Arc<Mutex<Vec<u8>>>,
    stall: Option<(Sender<()>, Receiver<()>)>,
    closed: Sender<()>,
}

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some((entered, release)) = self.stall.take() {
            let _ = entered.send(());
            let _ = release.recv();
        }
        self.written
            .lock()
            .expect("the capture lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let _ = self.closed.send(());
    }
}

/// What a test holds of a [`Capture`] it handed to a renderer.
struct Captured {
    written: Arc<Mutex<Vec<u8>>>,
    closed: Receiver<()>,
}

impl Captured {
    /// Every byte the renderer wrote, once it has drained and dropped its writer. Call after the
    /// [`Activity`] and every sink it issued are dropped.
    fn bytes(self) -> Vec<u8> {
        self.closed
            .recv_timeout(PATIENCE)
            .expect("the renderer drains and exits once every sink is dropped");
        self.written.lock().expect("the capture lock").clone()
    }
}

/// A writer that records, and the handle a test reads it back through.
fn capture() -> (Capture, Captured) {
    let written = Arc::new(Mutex::new(Vec::new()));
    let (closed_tx, closed) = mpsc::channel();
    (
        Capture {
            written: Arc::clone(&written),
            stall: None,
            closed: closed_tx,
        },
        Captured { written, closed },
    )
}

/// A book that names no sender, so every row carries the sender's whole key.
fn nameless() -> Book {
    Box::new(Contacts::default)
}

/// A book that names the sender `name`, as a home that saved its key would.
fn named(name: &'static str) -> Book {
    Box::new(move || {
        let mut book = Contacts::default();
        book.save(&name.parse().expect("a name"), sender().node_id())
            .expect("the name is free");
        book
    })
}

/// The node every fact here is pushed by.
fn sender() -> crate::testkit::TestNode {
    crate::testkit::TestNode::seeded(7)
}

fn landed(path: &str, bytes: u64) -> Received {
    Received {
        path: PathBuf::from(path),
        bytes,
        from: sender().verify_key(),
    }
}

/// `rows` with each row's clock read as `HH:MM` and replaced by `00:00`, so a row's bytes are asserted
/// whatever the time; a continuation line, indented, is kept as it is.
fn unclocked(rows: &str) -> String {
    rows.lines()
        .map(|line| {
            if line.len() < 5 || line.starts_with(' ') || line.starts_with("warning: ") {
                return format!("{line}\n");
            }
            let (clock, rest) = line.split_at(5);
            let digits = clock.bytes().filter(u8::is_ascii_digit).count();
            assert!(
                digits == 4 && clock.as_bytes()[2] == b':',
                "a clock: {line:?}"
            );
            format!("00:00{rest}\n")
        })
        .collect()
}

/// Everything one fact renders to, end to end, the sender named `me/laptop`: the sink, the queue, the
/// renderer thread, the writer. Held as a `String` so a failure prints the bytes escaped; string
/// equality is byte equality.
fn rendered(path: &str, bytes: u64) -> String {
    rendered_by(named("me/laptop"), path, bytes)
}

/// [`rendered`], the sender named by `names`.
fn rendered_by(names: Book, path: &str, bytes: u64) -> String {
    let (out, captured) = capture();
    let activity = Activity::spawn(out, names).expect("the renderer starts");
    activity.recv().received(landed(path, bytes));
    drop(activity);
    String::from_utf8(captured.bytes()).expect("a rendered row is utf-8")
}

/// A row leads with the clock and the sender, as this home names it, and the peer's file name is last,
/// so a name can never print a sender of its own before the real one.
#[test]
fn receive_row_leads_with_the_sender() {
    assert_eq!(
        unclocked(&rendered("photo.bin", 30_000_000)),
        "00:00  me/laptop sent 28.6 MiB: photo.bin\n"
    );
}

/// A sender this home has no name for prints its whole key, so the row breaks after the size and the
/// file takes a line of its own under the sender. At the widest size the first line is 79 columns.
#[test]
fn a_nameless_sender_breaks_after_the_size() {
    let key = sender().verify_key();
    let rows = rendered_by(nameless(), "notes.txt", 999 * 1024 * 1024 + 900 * 1024);
    assert_eq!(
        unclocked(&rows),
        format!("00:00  {key} sent 999.9 MiB:\n       notes.txt\n")
    );
    assert_eq!(rows.lines().next().map(str::len), Some(79), "{rows}");
}

/// A name for the sender long enough to leave the file less than its floor puts the file on a line of
/// its own, so the file keeps room to be read.
#[test]
fn a_long_sender_name_puts_the_file_on_its_own_line() {
    let rows = rendered_by(
        named("alice/a-machine-with-a-very-long-name-indeed-yes-it-is"),
        "notes.txt",
        3,
    );
    assert_eq!(
        unclocked(&rows),
        "00:00  alice/a-machine-with-a-very-long-name-indeed-yes-it-is sent 3 B:\n       notes.txt\n"
    );
}

/// A peer-named path carrying a newline, a carriage return, and an ESC sequence reaches the writer as
/// visible escapes on ONE line. The bytes are the assertion: no raw control byte and exactly one line
/// terminator, the renderer's own.
#[test]
fn a_hostile_received_path_is_escaped_in_the_rendered_bytes() {
    let line = rendered("evil\nname\u{1b}[31m\r.txt", 7);
    let bytes = line.as_bytes();
    assert!(
        !bytes.contains(&0x1b) && !bytes.contains(&b'\r'),
        "a raw ESC or carriage return reached the writer: {line:?}"
    );
    assert_eq!(
        bytes.iter().filter(|byte| **byte == b'\n').count(),
        1,
        "the peer's newline forged a second line: {line:?}"
    );
    assert_eq!(
        unclocked(&line),
        "00:00  me/laptop sent 7 B: evil\\nname\\u{1b}[31m\\r.txt\n",
        "every control character is escaped"
    );
}

/// The characters that hide or reorder text render escaped too: a C1 control, a bidi override, and a
/// zero-width space.
#[test]
fn a_path_that_reorders_or_hides_text_is_escaped() {
    assert_eq!(
        unclocked(&rendered("a\u{85}b\u{202e}c\u{200b}d", 1)),
        "00:00  me/laptop sent 1 B: a\\u{85}b\\u{202e}c\\u{200b}d\n",
    );
}

/// Letters that print as blank space render as escapes, so a name made of them is never an empty path.
#[test]
fn a_path_of_blank_letters_is_escaped() {
    let name: String = BLANK_LETTERS.iter().collect();
    assert_eq!(
        unclocked(&rendered(&name, 1)),
        "00:00  me/laptop sent 1 B: \\u{115f}\\u{1160}\\u{3164}\\u{ffa0}\\u{2800}\n",
    );
}

/// A long peer-named path cannot flood the row: it is cut to the room its line has left and marked.
#[test]
fn a_long_received_path_is_cut_to_its_room() {
    let long = "a".repeat(1024);
    assert_eq!(
        unclocked(&rendered(&long, 9)),
        format!("00:00  me/laptop sent 9 B: {}\u{2026}\n", "a".repeat(50)),
    );
}

/// A file name of wide glyphs fills at most the room its line has, counted at two columns for every
/// scalar that is not ASCII, so it can never wrap at column 80 and start a forged row with the text
/// after it. Each sample ends in a whole forged row; none reaches a line of its own.
#[test]
fn a_wide_peer_name_is_capped_by_display_width() {
    let forged = "00:48  me/boss sent 3.2 MiB: invoice.pdf";
    for wide in [
        "\u{6587}\u{4ef6}".repeat(40),
        "\u{ff21}\u{ff22}".repeat(40),
        "\u{200b}".repeat(80),
        "\u{1f600}".repeat(40),
        "a".repeat(80),
    ] {
        let name = format!("{wide}{forged}");
        for names in [named("me/laptop"), nameless()] {
            let rows = rendered_by(names, &name, 3_300_000);
            for line in rows.lines() {
                assert!(columns(line) < 80, "{line}");
                assert!(!line.starts_with("00:48"), "a forged row: {rows}");
            }
            assert!(!rows.contains(forged), "{rows}");
        }
    }
}

/// The bound, with the writer wedged: the renderer holds the first line inside a write that does not
/// return, the queue takes exactly its bound, and every report past it is dropped and counted, all
/// without the reporting thread ever waiting. Released, the writer receives exactly the lines that were
/// queued, in order, and then one notice counting the lines it lost. The queued rows render under one
/// read of the book.
#[test]
fn a_wedged_writer_never_blocks_a_report_and_the_queue_holds_its_bound() {
    const BACKLOG: usize = 4;
    const OVERFLOW: usize = 3;

    let (mut out, captured) = capture();
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    out.stall = Some((entered_tx, release_rx));
    // Counts the book's reads: one for the wedged row, then one for the whole queued batch.
    let reads = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&reads);
    let book = named("me/laptop");
    let book: Book = Box::new(move || {
        counted.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        book()
    });
    let activity = Activity::with_backlog(out, book, BACKLOG).expect("the renderer starts");
    let sink = activity.recv();

    // The first line reaches the writer and wedges it, so everything after it can only queue.
    sink.received(landed("first", 1));
    entered
        .recv_timeout(PATIENCE)
        .expect("the renderer takes the first line into the wedged write");

    // Report the bound plus an overflow from a thread of its own, so a report that waits for the writer
    // fails this test instead of hanging it.
    let (reported_tx, reported) = mpsc::channel();
    thread::spawn(move || {
        for n in 0..BACKLOG + OVERFLOW {
            sink.received(landed(&format!("queued-{n}"), 1));
        }
        let _ = reported_tx.send(sink);
    });
    let sink = match reported.recv_timeout(PATIENCE) {
        Ok(sink) => sink,
        Err(RecvTimeoutError::Timeout) => {
            panic!("a report waited on the wedged writer: the engine's stream would stall")
        }
        Err(RecvTimeoutError::Disconnected) => panic!("the reporting thread died"),
    };
    assert_eq!(
        activity.dropped(),
        OVERFLOW as u64,
        "past the bound, each report is dropped and counted"
    );

    let _ = release.send(());
    drop(sink);
    drop(activity);
    let lines = unclocked(&String::from_utf8(captured.bytes()).expect("the lines are utf-8"));
    let expected: Vec<String> = core::iter::once("00:00  me/laptop sent 1 B: first".to_owned())
        .chain((0..BACKLOG).map(|n| format!("00:00  me/laptop sent 1 B: queued-{n}")))
        .chain(core::iter::once(format!(
            "warning: {OVERFLOW} activity lines dropped while the output was stalled"
        )))
        .collect();
    assert_eq!(
        reads.load(core::sync::atomic::Ordering::Relaxed),
        2,
        "the book is read once for each batch the renderer drains, never once a row"
    );
    assert_eq!(
        lines.lines().collect::<Vec<_>>(),
        expected,
        "the writer receives the wedged line, exactly the queued ones, then the drop count"
    );
}

/// A drop that no later line follows is still reported, while the node runs. The drop is counted only
/// after the renderer has written its last line and gone idle, the race a fast writer opens between a
/// refused line and its count, so only the renderer's own idle check can see it. The node stays up (the
/// handle is held) until the notice is seen.
#[test]
fn a_drop_with_no_later_line_is_reported_while_the_node_runs() {
    let (out, captured) = capture();
    let activity = Activity::spawn(out, named("me/laptop")).expect("the renderer starts");
    let line = "00:00  me/laptop sent 1 B: last\n";
    let notice = "warning: 1 activity line dropped while the output was stalled\n";
    activity.recv().received(landed("last", 1));
    wait_for_bytes(&captured, line);
    // Past the line's own drain: the renderer has checked the count once and is waiting for work.
    thread::sleep(Duration::from_millis(100));
    activity
        .dropped
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let both = format!("{line}{notice}");
    wait_for_bytes(&captured, &both);
    drop(activity);
    assert_eq!(
        unclocked(&String::from_utf8(captured.bytes()).expect("utf-8")),
        both,
        "the notice is said once, after the line"
    );
}

/// Wait until the writer holds exactly `expected`, failing with what it does hold after [`PATIENCE`].
fn wait_for_bytes(captured: &Captured, expected: &str) {
    let deadline = std::time::Instant::now() + PATIENCE;
    loop {
        let written = captured.written.lock().expect("the capture lock").clone();
        if unclocked(&String::from_utf8_lossy(&written)) == expected {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the writer never reached {expected:?}: {:?}",
            String::from_utf8_lossy(&written)
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// The most columns `text` can fill in any terminal, counted here apart from the code under test: one per
/// ASCII scalar, two per any other.
fn columns(text: &str) -> usize {
    text.chars()
        .map(|scalar| if scalar.is_ascii() { 1 } else { 2 })
        .sum()
}
