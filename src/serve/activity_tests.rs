//! The activity renderer's guards, asserted on the bytes a writer receives: a hostile peer-named path is
//! escaped and capped at the one render site, a stalled writer never blocks the engine's report call,
//! the queue holds exactly its bound while the rest are dropped and counted, and the count reaches the
//! same writer once it moves again.

use core::time::Duration;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::{io, thread};

use transfer::{Received, ReceivedSink as _};

use super::{Activity, BLANK_LETTERS, MAX_RENDERED_PATH};

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

fn recv_route() -> nauthy::Service {
    "recv".parse().expect("a valid service name")
}

fn landed(path: &str, bytes: u64) -> Received {
    Received {
        path: PathBuf::from(path),
        bytes,
    }
}

/// Everything one fact renders to, end to end: the sink, the queue, the renderer thread, the writer.
/// Held as a `String` so a failure prints the bytes escaped; string equality is byte equality.
fn rendered(path: &str, bytes: u64) -> String {
    let (out, captured) = capture();
    let activity = Activity::spawn(out).expect("the renderer starts");
    activity.recv(recv_route()).received(landed(path, bytes));
    drop(activity);
    String::from_utf8(captured.bytes()).expect("a rendered line is utf-8")
}

/// A peer-named path carrying a newline, a carriage return, and an ESC sequence reaches the writer as
/// visible escapes on ONE line, service-qualified. The bytes are the assertion: no raw control byte and
/// exactly one line terminator, the renderer's own.
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
        line, "recv: received evil\\nname\\u{1b}[31m\\r.txt (7 bytes)\n",
        "the line is service-qualified and every control character is escaped"
    );
}

/// The characters that hide or reorder text render escaped too: a C1 control, a bidi override, and a
/// zero-width space.
#[test]
fn a_path_that_reorders_or_hides_text_is_escaped() {
    assert_eq!(
        rendered("a\u{85}b\u{202e}c\u{200b}d", 1),
        "recv: received a\\u{85}b\\u{202e}c\\u{200b}d (1 bytes)\n",
    );
}

/// Letters that print as blank space render as escapes, so a name made of them is never an empty path.
#[test]
fn a_path_of_blank_letters_is_escaped() {
    let name: String = BLANK_LETTERS.iter().collect();
    assert_eq!(
        rendered(&name, 1),
        "recv: received \\u{115f}\\u{1160}\\u{3164}\\u{ffa0}\\u{2800} (1 bytes)\n",
    );
}

/// A long peer-named path cannot flood the line: the path renders at most [`MAX_RENDERED_PATH`]
/// characters and marks the cut.
#[test]
fn a_long_received_path_is_capped() {
    let long = "a".repeat(MAX_RENDERED_PATH * 4);
    let expected = format!(
        "recv: received {}... (9 bytes)\n",
        "a".repeat(MAX_RENDERED_PATH)
    );
    assert_eq!(rendered(&long, 9), expected);
}

/// The cap cuts between escapes, never inside one: the 6-character ESC escape does not fit the last
/// slot whole, so the render backs off to the marker instead of writing a malformed half-escape.
#[test]
fn a_cap_cut_never_splits_an_escape() {
    let name = format!("{}\u{1b}", "a".repeat(MAX_RENDERED_PATH - 1));
    let expected = format!(
        "recv: received {}... (2 bytes)\n",
        "a".repeat(MAX_RENDERED_PATH - 1)
    );
    assert_eq!(rendered(&name, 2), expected);
}

/// Two receive routes on one node name themselves: the same path lands on two lines that say which
/// route received it.
#[test]
fn each_route_leads_its_own_line() {
    let (out, captured) = capture();
    let activity = Activity::spawn(out).expect("the renderer starts");
    activity
        .recv("alice".parse().expect("a valid service name"))
        .received(landed("notes.txt", 3));
    activity
        .recv("bob".parse().expect("a valid service name"))
        .received(landed("notes.txt", 4));
    drop(activity);
    assert_eq!(
        String::from_utf8(captured.bytes()).expect("the lines are utf-8"),
        "alice: received notes.txt (3 bytes)\nbob: received notes.txt (4 bytes)\n",
    );
}

/// The bound, with the writer wedged: the renderer holds the first line inside a write that does not
/// return, the queue takes exactly its bound, and every report past it is dropped and counted, all
/// without the reporting thread ever waiting. Released, the writer receives exactly the lines that were
/// queued, in order, and then one notice counting the lines it lost.
#[test]
fn a_wedged_writer_never_blocks_a_report_and_the_queue_holds_its_bound() {
    const BACKLOG: usize = 4;
    const OVERFLOW: usize = 3;

    let (mut out, captured) = capture();
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    out.stall = Some((entered_tx, release_rx));
    let activity = Activity::with_backlog(out, BACKLOG).expect("the renderer starts");
    let sink = activity.recv(recv_route());

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
    let lines = String::from_utf8(captured.bytes()).expect("the lines are utf-8");
    let expected: Vec<String> = core::iter::once("recv: received first (1 bytes)".to_owned())
        .chain((0..BACKLOG).map(|n| format!("recv: received queued-{n} (1 bytes)")))
        .chain(core::iter::once(format!(
            "{OVERFLOW} activity lines dropped while the output was stalled"
        )))
        .collect();
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
    let activity = Activity::spawn(out).expect("the renderer starts");
    let line = "recv: received last (1 bytes)\n";
    let notice = "1 activity line dropped while the output was stalled\n";
    activity.recv(recv_route()).received(landed("last", 1));
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
        captured.bytes(),
        both.as_bytes(),
        "the notice is said once, after the line"
    );
}

/// Wait until the writer holds exactly `expected`, failing with what it does hold after [`PATIENCE`].
fn wait_for_bytes(captured: &Captured, expected: &str) {
    let deadline = std::time::Instant::now() + PATIENCE;
    loop {
        let written = captured.written.lock().expect("the capture lock").clone();
        if written == expected.as_bytes() {
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
