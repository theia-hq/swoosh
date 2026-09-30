//! The refusal render: after admission the typed code chooses the phrase, never the detail prose, so a
//! rate-limited or busy run does not read as a missing service (the render table in
//! `notes/design/typed-refusal-and-errors.md`); and the peer's detail prints escaped.

use bifrost::RefusalDetail;
use measure::{MethodRefusal, Refusal};

use super::refusal_line;

/// A method refusal carrying `detail`.
fn method(code: MethodRefusal, detail: &str) -> Refusal {
    Refusal::Method {
        code,
        detail: RefusalDetail::bounded(detail),
    }
}

/// Each `MethodRefusal` code renders its own line: a missing method names the method, a rate limit or a
/// busy service reports the bound that stopped the run.
#[test]
fn a_method_refusal_renders_its_typed_code() {
    assert_eq!(
        refusal_line(
            "alice",
            &method(MethodRefusal::WrongMethod, "this service speaks ping")
        ),
        "alice does not serve `speed`: this service speaks ping"
    );
    assert_eq!(
        refusal_line(
            "alice",
            &method(MethodRefusal::RateLimited, "over the byte cap")
        ),
        "alice is rate limited: over the byte cap"
    );
    assert_eq!(
        refusal_line("alice", &method(MethodRefusal::Busy, "one run at a time")),
        "alice is busy: one run at a time"
    );
}

/// A peer's detail holding a carriage return, an ESC CSI sequence and a bidi override prints as escapes on
/// one line, whether the peer refused the dial or the method.
#[test]
fn a_hostile_refusal_prints_escaped() {
    let hostile = "no\r\u{1b}[2Kalice: 900 MiB/s\u{202e}";
    let escaped = r"no\r\u{1b}[2Kalice: 900 MiB/s\u{202e}";
    let dial = Refusal::Stream(bifrost::Refusal::Unavailable {
        detail: RefusalDetail::bounded(hostile),
    });
    let refused_the_method = method(MethodRefusal::Busy, hostile);
    for (refusal, line) in [
        (
            dial,
            format!("alice: reached, but refused: unavailable: {escaped}"),
        ),
        (refused_the_method, format!("alice is busy: {escaped}")),
    ] {
        let printed = refusal_line("alice", &refusal);
        assert_eq!(printed, line);
        assert!(
            !printed.contains(['\r', '\n', '\u{1b}', '\u{202e}']),
            "no raw byte of the peer's reaches the line: {printed:?}"
        );
    }
}
