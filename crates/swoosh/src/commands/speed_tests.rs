//! The post-admission refusal render: the typed code chooses the phrase, never the detail prose. A
//! rate-limited or busy run must not read as a missing service (the render table in
//! `notes/design/typed-refusal-and-errors.md`).

use measure::MethodRefusal;

use super::refusal_line;

/// Each `MethodRefusal` code renders its own line: a missing method names the method, a rate limit or a
/// busy service reports the bound that stopped the run.
#[test]
fn a_method_refusal_renders_its_typed_code() {
    assert_eq!(
        refusal_line(
            "alice",
            MethodRefusal::WrongMethod,
            "this service speaks ping"
        ),
        "alice does not serve `speed`: this service speaks ping"
    );
    assert_eq!(
        refusal_line("alice", MethodRefusal::RateLimited, "over the byte cap"),
        "alice is rate limited: over the byte cap"
    );
    assert_eq!(
        refusal_line("alice", MethodRefusal::Busy, "one run at a time"),
        "alice is busy: one run at a time"
    );
}
