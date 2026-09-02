//! Unit tests for `serve`'s stop classification: a GRACEFUL stop is a typed [`Stopped`] the run reports and
//! exits 0 on, and an ERRORED teardown never becomes one (it stays an `Err` the run propagates, so the
//! process exits non-zero). The end-to-end proof that a member `control.stop` makes the exposer return `Ok`
//! (which the run turns into [`Stopped::Requested`], exit 0) lives in `tests/gated_stop.rs`.

use super::Stopped;

/// Every graceful-stop reason reports a distinct, non-empty line, so a CI action log (the qat teardown)
/// reads a deliberate stop as a clean end rather than a bare exit. The line names WHY the node stopped.
#[test]
fn each_graceful_stop_reason_has_a_distinct_legible_message() {
    let requested = Stopped::Requested.message();
    let interrupted = Stopped::Interrupted.message();

    assert!(
        requested.contains("gracefully"),
        "an owner-requested stop reads as a graceful success: {requested:?}"
    );
    assert!(
        interrupted.contains("interrupted"),
        "a Ctrl-C reads as an interrupt: {interrupted:?}"
    );
    assert_ne!(
        requested, interrupted,
        "the two graceful reasons print distinct lines, so a log tells them apart"
    );
}

/// `Stopped` exists ONLY on the success path: it has an arm for each way an owner GRACEFULLY stops the
/// node (a requested `control.stop`/`--for`, or a Ctrl-C), and NO arm for a failure. A real teardown error
/// stays an `Err` the run propagates, so a graceful stop and an errored teardown are unconflatable by
/// construction: this is why a deliberate `swoosh stop` exits 0 while a crash exits non-zero.
#[test]
fn stopped_has_an_arm_only_for_graceful_reasons() {
    // A total match over `Stopped`: every arm is a graceful (exit-0) reason, so adding a non-graceful arm
    // would fail to compile here, forcing the author to keep failures OFF this type and on the `Err` path.
    for reason in [Stopped::Requested, Stopped::Interrupted] {
        let graceful = match reason {
            Stopped::Requested | Stopped::Interrupted => true,
        };
        assert!(graceful, "{reason:?} is a graceful, exit-0 stop");
    }
}
