//! Unit tests for `serve`'s stop classification: a GRACEFUL stop is a typed [`Stopped`] the run reports and
//! exits 0 on, and an ERRORED teardown never becomes one (it stays an `Err` the run propagates, so the
//! process exits non-zero). The end-to-end proof that a member `control.stop` makes the exposer return `Ok`
//! (which the run turns into [`Stopped::Requested`], exit 0) lives in `tests/gated_stop.rs`.

use std::path::PathBuf;

use nauthy::{Denylist, Gate, VerifyKey};

use super::{FetchScope, Stopped};

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

/// A `name=fetch:<origin>` service is a NAMED, origin-scoped fetch: `extract` strips the origin into the
/// allowlist and rewrites the entry to a bare `fetch:` the tunnel core parses as an ordinary handler, so the
/// name survives and the origin scopes the handler. Two such services yield two named, origin-scoped fetches.
#[test]
fn named_fetch_origins_are_extracted_and_the_entries_become_bare_fetch() {
    let mut requested = vec![
        "news=fetch:https://news.example".to_owned(),
        "apple=fetch:https://apple.example".to_owned(),
    ];
    let fetch = FetchScope::extract(&mut requested).expect("origins parse");

    assert_eq!(
        requested,
        vec!["news=fetch:".to_owned(), "apple=fetch:".to_owned()],
        "each origin-scoped entry is rewritten to a bare `fetch:` under its name, so the tunnel core \
         parses it as an ordinary handler"
    );
    assert!(
        !fetch.allow.is_unconstrained(),
        "two declared origins make a non-empty allowlist"
    );
    assert!(fetch.exposed, "two fetch services are exposed");
}

/// A bare `fetch:` is the UNSCOPED singleton: `extract` leaves it untouched and contributes no origin, so
/// the handler's allowlist stays empty (any public origin). This is the back-compat arm the grammar must
/// keep: bare `fetch:` self-names and is unconstrained; `name=fetch:<origin>` is a named, scoped multi.
#[test]
fn bare_fetch_is_left_untouched_and_unconstrained() {
    let mut requested = vec!["fetch:".to_owned()];
    let fetch = FetchScope::extract(&mut requested).expect("no origins to parse");

    assert_eq!(
        requested,
        vec!["fetch:".to_owned()],
        "a bare `fetch:` is not an origin-scoped entry, so it passes through unchanged"
    );
    assert!(
        fetch.allow.is_unconstrained(),
        "a bare `fetch:` declares no origin, so the allowlist is empty (unconstrained)"
    );
    assert!(
        fetch.exposed,
        "a bare `fetch:` still exposes a fetch service, even though it declares no origin"
    );
}

/// Non-fetch services are untouched, and a `fetch:<origin>` alongside them is the only entry rewritten, so
/// extraction is scoped to fetch and does not disturb the rest of the requested set.
#[test]
fn non_fetch_services_pass_through_and_only_fetch_is_rewritten() {
    let mut requested = vec![
        "ping:".to_owned(),
        "web=127.0.0.1:8080".to_owned(),
        "gh=fetch:https://api.github.com".to_owned(),
    ];
    FetchScope::extract(&mut requested).expect("origin parses");

    assert_eq!(
        requested,
        vec![
            "ping:".to_owned(),
            "web=127.0.0.1:8080".to_owned(),
            "gh=fetch:".to_owned(),
        ],
        "only the fetch entry is rewritten; ping and the raw forward are left exactly as given"
    );
}

/// A malformed origin fails at expose time with a teaching error, not at dial time as an opaque refusal, so
/// the operator learns of the typo when they type it.
#[test]
fn a_malformed_fetch_origin_is_refused_at_expose_time() {
    let mut requested = vec!["bad=fetch:not a url".to_owned()];
    assert!(
        FetchScope::extract(&mut requested).is_err(),
        "an unparseable origin is refused when the service is declared"
    );
}

/// An empty, non-persisting family gate, so a refusal test can exercise the GATED (non-open) arm without
/// standing up a signet. The path is never written; `Denylist::empty` needs no file to exist.
fn gated() -> Gate {
    Gate::family(VerifyKey::new([1u8; 32]), Denylist::empty(PathBuf::new()))
}

/// MAJOR-1 (delib-13 Adversary): a `serve fetch: --public` (an unconstrained public fetch) is an open egress
/// relay and is REFUSED at build time with a TEACHING error that names the problem and the fix, mirroring the
/// sshd-cannot-be-public refusal at `Exposer::new`.
#[test]
fn an_unconstrained_public_fetch_is_refused_as_an_open_relay() {
    let mut requested = vec!["fetch:".to_owned()];
    let fetch = FetchScope::extract(&mut requested).expect("bare fetch parses");
    let error = fetch
        .refuse_open_relay(&Gate::Open)
        .expect_err("a public bare fetch is an open relay and must be refused");
    let message = format!("{error}");
    assert!(
        message.contains("origin-scoped") && message.contains("open relay"),
        "the refusal teaches the fix (origin-scope it) and names the problem (an open relay): {message:?}"
    );
}

/// A `serve api=fetch:https://origin --public` (a SCOPED public fetch) is exactly the safe, intended shape:
/// the origin allowlist is armed, so the same open gate is ALLOWED.
#[test]
fn a_scoped_public_fetch_is_allowed() {
    let mut requested = vec!["api=fetch:https://origin.example".to_owned()];
    let fetch = FetchScope::extract(&mut requested).expect("origin parses");
    assert!(
        fetch.refuse_open_relay(&Gate::Open).is_ok(),
        "a public fetch scoped to an origin is armed, not an open relay"
    );
}

/// A bare `fetch:` behind the FAMILY gate stays legal: the gate is the terminator, so an empty allowlist is
/// not an open relay. Only the PUBLIC + empty combination is refused.
#[test]
fn a_gated_bare_fetch_is_allowed() {
    let mut requested = vec!["fetch:".to_owned()];
    let fetch = FetchScope::extract(&mut requested).expect("bare fetch parses");
    assert!(
        fetch.refuse_open_relay(&gated()).is_ok(),
        "a gated (member-only) bare fetch is unchanged; the family gate terminates it"
    );
}

/// A `--public` node that serves NO fetch (its allowlist is empty only because it declared no fetch) is not
/// an open relay: `exposed` is false, so the refusal does not fire on an unrelated public ping/speed node.
#[test]
fn a_public_node_without_fetch_is_not_refused() {
    let mut requested = vec!["ping:".to_owned(), "speed:".to_owned()];
    let fetch = FetchScope::extract(&mut requested).expect("no fetch to parse");
    assert!(!fetch.exposed, "no fetch service is exposed");
    assert!(
        fetch.refuse_open_relay(&Gate::Open).is_ok(),
        "an empty allowlist with no fetch service is not an open relay"
    );
}
