//! Unit tests for `serve`'s stop classification: a GRACEFUL stop is a typed [`Stopped`] the run reports and
//! exits 0 on, and an ERRORED teardown never becomes one (it stays an `Err` the run propagates, so the
//! process exits non-zero). The end-to-end proof that a member `control.stop` makes the exposer return `Ok`
//! (which the run turns into [`Stopped::Requested`], exit 0) lives in `tests/gated_stop.rs`.

use core::net::SocketAddr;
use std::collections::{HashMap, HashSet};

use tightbeam::tunnel::{Exposer, ManifestEntry, Posture, PublicRequest, Services, TargetKind};

use super::{
    FetchScope, MdnsState, ReachKind, Stopped, describe, display_targets, reach_section,
    render_ready_banner, serving_section,
};

/// A gated handler entry for a banner test (the common case: everything behind the family gate).
fn entry_gated(name: &str, kind: TargetKind, amplifier: bool) -> ManifestEntry {
    ManifestEntry {
        name: name.to_owned(),
        posture: Posture::Gated,
        kind,
        amplifier,
    }
}

/// An opened (public) handler entry for a banner test.
fn entry_open(name: &str, kind: TargetKind, amplifier: bool) -> ManifestEntry {
    ManifestEntry {
        name: name.to_owned(),
        posture: Posture::Open,
        kind,
        amplifier,
    }
}

/// The default `swoosh serve` manifest (gated ping + speed + the two control.* reads), name-sorted as the
/// exposer returns it, so a banner test exercises the same shape the product path builds.
fn default_manifest() -> Vec<ManifestEntry> {
    vec![
        entry_gated("control.services", TargetKind::Handler, false),
        entry_gated("control.stop", TargetKind::Handler, false),
        entry_gated("ping", TargetKind::Handler, true),
        entry_gated("speed", TargetKind::Handler, true),
    ]
}

/// The display map the default serve builds (control.* + ping + speed point at their own schemes).
fn default_targets() -> HashMap<String, String> {
    display_targets(&[
        "ping=ping:".to_owned(),
        "speed=speed:".to_owned(),
        "control.stop=control.stop:".to_owned(),
        "control.services=control.services:".to_owned(),
    ])
}

/// The default iroh + mDNS-on banner: a copy-clean full id, an `internet` channel that says "automatic" and
/// never names the backend, an mDNS LAN line, one family-gated group with the `control.*` fold, no public
/// group, and the plain stop line.
#[test]
fn the_default_banner_tells_reach_and_posture_without_backend_jargon() {
    let banner = render_ready_banner(
        "bf01exampleid",
        ReachKind::Internet,
        MdnsState::Available,
        &[],
        &default_manifest(),
        &default_targets(),
        &HashSet::new(),
        "ctrl-c to stop",
    );

    assert!(
        banner.starts_with("swoosh ready\n\n    bf01exampleid\n\n"),
        "{banner}"
    );
    assert!(banner.contains("how peers reach you"), "{banner}");
    assert!(
        banner.contains("internet"),
        "an iroh node shows the internet channel: {banner}"
    );
    assert!(
        !banner.contains("iroh"),
        "the backend is never named: {banner}"
    );
    // "automatic" leads BOTH auto channels (the Newcomer fix), not just LAN.
    assert_eq!(banner.matches("automatic").count(), 2, "{banner}");
    assert!(
        banner.contains("(mDNS)"),
        "the LAN line is an mDNS tell: {banner}"
    );
    assert!(banner.contains("family-gated"), "{banner}");
    assert!(
        banner.contains("control.*")
            && !banner.contains("control.stop")
            && !banner.contains("control.services"),
        "the two control reads fold to one control.* line: {banner}"
    );
    assert!(
        !banner.contains("public"),
        "no public group when nothing is opened: {banner}"
    );
    assert!(banner.trim_end().ends_with("ctrl-c to stop"), "{banner}");
}

/// The mix banner: a public amplifier carries a QUIET inline caveat (no loud glyph), the public-UNSAFE group
/// sits last carrying the loudest marker, `name -> target` renders only when they differ, and the danger
/// vocabulary is monotonic (the `public` marker is strictly shorter/quieter than `public-UNSAFE`).
#[test]
fn the_mix_banner_keeps_one_monotonic_danger_vocabulary() {
    let manifest = vec![
        entry_open("logs", TargetKind::RawStream, false),
        entry_gated("ping", TargetKind::Handler, true),
        entry_open("speed", TargetKind::Handler, true),
        entry_gated("ssh", TargetKind::Handler, false),
    ];
    let targets = display_targets(&[
        "ping=ping:".to_owned(),
        "speed=speed:".to_owned(),
        "ssh=sshd:".to_owned(),
        "logs=file:/var/log/app.log".to_owned(),
    ]);
    let section = serving_section(&manifest, &targets, &HashSet::new());

    // `name -> target` only when they differ: `ssh -> sshd`, but `speed` alone (name == scheme).
    assert!(section.contains("ssh -> sshd"), "{section}");
    assert!(
        section.contains("logs -> file:/var/log/app.log"),
        "{section}"
    );
    assert!(
        section.contains("\n    speed ") || section.contains("\n    speed\n"),
        "a name that equals its scheme renders without an arrow: {section}"
    );
    // The public amplifier caveat is quiet prose, NOT a competing loud glyph.
    assert!(
        section.contains("unmetered: a stranger can drain your uplink"),
        "{section}"
    );
    assert!(
        !section.contains("[!]"),
        "the amplifier caveat is not a loud glyph: {section}"
    );

    // Groups are safest-first and the danger marker is monotonic down the list.
    let family = section.find("family-gated").expect("family group present");
    let public = section.find("public !").expect("public group present");
    let unsafe_grp = section
        .find("public-UNSAFE !!")
        .expect("public-UNSAFE group present");
    assert!(
        family < public && public < unsafe_grp,
        "safest-first ordering: {section}"
    );
}

/// The reach section flips the LAN line to a next-step down-state when mDNS is blocked, and a quirk node with
/// a routable hint prints a `direct` channel with the address on its own copy-clean line.
#[test]
fn the_reach_section_handles_blocked_mdns_and_direct_hints() {
    let blocked = reach_section(ReachKind::Internet, MdnsState::Blocked, &[]);
    assert!(blocked.contains("off; multicast blocked here"), "{blocked}");
    assert!(
        blocked.contains("over the internet"),
        "the down-state says what to do instead: {blocked}"
    );

    let routable: SocketAddr = "192.168.1.20:58131".parse().expect("valid addr");
    let quirk = reach_section(ReachKind::DirectOnly, MdnsState::Available, &[routable]);
    assert!(
        !quirk.contains("internet"),
        "a direct-only node shows no internet channel: {quirk}"
    );
    assert!(quirk.contains("direct"), "{quirk}");
    assert!(quirk.contains("hand a peer this address:"), "{quirk}");
    assert!(quirk.contains("192.168.1.20:58131"), "{quirk}");

    // A loopback-only bind reads "on this machine only", never "hand a peer" an un-handable address.
    let loop_addr: SocketAddr = "127.0.0.1:58131".parse().expect("valid addr");
    let local = reach_section(ReachKind::DirectOnly, MdnsState::Available, &[loop_addr]);
    assert!(local.contains("reachable on this machine only:"), "{local}");
    assert!(!local.contains("hand a peer"), "{local}");
}

/// A de-merged fetch service glosses by name (its synthetic scheme is unspellable, so it never leaks into the
/// `name -> target` arrow), while a plain forward shows its address.
#[test]
fn a_fetch_service_glosses_by_name_and_never_leaks_the_synthetic_scheme() {
    let entry = entry_gated("news", TargetKind::Handler, false);
    let mut fetch_names = HashSet::new();
    fetch_names.insert("news".to_owned());
    let (label, gloss) = describe(&entry, &HashMap::new(), &fetch_names);
    assert_eq!(label, "news", "no synthetic scheme in the label");
    assert!(gloss.contains("fetches"), "{gloss}");
    assert!(
        !label.contains("fetch_"),
        "the synthetic scheme never appears: {label}"
    );
}

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

/// Two `name=fetch:<origin>` services de-merge into TWO separate `FetchService`s, each with its own served
/// name, its OWN unspellable synthetic scheme, and ONLY its own origin scope. `extract` removes them from the
/// requested set (leaving the non-fetch entries for `Services::parse`).
#[test]
fn named_fetch_origins_de_merge_into_per_service_instances() {
    let mut requested = vec![
        "news=fetch:https://news.example".to_owned(),
        "apple=fetch:https://apple.example".to_owned(),
    ];
    let fetch = FetchScope::extract(&mut requested).expect("origins parse");

    assert!(
        requested.is_empty(),
        "fetch entries are removed from the set `Services::parse` then sees"
    );
    let services = fetch.services();
    assert_eq!(
        services.len(),
        2,
        "two fetch services de-merge into two instances"
    );
    let names: Vec<&str> = services.iter().map(super::FetchService::name).collect();
    assert!(
        names.contains(&"news") && names.contains(&"apple"),
        "each keeps its served name"
    );
    assert_ne!(
        services[0].scheme(),
        services[1].scheme(),
        "each fetch service gets its OWN synthetic scheme, never a shared one"
    );
    assert!(
        services.iter().all(|s| !s.allow().is_unconstrained()),
        "each declared its own origin, so each allowlist is scoped"
    );
}

/// A bare `fetch:` (no origin, no name) is the UNSCOPED singleton under the `default` name: `extract` gives it
/// its own instance with an empty (unconstrained) allowlist.
#[test]
fn bare_fetch_is_a_default_named_unconstrained_instance() {
    let mut requested = vec!["fetch:".to_owned()];
    let fetch = FetchScope::extract(&mut requested).expect("no origins to parse");

    assert!(requested.is_empty(), "the bare fetch entry is removed");
    let services = fetch.services();
    assert_eq!(services.len(), 1);
    assert_eq!(
        services[0].name(),
        "default",
        "a bare fetch entry defaults to the `default` name"
    );
    assert!(
        services[0].allow().is_unconstrained(),
        "a bare `fetch:` declares no origin, so its own allowlist is unconstrained"
    );
}

/// Non-fetch services pass through in order, and only fetch is de-merged out, so extraction is scoped to fetch
/// and does not disturb the rest of the requested set.
#[test]
fn non_fetch_services_pass_through_and_only_fetch_is_removed() {
    let mut requested = vec![
        "ping:".to_owned(),
        "web=127.0.0.1:8080".to_owned(),
        "gh=fetch:https://api.github.com".to_owned(),
    ];
    let fetch = FetchScope::extract(&mut requested).expect("origin parses");

    assert_eq!(
        requested,
        vec!["ping:".to_owned(), "web=127.0.0.1:8080".to_owned()],
        "the fetch entry is removed; ping and the raw forward are left exactly as given, in order"
    );
    assert_eq!(
        fetch.services().len(),
        1,
        "only the one fetch service is de-merged out"
    );
}

/// A malformed origin fails at expose time with a teaching error, not at dial time as an opaque refusal.
#[test]
fn a_malformed_fetch_origin_is_refused_at_expose_time() {
    let mut requested = vec!["bad=fetch:not a url".to_owned()];
    assert!(
        FetchScope::extract(&mut requested).is_err(),
        "an unparseable origin is refused when the service is declared"
    );
}

/// The synthetic per-service scheme is UNSPELLABLE (delib-39 B1): it carries a `_`, which the tunnel's
/// handler-scheme grammar rejects, so an operator entry `x=fetch_0:` is a parse error and can never resolve
/// onto a synthetic fetch instance. The de-merge builds it directly, bypassing that grammar.
#[test]
fn the_synthetic_fetch_scheme_is_unspellable_by_an_operator_entry() {
    let mut requested = vec!["news=fetch:https://news.example".to_owned()];
    let fetch = FetchScope::extract(&mut requested).expect("parse");
    let scheme = fetch.services()[0].scheme().to_owned();
    assert!(
        scheme.contains('_'),
        "the synthetic scheme carries the byte the grammar rejects: {scheme}"
    );
    // Spelled as an operator service entry, that same scheme is not a handler; it is a parse error.
    assert!(
        Services::parse(&[format!("x={scheme}:")]).is_err(),
        "`x={scheme}:` must be rejected by the handler-scheme grammar (the pivot cannot be spelled)"
    );
}

/// BLOCKER-3: a PUBLIC fetch instance holds ONLY its own origin scope, so it cannot reach a GATED fetch
/// instance's origins. De-merged, the public `pub` and the gated `internal` are separate instances under
/// separate schemes, each scoped to its OWN origin; there is no shared allowlist to over-permit.
#[test]
fn a_public_fetch_instance_cannot_reach_a_gated_fetch_s_origins() {
    let mut requested = vec![
        "pub=fetch:https://public.example".to_owned(),
        "internal=fetch:http://10.0.0.5".to_owned(),
    ];
    let fetch = FetchScope::extract(&mut requested).expect("parse");
    let public = fetch
        .services()
        .iter()
        .find(|s| s.name() == "pub")
        .expect("pub");
    let internal = fetch
        .services()
        .iter()
        .find(|s| s.name() == "internal")
        .expect("internal");

    assert_ne!(
        public.scheme(),
        internal.scheme(),
        "the public and gated fetches are distinct instances under distinct schemes"
    );
    // The public instance is scoped to its OWN origin (not unconstrained), and it is a SEPARATE allowlist
    // from the gated instance's: there is no shared list holding the internal origin for it to reach. (That
    // an allowlist admits ONLY its listed origin, exact-match, is proven in `fetch`'s own origin tests.)
    assert!(
        !public.allow().is_unconstrained(),
        "the public fetch is scoped to its own origin only"
    );
    assert!(
        !internal.allow().is_unconstrained(),
        "the gated fetch holds its own internal origin only"
    );
}

/// BLOCKER-3 masking sub-attack: an origin-scoped GATED fetch beside a bare PUBLIC fetch must NOT mask the
/// open relay. Per-service, `refuse_open_relay` reasons about the PUBLIC fetch's own scope, so a bare public
/// fetch is refused even when a second, scoped, gated fetch is present.
#[test]
fn a_scoped_gated_fetch_does_not_mask_a_bare_public_open_relay() {
    let mut requested = vec![
        "internal=fetch:http://10.0.0.5".to_owned(), // scoped, gated
        "pub=fetch:".to_owned(),                     // bare, public
    ];
    let fetch = FetchScope::extract(&mut requested).expect("parse");
    let public = PublicRequest::new(["pub".to_owned()]);
    assert!(
        fetch.refuse_open_relay(&public).is_err(),
        "a bare public fetch is an open relay even beside a scoped gated fetch (no masking)"
    );
}

/// MAJOR-1: a bare, unconstrained fetch NAMED in `--public` is refused at build time with a teaching error
/// that names the problem and the fix, mirroring the sshd-cannot-be-public refusal.
#[test]
fn an_unconstrained_public_fetch_is_refused_as_an_open_relay() {
    let mut requested = vec!["api=fetch:".to_owned()];
    let fetch = FetchScope::extract(&mut requested).expect("bare fetch parses");
    let public = PublicRequest::new(["api".to_owned()]);
    let error = fetch
        .refuse_open_relay(&public)
        .expect_err("a public bare fetch is an open relay and must be refused");
    let message = format!("{error}");
    assert!(
        message.contains("origin-scoped") && message.contains("open relay"),
        "the refusal teaches the fix (origin-scope it) and names the problem (an open relay): {message:?}"
    );
}

/// A `serve api=fetch:https://origin --public api` (a SCOPED public fetch) is the safe, intended shape: its
/// own allowlist is armed, so it is allowed.
#[test]
fn a_scoped_public_fetch_is_allowed() {
    let mut requested = vec!["api=fetch:https://origin.example".to_owned()];
    let fetch = FetchScope::extract(&mut requested).expect("origin parses");
    let public = PublicRequest::new(["api".to_owned()]);
    assert!(
        fetch.refuse_open_relay(&public).is_ok(),
        "a public fetch scoped to an origin is armed, not an open relay"
    );
}

/// A bare `fetch:` that is NOT named in `--public` stays legal: it is gated (the family gate terminates it),
/// so an unconstrained allowlist is not an open relay. Only a PUBLIC unconstrained fetch is refused.
#[test]
fn a_gated_bare_fetch_is_allowed() {
    let mut requested = vec!["api=fetch:".to_owned()];
    let fetch = FetchScope::extract(&mut requested).expect("bare fetch parses");
    // `api` is served but NOT public.
    assert!(
        fetch.refuse_open_relay(&PublicRequest::none()).is_ok(),
        "a gated (member-only) bare fetch is unchanged; the family gate terminates it"
    );
}

/// A minimal family gate for a construction test: an empty, non-persisting family gate, so `with_public`'s
/// per-service proof runs without standing up a signet.
fn gated() -> nauthy::Gate {
    nauthy::Gate::family(
        nauthy::VerifyKey::new([1u8; 32]),
        nauthy::Denylist::empty(std::path::PathBuf::new()),
    )
}

/// `serve speed --public speed` BUILDS (speed is OptIn, openable), and `--public <unknown>` is refused with a
/// message that names the served set. Proves the CLI's per-service overlay wires onto the real swoosh
/// handlers through `Exposer::with_public`.
#[test]
fn public_speed_builds_and_public_unknown_is_refused() {
    let services = || Services::parse(&["speed=speed:".to_owned()]).unwrap();
    // `--public speed` builds: `speed` is an OptIn handler, so the overlay proves it open-safe.
    let built = Exposer::new(
        services(),
        super::registry([0u8; 32], std::env::temp_dir()).unwrap(),
        gated(),
    )
    .unwrap()
    .with_public(PublicRequest::new(["speed".to_owned()]));
    assert!(
        built.is_ok(),
        "`--public speed` must build (speed is openable)"
    );

    // `--public <unknown>` is refused, naming what the node DOES serve.
    let assembled = Exposer::new(
        services(),
        super::registry([0u8; 32], std::env::temp_dir()).unwrap(),
        gated(),
    )
    .unwrap();
    let Err(error) = assembled.with_public(PublicRequest::new(["nope".to_owned()])) else {
        panic!("an unknown public name must be refused");
    };
    assert!(
        error.to_string().contains("no service named"),
        "an unknown public name is refused with the served list: {error}"
    );
}

/// `--public sshd` (naming the keyless shell) is refused with a TEACHING error that names the service and the
/// fix and never leaks the marker names, posture winning over the operator's request.
#[cfg(feature = "ssh")]
#[test]
fn public_sshd_is_refused_with_a_teaching_error() {
    let services = Services::parse(&["ssh=sshd:".to_owned()]).unwrap();
    // The `ssh` feature registers the `sshd` handler; without it, `Exposer::new` would refuse it as
    // unregistered before `with_public` ever runs, which is why this test is feature-gated.
    let registry = super::registry([0u8; 32], std::env::temp_dir()).unwrap();
    let assembled = Exposer::new(services, registry, gated()).unwrap();
    let Err(error) = assembled.with_public(PublicRequest::new(["ssh".to_owned()])) else {
        panic!("`--public ssh` (a keyless shell) must be refused");
    };
    let message = error.to_string();
    assert!(
        message.contains("ssh") && message.contains("gated"),
        "the teaching error names the service and leads with the fix: {message:?}"
    );
    for marker in ["Never", "OptIn"] {
        assert!(
            !message.contains(marker),
            "the refusal must not leak the marker {marker:?}: {message:?}"
        );
    }
}

/// The `--public` CLI surface: bare `--public` (the node-wide open that caused the bug) is an ERROR by
/// construction, the value is a comma-list, and omitting it opens nothing.
#[test]
fn public_flag_requires_a_value_and_splits_on_commas() {
    use clap::Parser as _;

    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        serve: super::ServeCmd,
    }

    // Bare `--public` (no value) is a parse error: node-wide-open is untypeable.
    assert!(
        Wrap::try_parse_from(["x", "--public"]).is_err(),
        "bare --public must be an error (no whole-node open)"
    );
    // The value is a comma-list of service names.
    let wrap = Wrap::try_parse_from(["x", "speed=speed:", "--public", "speed,fetch"])
        .expect("a comma-list parses");
    assert_eq!(
        wrap.serve.public,
        vec!["speed".to_owned(), "fetch".to_owned()],
        "--public splits on commas into the per-service set"
    );
    // Omitting `--public` opens nothing.
    let wrap = Wrap::try_parse_from(["x"]).expect("no --public parses");
    assert!(
        wrap.serve.public.is_empty(),
        "no --public means nothing is opened"
    );
}

/// The duration timer moved off `--for` onto `--expires` (`--for` is now the WHO family, reserved for
/// `grant issue`). `--expires 30m` parses into the local timer; `--for 30m` no longer parses (the flag is
/// gone), so the overloaded word can never mean two things.
#[test]
fn serve_duration_is_expires_not_for() {
    use clap::Parser as _;

    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        serve: super::ServeCmd,
    }

    // `--expires 30m` arms the bounded-time timer.
    let wrap = Wrap::try_parse_from(["x", "--expires", "30m"]).expect("--expires parses");
    let expires = wrap.serve.expires.expect("the timer is armed");
    assert_eq!(
        expires.duration(),
        core::time::Duration::from_secs(30 * 60),
        "--expires 30m arms a 30-minute local timer"
    );

    // `--for 30m` no longer parses as a duration: the flag is gone from `serve`.
    assert!(
        Wrap::try_parse_from(["x", "--for", "30m"]).is_err(),
        "serve --for is gone; the duration is --expires now"
    );

    // Omitting it leaves the node running until Ctrl-C (no timer).
    let wrap = Wrap::try_parse_from(["x"]).expect("no timer parses");
    assert!(
        wrap.serve.expires.is_none(),
        "no --expires means run until stopped"
    );
}
