//! The `serve` node engine: assemble the exposer's route table, its member-only control surface, and
//! the resident arm. The `serve` COMMAND (its flags, banner, and run loop) lives in the binary; this
//! module is the reusable half the command drives and the integration proofs assemble their nodes
//! from, so a test builds the same routers the product path binds.
//!
//! `bind_entry`/`diagnostics` bind the named routes (the diagnostics engines, tightbeam's own
//! primitives), and the `control.*` handlers plus `Resident`/`InstanceLock`
//! carry the node's local control surface. [`Activity`] is where an engine's reported fact becomes a
//! line, and the only place one does. Nothing here SIGNS: `serve` relays a roster its operator's
//! signet cut elsewhere, so the long-lived process never holds a signing identity.

use std::path::{Path, PathBuf};

use ::fetch::OriginAllowlist;
use nauthy::Service;
use tightbeam::tunnel::{Router, Serve};

use crate::names::{Name, NameError};

mod activity;
mod control;
mod resident;
mod roster;
mod services;
mod single;
mod stop;
pub mod control_codec {
    pub use super::control::{
        ControlError, DisabledList, MAX_DISABLED_NAMES, MAX_FRAME, MAX_STATUS_STRING,
        MAX_WARM_ENTRIES, PeerEntry, Request, Response, ServiceMenu, StatusReply, WireVersion,
    };
}
pub use activity::{Activity, RecvLines};
pub use resident::{MAX_CONTROL_CONNS, READ_TIMEOUT, Resident, StopKind, StopSource};
pub use single::{InstanceLock, RuntimeDir, SingleError, acquire as acquire_single};
// `roster` shadows `crate::roster`, reached in full above. The general engines (`fetch`, `measure`,
// `sshh`, `transfer`) are consumed from the services repo, so the names resolve to those crates.
pub use transfer::Recv;

pub use self::roster::Roster;
pub use self::services::ServiceList;
pub use self::stop::{STOP_ACK, Stop};

/// The node-control service that stops this node: an admitted caller reaching it triggers a graceful
/// teardown (the remote twin of a local Ctrl-C or a `--expires` deadline). The client verb is `swoosh stop`.
///
/// One unified `control.*` family covers both the reads (`control.status`) and the mutations
/// (`control.stop`); the dotted name is the verbatim wire name,
/// gated exact-name, so a grant for one method can never open another. Public so the `swoosh stop` client
/// verb requests the SAME name the served handler is keyed under, one source of truth for the wire string.
pub const CONTROL_STOP_SERVICE: &str = "control.stop";

/// The node-control service that LISTS what this node serves: an admitted caller reaching it reads back the
/// node's served services, each with its NAME and reach posture (gated behind a member badge, or open to
/// anyone). A pure READ of what the exposer was built with, no mutable state and no authority granted. The
/// client verb is `swoosh service --at <peer>`.
///
/// GATED (`type Exposure = Never`, like `control.stop`): the service menu is member-only, so a stranger never
/// learns what a node serves: existence and shape are revealed only AFTER admission, and this is the
/// teaching read the wrong-name path deliberately withholds. One unified `control.*` family, the dotted
/// name is the verbatim wire name. Public so the `swoosh service` client requests the SAME name the
/// served handler is keyed under, one source of truth for the wire string.
pub const CONTROL_SERVICES_SERVICE: &str = "control.services";

/// The update route: every `serve` binds it, member-gated, and serves the home's signed roster
/// artifact from it, whatever the standing. It is bound by the node, never named in a `serve` entry.
/// Public so the client that pulls it requests the SAME name the served handler is keyed under.
pub const ROSTER_SERVICE: &str = "roster";

/// WHY a `serve` run stopped, for a GRACEFUL stop: an enum, not a bool, so a new stop reason forces a
/// decision at every match site (STYLE: prefer enums to bools). Every arm is a SUCCESS: an owner asked the
/// node to stop and it did, so the process exits 0. A real teardown FAILURE never becomes a `Stopped`, it
/// stays an `Err` the run propagates, so "graceful" and "errored" cannot be confused: the type only exists
/// on the success path. This is the distinction a CI action reads, a deliberate stop is green.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// An owner requested the stop: an admitted `control.stop` caller, or a `--expires` deadline. The exposer's
    /// `run` returned `Ok` because its teardown token fired, the ordinary end of a node's life.
    Requested,
    /// The local operator pressed Ctrl-C: the same graceful stop, driven from the keyboard rather than the
    /// overlay.
    Interrupted,
    /// A same-user local client asked over the resident control socket: the socket twin of a SIGTERM
    /// the local user already holds. Kept distinct from `Requested` (the wire stop) so the stop
    /// source bookkeeping never collapses the two.
    Local,
}

impl Stopped {
    /// The one clear line printed on a graceful stop, so a CI action log (a CI teardown) reads a
    /// deliberate stop as a clean end, not a mystery exit. Names the reason plainly.
    pub fn message(self) -> &'static str {
        match self {
            Self::Requested => "\nnode stopped gracefully.",
            Self::Interrupted => "\nnode stopped (interrupted).",
            Self::Local => "\nnode stopped (local request).",
        }
    }
}

/// Classify a finished resident run from its recorded [`StopSource`], never from the select arm
/// that happened to complete: the socket `Stop` records [`StopKind::Socket`] before it cancels the
/// token, so the local stop stays [`Stopped::Local`] even when the exposer arm wins the poll. A
/// wire `control.stop` records nothing and a `--expires` deadline records nothing, so both render
/// as [`Stopped::Requested`]; a Ctrl-C records itself and renders [`Stopped::Interrupted`].
pub fn classify_stop(source: Option<StopKind>) -> Stopped {
    match source {
        Some(StopKind::Socket) => Stopped::Local,
        Some(StopKind::Interrupted) => Stopped::Interrupted,
        Some(StopKind::Expires | StopKind::Wire) | None => Stopped::Requested,
    }
}

/// Parse one typed `serve` entry: the name follows the one name rule and is folded, the target passes
/// through for [`bind_entry`] to read. A typed name is never dotted, so it can never be an internal route
/// (`control.stop`). A bare `<service>` (no `=`) is a name too, folded the same way; a bare target
/// (`fetch:`, holding the scheme's `:`) passes through, so the tunnel grammar teaches the `name=target` shape.
pub fn service_entry(entry: &str) -> Result<String, NameError> {
    match entry.split_once('=') {
        Some((name, target)) => Ok(format!("{}={target}", name.parse::<Name>()?)),
        None if entry.contains(':') => Ok(entry.to_owned()),
        None => Ok(entry.parse::<Name>()?.into()),
    }
}

/// Bind one operator `name=addr` service entry onto `router`. Handlers bind by VALUE (the scheme namespace
/// left tightbeam's public API, so a handler route is never a spellable addr): the diagnostic engines here,
/// and tightbeam's own primitives (a `tcp:`/`unix:` forward, a `file:`/`fifo:`/`stdin:` raw stream, the
/// `echo:` reflector) through [`Router::parse`], which owns the grammar and its teaching errors.
///
/// `public` is the operator's parsed open set: a diagnostic name in it binds the METERED engine (the safety
/// caps by construction, the only one the public proof opens), a name outside it binds the OWNER engine
/// (owner limits, effectively unbounded, at a family gate). One input decides both the engine and the
/// overlay, so an open diagnostic cannot be armed uncapped.
///
/// Public as the per-entry edge the split-service proof drives to offer a SUBSET of the diagnostics.
pub fn bind_entry(
    router: Router,
    entry: &str,
    host_seed: [u8; 32],
    public: &[Service],
) -> eyre::Result<Router> {
    #[cfg(not(feature = "ssh"))]
    let _ = host_seed;
    let Some((name, addr)) = entry.split_once('=') else {
        // No `=`: tightbeam's grammar owns the `name=addr` teaching error.
        return router.parse(&[entry.to_owned()]);
    };
    let name: Service = name.parse()?;
    // Every target is `<scheme>:<rest>`, so the dispatch splits the addr ONCE and matches the SCHEME, never
    // the whole string. No scheme at all is not swoosh's to refuse either: tightbeam's grammar owns that
    // teaching error like every other.
    let Some((scheme, rest)) = addr.split_once(':') else {
        return router.parse(&[entry.to_owned()]).map_err(target_help);
    };
    // ONE arm per scheme swoosh serves, matching the scheme alone. The arity check is a call inside each
    // arm rather than a second arm listing the schemes again: two arms that must agree is how `ping:80`
    // came to mean a forward to a host named `ping` in the first place, and a fifth zero-argument engine
    // added to a second list is the same bug waiting.
    match scheme {
        "ping" => {
            no_argument(scheme, rest, entry)?;
            bind_ping(router, name, public)
        }
        "speed" => {
            no_argument(scheme, rest, entry)?;
            bind_speed(router, name, public)
        }
        // Without the `ssh` engine compiled in there is no arm at all, so `sshd:` falls through to the
        // refusal below and is told it is unknown, which is true of this build.
        #[cfg(feature = "ssh")]
        "sshd" => {
            no_argument(scheme, rest, entry)?;
            router.service(name, sshh::Sshd::new(host_seed))
        }
        // Not swoosh's: a `tcp:`/`unix:` forward, a `file:`/`fifo:`/`stdin:` raw stream, the `echo:`
        // reflector, or a scheme nobody serves. tightbeam's grammar owns it, refusal included. Its
        // refusal names the schemes IT routes, which cannot include the ones above without handing it a
        // scheme registry it deliberately does not have, so the pointer is added here instead: a reader
        // refused by either half gets told where the whole list is.
        _ => router.parse(&[entry.to_owned()]).map_err(target_help),
    }
}

/// Point a refused target at the one complete list. The tunnel grammar refuses by naming the schemes IT
/// routes, which cannot include the engines above without handing it a scheme registry it deliberately
/// does not have. So the pointer is added on this side, where both halves are known, and `serve --help`
/// is the page that carries them.
fn target_help(error: eyre::Report) -> eyre::Report {
    error.wrap_err("`swoosh serve --help` lists every target this node accepts")
}

/// Refuse a tail on a scheme that takes no argument. Every engine swoosh binds by scheme IS the whole
/// target (a probe, a throughput test, a shell), so none of them takes one, and a
/// tail is a typo. Refused HERE, by the layer that serves the scheme: falling through would hand
/// `ping=ping:80` to tightbeam, which would call `ping` unknown when swoosh is the thing serving it.
fn no_argument(scheme: &str, rest: &str, entry: &str) -> eyre::Result<()> {
    if rest.is_empty() {
        return Ok(());
    }
    eyre::bail!("`{scheme}:` takes no argument, but `{entry}` gives it `{rest}`")
}

/// Bind the `ping:` engine a route's exposure requires: the METERED engine when `name` is in the open set,
/// else the OWNER engine. The metered engine is capped by construction and the owner engine declares
/// `Never`, so this choice cannot arm a public route uncapped: even if the wrong arm were taken, the public
/// proof would refuse the owner engine before the node serves.
fn bind_ping(router: Router, name: Service, public: &[Service]) -> eyre::Result<Router> {
    if public.contains(&name) {
        router.service(name, measure::server::MeteredPing::new())
    } else {
        router.service(
            name,
            Serve(measure::server::Ping::new(&measure::server::Limits::owner())),
        )
    }
}

/// Bind the `speed:` engine a route's exposure requires, exactly as [`bind_ping`] does for ping.
fn bind_speed(router: Router, name: Service, public: &[Service]) -> eyre::Result<Router> {
    if public.contains(&name) {
        router.service(name, measure::server::MeteredSpeed::new())
    } else {
        router.service(
            name,
            Serve(measure::server::Speed::new(
                &measure::server::Limits::owner(),
            )),
        )
    }
}

/// Bind the conventional diagnostic routes (`ping` and `speed`) onto `router`, one engine handler
/// instance per name.
///
/// `public` is the SAME open overlay the caller wants, so the helper applies it here and the engine choice
/// runs on the same input, through the same [`bind_ping`]/[`bind_speed`] edges the product `serve` path
/// uses: the open decision and the bound profile cannot drift. The caller adds any extra member-only routes
/// (e.g. `control.stop`) after.
///
/// EXACTLY the diagnostics a bare `serve` binds, and nothing else. This helper is what the integration
/// proofs assemble their nodes from, so a route here that the product's bare set does not carry makes
/// every one of those proofs a proof about a node nobody runs. A shell is the sharpest case, and the
/// reason this is written down: the bare set binds no shell at all, and no client ever requests the
/// name `sshd` anyway (a `sshd:` target auto-names to `ssh`). A proof that wants a shell binds one
/// itself, by name.
///
/// ping and speed are TWO independent services so a node may offer ping without speed (or the reverse),
/// and each carries its own gate: `ping` answers only ping frames, `speed` only speed frames, refusing the
/// other method at the wire (`ProtocolError::WrongService`), so a grant for one can never open the other.
pub fn diagnostics(router: Router, public: &[Service]) -> eyre::Result<Router> {
    let ping: Service = "ping".parse()?;
    let speed: Service = "speed".parse()?;
    let router = bind_ping(router, ping, public)?;
    let router = bind_speed(router, speed, public)?;
    Ok(router.public(public.iter().cloned()))
}

/// The scheme a receive service names, so the sink-dir extraction matches `recv:<dir>` on the ONE literal
/// (the same literal the extraction and the banner gloss match), not a re-typed string that could drift.
pub const RECV_SCHEME: &str = "recv";

/// One de-merged receive service: its served NAME (the wire name `swoosh send --service` requests, e.g. the
/// default `recv`) and ONLY its own output directory. Because each receive service holds its own [`Recv`]
/// instance, `a=recv:/x b=recv:/y` writes alice's pushes into /x and bob's into /y: a node-wide sink cannot
/// say which of two receive services saves where, so the dir rides the per-service instance, the same
/// de-merge `fetch:` uses.
pub struct RecvService {
    name: String,
    out: PathBuf,
}

impl RecvService {
    /// The served name a dialer requests (`swoosh send --service <name>`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// This service's own output directory (only its own; never shared with another receive service).
    pub fn out(&self) -> &Path {
        &self.out
    }
}

/// Bind one receive route: a [`Recv`] that lands files in `out`, under `name`. With a renderer the engine
/// is handed that route's sink, so every landed file becomes one activity line naming the route; with
/// none (a `--quiet` node) it gets no sink and stays silent. This is the only place a receive engine is
/// built for a serving node, so the product and the integration proofs bind it the same way.
pub fn bind_recv(
    router: Router,
    name: Service,
    out: PathBuf,
    activity: Option<&Activity>,
) -> eyre::Result<Router> {
    let engine = Recv::new(out);
    let engine = match activity {
        Some(activity) => engine.with_sink(activity.recv(name.clone())),
        None => engine,
    };
    router.service(name, engine)
}

/// De-merges the receive services out of the requested set: a `name=recv:<dir>` entry hands the router a
/// output directory its addr grammar cannot carry, so swoosh separates each into its OWN [`RecvService`]
/// (name + its own output dir) here, then binds one `Recv` instance per name by value. A `name=recv:` (no dir)
/// saves into `.`. An entry without `=` is a teaching error, mirroring tightbeam's grammar. Non-recv entries
/// are left in place, in order.
pub fn extract_recv_services(requested: &mut Vec<String>) -> eyre::Result<Vec<RecvService>> {
    let mut services: Vec<RecvService> = Vec::new();
    let mut remaining: Vec<String> = Vec::new();
    for entry in requested.drain(..) {
        // Split off the `name=` prefix; only the ADDR side names a scheme, so the dir is read from there.
        let Some((name, addr)) = entry.split_once('=') else {
            eyre::bail!(
                "`{entry}` names no service. Every serve entry must be `name=target`, e.g. \
                 `inbox=recv:/tmp/x`"
            );
        };
        // A receive service is `recv:` optionally followed by a dir. A non-recv entry passes through
        // unchanged, in order, for the router's own grammar.
        let Some(dir) = addr
            .strip_prefix(RECV_SCHEME)
            .and_then(|rest| rest.strip_prefix(':'))
        else {
            remaining.push(entry);
            continue;
        };
        // A `name=recv:` (no dir) saves into `.`; `name=recv:<dir>` into <dir>. The dir is this service's
        // OWN, on its OWN instance, so two receive services never share one output directory.
        let out = if dir.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(dir)
        };
        services.push(RecvService {
            name: name.to_owned(),
            out,
        });
    }
    *requested = remaining;
    Ok(services)
}

/// The scheme prefix a fetch service names, so the origin-extraction matches `fetch:<origin>` on the ONE
/// literal, not a re-typed string that could drift from it.
const FETCH_SCHEME: &str = "fetch";

/// One de-merged fetch service: its served NAME (the wire name a dialer requests, e.g. `news`) and ONLY its
/// own origin scope. Because each fetch service holds its own [`Fetch`] instance, a public fetch physically
/// cannot reach a gated fetch's origins: the SSRF pivot is unrepresentable, not
/// fail-closed-by-convention.
pub struct FetchService {
    name: String,
    allow: OriginAllowlist,
}

impl FetchService {
    /// The served name a dialer requests and `--public` names.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// This service's own origin scope (only its own; never merged with another's).
    pub fn allow(&self) -> &OriginAllowlist {
        &self.allow
    }
}

/// De-merges the fetch services out of the requested set: a `name=fetch:<origin>` entry hands the router an
/// origin its addr grammar cannot carry, so swoosh separates each into its OWN [`FetchService`] (name + its
/// own origin scope) here, then binds one `Fetch` instance per name by value.
///
/// A pure edge adapter over the raw request strings. A `name=fetch:` (no origin) is an unconstrained fetch
/// under its own name; a `name=fetch:<origin>` is a named, origin-scoped fetch. An entry without `=` names
/// no service and is a teaching error, mirroring tightbeam's grammar. A malformed origin fails HERE, at
/// expose time, not at dial time.
pub struct FetchScope;

impl FetchScope {
    /// Remove every fetch entry from `requested` (leaving the non-fetch services for the router's grammar)
    /// and return them as one [`FetchService`] each: its served name and only its own [`OriginAllowlist`].
    /// Non-fetch entries are left in place, in order. A malformed origin fails HERE with a teaching message.
    pub fn extract(requested: &mut Vec<String>) -> eyre::Result<FetchExposure> {
        let mut services: Vec<FetchService> = Vec::new();
        let mut remaining: Vec<String> = Vec::new();
        for entry in requested.drain(..) {
            // Split off the `name=` prefix; only the ADDR side names a scheme, so the origin is read
            // from there.
            let Some((name, addr)) = entry.split_once('=') else {
                eyre::bail!(
                    "`{entry}` names no service. Every serve entry must be `name=target`, e.g. \
                     `news=fetch:https://news.example`"
                );
            };
            // A fetch service is `fetch:` optionally followed by an origin. A non-fetch entry passes through
            // unchanged, in order, for the router's own grammar.
            let Some(origin) = addr
                .strip_prefix(FETCH_SCHEME)
                .and_then(|rest| rest.strip_prefix(':'))
            else {
                remaining.push(entry);
                continue;
            };
            // Each fetch service gets its OWN allowlist (only its own origin; empty = unconstrained): the
            // per-instance isolation that makes the SSRF pivot unrepresentable.
            let allow = if origin.is_empty() {
                OriginAllowlist::default()
            } else {
                OriginAllowlist::parse([origin]).map_err(|error| eyre::eyre!(error))?
            };
            services.push(FetchService {
                name: name.to_owned(),
                allow,
            });
        }
        *requested = remaining;
        Ok(FetchExposure { services })
    }
}

/// The operator's per-service fetch posture pulled from the requested services: one [`FetchService`] per
/// exposed fetch, each with its own scope. Read off the raw request strings in ONE place
/// ([`FetchScope::extract`]), so the refusal of an unconstrained public fetch has a single source of truth.
pub struct FetchExposure {
    services: Vec<FetchService>,
}

impl FetchExposure {
    /// The de-merged fetch services, each to be bound as its own `Fetch` instance.
    pub fn services(&self) -> &[FetchService] {
        &self.services
    }

    /// Refuse the one illegal fetch shape PER SERVICE: a fetch service NAMED in `--public` whose allowlist is
    /// unconstrained (any origin), which is an open egress relay (traffic-source laundering, a reflector, a
    /// free anonymizing hop). Because each fetch service carries its own scope, this reasons about THIS public
    /// fetch, so a second origin-scoped fetch can no longer mask a bare public one. Refused at build time,
    /// before any banner or accepted stream, mirroring the sshd-cannot-be-public wall. A GATED fetch (not in
    /// `--public`) stays legal unconstrained: the family gate is the terminator there.
    pub fn refuse_open_relay(&self, public: &[Service]) -> eyre::Result<()> {
        for service in &self.services {
            if public.iter().any(|name| name.as_str() == service.name)
                && service.allow.is_unconstrained()
            {
                eyre::bail!(
                    "a public fetch service must be origin-scoped \
                     (`serve {name}=fetch:https://origin --public {name}`); an unconstrained public fetch \
                     is an open relay",
                    name = service.name
                );
            }
        }
        Ok(())
    }
}
