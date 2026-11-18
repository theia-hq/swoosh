//! The `serve` node engine: assemble the exposer's route table, its member-only control surface, and
//! the resident arm. The `serve` COMMAND (its flags, banner, and run loop) lives in the binary; this
//! module is the reusable half the command drives and the integration proofs assemble their nodes
//! from, so a test builds the same routers the product path binds.
//!
//! `bind_entry`/`diagnostics` bind the named routes (the diagnostics engines, tightbeam's own
//! primitives), and the `control.*` handlers plus `Resident`/`InstanceLock`
//! carry the node's local control surface. [`Activity`] is where an engine's reported fact becomes a
//! line, and the only place one does. Nothing here SIGNS: `serve` exchanges updates its root cut
//! elsewhere, so the long-lived process never holds a signing identity.

use std::path::{Path, PathBuf};

use ::fetch::OriginAllowlist;
use definition::{Receive, Target, ValidatedDefinition};
use eyre::WrapErr as _;
use nauthy::Service;
use tightbeam::tunnel::{Router, Serve};

use crate::escape::EscapedPath;
use crate::home::{Home, canonical_to_be};

mod activity;
mod definition;
mod lookup;
#[cfg(test)]
#[path = "serve/recv_home_tests.rs"]
mod recv_home_tests;
mod renewal;
mod resident;
mod roster;
mod scheme;
mod services;
mod serving;
mod single;
mod socket;
mod stop;
pub mod control_codec {
    pub use super::socket::{
        ControlError, DisabledList, LocalDetailCaptureError, LocalDetailError, LocalDetailLimit,
        LocalServiceName, LocalServicePair, LocalServicePairs, LocalServiceSnapshot,
        LocalServiceTarget, MAX_DISABLED_NAMES, MAX_FRAME, MAX_OPEN_REQUEST, MAX_STATUS_STRING,
        MAX_WARM_ENTRIES, MalformedOpen, OpenLane, OpenRefusal, OpenRequest, PeerEntry,
        PeerRefusal, Request, Response, ServiceMenu, StatusReply, WireVersion,
    };
}
pub use activity::{Activity, RecvLines};
pub use resident::{MAX_CONTROL_CONNS, READ_TIMEOUT, Resident, StopKind, StopSource};
pub use single::{InstanceLock, RuntimeDir, SingleError, acquire as acquire_single};
#[cfg(test)]
pub(crate) use socket::measure_allocations;
// `roster` shadows `crate::roster`, reached in full above. The general engines (`fetch`, `measure`,
// `sshh`, `transfer`) are consumed from the services repo, so the names resolve to those crates.
pub use transfer::Recv;

pub use self::definition::{DefinitionCause, DefinitionError, Operand};
#[cfg(test)]
pub(crate) use self::lookup::answer as lookup_answer;
pub use self::lookup::{Devices, Lookup};
pub use self::renewal::{Known, Renewal};
pub use self::roster::Exchange;
pub use self::scheme::{BoundTargets, NotATarget, Scheme, ServedTarget};
pub use self::services::ServiceList;
pub use self::serving::{Added, EditError, Mistyped, ServingError, Started};
pub use self::stop::{ACK_GRACE, FirstRound, STOP_ACK, Stop, StopAfterFirstRound, stopped_by};

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

/// The update route: every `serve` binds it, member-gated, and answers the exchange on it
/// ([`crate::sync`]), whatever the standing. It is bound by the node, never named in a `serve` entry, and
/// its dotted name is one no name a person types can be. Public so every dialer requests the SAME name
/// the served handler is keyed under.
pub const SYNC_SERVICE: &str = "control.sync";

/// The pick-up route: every `serve` binds it, proven-only, and hands a device of this root its own newest
/// standing on it ([`crate::renewal`]), with no token read. Like the update route it is bound by the node,
/// never named in a `serve` entry, never printed, and dotted, so no name a person types can be it.
pub const RENEWAL_SERVICE: &str = "control.renewal";

/// The root route: every `serve` binds it, proven-only, and hands a peer this machine saves as one machine
/// of a person this machine's own standing, which names the root that vouches for it ([`Lookup`]). Its
/// group answers other roots' devices, so it is a sibling of the family-only `control` group, never in it.
/// Like the pick-up route it is bound by the node, never named in a `serve` entry, and dotted, so no name a
/// person types can be it.
pub const LOOKUP_ROOT_SERVICE: &str = "lookup.root";

/// The routes a peer reaches proven-only: the transport's proof of its key is all they read, so a stream to
/// one presents nothing, and never renews this home's standing first.
pub const PROVEN_ROUTES: [&str; 2] = [RENEWAL_SERVICE, LOOKUP_ROOT_SERVICE];

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
/// wire `control.stop` records the key that asked and a `--expires` deadline records nothing, so both
/// render as [`Stopped::Requested`]; a Ctrl-C records itself and renders [`Stopped::Interrupted`].
pub fn classify_stop(source: Option<StopKind>) -> Stopped {
    match source {
        Some(StopKind::Socket) => Stopped::Local,
        Some(StopKind::Interrupted) => Stopped::Interrupted,
        Some(StopKind::Expires | StopKind::Wire(_)) | None => Stopped::Requested,
    }
}

/// Bind the pick-up route ([`RENEWAL_SERVICE`]) on `router`, proven-only, answering from `home`. The keys
/// it knows are read once here into the returned [`Known`]; the caller keeps them fresh with
/// [`Known::watch`] for as long as it serves.
pub async fn bind_renewal(
    router: Router,
    home: &crate::home::Home,
) -> eyre::Result<(Router, Known)> {
    let known = Known::load(home).await;
    let knows = known.clone();
    let router = router.proven_service(
        RENEWAL_SERVICE.parse()?,
        Renewal::new(home.clone()),
        move |key| knows.knows(key),
    )?;
    Ok((router, known))
}

/// Bind the root route ([`LOOKUP_ROOT_SERVICE`]) on `router`, proven-only, answering from `home`. The keys it
/// answers are read once here into the returned [`Devices`]; the caller keeps them fresh with
/// [`Devices::watch`] for as long as it serves.
pub async fn bind_lookup(
    router: Router,
    home: &crate::home::Home,
) -> eyre::Result<(Router, Devices)> {
    let devices = Devices::load(home).await;
    let knows = devices.clone();
    let router = router.proven_service(
        LOOKUP_ROOT_SERVICE.parse()?,
        Lookup::new(home.clone()),
        move |key| knows.knows(key),
    )?;
    Ok((router, devices))
}

/// The services a `serve` with nothing named and nothing to resume serves: the two diagnostics, each its
/// own service, so a node may later offer one without the other.
pub const DEFAULT_SERVICES: [&str; 2] = ["ping=ping:", "speed=speed:"];

/// The services swoosh serves itself, by the name a person types and the target that name stands for:
/// `swoosh serve ssh ping` is `ssh=sshd: ping=ping:`.
const BUILT_IN: [(&str, &str); 3] = [("ping", "ping:"), ("speed", "speed:"), ("ssh", "sshd:")];

/// `entry` (as the service-entry parser gives it) the way a person types it: a built-in by its bare name
/// (`ssh=sshd:` is `ssh`), a proxy named `proxy` or a receiver named `recv` by its target (`proxy:<url>`,
/// `recv:<dir>`), any other as it is. What a line that hands an entry back to the person prints, so the
/// command it shows is the shortest that works.
pub fn as_typed(entry: &str) -> &str {
    let Some((name, target)) = entry.split_once('=') else {
        return entry;
    };
    if BUILT_IN
        .iter()
        .any(|&(built_in, full)| built_in == name && full == target)
    {
        return name;
    }
    let names_itself = [Scheme::Proxy, Scheme::Recv].into_iter().any(|scheme| {
        name == scheme.as_str()
            && matches!(Scheme::parse(target), Some((found, _)) if found == scheme)
    });
    if names_itself {
        return target;
    }
    entry
}

/// The shortest entry a person types to serve `name`: a built-in alone (`ssh`), `proxy` with the URL it
/// needs (`proxy:<url>`), `recv` with the directory it saves into (`recv:<dir>`: where files land is the
/// person's choice), and any other name with a TCP target (`db=tcp:<address>:<port>`), the common case
/// whole. Only the person can fill the placeholders, so they print as they are.
pub fn entry_for(name: &str) -> String {
    if BUILT_IN.iter().any(|&(built_in, _)| built_in == name) {
        return name.to_owned();
    }
    if name == Scheme::Proxy.as_str() {
        return format!("{name}:<url>");
    }
    if name == Scheme::Recv.as_str() {
        return format!("{name}:<dir>");
    }
    format!("{name}=tcp:<address>:<port>")
}

/// Bind one primitive, diagnostic, or supported SSH service after complete syntax validation.
/// Primitives bind through [`Router::target`]; other supported entries bind their handlers by value.
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
    let definition = ValidatedDefinition::parse(entry).map_err(|cause| DefinitionError {
        operand: Operand::Positional,
        index: 1,
        cause,
    })?;
    let name = definition.name;
    match definition.target {
        Target::Primitive(spec) => router.target(name, spec).map_err(eyre::Report::new),
        Target::Ping => bind_ping(router, name, public),
        Target::Speed => bind_speed(router, name, public),
        #[cfg(feature = "ssh")]
        Target::Sshd => router.service(name, sshh::Sshd::new(host_seed)),
        Target::Receive(_) | Target::Proxy { .. } => Err(DefinitionError {
            operand: Operand::Positional,
            index: 1,
            cause: DefinitionCause::Scheme,
        }
        .into()),
    }
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

/// One de-merged receive service: its served NAME (the wire name `swoosh send --service` requests, e.g. the
/// default `recv`) and ONLY its own output directory. Because each receive service holds its own [`Recv`]
/// instance, `a=recv:/x b=recv:/y` writes alice's pushes into /x and bob's into /y: a node-wide sink cannot
/// say which of two receive services saves where, so the dir rides the per-service instance, the same
/// de-merge `proxy:` uses.
pub struct RecvService {
    name: String,
    out: PathBuf,
    /// Whether `out` is the inbox a `recv:` with no directory saves into, which `serve` creates.
    inbox: bool,
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

    /// Create the inbox, owner-only, when this service saves there; a named directory is used as it is.
    pub fn create_inbox(&self) -> eyre::Result<()> {
        use std::os::unix::fs::DirBuilderExt as _;

        if !self.inbox {
            return Ok(());
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.out)
            .wrap_err_with(|| format!("could not create {}", EscapedPath(&self.out)))
    }
}

/// Refuse a receive service whose output directory is `$HOME` (`user_home`), the swoosh home, a directory
/// that holds the swoosh home, or a directory inside it. A push names its own path under the output
/// directory, so any of these puts the home's files (the pin the gate reads, the root key) in reach of
/// every sender. Each directory is compared by its canonical path and, once it exists, by its device and
/// inode, so another name for the same directory (a macOS firmlink such as `/System/Volumes/Data/...`, a
/// Linux bind mount) is caught too. Checked at start and on resume, before anything binds.
pub fn refuse_recv_into_home(
    services: &[RecvService],
    home: &Home,
    user_home: Option<&Path>,
) -> eyre::Result<()> {
    refuse_recv_into_home_with(services, || (Dir::of(home.dir()), user_home.map(Dir::of)))
}

fn refuse_recv_into_home_with(
    services: &[RecvService],
    homes: impl FnOnce() -> (Dir, Option<Dir>),
) -> eyre::Result<()> {
    // Resolving receive safety boundaries can access an unavailable filesystem. An empty receive
    // selection needs no probes, so even home resolution stays deferred until a receiver is present.
    if services.is_empty() {
        return Ok(());
    }
    let (swoosh_home, user_home) = homes();
    // A canonical path's ancestors are canonical too, so each is only looked up.
    let holders: Vec<Dir> = swoosh_home.path.ancestors().skip(1).map(Dir::at).collect();
    for service in services {
        let out = Dir::of(&service.out);
        let why = if user_home
            .as_ref()
            .is_some_and(|user_home| out.is(user_home))
        {
            "it is your home directory"
        } else if out.is(&swoosh_home) {
            "it is the swoosh home"
        } else if holders.iter().any(|holder| out.is(holder)) {
            "it holds the swoosh home"
        } else if out
            .path
            .ancestors()
            .skip(1)
            .any(|above| Dir::at(above).is(&swoosh_home))
        {
            "it is inside the swoosh home"
        } else {
            continue;
        };
        // Named as typed (made absolute when it was relative), with `.` components dropped.
        let named: PathBuf = service.out.components().collect();
        eyre::bail!(
            "{} cannot save into {}: {why}",
            service.name,
            EscapedPath(&named)
        );
    }
    Ok(())
}

/// A directory as the refusal compares it: its canonical path, and its device and inode once it exists.
struct Dir {
    path: PathBuf,
    id: Option<(u64, u64)>,
}

impl Dir {
    /// `path` canonicalized, as it will be named once it exists.
    fn of(path: &Path) -> Self {
        Self::at(&canonical_to_be(path))
    }

    /// `path` as it is, already canonical.
    fn at(path: &Path) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        let id = std::fs::metadata(path)
            .ok()
            .map(|meta| (meta.dev(), meta.ino()));
        Self {
            path: path.to_owned(),
            id,
        }
    }

    /// Whether `self` and `other` are the same directory, by path or, when both exist, by identity.
    fn is(&self, other: &Self) -> bool {
        self.path == other.path || (self.id.is_some() && self.id == other.id)
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
/// saves into the inbox `inbox` names (`None` when `HOME` is unset), never the current directory. An entry
/// without `=` is a teaching error, mirroring tightbeam's grammar. Non-recv entries are left in place, in
/// order.
pub fn extract_recv_services(
    requested: &mut Vec<String>,
    inbox: impl Fn() -> Option<PathBuf>,
) -> eyre::Result<Vec<RecvService>> {
    let definitions = ValidatedDefinition::list(requested, Operand::Positional, None)?;
    let mut services = Vec::new();
    let mut remaining = Vec::new();
    for definition in definitions {
        let Target::Receive(receive) = definition.target else {
            remaining.push(definition.entry());
            continue;
        };
        let name = definition.name.to_string();
        let (out, inbox) = match receive {
            Receive::Inbox => {
                let Some(out) = inbox() else {
                    eyre::bail!(
                        "HOME is not set, so recv: has no inbox to save into; name a directory: \
                         swoosh serve {name}=recv:<dir>"
                    );
                };
                (out, true)
            }
            Receive::Path(path) => (path, false),
        };
        services.push(RecvService { name, out, inbox });
    }
    *requested = remaining;
    Ok(services)
}

/// One de-merged proxy service: its served NAME (the wire name a dialer requests, e.g. `news`) and ONLY its
/// own origin scope. Because each proxy service holds its own engine instance, a public proxy physically
/// cannot reach a gated proxy's origins: the SSRF pivot is unrepresentable, not
/// fail-closed-by-convention.
pub struct ProxyService {
    name: String,
    /// Never empty: [`ProxyScope::extract`] refuses a proxy with no origin.
    allow: OriginAllowlist,
}

impl ProxyService {
    /// The served name a dialer requests and `--public` names.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// This service's own origin scope (only its own; never merged with another's).
    pub fn allow(&self) -> &OriginAllowlist {
        &self.allow
    }
}

/// De-merges the proxy services out of the requested set: a `name=proxy:<url>` entry hands the router an
/// origin its addr grammar cannot carry, so swoosh separates each into its OWN [`ProxyService`] (name + its
/// own origin scope) here, then binds one engine instance per name by value.
///
/// A pure edge adapter over the raw request strings. A `name=proxy:<url>` is a named, origin-scoped proxy.
/// A `name=proxy:` (no origin) would be an open egress relay; definition validation refuses it before an
/// entry gets here, and this refuses it again for an entry from anywhere else, so no [`ProxyService`] holds an
/// unconstrained scope and the binder has only the scoped engine to build. An entry without `=` names no
/// service and is a teaching error, mirroring tightbeam's grammar. A malformed origin fails HERE, at expose
/// time, not at dial time.
pub struct ProxyScope;

impl ProxyScope {
    /// Remove every proxy entry from `requested` (leaving the other services for the router's grammar)
    /// and return them as one [`ProxyService`] each: its served name and only its own [`OriginAllowlist`].
    /// Other entries are left in place, in order. A malformed origin fails HERE with a teaching message.
    pub fn extract(requested: &mut Vec<String>) -> eyre::Result<ProxyExposure> {
        let definitions = ValidatedDefinition::list(requested, Operand::Positional, None)?;
        let mut services = Vec::new();
        let mut remaining = Vec::new();
        for definition in definitions {
            if let Target::Proxy { allow, .. } = definition.target {
                services.push(ProxyService {
                    name: definition.name.to_string(),
                    allow,
                });
            } else {
                remaining.push(definition.entry());
            }
        }
        *requested = remaining;
        Ok(ProxyExposure { services })
    }
}

/// The operator's per-service proxy posture pulled from the requested services: one [`ProxyService`] per
/// exposed proxy, each with its own scope. Read off the raw request strings in ONE place
/// ([`ProxyScope::extract`]).
pub struct ProxyExposure {
    services: Vec<ProxyService>,
}

impl ProxyExposure {
    /// The de-merged proxy services, each to be bound as its own engine instance.
    pub fn services(&self) -> &[ProxyService] {
        &self.services
    }
}
