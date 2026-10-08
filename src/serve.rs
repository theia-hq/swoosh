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
use eyre::WrapErr as _;
use nauthy::Service;
use tightbeam::tunnel::{Router, Serve};

use crate::escape::EscapedPath;
use crate::home::{Home, canonical_to_be};
use crate::names::{Name, NameError};

mod activity;
mod control;
mod renewal;
mod resident;
mod roster;
mod scheme;
mod services;
mod serving;
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

pub use self::renewal::{Known, Renewal};
pub use self::roster::Exchange;
pub use self::scheme::{BoundTargets, NotATarget, Scheme, ServedTarget};
pub use self::services::ServiceList;
pub use self::serving::{ServingError, Started};
pub use self::stop::{ACK_GRACE, STOP_ACK, Stop, stopped_by};

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

/// The services a `serve` with nothing named and nothing to resume serves: the two diagnostics, each its
/// own service, so a node may later offer one without the other.
pub const DEFAULT_SERVICES: [&str; 2] = ["ping=ping:", "speed=speed:"];

/// The services swoosh serves itself, by the name a person types and the target that name stands for:
/// `swoosh serve ssh ping` is `ssh=sshd: ping=ping:`.
const BUILT_IN: [(&str, &str); 3] = [("ping", "ping:"), ("speed", "speed:"), ("ssh", "sshd:")];

/// Parse one typed `serve` entry: the name follows the one name rule and is folded, the target passes
/// through for [`bind_entry`] to read. A typed name is never dotted, so it can never be an internal route
/// (`control.stop`). A bare `<service>` (no `=`) is a name too, folded the same way, and a built-in one
/// becomes its full form (`ssh` is `ssh=sshd:`). A bare `proxy:<url>` names itself `proxy`, the way
/// `sshd:` is named `ssh`; any other bare target (`tcp:…`, holding the scheme's `:`) passes through, so the
/// tunnel grammar teaches the `name=target` shape.
///
/// A proxy is always served with what it reaches, named or not: an empty origin is an open egress relay
/// under this machine's address, and a name changes what a service is called, never what it reaches. So
/// `proxy`, `proxy:` and `<name>=proxy:` refuse, and a proxy's URL is an origin only (see
/// [`proxy_origin`]).
///
/// A bare `proxy:<url>` is read before any `name=` split, so an `=` in its query (a signed link) stays in
/// the URL and the refusal names the URL, never a name the person did not type. Every other entry splits
/// on its first `=`, so a name holding a `:` still meets the name rule.
pub fn service_entry(entry: &str) -> Result<String, EntryError> {
    if let Some((Scheme::Proxy, url)) = Scheme::parse(entry) {
        proxy_origin(Scheme::Proxy.as_str(), url)?;
        return Ok(format!("{}={entry}", Scheme::Proxy.as_str()));
    }
    if let Some((name, target)) = entry.split_once('=') {
        let name = name.parse::<Name>()?;
        if let Some((Scheme::Proxy, url)) = Scheme::parse(target) {
            proxy_origin(name.as_str(), url)?;
        }
        return Ok(format!("{name}={target}"));
    }
    if entry.contains(':') {
        return Ok(entry.to_owned());
    }
    let name: String = entry.parse::<Name>()?.into();
    if name == Scheme::Proxy.as_str() {
        return Err(EntryError::ProxyWithoutTarget(ProxyLine::new(
            &name, "<url>",
        )));
    }
    Ok(
        match BUILT_IN.iter().find(|(built_in, _)| *built_in == name) {
            Some((_, target)) => format!("{name}={target}"),
            None => name,
        },
    )
}

/// Hold a proxy's URL to what the engine scopes by: one origin, the scheme, host and port. The engine
/// admits every path and query on that origin, so a URL that carried a path would promise less than the
/// service gives, and a query (a signed download link, say) would be stored and printed for nothing. An
/// empty URL is no origin at all. A URL that does not parse passes here: the origin parse at expose time
/// refuses it with the cause ([`ProxyScope::extract`]).
///
/// The engine fetches only `http` and `https`, so any other scheme is refused here, before its path and
/// query could be stored; the line names neither. Both are special schemes in the URL grammar, so every
/// URL past this check has a tuple origin.
fn proxy_origin(name: &str, url: &str) -> Result<(), EntryError> {
    if url.is_empty() {
        return Err(EntryError::ProxyWithoutTarget(ProxyLine::new(
            name, "<url>",
        )));
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return Ok(());
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(EntryError::ProxyNotHttp(ProxyLine::new(
            name,
            "https://<host>",
        )));
    }
    let origin = parsed.origin();
    let bare = matches!(parsed.path(), "" | "/")
        && parsed.query().is_none()
        && parsed.fragment().is_none();
    if bare {
        return Ok(());
    }
    Err(EntryError::ProxyNotAnOrigin(ProxyLine::new(
        name,
        &origin.ascii_serialization(),
    )))
}

/// The `serve` entry a proxy refusal teaches, in its shortest form: `proxy:<url>` for the service named
/// `proxy` (it names itself), `<name>=proxy:<url>` for any other.
#[derive(Debug)]
pub struct ProxyLine {
    /// The served name, folded.
    name: String,
    /// What follows `proxy:`: a placeholder, or the origin to type.
    url: String,
}

impl ProxyLine {
    /// The line for the service `name`, reaching `url`.
    fn new(name: &str, url: &str) -> Self {
        Self {
            name: name.to_owned(),
            url: url.to_owned(),
        }
    }
}

impl core::fmt::Display for ProxyLine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let proxy = Scheme::Proxy.as_str();
        if self.name != proxy {
            write!(f, "{}=", self.name)?;
        }
        write!(f, "{proxy}:{}", self.url)
    }
}

/// Why a typed `serve` entry is not one.
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    /// Its name breaks the one name rule: the rule's own line.
    #[error(transparent)]
    Name(#[from] NameError),
    /// A proxy with nothing to reach, named or not (see [`service_entry`]).
    #[error("proxy needs what it reaches: swoosh serve {0}")]
    ProxyWithoutTarget(ProxyLine),
    /// A proxy whose URL carries a path, a query or a fragment; the line names its origin.
    #[error("a proxy reaches a whole site, so its URL takes no path or query: swoosh serve {0}")]
    ProxyNotAnOrigin(ProxyLine),
    /// A proxy whose URL is neither `http` nor `https`; the line names neither its host nor its path.
    #[error("a proxy reaches only http and https sites: swoosh serve {0}")]
    ProxyNotHttp(ProxyLine),
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
    // Every target is `<scheme>:<rest>`, so the dispatch parses the addr ONCE into its [`Scheme`] and
    // matches that, never the whole string: an engine added to `Scheme` cannot compile without an arm here.
    // No scheme at all, or one no `serve` binds, is not swoosh's to refuse either: tightbeam's grammar owns
    // that teaching error like every other.
    let Some((scheme, rest)) = Scheme::parse(addr) else {
        return router.parse(&[entry.to_owned()]).map_err(target_help);
    };
    // ONE arm per scheme swoosh serves. The arity check is a call inside each arm rather than a second arm
    // listing the schemes again: two arms that must agree is how `ping:80` came to mean a forward to a host
    // named `ping` in the first place, and a fifth zero-argument engine added to a second list is the same
    // bug waiting.
    match scheme {
        Scheme::Ping => {
            no_argument(scheme, rest, entry)?;
            bind_ping(router, name, public)
        }
        Scheme::Speed => {
            no_argument(scheme, rest, entry)?;
            bind_speed(router, name, public)
        }
        #[cfg(feature = "ssh")]
        Scheme::Sshd => {
            no_argument(scheme, rest, entry)?;
            router.service(name, sshh::Sshd::new(host_seed))
        }
        // Without the `ssh` engine compiled in, `sshd:` falls through to tightbeam's refusal and is told it
        // is unknown, which is true of this build.
        #[cfg(not(feature = "ssh"))]
        Scheme::Sshd => router.parse(&[entry.to_owned()]).map_err(target_help),
        // Not swoosh's: a `tcp:`/`unix:` forward, a `file:`/`fifo:`/`stdin:` raw stream, the `echo:`
        // reflector. tightbeam's grammar owns them, refusal included. `recv:` and `proxy:` are taken out of
        // the entries before any is bound here, so one that reaches this is refused by that grammar too.
        // Its refusal names the schemes IT routes, which cannot include swoosh's without handing it a
        // scheme registry it deliberately does not have, so the pointer is added here instead: a reader
        // refused by either half gets told where the whole list is.
        Scheme::Recv
        | Scheme::Proxy
        | Scheme::Tcp
        | Scheme::Unix
        | Scheme::File
        | Scheme::Fifo
        | Scheme::Stdin
        | Scheme::Echo => router.parse(&[entry.to_owned()]).map_err(target_help),
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
fn no_argument(scheme: Scheme, rest: &str, entry: &str) -> eyre::Result<()> {
    if rest.is_empty() {
        return Ok(());
    }
    eyre::bail!(
        "`{}:` takes no argument, but `{entry}` gives it `{rest}`",
        scheme.as_str()
    )
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
pub const RECV_SCHEME: &str = Scheme::Recv.as_str();

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
    let swoosh_home = Dir::of(home.dir());
    let user_home = user_home.map(Dir::of);
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
        // A `name=recv:` (no dir) saves into the inbox; `name=recv:<dir>` into <dir>. The dir is this
        // service's OWN, on its OWN instance, so two receive services never share one output directory.
        let (out, inbox) = if dir.is_empty() {
            let Some(out) = inbox() else {
                eyre::bail!(
                    "HOME is not set, so recv: has no inbox to save into; name a directory: \
                     swoosh serve {name}=recv:<dir>"
                );
            };
            (out, true)
        } else {
            (PathBuf::from(dir), false)
        };
        services.push(RecvService {
            name: name.to_owned(),
            out,
            inbox,
        });
    }
    *requested = remaining;
    Ok(services)
}

/// The scheme prefix a proxy service names, so the origin-extraction matches `proxy:<url>` on the ONE
/// literal, not a re-typed string that could drift from it.
const PROXY_SCHEME: &str = Scheme::Proxy.as_str();

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
/// A `name=proxy:` (no origin) would be an open egress relay; [`service_entry`] refuses it before an entry
/// gets here, and this refuses it again for an entry from anywhere else, so no [`ProxyService`] holds an
/// unconstrained scope and the binder has only the scoped engine to build. An entry without `=` names no
/// service and is a teaching error, mirroring tightbeam's grammar. A malformed origin fails HERE, at expose
/// time, not at dial time.
pub struct ProxyScope;

impl ProxyScope {
    /// Remove every proxy entry from `requested` (leaving the other services for the router's grammar)
    /// and return them as one [`ProxyService`] each: its served name and only its own [`OriginAllowlist`].
    /// Other entries are left in place, in order. A malformed origin fails HERE with a teaching message.
    pub fn extract(requested: &mut Vec<String>) -> eyre::Result<ProxyExposure> {
        let mut services: Vec<ProxyService> = Vec::new();
        let mut remaining: Vec<String> = Vec::new();
        for entry in requested.drain(..) {
            // Split off the `name=` prefix; only the ADDR side names a scheme, so the origin is read
            // from there.
            let Some((name, addr)) = entry.split_once('=') else {
                eyre::bail!(
                    "`{entry}` names no service. Every serve entry must be `name=target`, e.g. \
                     `news=proxy:https://news.example`"
                );
            };
            // A proxy service is `proxy:` optionally followed by an origin. Any other entry passes through
            // unchanged, in order, for the router's own grammar.
            let Some(origin) = addr
                .strip_prefix(PROXY_SCHEME)
                .and_then(|rest| rest.strip_prefix(':'))
            else {
                remaining.push(entry);
                continue;
            };
            // No origin is an open relay, never a scope.
            if origin.is_empty() {
                return Err(EntryError::ProxyWithoutTarget(ProxyLine::new(name, "<url>")).into());
            }
            // Each proxy service gets its OWN allowlist (only its own origin): the per-instance isolation
            // that makes the SSRF pivot unrepresentable.
            let allow = OriginAllowlist::parse([origin]).map_err(origin_refusal)?;
            services.push(ProxyService {
                name: name.to_owned(),
                allow,
            });
        }
        *requested = remaining;
        Ok(ProxyExposure { services })
    }
}

/// An origin the engine refused, in swoosh's words where the engine's own line names the engine: `fetch`
/// is the services crate's internal name and never a word a person types or reads. Matched on the variant, never
/// on its text; every other refusal already speaks of the URL alone, and passes through as it is.
fn origin_refusal(error: ::fetch::OriginError) -> eyre::Report {
    match error {
        ::fetch::OriginError::Userinfo => {
            eyre::eyre!("a proxy URL cannot carry a user or password (user:pass@)")
        }
        other @ (::fetch::OriginError::Url(_)
        | ::fetch::OriginError::NoHost
        | ::fetch::OriginError::NoPort) => eyre::eyre!(other),
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
