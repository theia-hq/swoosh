//! `swoosh serve [<name>=<svc>...]`: be a node. Publish named services behind this node's signet gate,
//! then stay reachable so peers who hold this node's key can reach them.
//!
//! This IS the node. `swoosh serve` with no services answers reach diagnostics (`ping`/`speed`) from
//! peers your signet admits: `ping` (RTT) and `speed` (throughput) are the default services, two
//! so a node may offer one without the other. `swoosh serve ssh=sshd: ping=ping:` publishes a
//! shell and a public-able ping responder without exposing speed. It drives tightbeam's tunnel LIBRARY
//! (`Exposer`) directly under swoosh's OWN persisted identity:
//! the node binds the same key `swoosh ssh` and a minted `swoosh grant issue` link root at, gates on the
//! signet read from swoosh's own store, and derives the ssh host seed from swoosh's secret, so an
//! `ssh=sshd:` service presents the host key a client pins. swoosh assembles the whole handler registry
//! itself (`fetch:`, `ping:`/`speed:`, and `sshd:` under the `ssh` feature), builds the gate through the shared
//! [`resolve_gate`](tightbeam::tunnel::resolve_gate) policy, and prints its OWN readiness banner. `--public`
//! and `--quiet` live on THIS verb (not root), and reach comes via the shared
//! [`ReachArgs`](crate::transport::ReachArgs), flattened like every other reaching verb.

use std::path::PathBuf;
use std::sync::Arc;

use ::fetch::OriginAllowlist;
use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use nauthy::{Denylist, VerifyKey};
use tightbeam::duration::Lifetime;
use tightbeam::tunnel::{self, CancellationToken, Exposer, PublicRequest, Registry, Services};

use crate::contacts::{Contacts, Petname};
use crate::identity::Secret;
use crate::roster::{Epoch, Member, RosterDoc};
use crate::transport::ReachArgs;

mod beam;
mod fetch;
mod ping;
mod roster;
mod services;
mod speed;
#[cfg(feature = "ssh")]
mod sshd;
mod stop;

// These are all `self::` submodules: `beam` and `fetch` share a name with the extern crates they shadow, so
// the handler types come through `self::` and the crates are reached as `::beam` / `::fetch` (the
// `::fetch::OriginAllowlist` import above); `roster` likewise shadows `crate::roster`, reached in full above.
// The rest take `self::` too, so the whole set reads as one local-submodule import group.
use self::beam::Beam;
use self::fetch::Fetch;
use self::ping::Ping;
pub use self::roster::Roster;
pub use self::services::ServiceList;
use self::speed::Speed;
#[cfg(feature = "ssh")]
use self::sshd::Sshd;
pub use self::stop::{STOP_ACK, Stop};

/// The node-control service that stops this node: an admitted caller reaching it triggers a graceful
/// teardown (the remote twin of a local Ctrl-C or a `--for` deadline). The client verb is `swoosh stop`.
///
/// SETTLED name (delib-23, Principal-ruled): one unified `control.*` family over both the reads
/// (`control.status`) and the mutations (`control.stop`); the dotted scheme is the verbatim registry key,
/// gated exact-name, so a grant for one method can never open another. Public so the `swoosh stop` client
/// verb requests the SAME name the served handler is keyed under, one source of truth for the wire string.
pub const CONTROL_STOP_SERVICE: &str = "control.stop";

/// The node-control service that LISTS what this node serves: an admitted caller reaching it reads back the
/// node's served services, each with its NAME and reach posture (gated behind a member badge, or open to
/// anyone). A pure READ of what the exposer was built with, no mutable state and no authority granted. The
/// client verb is `swoosh service --at <peer>`.
///
/// GATED (`type Public = Never`, like `control.stop`): the service menu is member-only, so a stranger never
/// learns what a node serves (delib-18: existence and shape are revealed only AFTER admission; this is the
/// teaching read the wrong-name path deliberately withholds). One unified `control.*` family, the dotted
/// scheme is the verbatim registry key. Public so the `swoosh service` client requests the SAME name the
/// served handler is keyed under, one source of truth for the wire string.
pub const CONTROL_SERVICES_SERVICE: &str = "control.services";

/// The default services `serve` publishes when none is named: swoosh's own gated `ping` and
/// `speed` handlers, under the names a client requests. ping and speed are TWO independent services (cheap
/// RTT vs bandwidth-eating throughput), so a bare `swoosh serve` answers BOTH behind the signet gate, and a
/// node that wants to offer only one names just that one (`swoosh serve ping=ping:`). Each may be
/// made `--public` independently.
const DEFAULT_SERVICES: [&str; 2] = ["ping=ping:", "speed=speed:"];

/// Be a node: publish these services behind your signet gate, then stay reachable.
#[derive(Debug, Args)]
pub struct ServeCmd {
    /// publish local services as `name=svc` (bare = `ping=ping: speed=speed:`, reach diagnostics)
    #[arg(value_name = "name=svc")]
    pub services: Vec<String>,
    /// Open these NAMED services to anyone, unauthenticated (comma-list, repeatable: `--public speed,fetch`
    /// or `--public speed --public fetch`): the per-service opt-out from the signet gate. Each name must be a
    /// service you serve. A keyless shell (`sshd:`, remote code execution) is refused with a teaching error,
    /// and `control.stop`/`control.services` can never be opened. `ping`/`speed` MAY be opened, but they have
    /// no responder-side rate limit yet, so an open one lets an anonymous caller drain this node's uplink (an
    /// amplifier); the readiness banner says so.
    #[arg(long, value_name = "svc", value_delimiter = ',')]
    pub public: Vec<String>,
    /// Suppress the readiness banner (the node id, services, and gate), for unattended/CI use.
    #[arg(long)]
    pub quiet: bool,
    /// Directory a `beam:` service saves pushed files into (received files land here).
    #[arg(long, value_name = "dir", default_value = ".")]
    pub out: PathBuf,
    /// Serve for a bounded time, then stop by itself (`30m`, `2h`, `1d`). A local timer, no security
    /// surface: the node ends when the deadline passes, the same graceful teardown a Ctrl-C gives.
    #[arg(long, value_name = "duration")]
    pub r#for: Option<Lifetime>,
    #[command(flatten)]
    pub reach: ReachArgs,
    /// What `serve` needs beyond the bound node, resolved by the composition root BEFORE the transport
    /// consumes the secret (the ssh host seed derives from it). Not a flag: clap skips it, and the root
    /// fills it in via [`with_expose`](Self::with_expose) before dispatch. Lives HERE, on `ServeCmd`, so
    /// `serve` reads its OWN context (Craftsman): it is deliberately NOT a `ReachCtx` field, so the reach
    /// context stays uniform, and the old `Option<ExposeContext>` threaded through the generic reach
    /// dispatch plus its "internal: serve reached without its expose context" runtime guard are gone.
    #[arg(skip)]
    pub expose: Option<ExposeContext>,
}

/// What `serve` needs beyond the bound node: swoosh's ssh host seed, the trusted signet, the revocation
/// denylist the gate honors, and the pre-cut signed roster blob. All resolved in the composition root (the
/// host seed needs the secret before the transport consumes it), then attached to [`ServeCmd`] via
/// [`with_expose`](ServeCmd::with_expose). Moved here from `main.rs` so `serve` reads its own context.
pub struct ExposeContext {
    /// swoosh's ssh host key seed, derived from the secret so an `ssh=sshd:` service presents the host
    /// key a client pins.
    pub host_seed: [u8; 32],
    /// The signet the default gate trusts: a provisioned signet if one was adopted, else this node's OWN
    /// key (person-zero self-trusts).
    pub signet: Option<NodeId>,
    /// The revocation denylist the gate honors.
    pub denylist: Denylist,
    /// The signet-signed roster blob the `roster:` handler serves, cut once per `serve` from the
    /// operator's contacts while the secret is still live.
    pub roster_blob: Arc<Vec<u8>>,
}

impl core::fmt::Debug for ExposeContext {
    /// `Denylist` holds a `Mutex` (not `Debug`), so this impl names the fields it can and elides that one,
    /// which is enough for the derived `Debug` on `ServeCmd`/`Command` to compile.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExposeContext")
            .field("host_seed", &self.host_seed)
            .field("signet", &self.signet)
            .field("roster_blob_len", &self.roster_blob.len())
            .finish_non_exhaustive()
    }
}

impl crate::reaching::Reaching for ServeCmd {
    fn reach_args(&self) -> &crate::transport::ReachArgs {
        &self.reach
    }

    /// `serve` RECEIVES badges (it is the gate), it never presents one, so it dials as no one:
    /// `Anonymous`. It must bind `Persisted` (a stable address), which is a SEPARATE, non-forgettable
    /// concern, not this credential's derived `Ephemeral`: the composition root's identity override, not
    /// this method, supplies it.
    fn credential(&self) -> crate::credential::Credential {
        crate::credential::Credential::Anonymous
    }

    /// `serve` MUST be reachable at one stable address across runs, so it declares `Persisted` EXPLICITLY
    /// rather than inheriting the credential's derived `Ephemeral` (which would give a new address every
    /// run: a broken node). This is a written declaration the compiler requires, not a forgettable
    /// override, so a serve verb cannot silently come up ephemeral.
    fn identity(&self) -> crate::identity::Identity {
        crate::identity::Identity::Persisted
    }

    /// Uniform dispatch: `serve` reads its OWN [`ExposeContext`] (attached by the root via
    /// [`with_expose`](Self::with_expose)), so it ignores every `ReachCtx` field. This is where the old
    /// `Option<ExposeContext>` threaded through the generic reach dispatch, and its
    /// "internal: serve reached without its expose context" guard in `main.rs`, are gone: the context is
    /// serve's own, attached before dispatch.
    async fn run<T: Transport, D: Discovery>(
        mut self,
        node: &Node<T, D>,
        _ctx: crate::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        // The root always attaches the expose context to a `serve` verb before dispatch (it is the only
        // caller, and `with_expose` is the only path to a runnable `ServeCmd`), so a missing one is a
        // composition-root bug, not a user error. Surface it as an internal error rather than panicking:
        // unlike the OLD guard, this is not a threaded `Option` a whole family of verbs could trip, it is
        // serve reading its own field, so the failure is local and one verb wide.
        let Some(ExposeContext {
            host_seed,
            signet,
            denylist,
            roster_blob,
        }) = self.expose.take()
        else {
            eyre::bail!(
                "internal: serve reached run without its expose context (composition-root bug)"
            );
        };
        self.run_serve(node, host_seed, signet, denylist, roster_blob)
            .await
    }
}

impl ServeCmd {
    /// Attach the resolved [`ExposeContext`] the composition root cut while the secret was still live, so
    /// `serve` reads its own context at run time. The ONE path the root uses to make a `ServeCmd`
    /// runnable, so a `serve` that reached `run` without one is a root bug, not a representable state a
    /// user hits.
    pub fn with_expose(mut self, expose: ExposeContext) -> Self {
        self.expose = Some(expose);
        self
    }
}

impl ServeCmd {
    /// Serve the named services (default `ping:` + `speed:`) under swoosh's identity by driving the
    /// tunnel core directly: parse the services, resolve the gate from swoosh's own signet + denylist (through
    /// the shared `resolve_gate` policy, so `--public` opens, else a family gate on the signet), assemble the
    /// handler registry (`fetch:`, `ping:`/`speed:`, and `sshd:` under the `ssh` feature), print
    /// swoosh's banner, and run the exposer. A `sshd:`/`ping:`/`speed:` service stays gated regardless. The `signet` here is already
    /// resolved by the composition root: a provisioned signet if one was adopted, else this node's OWN key
    /// (person-zero self-trusts), so a plain node gates on itself rather than failing "no signet".
    async fn run_serve<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        host_seed: [u8; 32],
        signet: Option<NodeId>,
        denylist: Denylist,
        roster_blob: Arc<Vec<u8>>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let mut requested: Vec<String> = if self.services.is_empty() {
            DEFAULT_SERVICES.iter().map(|s| (*s).to_owned()).collect()
        } else {
            self.services.clone()
        };
        // Every node answers its own `control.stop`, always, whatever else it serves: the node-lifecycle
        // control surface is part of being a node, not a service the operator opts into. It is GATED by the
        // same family gate as everything else, so only an admitted caller (a member of this node's family)
        // can reach it (see `stop_handler`). Pointed at the `control.stop:` handler injected below.
        requested.push(format!("{CONTROL_STOP_SERVICE}={CONTROL_STOP_SERVICE}:"));
        // Every node also answers its own gated `control.services` read: the node-lifecycle READ twin of
        // `control.stop`, part of being a node. Pointed at the `control.services:` handler injected below.
        requested.push(format!(
            "{CONTROL_SERVICES_SERVICE}={CONTROL_SERVICES_SERVICE}:"
        ));
        // Pull each fetch service out of the requested set BEFORE tightbeam parses them, and de-merge them:
        // every `name=fetch:<origin>` becomes its OWN handler instance holding ONLY its own origin scope,
        // registered under a distinct UNSPELLABLE synthetic scheme (`fetch_0`, `fetch_1`, ...). A public
        // fetch handler therefore physically holds only its own origins and cannot reach a gated fetch's
        // origins: the SSRF pivot is unrepresentable, not fail-closed-by-convention (delib-39 BLOCKER-3). The
        // synthetic scheme carries a `_`, which the addr grammar rejects, so no operator entry (`x=fetch_0:`)
        // can ever resolve onto a synthetic instance.
        let fetch = FetchScope::extract(&mut requested)?;
        let mut services = Services::parse(&requested)?;
        for scoped in fetch.services() {
            // Inserted DIRECTLY (bypassing the addr grammar) so the synthetic `_`-bearing scheme is usable.
            services = services.with_handler(scoped.name(), scoped.scheme())?;
        }
        // The operator's raw `--public` request: the UNPROVEN set of names to open. `Exposer::with_public`
        // below is the wall that proves each one exposed and open-safe (per-service), turning it into the
        // gate's proven overlay; a `Never` service or an unknown name bails there.
        let public = PublicRequest::new(self.public.clone());
        // Resolve the node BASE gate before announcing readiness: an unprovisioned node fails HERE, through
        // the ONE shared policy point, rather than ever serving on a permissive default. Opening individual
        // services is the separate `--public` overlay, never a node-wide value.
        let gate = tunnel::resolve_gate(signet, denylist)?;
        // Refuse an unconstrained PUBLIC fetch per-service: for each fetch service NAMED in `--public` whose
        // allowlist is unconstrained, bail at build time (an open egress relay). With per-service scopes in
        // hand this reasons about "is THIS public fetch unconstrained", so a second origin-scoped fetch can no
        // longer mask a bare public one. Stays swoosh-side; tightbeam's `with_public` handles the sshd/raw wall.
        fetch.refuse_open_relay(&public)?;
        // Snapshot the served catalog (names + effective PER-SERVICE posture: open iff opened by `--public`,
        // else gated) ONCE, here, for the `control.services` read handler to serve. Built from the same raw
        // request `with_public` proves below, so a name reads `open` only when the proof would also pass.
        let catalog = services.catalog(&gate, &public);
        // The node's ONE teardown authority. The exposer owns it (it is what acts on the cancel); a local
        // `--for` timer and the gated `control.stop` handler each hold a CLONE as the node-control
        // capability -- they may REQUEST the stop, never tear the node down themselves. So this one token is
        // the join point for every way the node can stop: a Ctrl-C, a `--for` deadline, or a remote
        // `swoosh stop`.
        let cancel = CancellationToken::new();
        // Assemble the registry: the base handlers, then one `Fetch` instance per fetch service under its own
        // synthetic scheme, then roster + the two `control.*` handlers. `Exposer::new` enforces every named
        // handler is registered and guards a node-wide-open base; `with_public` then proves the per-service
        // overlay (sshd/raw/unknown bail here, before any banner advertises a service it will not serve).
        let mut registry = registry(host_seed, self.out.clone())?;
        for scoped in fetch.services() {
            registry = registry.with(
                scoped.scheme(),
                Fetch {
                    allow: scoped.allow().clone(),
                },
            );
        }
        let registry = registry
            .with("roster", Roster::new(roster_blob))
            .with(CONTROL_STOP_SERVICE, Stop::new(cancel.clone()))
            .with(CONTROL_SERVICES_SERVICE, ServiceList::new(catalog));
        let exposer = Exposer::new(services.clone(), registry, gate)?.with_public(public)?;

        if !self.quiet {
            let addr = node.local_addr();
            println!("swoosh ready. peers can reach this node at:\n");
            println!("    {}\n", addr.node);
            // Direct-only transports (quirk) cannot discover this address, so print the dialable hint a
            // client feeds back via `--peer`. Self-discovering transports (iroh) carry no local hints here,
            // so this loop prints nothing for them.
            for hint in &addr.hints {
                println!("    --peer {}={hint}\n", addr.node);
            }
            let names: Vec<&str> = services.names().collect();
            let stop = match self.r#for {
                Some(lifetime) => format!("stops in {}, or ctrl-c", humanize(lifetime.duration())),
                None => "ctrl-c to stop".to_owned(),
            };
            println!(
                "serving {} (gate: {}). {stop}.",
                names.join(", "),
                self.gate_description(signet, addr.node),
            );
            if !self.public.is_empty() {
                println!(
                    "open to anyone, unauthenticated: {}.",
                    self.public.join(", ")
                );
            }
            // Honesty (delib-39 B2/MAJOR-1): a public `ping`/`speed` answers any anonymous caller with no
            // responder-side rate limit yet, so it lets a stranger drain this node's uplink. State the
            // amplification plainly so the operator's opt-in is informed.
            let amplifiers = public_amplifiers(&requested, &self.public);
            if !amplifiers.is_empty() {
                println!(
                    "  note: {} answer anyone with no rate limit yet, so an anonymous caller can drain \
                     this node's uplink (an amplifier).",
                    amplifiers.join(", ")
                );
            }
        }

        // A `--for` deadline is a LOCAL timer with no security surface: after it elapses it cancels the
        // node's teardown token, the same graceful stop a Ctrl-C or a remote `control.stop` gives. Spawn it
        // beside the run holding a CLONE of the one token; if no `--for` is set, no timer is spawned.
        if let Some(lifetime) = self.r#for {
            let cancel = cancel.clone();
            let deadline = lifetime.duration();
            tokio::spawn(async move {
                tokio::time::sleep(deadline).await;
                cancel.cancel();
            });
        }

        // Run until a stop, distinguishing a GRACEFUL stop (an owner-requested `control.stop` or a `--for`
        // deadline, or a Ctrl-C) from an ERRORED teardown. The exposer returns `Ok` when the token fires and
        // an `Err` only on a real failure, so `run_until_stopped` maps that into a typed [`Stopped`] reason
        // for a graceful end and propagates the error otherwise. A requested stop is SUCCESS: a deliberate
        // `swoosh stop` (or a timer, or a Ctrl-C) must exit 0 so the qat CI action reads a clean teardown as
        // green, not a crash; only a genuine error teardown exits non-zero.
        let stopped = self.run_until_stopped(exposer, node, cancel).await?;
        println!("{}", stopped.message());
        node.close().await;
        Ok(())
    }

    /// Drive the exposer until it stops, returning WHY it stopped for a graceful end or propagating the
    /// error for a failed teardown. The one seam that classifies a stop: the exposer's `run` returns `Ok`
    /// the instant the teardown token fires (an owner's `control.stop`, or a `--for` deadline) and an `Err`
    /// only on a real failure, so an `Ok` return is a [`Stopped::Requested`]; a Ctrl-C is a
    /// [`Stopped::Interrupted`] (the local operator asking for the same graceful stop). A returned `Err` is
    /// a genuine teardown failure the caller propagates, so the process exits non-zero ONLY then.
    async fn run_until_stopped<T: Transport, D: Discovery>(
        &self,
        exposer: Exposer,
        node: &Node<T, D>,
        cancel: CancellationToken,
    ) -> eyre::Result<Stopped>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        // The exposer owns the teardown: it returns when the token fires (a `--for` deadline, or an admitted
        // `control.stop` caller). A Ctrl-C is the same graceful stop, driven here by cancelling the token so
        // there is ONE stop path, then letting the run finish.
        tokio::select! {
            result = exposer.run(node, cancel.clone()) => {
                // `Ok` here means the token fired (a requested stop): success. An `Err` is a real teardown
                // failure, propagated so the process exits non-zero (the one non-zero path).
                result?;
                Ok(Stopped::Requested)
            }
            signalled = tokio::signal::ctrl_c() => {
                // A failure INSTALLING the signal handler is a real error (propagate); an actual Ctrl-C is a
                // graceful interrupt, so cancel the one token and let the run finish, then report it.
                signalled?;
                cancel.cancel();
                Ok(Stopped::Interrupted)
            }
        }
    }

    /// A one-line description of the node's BASE gate, for the readiness banner: trust made visible. `self_id`
    /// is this node's own id, so the banner can say "self" when the gate roots at the node's OWN key (a
    /// person-zero node with no provisioned signet self-trusts) rather than naming its own id as a "signet".
    /// The base is always the family gate now; services opened with `--public` are reported on their own line,
    /// not folded into the base description.
    fn gate_description(&self, signet: Option<NodeId>, self_id: NodeId) -> String {
        match signet {
            Some(root) if root == self_id => {
                "self (person-zero: this node and its devices)".to_owned()
            }
            Some(root) => format!("signet {}", root.short()),
            None => "unprovisioned".to_owned(),
        }
    }
}

/// The public service names that are reach-diagnostic AMPLIFIERS (`ping`/`speed`): a public one answers any
/// anonymous caller with no responder-side rate limit yet, so the banner names them so the operator's opt-in
/// is informed (delib-39 B2/MAJOR-1). Reads the resolved request entries (`name=addr`, control.* and defaults
/// already folded in), so a renamed amplifier (`fast=speed:`) is caught by its `speed:`/`ping:` scheme, not
/// by a hard-coded name. A bare `ping:`/`speed:` with no name defaults to `default`, matching `Services::parse`.
fn public_amplifiers(requested: &[String], public: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter_map(|entry| {
            let (name, addr) = match entry.split_once('=') {
                Some((name, addr)) => (name, addr),
                None => ("default", entry.as_str()),
            };
            (matches!(addr, "ping:" | "speed:") && public.iter().any(|p| p == name))
                .then(|| name.to_owned())
        })
        .collect()
}

/// WHY a `serve` run stopped, for a GRACEFUL stop: an enum, not a bool, so a new stop reason forces a
/// decision at every match site (STYLE: prefer enums to bools). Every arm is a SUCCESS: an owner asked the
/// node to stop and it did, so the process exits 0. A real teardown FAILURE never becomes a `Stopped`, it
/// stays an `Err` the run propagates, so "graceful" and "errored" cannot be confused: the type only exists
/// on the success path. This is the distinction the qat CI action reads, a deliberate stop is green.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// An owner requested the stop: an admitted `control.stop` caller, or a `--for` deadline. The exposer's
    /// `run` returned `Ok` because its teardown token fired, the ordinary end of a node's life.
    Requested,
    /// The local operator pressed Ctrl-C: the same graceful stop, driven from the keyboard rather than the
    /// overlay.
    Interrupted,
}

impl Stopped {
    /// The one clear line printed on a graceful stop, so a CI action log (the qat teardown) reads a
    /// deliberate stop as a clean end, not a mystery exit. Names the reason plainly.
    pub fn message(self) -> &'static str {
        match self {
            Self::Requested => "\nnode stopped gracefully.",
            Self::Interrupted => "\nnode stopped (interrupted).",
        }
    }
}

/// Render a `--for` duration back to a short human span for the banner (`90m` -> `1h 30m`, `3600s` ->
/// `1h`), so the readiness line reads the way the operator thinks about it rather than in raw seconds.
/// Coarsest non-zero units only, at most two, so `1d` stays `1d` and `5400s` reads `1h 30m`.
fn humanize(duration: core::time::Duration) -> String {
    let mut secs = duration.as_secs();
    let mut parts = Vec::new();
    for (unit, per) in [("d", 86_400), ("h", 3_600), ("m", 60), ("s", 1)] {
        let n = secs / per;
        if n > 0 {
            parts.push(format!("{n}{unit}"));
            secs %= per;
        }
        if parts.len() == 2 {
            break;
        }
    }
    // A sub-second `--for` cannot occur (`Lifetime` rejects zero and parses whole seconds), so `parts` is
    // never empty; guard defensively rather than unwrap.
    if parts.is_empty() {
        "0s".to_owned()
    } else {
        parts.join(" ")
    }
}

/// Assemble the BASE handler registry swoosh serves: the two gated diagnostic services `ping:` and `speed:`,
/// the gated file-receive `beam:`, and (under the `ssh` feature) the keyless shell `sshd:`. swoosh is the one
/// crate that depends on every service crate, so it is the one place these are wired: tightbeam names no
/// service crate and ships no built-in, and this function injects them all with `.with(...)`.
///
/// Fetch is NOT here: each fetch service is de-merged into its OWN `Fetch` instance holding only its own
/// origin scope, registered by `run_serve` under a distinct synthetic scheme (delib-39 BLOCKER-3), so there
/// is no single shared `fetch:` handler to over-permit. `roster:` and the two `control.*` handlers are
/// likewise added by `run_serve` (they hold per-run state: the signed roster blob, the teardown token, the
/// catalog snapshot).
///
/// ping and speed are TWO independent services so a node may offer ping without speed (or the reverse),
/// and each carries its own gate: `ping` answers only ping frames, `speed` only speed frames, refusing the
/// other method at the wire (`ProtocolError::WrongService`), so a grant for one can never open the other.
///
/// `beam_out` is the directory a `beam:` service saves pushed files into; the handler reduces each
/// sender-supplied name to a safe relative path under it (`beam::safe_relative_path`), so a peer can never
/// write outside the directory.
///
/// The ONE assembly the product verb and the `gated_measure` proof test both build, so the test exercises the
/// identical handlers swoosh serves rather than a hand-rolled near-copy.
pub fn registry(host_seed: [u8; 32], beam_out: PathBuf) -> eyre::Result<Registry> {
    let registry = Registry::new()
        .with("ping", Ping)
        .with("speed", Speed)
        .with("beam", Beam::new(beam_out));
    #[cfg(feature = "ssh")]
    let registry = registry.with("sshd", Sshd { host_seed });
    #[cfg(not(feature = "ssh"))]
    let _ = host_seed;
    Ok(registry)
}

/// Cut the current roster from the operator's own contacts (the `me/<label>` partition, where `mint`
/// records each member) and sign it with the signet, returning the encoded blob the `roster:` handler
/// serves. The SIGNET signs it (via [`Secret::cap_identity`]), so any member node can serve it and none can
/// forge it. Cut ONCE at serve start (a snapshot); a member added later is picked up on the next `serve`.
///
/// The epoch is READ from the persisted roster epoch beside the contacts (default 0 before any is set), so
/// the puller's anti-rollback floor is not pinned at 0. The BUMP verb (a `swoosh fleet cut` that increments
/// and re-signs) is deferred to B2; today the read is real, so once the counter advances the floor tracks
/// it. A member's label IS a [`DeviceLabel`], the same type contacts hold, so there is no lossy re-parse.
pub fn cut_roster(contacts: &Contacts, secret: &Secret) -> eyre::Result<Vec<u8>> {
    let me: Petname = "me".parse()?;
    let members: Vec<Member> = contacts
        .devices(&me)
        .into_iter()
        .flatten()
        .map(|(label, node)| Member {
            node: VerifyKey::new(*node.key()),
            label: label.clone(),
        })
        .collect();
    let epoch = Epoch(contacts.roster_epoch().unwrap_or(0));
    let doc = RosterDoc::new(epoch, members)?;
    // One-writer LOCK (delib-28): the SIGNET is the sole cutter. Cutting needs the live secret (only it
    // signs a roster the signet verifies), so this path holds `secret`; a relay-only `serve` node holds
    // just the bytes and cannot cut. See `roster::cut` for the full rule and why multi-writer is rejected.
    Ok(crate::roster::cut(&secret.cap_identity()?, &doc))
}

/// The scheme prefix a fetch service names, so the origin-extraction matches `fetch:<origin>` on the ONE
/// literal, not a re-typed string that could drift from it.
const FETCH_SCHEME: &str = "fetch";

/// One de-merged fetch service: its served NAME (the wire name a dialer requests, e.g. `news`), the
/// UNSPELLABLE synthetic registry scheme its own `Fetch` instance is keyed under (`fetch_0`, `fetch_1`, ...),
/// and ONLY its own origin scope. Because each fetch service holds its own instance under its own scheme, a
/// public fetch physically cannot reach a gated fetch's origins: the SSRF pivot is unrepresentable, not
/// fail-closed-by-convention (delib-39 BLOCKER-3).
struct FetchService {
    name: String,
    scheme: String,
    allow: OriginAllowlist,
}

impl FetchService {
    /// The served name a dialer requests and `--public` names.
    fn name(&self) -> &str {
        &self.name
    }

    /// The synthetic, unspellable registry scheme this service's own `Fetch` instance is keyed under.
    fn scheme(&self) -> &str {
        &self.scheme
    }

    /// This service's own origin scope (only its own; never merged with another's).
    fn allow(&self) -> &OriginAllowlist {
        &self.allow
    }
}

/// De-merges the fetch services out of the requested set: a `name=fetch:<origin>` entry hands tightbeam an
/// origin its bare-scheme `Target::Handler` cannot hold, so swoosh separates each into its OWN
/// [`FetchService`] (name + a distinct synthetic scheme + its own origin scope) here, before `Services::parse`.
///
/// A pure edge adapter over the raw request strings. A bare `fetch:` (no origin) is an unconstrained fetch
/// under the name `default` (matching `Services::parse`'s bare-entry rule); a `name=fetch:<origin>` is a
/// named, origin-scoped fetch. A malformed origin fails HERE, at expose time, not at dial time.
struct FetchScope;

impl FetchScope {
    /// Remove every fetch entry from `requested` (leaving the non-fetch services for `Services::parse`) and
    /// return them as one [`FetchService`] each: its served name, a distinct synthetic `fetch_<i>` scheme, and
    /// only its own [`OriginAllowlist`]. Non-fetch entries are left in place, in order. A malformed origin
    /// fails HERE with a teaching message.
    fn extract(requested: &mut Vec<String>) -> eyre::Result<FetchExposure> {
        let mut services: Vec<FetchService> = Vec::new();
        let mut remaining: Vec<String> = Vec::new();
        for entry in requested.drain(..) {
            // Split off the optional `name=` prefix; a bare entry (no `=`) is its own addr under the `default`
            // name. Only the ADDR side names a scheme, so the origin is read from there.
            let (name, addr) = match entry.split_once('=') {
                Some((name, addr)) => (name.to_owned(), addr),
                None => ("default".to_owned(), entry.as_str()),
            };
            // A fetch service is `fetch:` optionally followed by an origin. A non-fetch entry passes through
            // unchanged, in order, for `Services::parse`.
            let Some(origin) = addr
                .strip_prefix(FETCH_SCHEME)
                .and_then(|rest| rest.strip_prefix(':'))
            else {
                remaining.push(entry);
                continue;
            };
            // Each fetch service gets its OWN allowlist (only its own origin; empty = unconstrained) and its
            // OWN unspellable synthetic scheme, indexed so two fetch services never collide.
            let allow = if origin.is_empty() {
                OriginAllowlist::default()
            } else {
                OriginAllowlist::parse([origin]).map_err(|error| eyre::eyre!(error))?
            };
            let scheme = format!("{FETCH_SCHEME}_{}", services.len());
            services.push(FetchService {
                name,
                scheme,
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
struct FetchExposure {
    services: Vec<FetchService>,
}

impl FetchExposure {
    /// The de-merged fetch services, each to be registered under its own synthetic scheme.
    fn services(&self) -> &[FetchService] {
        &self.services
    }

    /// Refuse the one illegal fetch shape PER SERVICE: a fetch service NAMED in `--public` whose allowlist is
    /// unconstrained (any origin), which is an open egress relay (traffic-source laundering, a reflector, a
    /// free anonymizing hop). Because each fetch service carries its own scope, this reasons about THIS public
    /// fetch, so a second origin-scoped fetch can no longer mask a bare public one. Refused at build time,
    /// before any banner or accepted stream, mirroring the sshd-cannot-be-public wall. A GATED fetch (not in
    /// `--public`) stays legal unconstrained: the family gate is the terminator there.
    fn refuse_open_relay(&self, public: &PublicRequest) -> eyre::Result<()> {
        for service in &self.services {
            if public.contains(&service.name) && service.allow.is_unconstrained() {
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

#[cfg(test)]
#[path = "serve_tests.rs"]
mod serve_tests;
