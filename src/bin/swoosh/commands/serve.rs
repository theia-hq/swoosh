//! `swoosh serve [<name>=<svc>...]`: be a node. Publish named services behind this node's signet gate,
//! then stay reachable so peers who hold this node's key can reach them.
//!
//! This IS the node. `swoosh serve` with no services answers reach diagnostics (`ping`/`speed`) from
//! peers your signet admits: `ping` (RTT) and `speed` (throughput) are the default services, two
//! so a node may offer one without the other. `swoosh serve ssh=sshd: ping=ping:` publishes a
//! shell and a public-able ping responder without exposing speed. Every entry after `serve` names its
//! service (`ping=ping:`, never a bare `ping:`). It drives tightbeam's tunnel LIBRARY
//! (`Exposer`) directly under swoosh's OWN persisted identity:
//! the node binds the same key `swoosh ssh` and a minted `swoosh grant issue` link root at, gates on the
//! pin read live from swoosh's own store and on the links this machine signed, and derives the ssh host
//! seed from swoosh's secret, so an `ssh=sshd:` service presents the host key a client pins. swoosh
//! assembles the whole route table itself (`fetch`/`recv` instances, `ping`/`speed`, the update route,
//! and `sshd` under the `ssh` feature), takes the gate the composition root built
//! ([`swoosh::gate::anchored`]), and prints its OWN readiness banner. `--public`
//! and `--quiet` live on THIS verb (not root), and reach comes via the shared
//! [`ReachArgs`](swoosh::transport::ReachArgs), flattened like every other reaching verb. `--expires` is a
//! LOCAL timer with no security surface: when its deadline passes the node ends by itself, the same
//! graceful teardown a Ctrl-C gives.
//!
//! This file owns the VERB: its flags, the readiness banner, and the run loop. The node engine it
//! drives (the route-table edges, the `control.*` handlers, the resident arm) is the library's `serve`
//! module, which the integration proofs also assemble their nodes from.

use core::net::SocketAddr;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use bifrost_mdns::{At, Dialable, Expiring, Missing, ScopeClass};
use clap::Args;
use eyre::WrapErr as _;
use nauthy::{Gate, Service};
use swoosh::gate::AnchorCut;
use swoosh::home::Home;
use swoosh::identity::Identity;
use swoosh::reaching::{BindRole, ReachCtx, Reaching};
use swoosh::serve::{
    Activity, CONTROL_SERVICES_SERVICE, CONTROL_STOP_SERVICE, FetchScope, InstanceLock,
    RECV_SCHEME, ROSTER_SERVICE, Resident, Roster, ServiceList, Stop, StopKind, Stopped,
    acquire_single, bind_entry, bind_recv, classify_stop, extract_recv_services,
};
use swoosh::transport::{MdnsState, Reach, ReachArgs, RelayHome, Resolver};
use tightbeam::duration::Lifetime;
use tightbeam::enabled::FileDisabledList;
use tightbeam::tunnel::{
    CancellationToken, Exposer, ManifestEntry, Metering, Posture, RawSource, Router, TargetKind,
};

/// The default services `serve` publishes when none is named: the gated `ping` and `speed` engine
/// handlers, under the names a client requests. ping and speed are TWO independent services (cheap
/// RTT vs bandwidth-eating throughput), so a bare `swoosh serve` answers BOTH behind the signet gate, and a
/// node that wants to offer only one names just that one (`swoosh serve ping=ping:`). Each may be
/// made `--public` independently.
const DEFAULT_SERVICES: [&str; 2] = ["ping=ping:", "speed=speed:"];

/// Be a node: publish these services behind your signet gate, then stay reachable.
#[derive(Debug, Args)]
pub struct ServeCmd {
    /// publish services as `name=target` (bare: `ping` and `speed`)
    // The long form lists every target scheme, both halves: the three engines swoosh serves and the six
    // forms the tunnel grammar routes. A refusal from either half points here, so this list is the one a
    // mistyped scheme is sent to and it has to be complete.
    #[arg(
        value_name = "name=target",
        value_parser = swoosh::serve::service_entry,
        long_help = "publish services as `name=target` (bare: `ping` and `speed`)\n\
                     \n\
                     Every target carries a scheme. swoosh serves:\n\
                     \x20 ping:            round-trip probe\n\
                     \x20 speed:           throughput test\n\
                     \x20 sshd:            a shell, keyless (the node's gate is the auth)\n\
                     \n\
                     and it forwards or streams:\n\
                     \x20 tcp:<host>:<port>  a local TCP service\n\
                     \x20 unix:<path>        a local Unix socket\n\
                     \x20 file:<path>        an existing file's bytes\n\
                     \x20 fifo:<path>        a named pipe, live\n\
                     \x20 stdin:             this process's own stdin\n\
                     \x20 echo:              reflects whatever is sent\n\
                     \n\
                     The three swoosh serves take no argument, and neither do `stdin:` and `echo:`. \
                     A live single-writer source (`stdin:`, `fifo:`) may be suffixed `+lossy` to fan \
                     out to many readers at once, dropping bytes for one that falls behind."
    )]
    pub services: Vec<String>,
    /// open named services to anyone (comma-list, repeatable)
    #[arg(
        long,
        value_name = "svc",
        value_delimiter = ',',
        long_help = "A keyless shell is refused; a raw stream goes to `--public-unsafe`."
    )]
    pub public: Vec<String>,
    /// open named raw-stream services (file:, fifo:, stdin:) to anyone
    // A raw stream opens only through this flag, and only when named: no bang suffix, no whole-node form.
    #[arg(
        long,
        value_name = "svc",
        value_delimiter = ',',
        long_help = "A raw stream has no auth of its own; `--public` refuses it and points here."
    )]
    pub public_unsafe: Vec<String>,
    /// suppress the readiness banner and activity lines
    #[arg(long)]
    pub quiet: bool,
    /// serve for a bounded time, then stop (`30m`, `2h`, `1d`)
    #[arg(long, value_name = "duration")]
    pub expires: Option<Lifetime>,
    /// be the resident node: one per home, control socket; stays foreground
    #[arg(long)]
    pub resident: bool,
    #[command(flatten)]
    pub reach: ReachArgs,
    /// What `serve` needs beyond the bound node, resolved by the composition root BEFORE the transport
    /// consumes the secret (the ssh host seed derives from it). Not a flag: clap skips it, and the root
    /// fills it in via [`with_expose`](Self::with_expose) before dispatch. Lives HERE, on `ServeCmd`, so
    /// `serve` reads its OWN context: it is deliberately NOT a `ReachCtx` field, so the reach
    /// context stays uniform, and the old `Option<ExposeContext>` threaded through the generic reach
    /// dispatch plus its "internal: serve reached without its expose context" runtime guard are gone.
    // Boxed so the runtime context (which embeds a `FileDenylist`, itself carrying a `Mutex` and its
    // live-reload state) does not bloat `ServeCmd` inline: `Serve(ServeCmd)` is a variant of the clap
    // command enums, and an unboxed context makes that one variant far larger than the rest
    // (`clippy::large_enum_variant`). A `Box` keeps `ServeCmd` pointer-sized here; the context is a
    // root-attached, run-once value, so the one allocation is free of any hot path.
    #[arg(skip)]
    pub expose: Option<Box<ExposeContext>>,
    /// Whether the composed discovery's mDNS half came up, attached by the composition root AFTER the
    /// transport binds (the bit is known only then, from the same `advertise` call that composed
    /// discovery). Not a flag: clap skips it, and the root fills it in via
    /// [`with_mdns`](Self::with_mdns) before dispatch, exactly like [`expose`](Self::expose). `serve`
    /// is the one verb that reports discovery, so the tell lives HERE and the reach context stays
    /// uniform; the banner reports what started rather than assuming it.
    #[arg(skip)]
    pub mdns: Option<MdnsState>,
    /// The relay and the resolver this bind actually leaned on, attached by the composition root after
    /// it composed them from the flags and the home files. Not a flag: clap skips it, and the root fills
    /// it in via [`with_bound_reach`](Self::with_bound_reach) alongside [`mdns`](Self::mdns). The
    /// default is n0's on both halves, which is what every bind that has no relay or resolver of its own
    /// (quirk, `--local`) leans on, so an un-attached value still tells the banner the truth.
    // Boxed for the same reason [`expose`](Self::expose) is: each named half holds a parsed URL, which is
    // large by value, and `Serve(ServeCmd)` is a variant of the clap command enums, so inline this one
    // pair would make that variant tower over the rest (`clippy::large_enum_variant`). A root-attached,
    // run-once value, so the one allocation is free of any hot path.
    #[arg(skip)]
    pub bound_reach: Box<Reach>,
}

/// What `serve` needs beyond the bound node: swoosh's ssh host seed, the gate and the live cut beside it,
/// and the signed roster artifact it relays. All resolved in the composition root (the
/// host seed needs the secret before the transport consumes it), then attached to [`ServeCmd`] via
/// [`with_expose`](ServeCmd::with_expose). Moved here from `main.rs` so `serve` reads its own context.
/// The home rides along too: `serve --resident` names its socket/lock off the home, and the SAME `home`
/// value the root resolved (never a re-derive), so the resident paths and the daemon's future clients
/// can never disagree on which home they mean.
pub struct ExposeContext {
    /// swoosh's ssh host key seed, derived from the secret so an `ssh=sshd:` service presents the host
    /// key a client pins.
    pub host_seed: [u8; 32],
    /// The one gate this node runs in every standing ([`swoosh::gate::anchored`]): the pin read live,
    /// this machine's own key for the links it signed, and the revocations.
    pub gate: Gate,
    /// The live cut over the same pin and revocations the gate reads, wired beside it.
    pub cut: AnchorCut,
    /// The live enable/disable oracle the exposer's per-stream gate consults: a `service disable`
    /// written to `<home>/disabled` refuses the service live, and a `service enable` restores it, both with no
    /// restart. The exact mtime-watch shape as the denylist, loaded beside it in the composition root.
    pub enabled: FileDisabledList,
    /// The home's signed roster artifact, served on the update route every `serve` binds. `serve` READS
    /// it and never signs, so this long-lived process holds no signing identity. A missing file reads as
    /// none. Re-read per pull (a debounced stat), so an update lands without a restart.
    pub roster: Arc<swoosh::roster::Artifact>,
    /// The node home this serve runs under: the resident socket/lock derive from it, and the composition
    /// root resolves it ONCE, so a `--resident` serve and its future control clients name the same paths.
    pub home: Home,
}

impl core::fmt::Debug for ExposeContext {
    /// The gate, the cut and `FileDisabledList` are not `Debug`, so this impl names the fields it can and
    /// elides those, which is enough for the derived `Debug` on `ServeCmd`/`Command` to compile.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExposeContext")
            .field("host_seed", &self.host_seed)
            .field("roster", &self.roster.path())
            .finish_non_exhaustive()
    }
}

impl Reaching for ServeCmd {
    fn reach_args(&self) -> &ReachArgs {
        &self.reach
    }

    /// `serve` is the gate: it dials no peer and takes no `--present`, so there is no self-addressing link
    /// peer to conflict with. The check is vacuously satisfied.
    fn reject_redundant_present(&self) -> eyre::Result<()> {
        Ok(())
    }

    /// `serve` MUST be reachable at one stable address across runs, so it declares `Persisted`
    /// EXPLICITLY. This is a written declaration the compiler requires, not a forgettable override, so a
    /// serve verb cannot silently come up on a key that changes every run.
    fn identity(&self) -> Identity {
        Identity::Persisted
    }

    /// Serving: `serve` is the process that accepts connections under the home key, so its bind publishes
    /// the key's address record (n0 pkarr/DNS) for peers to dial. The one `Serving` verb, and the one verb
    /// that states NO dial credential: it is the gate, so it verifies badges and never presents one. There
    /// is no "not applicable" credential for it to declare, which is why there is none for a dialing verb
    /// to be transcribed with either.
    fn bind_role(&self) -> BindRole {
        BindRole::Serving
    }

    /// Uniform dispatch: `serve` reads its OWN [`ExposeContext`] (attached by the root via
    /// [`with_expose`](Self::with_expose)), so it ignores every `ReachCtx` field. This is where the old
    /// `Option<ExposeContext>` threaded through the generic reach dispatch, and its
    /// "internal: serve reached without its expose context" guard in `main.rs`, are gone: the context is
    /// serve's own, attached before dispatch.
    async fn run<T: Transport, D: Discovery>(
        mut self,
        node: &Node<T, D>,
        _ctx: ReachCtx<'_>,
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
        let Some(expose) = self.expose.take() else {
            eyre::bail!(
                "internal: serve reached run without its expose context (composition-root bug)"
            );
        };
        let ExposeContext {
            host_seed,
            gate,
            cut,
            enabled,
            roster,
            home,
        } = *expose;
        self.run_serve(node, host_seed, gate, cut, enabled, roster, home)
            .await
    }
}

impl ServeCmd {
    /// Attach the resolved [`ExposeContext`] the composition root cut while the secret was still live, so
    /// `serve` reads its own context at run time. The ONE path the root uses to make a `ServeCmd`
    /// runnable, so a `serve` that reached `run` without one is a root bug, not a representable state a
    /// user hits.
    pub fn with_expose(mut self, expose: ExposeContext) -> Self {
        self.expose = Some(Box::new(expose));
        self
    }

    /// Attach the live [`MdnsState`] the composition root read off the composed discovery, so the
    /// banner reports the discovery that started rather than one it assumed. The root calls this after
    /// `PeerHint::discovery` and before dispatch; a `serve` that reached its banner without one is a
    /// root bug, surfaced there rather than defaulted.
    pub fn with_mdns(mut self, mdns: MdnsState) -> Self {
        self.mdns = Some(mdns);
        self
    }

    /// Attach the [`Reach`] the composition root composed for this bind, so the banner names the relay
    /// this node offers and the resolver it publishes to rather than promising n0's. Called at the iroh
    /// arm only, beside [`with_mdns`](Self::with_mdns).
    pub fn with_bound_reach(mut self, bound_reach: Reach) -> Self {
        self.bound_reach = Box::new(bound_reach);
        self
    }
}

impl ServeCmd {
    /// Serve the named services (default `ping:` + `speed:`) under swoosh's identity by driving the
    /// tunnel core directly: parse the services, assemble the route table (`fetch`/`recv` instances,
    /// `ping`/`speed`, the update route, and `sshd` under the `ssh` feature) behind the gate the
    /// composition root built, print swoosh's banner, and run the exposer with the live cut wired. A
    /// `sshd:`/`ping:`/`speed:` service stays gated unless `--public` opens it.
    #[expect(
        clippy::too_many_arguments,
        reason = "run_serve takes the pre-resolved serve inputs one by one (seed, gate, cut, oracle, \
                  roster, home) so each stays a named parameter at the one call site; bundling them \
                  into a struct would only rename the list"
    )]
    async fn run_serve<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        host_seed: [u8; 32],
        gate: Gate,
        cut: AnchorCut,
        enabled: FileDisabledList,
        roster: Arc<swoosh::roster::Artifact>,
        home: Home,
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
        // Every node answers its own `control.stop` and member-only `control.services`, always, whatever
        // else it serves: the node-lifecycle control surface is part of being a node, not a service the
        // operator opts into. Both are MEMBER-only (`.member_service` below): the gate admits a family
        // badge or a service slip, and the route's access floor then refuses anything that is not a
        // whole-node member BEFORE any `Response::Ok`, so a delegate holding a `control.stop` slip cannot
        // stop the node.
        //
        // They are bound by VALUE, not named in the `name=addr` set: the scheme namespace left tightbeam's
        // public API, so a handler route is a `.service(name, value)` call, never a spellable addr.
        //
        // Pull each fetch service out of the requested set BEFORE the router binds it, and de-merge: every
        // `name=fetch:<origin>` becomes its OWN handler instance holding ONLY its own origin scope. A public
        // fetch handler therefore physically holds only its own origins and cannot reach a gated fetch's
        // origins: the SSRF pivot is unrepresentable, not fail-closed-by-convention.
        let fetch = FetchScope::extract(&mut requested)?;
        // De-merge the receive services the SAME way: every `name=recv:<dir>` becomes its OWN
        // `Recv` instance bound to ONLY its own output directory, so `a=recv:/x b=recv:/y` writes alice's
        // pushes into /x and bob's into /y, each scoped to its own service and grant. A public fetch's
        // SSRF-pivot argument does not apply (recv is always gated), so this is the plain per-instance
        // de-merge without an open-relay wall. A `name=recv:` (no dir) saves into `.`.
        let recv = extract_recv_services(&mut requested)?;
        // The node's ONE teardown authority. The exposer owns it (it is what acts on the cancel); a local
        // `--expires` timer, the gated `control.stop` handler, and (under `--resident`) the local socket
        // `Stop` each hold a CLONE as the node-control capability: they may REQUEST the stop, never tear
        // the node down themselves. So this one token is the join point for every way the node can stop:
        // a Ctrl-C, a `--expires` deadline, a remote `swoosh stop`, or the local socket stop.
        let cancel = CancellationToken::new();
        // The node BASE gate is the one the composition root built, the same in every standing. Opening
        // individual services is the separate `--public`/`--public-unsafe` overlay, never a node-wide value.
        //
        // One `Router`: each route binds a handler VALUE (the engine handlers, roster, stop, the fetch and
        // recv instances) or tightbeam's own primitives (forwards, raw streams, the `echo:` reflector)
        // through the `name=addr` grammar. The public overlays prove at `.expose()` below, so
        // prove-before-announce holds. The operator's `--public` set is parsed ONCE here, before the bind,
        // and drives the overlay, the per-route diagnostic engine (the metered engine for an open name,
        // the owner engine otherwise), and the per-service fetch posture (one source of truth).
        let public = parse_services(&self.public)?;
        let mut router = Router::new(gate);
        for entry in &requested {
            router = bind_entry(router, entry, host_seed, &public)?;
        }
        // The update route, on every `serve` whatever the standing, member-gated: only this root's devices
        // read it. Bound by the node, never by an entry, so no typed name reaches it.
        router = router.member_service(ROSTER_SERVICE.parse()?, Roster::new(roster))?;
        for scoped in fetch.services() {
            // One engine handler per fetch service, holding ONLY its own origin scope: the SSRF pivot is
            // unrepresentable, not merely refused. An unconstrained scope is the NEVER engine (the open
            // proof refuses to expose it); a non-empty scope is the OPT-IN engine, which applies the
            // 16 MiB/30s responder bounds by construction.
            let name = scoped.name().parse()?;
            router = if scoped.allow().is_unconstrained() {
                router.service(name, ::fetch::Fetch)?
            } else {
                let scoped_fetch = ::fetch::ScopedFetch::new(scoped.allow().clone())
                    .map_err(|error| eyre::eyre!(error))?;
                router.service(name, scoped_fetch)?
            };
        }
        // The node's activity renderer, or none at all under `--quiet`: with no renderer no engine gets a
        // sink, so quiet silences every activity line by construction and no log directive can bring one
        // back. Activity rides stderr beside the diagnostics, keeping stdout to the banner.
        let activity = self.activity(std::io::stderr())?;
        for service in &recv {
            // One `Recv` instance per receive service, holding ONLY its own output dir, so a push to one
            // receive service can never land in another's directory. Its sink carries the route's own
            // name, so the line says which receive service a file landed through.
            let name: Service = service.name().parse()?;
            router = bind_recv(router, name, service.out().to_owned(), activity.as_ref())?;
        }
        // The two node-lifecycle control verbs are MEMBER-only, not merely gated: tightbeam checks the
        // route's access class after the gate admits and before any `Response::Ok`, so a delegated slip
        // that grants `control.stop`/`control.services` is refused with the same uniform refusal a gate
        // miss gives, pre-Ok. Access is a property of the route, declared at the bind.
        router = router.member_service(CONTROL_STOP_SERVICE.parse()?, Stop::new(cancel.clone()))?;
        // Refuse an unconstrained PUBLIC fetch per-service: for each fetch service NAMED in `--public`
        // whose allowlist is unconstrained, bail at build time (an open egress relay). With per-service
        // scopes in hand this reasons about "is THIS public fetch unconstrained", so a second origin-scoped
        // fetch can no longer mask a named public one.
        fetch.refuse_open_relay(&self.public)?;
        // Declare both open overlays from the operator's raw names: the safe `--public` set and the
        // distinct, louder `--public-unsafe` raw-stream set. The proof (an unknown name, a `Never` handler,
        // a raw stream in the safe set, a handler in the unsafe set) runs at `.expose()` below, before any
        // banner advertises a service it will not serve.
        let public_unsafe = parse_services(&self.public_unsafe)?;
        router = router.public(public).public_unsafe(public_unsafe);
        // Snapshot the served catalog (names + effective PER-SERVICE posture: open iff opened by an
        // overlay, else gated) ONCE, here, for the `control.services` read handler AND the resident socket
        // read to serve. Both serve the same snapshot. `self_listing` renders the one row being built:
        // `control.services` itself, always gated (a `Never` route can never be open).
        let catalog = router.catalog(Some(CONTROL_SERVICES_SERVICE.parse()?));
        let router = router.member_service(
            CONTROL_SERVICES_SERVICE.parse()?,
            ServiceList::new(catalog.clone()),
        )?;
        // Wire the live enable/disable oracle alongside the proven public overlay: a stream for a
        // service named in `<home>/disabled` is refused at the gate seam, live, and a re-enable restores it
        // with no restart. `with_enabled` cannot fail (it only stores the oracle), so it tails the chain.
        //
        // The live cut reads the one pin and the one revocation instance the gate reads: a session admitted
        // on a cap since revoked, rooted at a key since disabled, anchored at a root no longer pinned, or
        // held by a device key since revoked, ends itself within a sweep rather than running on.
        let exposer = router.expose()?.with_enabled(enabled).with_live_cuts(cut);
        // Prove the transport can carry this gate BEFORE announcing readiness or binding the resident
        // socket: a rooted gate over a transport that does not prove the peer refuses here with the
        // teaching error, never after a "ready" banner the node cannot honor (and never with a lock or
        // socket taken for a serve that cannot arm).
        exposer
            .prove_security::<T>()
            .wrap_err(
                "bare quirk cannot serve: it does not prove the peer's key; use `--transport quirk+noise`",
            )?;

        // ONE expansion of this bind, read by BOTH the resident arm's status address and the banner
        // below it. Expanding twice put a `getifaddrs` on either side of the flock and the unix bind,
        // and a VPN or a wifi flap in that window makes the status address and the banner's lead line
        // name different hosts. Bind truth cannot disagree with itself; the interface list very much
        // can, so it is read once. Still lazy: a plain quiet serve reads neither, so it performs no
        // new syscall at all.
        // Expanded here ONLY for the resident arm, which needs the status address before the
        // banner runs. The banner expands for itself when this is `None`, so a plain serve is
        // still one expansion and a quiet non-resident serve is still none. Gating this on
        // `resident || !quiet` instead would make `None` unreachable at the banner and leave a
        // state that cannot happen to be handled there anyway.
        let dialable = self.resident.then(|| Dialable::of(node.bound_sockets()));

        // The resident listener arm (S4), after the proven overlay so a refused serve never binds
        // a socket. Order: (1) plain serve acquires nothing (byte-identical, no dir, no lock, no
        // socket); (2) `--resident` acquires single-instance off the THREADED home (flock truth +
        // bound listener, held for life); the LIVE catalog snapshot above plus a CLONE of the node's
        // one teardown token ride the `Resident` state the accept loop serves from. The bound
        // address rides along as the status `addr`, carried with the arm (no second `local_addr`).
        let resident = if self.resident {
            // The per-user runtime root, resolved ONCE here at the serve edge and handed to the lock
            // module as a value: `single` never reads `XDG_RUNTIME_DIR`/`confstr`, so a test drives
            // `acquire` with its own temp root and no process-global environment mutation. Resolution
            // stays inside the `--resident` branch (a plain serve must not need a runtime root) and at
            // the same point the acquire runs, so the unset/relative-XDG refusal and its timing are
            // unchanged.
            let runtime_root = swoosh::home::runtime_root()
                .map_err(|error| eyre::eyre!("could not resolve the runtime root: {error}"))?;
            let addr = node.local_addr();
            // The status address is the first entry of the bind's own dialable set, the address the
            // banner leads with: a peer elsewhere can route to it where one exists, and it falls back
            // to loopback on a host that has nothing else. `local_addr().hints` cannot stand in, since
            // it rewrites every wildcard bind to loopback.
            let status_addr = dialable
                .as_ref()
                .and_then(|dialable| dialable.all().first())
                .map(|at| at.socket);
            Some(self.resident_parts(
                &home,
                &runtime_root,
                tightbeam::tunnel::ServiceCatalog::clone(&catalog),
                addr.node,
                status_addr,
                &cancel,
            )?)
        } else {
            None
        };

        if !self.quiet {
            // The id comes from `local_addr`; the addresses to hand over come from the one expansion
            // above, which the resident arm's status address was read from too, so the two can only
            // ever name the same host.
            let addr = node.local_addr();
            // The resident arm's expansion when there was one, so the status address and the banner
            // can only ever name the same host; otherwise this is the only one taken.
            let dialable = dialable.unwrap_or_else(|| Dialable::of(node.bound_sockets()));
            // A display map of served name -> target address, read off the SAME requested strings the router
            // bound (fetch already de-merged out), so the banner renders `name -> target` from what the
            // operator wrote, while tightbeam's manifest declares the load-bearing facts (posture, kind, the
            // unmetered caveat). Fetch names are handled by gloss (their addr carries the origin scope).
            let mut addr_by_name = display_targets(&requested)?;
            for service in &recv {
                // Receive services are de-merged out of `requested` (their dir is not an addr the router can
                // read), so re-add each under its served name pointing at the `recv:` scheme. The banner then
                // renders it through the SAME handler-scheme path as any other handler (`in -> recv`,
                // "receives pushed files"), never leaking the synthetic scheme.
                addr_by_name.insert(service.name().to_owned(), format!("{RECV_SCHEME}:"));
            }
            let fetch_names: HashSet<String> = fetch
                .services()
                .iter()
                .map(|s| s.name().to_owned())
                .collect();
            // Reach-kind is the selected transport, not an inference from whether hints are present (which
            // conflates the channel with the hint state): iroh routes across the internet, quirk is
            // direct-only. How far the advertisement reaches is a SEPARATE fact, attached by the
            // composition root from the SAME `advertise` call that composed discovery, so the banner
            // reports what was published rather than assuming it.
            let reach = ReachKind::of(self.reach.transport, self.reach.local);
            let Some(mdns) = self.mdns.as_ref() else {
                eyre::bail!(
                    "internal: serve reached its banner without the mDNS state (composition-root bug)"
                );
            };
            let stop_line = match self.expires {
                Some(lifetime) => {
                    format!(
                        "runs for {}, then stops (or ctrl-c)",
                        humanize_secs(lifetime.duration().as_secs())
                    )
                }
                None => "ctrl-c to stop".to_owned(),
            };
            let manifest = exposer.manifest();
            let resident_socket = resident.as_ref().map(|(_, _, lock)| lock.socket_path());
            let control_line = self.control_line(resident_socket);
            print!(
                "{}",
                render_ready_banner(
                    &addr.node.to_string(),
                    reach,
                    mdns,
                    &self.bound_reach,
                    &dialable,
                    &manifest,
                    &addr_by_name,
                    &fetch_names,
                    &stop_line,
                    control_line.as_deref(),
                )
            );
        }

        // The acquire above already ran: nothing new executes here. Plain serve ran nothing at all
        // (the flag defaults off), so it stays byte-identical: no dir, no lock, no socket.
        //
        // An `--expires` deadline is a LOCAL timer with no security surface: after it elapses it cancels the
        // node's teardown token, the same graceful stop a Ctrl-C or a remote `control.stop` gives. Spawn it
        // beside the run holding a CLONE of the one token; if no `--expires` is set, no timer is spawned.
        if let Some(lifetime) = self.expires {
            let cancel = cancel.clone();
            let deadline = lifetime.duration();
            tokio::spawn(async move {
                tokio::time::sleep(deadline).await;
                cancel.cancel();
            });
        }

        // Run until a stop, distinguishing a GRACEFUL stop (an owner-requested `control.stop` or a `--expires`
        // deadline, or a Ctrl-C) from an ERRORED teardown. The exposer returns `Ok` when the token fires and
        // an `Err` only on a real failure, so `run_until_stopped` maps that into a typed [`Stopped`] reason
        // for a graceful end and propagates the error otherwise. A requested stop is SUCCESS: a deliberate
        // `swoosh stop` (or a timer, or a Ctrl-C) must exit 0 so the qat CI action reads a clean teardown as
        // green, not a crash; only a genuine error teardown exits non-zero. The resident arm (when `Some`)
        // joins as the third select arm there; plain serve passes `None`, so nothing new executes.
        let stopped = self
            .run_until_stopped(exposer, node, cancel, resident)
            .await?;
        // The teardown line is best-effort: a piped consumer (a supervisor, `swoosh serve | head`) may have
        // already closed stdout by the time the node stops, so a broken-pipe write must NOT turn a clean stop
        // into a panic. `println!` panics on a write error, so write directly and ignore a closed pipe.
        {
            use std::io::Write as _;
            let _ = writeln!(std::io::stdout(), "{}", stopped.message());
        }
        // The bound node's teardown (iroh's graceful `Endpoint::close`) is owned by the composition root,
        // which closes it after every reaching verb returns; `serve` only drives the exposer's own graceful
        // drain above, then hands back so the root closes once for the whole family.
        Ok(())
    }

    /// Drive the exposer until it stops, returning WHY it stopped for a graceful end or propagating the
    /// error for a failed teardown. The one seam that classifies a stop: the exposer's `run` returns `Ok`
    /// the instant the teardown token fires (an owner's `control.stop`, or a `--expires` deadline) and an `Err`
    /// only on a real failure, so an `Ok` return is a [`Stopped::Requested`]; a Ctrl-C is a
    /// [`Stopped::Interrupted`] (the local operator asking for the same graceful stop). A returned `Err` is
    /// a genuine teardown failure the caller propagates, so the process exits non-zero ONLY then.
    ///
    /// Under `--resident` the control listener joins as a THIRD arm beside the exposer and Ctrl-C:
    /// it serves the local socket until the same token fires, then the teardown unlinks the socket
    /// and drops the lock. Without `--resident` nothing new executes (the arm is absent, not idle).
    /// Because the socket `Stop` cancels the SAME token the exposer watches, every resident arm
    /// classifies its result from the recorded [`StopSource`] rather than from the arm that won
    /// the poll: a socket stop renders [`Stopped::Local`], a wire
    /// `control.stop` or a `--expires` deadline renders [`Stopped::Requested`], and a Ctrl-C records
    /// itself and renders [`Stopped::Interrupted`], so the kinds never collapse into one.
    #[allow(clippy::too_many_arguments)]
    async fn run_until_stopped<T: Transport, D: Discovery>(
        &self,
        exposer: Exposer,
        node: &Node<T, D>,
        cancel: CancellationToken,
        resident: Option<(
            Arc<Resident>,
            std::os::unix::net::UnixListener,
            InstanceLock,
        )>,
    ) -> eyre::Result<Stopped>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        // The exposer owns the teardown: it returns when the token fires (a `--expires` deadline, or an admitted
        // `control.stop` caller). A Ctrl-C is the same graceful stop, driven here by cancelling the token so
        // there is ONE stop path, then letting the run finish.
        let stopped = match resident {
            None => {
                tokio::select! {
                    result = exposer.run(node, cancel.clone()) => {
                        // `Ok` here means the token fired (a requested stop): success. An `Err` is a real teardown
                        // failure, propagated so the process exits non-zero (the one non-zero path).
                        result?;
                        Stopped::Requested
                    }
                    signalled = tokio::signal::ctrl_c() => {
                        // A failure INSTALLING the signal handler is a real error (propagate); an actual Ctrl-C is a
                        // graceful interrupt, so cancel the one token and let the run finish, then report it.
                        signalled?;
                        cancel.cancel();
                        Stopped::Interrupted
                    }
                }
            }
            Some((state, listener, lock)) => {
                // The stop source is read AFTER the select, never inferred from the arm that won:
                // a socket `Stop` records its kind and cancels the same token the exposer watches,
                // so both the exposer arm and the resident arm become ready together and tokio may
                // complete either. Classifying from the record keeps the socket stop on the local
                // line even when the exposer arm wins the poll, while a wire `control.stop` (which
                // records nothing) still renders as the requested stop.
                let source = state.stop_source();
                let resident = state.serve(listener);
                tokio::select! {
                    result = exposer.run(node, cancel.clone()) => {
                        result?;
                        lock.release();
                        classify_stop(source.first())
                    }
                    output = resident => {
                        output?;
                        lock.release();
                        classify_stop(source.first())
                    }
                    signalled = tokio::signal::ctrl_c() => {
                        signalled?;
                        source.note(StopKind::Interrupted);
                        cancel.cancel();
                        lock.release();
                        classify_stop(source.first())
                    }
                }
            }
        };
        Ok(stopped)
    }

    /// The activity renderer this serve writes onto `out`, or `None` under `--quiet`. The one gate for the
    /// whole activity class: a line exists only if an engine was handed a sink from this renderer.
    fn activity(
        &self,
        out: impl std::io::Write + Send + 'static,
    ) -> eyre::Result<Option<Activity>> {
        if self.quiet {
            return Ok(None);
        }
        let activity = Activity::spawn(out).wrap_err("could not start the activity renderer")?;
        Ok(Some(activity))
    }

    /// The resident control line for the banner, under `--resident` only: `control <socket path>
    /// (local, this user)`. `None` for a plain serve (no line, byte-identical output). The socket
    /// path comes from the acquired lock (the threaded home, never a re-derive), so the banner names
    /// the same path the listener bound and future clients dial.
    fn control_line(&self, socket: Option<&Path>) -> Option<String> {
        if !self.resident {
            return None;
        }
        let path = socket
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<socket>".to_owned());
        Some(format!("control {path} (local, this user)"))
    }

    /// Start the resident arm off the threaded home and the composition edge's resolved runtime
    /// `root`: the flock truth plus the bound listener (held for process life), the live catalog
    /// snapshot, and a clone of the node's one teardown token. A method so the acquire reads as part
    /// of the serve run, not a free helper beside it.
    fn resident_parts(
        &self,
        home: &Home,
        runtime_root: &Path,
        catalog: tightbeam::tunnel::ServiceCatalog,
        node_id: NodeId,
        addr: Option<SocketAddr>,
        cancel: &CancellationToken,
    ) -> eyre::Result<(
        Arc<Resident>,
        std::os::unix::net::UnixListener,
        InstanceLock,
    )> {
        let (lock, listener) =
            acquire_single(home, runtime_root).map_err(|error| eyre::eyre!(error))?;
        let disabled_path = home.disabled();
        let state = Arc::new(Resident::new(
            node_id,
            addr,
            catalog,
            disabled_path,
            cancel.clone(),
        ));
        Ok((state, listener, lock))
    }
}

/// Build the `name -> target` display map from the SAME requested strings the router bound: each
/// `name=addr`. This is swoosh's own render vocabulary; tightbeam's manifest supplies the load-bearing
/// facts (posture, kind, the unmetered caveat). Fetch entries are already de-merged out of `requested`,
/// so they never appear here (the banner glosses them by name instead, their addr being an origin scope).
/// A bare entry (no `=`) is a teaching error, mirroring tightbeam's `name=addr` grammar.
fn display_targets(requested: &[String]) -> eyre::Result<HashMap<String, String>> {
    let mut map = HashMap::with_capacity(requested.len());
    for entry in requested {
        let Some((name, addr)) = entry.split_once('=') else {
            eyre::bail!(
                "`{entry}` names no service. Every serve entry must be `name=target`, e.g. \
                 `ping=ping:`, `web=tcp:127.0.0.1:8080`"
            );
        };
        map.insert(name.to_owned(), addr.to_owned());
    }
    Ok(map)
}

/// How peers reach this node, for the banner's `how peers reach you` section: whether the bound transport
/// routes across the internet (an `internet` channel) or is local/direct-only. Read off the SELECTED
/// transport and bind mode at the composition seam, never inferred from whether hints are present (that
/// would conflate the channel with the hint state). An enum, not a bool, so a
/// third reach kind forces a decision here rather than defaulting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReachKind {
    /// The transport routes across the internet and NATs (iroh, not `--local`): a peer reaches this node
    /// by the key alone.
    Internet,
    /// The bind is local/direct-only (quirk, bare or sealed, or an iroh `--local` bind): a peer reaches
    /// this node over local mDNS, or by a handed-over address.
    DirectOnly,
}

impl ReachKind {
    /// Map the selected transport and bind mode to its reach kind. The one place the transport identity
    /// becomes a reach tell for the banner; every other surface stays transport-blind. `--local` drops the
    /// internet channel: the minimal bind has no n0 lookup and no relays, so its story is the same as
    /// quirk's.
    fn of(transport: swoosh::transport::Transport, local: bool) -> Self {
        match transport {
            swoosh::transport::Transport::Iroh if local => Self::DirectOnly,
            swoosh::transport::Transport::Iroh => Self::Internet,
            swoosh::transport::Transport::Quirk | swoosh::transport::Transport::QuirkNoise => {
                Self::DirectOnly
            }
        }
    }
}

/// The posture group a served service sits under in the banner, safest-first. The security weight lives on the
/// GROUP and escalates monotonically DOWN the list: `FamilyGated` (no overlay) <
/// `Public` (an open overlay) < `PublicUnsafe` (the loudest). A per-service caveat (an unmetered one) is quiet inline
/// prose, never a marker louder than the group above it, so a reader can never conclude a `public` service is
/// scarier than a `public-UNSAFE` one. Ordered so the derived `Ord` IS the safest-first render order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Group {
    FamilyGated,
    Public,
    PublicUnsafe,
}

impl Group {
    /// Which group a service sits under: gated is always family-gated; an OPEN raw stream is the loudest
    /// (public-UNSAFE: raw bytes to anyone), any other open service is public. Reads the manifest's declared
    /// posture + kind, so the split is tightbeam's, not a swoosh string match.
    fn of(entry: &ManifestEntry) -> Self {
        match (entry.posture, entry.kind) {
            (Posture::Gated, _) => Self::FamilyGated,
            (Posture::Open, TargetKind::RawStream) => Self::PublicUnsafe,
            (Posture::Open, _) => Self::Public,
        }
    }

    /// The header this group renders: its name carrying the monotonic danger marker, and its one-line
    /// audience gloss. The marker escalates down the list and is the ONLY loud danger glyph in the section.
    fn header(self) -> (&'static str, &'static str) {
        match self {
            Self::FamilyGated => ("family-gated", "your devices + peers you've granted"),
            Self::Public => ("public !", "anyone, unauthenticated"),
            Self::PublicUnsafe => ("public-UNSAFE !!", "raw bytes to anyone who connects"),
        }
    }
}

/// The gloss for a named engine's scheme, the terse right-column description.
/// An unrecognized scheme falls back to a plain `<scheme> service`, so a future handler still renders a line.
fn handler_gloss(scheme: &str) -> String {
    match scheme {
        "ping" => "round-trip probe".to_owned(),
        "speed" => "throughput test".to_owned(),
        "sshd" => "a shell on this machine".to_owned(),
        "recv" => "receives pushed files".to_owned(),
        other => format!("{other} service"),
    }
}

/// The rendered `<label>` and `<gloss>` for one service row: `name -> target` when the name points elsewhere
/// (`ssh -> sshd`, `logs -> file:...`), or just `name` when the name IS the target scheme (`speed`). Fetch
/// services gloss by name (their synthetic scheme is unspellable). The KIND is tightbeam's declared
/// [`TargetKind`] (handler vs raw stream); within the handler kind the operator's typed target distinguishes
/// the built-in forward and the `echo:` reflector from a named engine, because both built-ins are
/// first-party handlers now and carry no addr tail of their own.
fn describe(
    entry: &ManifestEntry,
    addr_by_name: &HashMap<String, String>,
    fetch_names: &HashSet<String>,
) -> (String, String) {
    let name = entry.name.as_str();
    // A de-merged fetch's row glosses by name only (its origin is not reconstructed here, the synthetic
    // scheme being unspellable). `fetches URLs for callers` names the object for parallelism with the
    // sibling glosses (`receives pushed files`, the round-trip probes).
    if fetch_names.contains(name) {
        return (name.to_owned(), "fetches URLs for callers".to_owned());
    }
    let addr = addr_by_name
        .get(name)
        .map(String::as_str)
        .unwrap_or_default();
    match entry.kind {
        TargetKind::Handler => {
            // tightbeam's built-in loopback reflector: it opens no host resource and reflects only the
            // caller's own bytes, so it carries no danger gloss (an open echo sits in the plain `public`
            // group, never `public-UNSAFE`). The name reads alone (like `speed`), the target being the
            // built-in itself.
            if addr == "echo:" {
                return (name.to_owned(), "echoes your bytes back to you".to_owned());
            }
            // tightbeam's built-in local forward (`tcp:<host>:<port>` / `unix:<path>`): a socket the
            // operator deliberately stood up, glossed as such.
            if is_forward(addr) {
                return (format!("{name} -> {addr}"), "local TCP service".to_owned());
            }
            let scheme = addr.strip_suffix(':').unwrap_or(addr);
            let label = if name == scheme {
                name.to_owned()
            } else {
                format!("{name} -> {scheme}")
            };
            (label, handler_gloss(scheme))
        }
        // The label keeps the operator's typed target (`logs -> file:~/...`); the GLOSS is where the danger
        // is loud. An OPEN raw stream names the RESOLVED ABSOLUTE source (from tightbeam's declared
        // `raw_source`, not the un-resolved typed string) so the warning shows the exact bytes at risk; the
        // loud path is reserved for the actually-open case, so it fires exactly where the danger is. A GATED
        // raw stream keeps the quiet gloss (the family gate terminates it).
        TargetKind::RawStream => {
            let gloss = match (entry.posture, &entry.raw_source) {
                (Posture::Open, Some(RawSource::Path(absolute))) => {
                    format!("serving the raw bytes of {absolute} to anyone, no auth")
                }
                (Posture::Open, Some(RawSource::Stdin)) => {
                    "serving this process's piped stdin to anyone, no auth".to_owned()
                }
                // Open but no declared source (defensive: a raw stream always declares one) or gated: the
                // quiet gloss the family-gated case has always shown.
                (Posture::Open, None) | (Posture::Gated, _) => {
                    "streams raw bytes to any caller, no auth".to_owned()
                }
            };
            (format!("{name} -> {addr}"), gloss)
        }
    }
}

/// Whether the operator's typed target is tightbeam's built-in local forward (`tcp:<host>:<port>` /
/// `unix:<path>`) rather than a named engine. Both forwards and the `echo:` reflector are first-party
/// [`Handler`]s, so the manifest's [`TargetKind`] names only handler-vs-raw-stream; the display map carries
/// the finer render distinction. Now that every target carries a scheme this is the scheme test it always
/// wanted to be: no port sniffing, and a host named like an engine can never read as one.
fn is_forward(addr: &str) -> bool {
    matches!(addr.split_once(':'), Some(("tcp" | "unix", _)))
}

/// Render the full readiness banner as ONE string (pure, so it is unit-testable and printed once): the
/// `swoosh ready` header, the copy-clean node id, the `how peers reach you` section, the grouped `serving`
/// section, and the stop line. Every line is a tell: no raw dial flags, no split posture, one
/// monotonic danger vocabulary. Blank-line framed so the id (and any direct address) is copy-paste-clean.
#[expect(
    clippy::too_many_arguments,
    reason = "the banner is assembled from independent facts (id, reach kind, mDNS state, the bound \
              relay and resolver, the bind's dialable set, the declared manifest, swoosh's display map, \
              the fetch names, the stop line); bundling them into one struct would only move the \
              argument list, not remove it"
)]
fn render_ready_banner(
    node_id: &str,
    reach: ReachKind,
    mdns: &MdnsState,
    bound_reach: &Reach,
    dialable: &Dialable,
    manifest: &[ManifestEntry],
    addr_by_name: &HashMap<String, String>,
    fetch_names: &HashSet<String>,
    stop_line: &str,
    control_line: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push_str("swoosh ready\n\n");
    // The FULL node id, alone, indented, blank-framed, no trailing gloss (a trailing label would spoil a
    // select-to-end-of-line copy). The next section explains what the key is for.
    out.push_str(&format!("    {node_id}\n\n"));
    out.push_str(&reach_section(reach, mdns, bound_reach, dialable));
    out.push('\n');
    out.push_str(&serving_section(manifest, addr_by_name, fetch_names));
    out.push('\n');
    // Under `--resident` only, one extra line after the reach section: `control <socket path>
    // (local, this user)`. Plain serve passes `None`, so its output is byte-identical to today.
    if let Some(control) = control_line {
        out.push_str(control);
        out.push('\n');
    }
    out.push_str(stop_line);
    out.push('\n');
    out
}

/// The `how peers reach you` section: one channel per line with a short label column that scans at a glance.
/// The `internet` channel appears only when the transport routes across the internet; `direct` on every
/// direct-only bind, because that bind has no relay and no NAT traversal, so an address is the whole of its
/// reach and a direct-only banner without one hands the operator nothing. "automatic" leads both auto
/// channels, and the local lane carries the ADVERTISEMENT's own outcome: how far this node was published is a
/// fact only the advertisement knows, and the dial hints cannot stand in for it (they rewrite a wildcard bind
/// to loopback, so every bind would read the same whatever it reaches).
///
/// ONE address list per banner: under direct-only the addresses live on the `direct` lane, which is the lane
/// that exists to hand one over, and the `local` lane keeps only its mDNS-outcome sentence.
// No gloss here names the transport backend: the operator is told how far they can be reached, never which
// implementation carries it, because the backend is swappable and the reach promise is not.
fn reach_section(
    reach: ReachKind,
    mdns: &MdnsState,
    bound_reach: &Reach,
    dialable: &Dialable,
) -> String {
    // The lane renders on every direct-only bind, off the BIND's own expansion. Never off `hints()`
    // (a dial-side convenience that rewrites a wildcard to loopback, which filtered the lane away on
    // every bind swoosh can make, since there is no bind flag) and never off the mDNS report, which
    // says how far an ANNOUNCEMENT reached: on a network that blocks multicast that report is empty
    // while the host's addresses are exactly as dialable as ever.
    let direct = matches!(reach, ReachKind::DirectOnly);
    // Where the node's addresses go. EVERY internet bind publishes them, so every internet bind says so:
    // the default is the one nobody chose, and telling an operator about the mDNS announcement on their
    // LAN while staying quiet about the public one would disclose the smaller thing and hide the larger.
    // The line states the CONSEQUENCE rather than the record format, because the operator who needs it is
    // the one not thinking about DNS at all: their addresses are readable by key, without a dial.
    let records = (reach == ReachKind::Internet).then(|| match &bound_reach.resolver {
        Resolver::N0 => {
            "n0's public discovery: your addresses, for anyone with your key".to_owned()
        }
        // The same consequence, said the same way. A custom resolver is not a private one: pkarr records
        // are readable by anyone holding the key, so naming only the URL here would let the operator who
        // stood one up read this line as the disclosure going away.
        Resolver::Custom(url) => format!("{url}: your addresses, for anyone with your key"),
    });
    // Which relay this node offers, and only for a node that named one: a bind on n0's relays is the
    // default every page describes, and it costs the operator nothing they did not already read. Naming
    // EITHER of the two servers prints this line, because what an operator who runs half of this most
    // needs to see is which half is still n0's, and a line that is absent says nothing.
    let split = reach == ReachKind::Internet
        && (bound_reach.relay != RelayHome::N0 || bound_reach.resolver != Resolver::N0);
    let relay = split.then(|| match &bound_reach.relay {
        RelayHome::N0 => "n0's public relays".to_owned(),
        RelayHome::Custom(url) => url.to_string(),
    });
    // Width the label column to the widest channel label actually shown.
    let mut labels: Vec<&str> = Vec::new();
    if reach == ReachKind::Internet {
        labels.push("internet");
    }
    if records.is_some() {
        labels.push("records");
    }
    if relay.is_some() {
        labels.push("relay");
    }
    labels.push("local");
    if direct {
        labels.push("direct");
    }
    let width = labels.iter().map(|l| l.len()).max().unwrap_or(0);
    let gutter = 3;
    let gloss_col = 2 + width + gutter;

    let mut out = String::from("how peers reach you\n");
    if reach == ReachKind::Internet {
        out.push_str(&reach_line(
            width,
            gutter,
            "internet",
            "automatic; peers reach you by the key above, even across NATs",
        ));
    }
    // Directly under the internet channel: the two servers that channel runs on, in the order a dial
    // uses them (find the peer's record, then fall back to its relay).
    if let Some(records) = &records {
        out.push_str(&reach_line(width, gutter, "records", records));
    }
    if let Some(relay) = &relay {
        out.push_str(&reach_line(width, gutter, "relay", relay));
    }
    // One arm per outcome of the ONE advertise call: a node another host can hear, a node only this host
    // can, a node that hears but is not heard, and no mDNS at all. The three degraded arms each name the
    // next step (or the cause), because from the inside they all look identical to a live advertisement.
    let (local, announced): (String, &[SocketAddr]) = match (mdns, reach) {
        (MdnsState::OnLan(addrs), ReachKind::Internet) => (
            "automatic; your devices just need the key (mDNS), announced at:".to_owned(),
            addrs,
        ),
        // The announced set is a subset of the direct lane's below, and one banner carries one address
        // list: a direct-only node names its addresses once, where a peer is told to take them.
        (MdnsState::OnLan(_), ReachKind::DirectOnly) => (
            "automatic; local mDNS, or direct, no NAT traversal".to_owned(),
            &[],
        ),
        (MdnsState::LoopbackOnly, _) => (
            "mDNS on this host only; another host needs a direct address hint".to_owned(),
            &[],
        ),
        (MdnsState::BrowseOnly(cause), _) => {
            (format!("finding peers, not announcing you ({cause})"), &[])
        }
        (MdnsState::Blocked, ReachKind::Internet) => (
            "off; mDNS unavailable here, so reach by the key over the internet".to_owned(),
            &[],
        ),
        // The direct lane always renders under direct-only, so the down-state can always point at it:
        // there is no bind whose banner offers no address to hand over.
        (MdnsState::Blocked, ReachKind::DirectOnly) => (
            "off; mDNS unavailable here, so hand a peer the address below".to_owned(),
            &[],
        ),
    };
    out.push_str(&reach_line(width, gutter, "local", &local));
    // Each address on its own line, bare and copy-clean (the same standard as the node id), aligned under
    // the header's gloss column.
    for addr in announced {
        out.push_str(&format!("{:gloss_col$}{addr}\n", ""));
    }
    if direct {
        out.push_str(&direct_lane(dialable, width, gutter));
    }
    out
}

/// The `direct` lane: the gloss that says what to DO with the lines, then ONE address per reach class.
///
/// A rendering adapter over a type that lives in a lower crate, which is why it is a function and not a
/// method: the order, the classes and the ports are the expansion's facts, and this only spells them.
///
/// ONE LINE PER CLASS, the v4 address where that class has one. An ordinary two-interface laptop
/// expands to eight entries and a wifi+ethernet+VPN+docker host to fifteen, but they offer at most
/// FOUR decisions: the peer is out on the internet, on this network, on one named link, or on this
/// machine. A second address in the same class is noise rather than a choice, so it does not render,
/// and there is no flag to bring it back. v4 leads its class because it is the address a peer can
/// paste anywhere.
///
/// The ORDER comes from the expansion ([`Dialable::all`]): everything a peer elsewhere can route to
/// first, then a tunnel address, then loopback last, so the lane can never lead with the one address
/// that works only for a peer already on this machine.
///
/// EVERY line carries a mark, the widest included. A bare line reads as the default and there is no
/// default: this host cannot know where the operator's peer is, so it states how far each address goes
/// and leaves the choosing to the one person who does know. After the cap the mark is the ONLY thing
/// telling two lines apart, which raises its bar rather than lowering it: it CLASSIFIES and never
/// predicts. `the internet` says who can route to the address, not that a default-deny firewall will
/// let them through.
///
/// The marks align in a column so the classes scan against each other rather than ragged against the
/// addresses, and the padding sits BEFORE the mark, so a copy that ends at the address is still clean.
///
/// The 80-column bound holds BY CONSTRUCTION, with nothing to check at runtime: every term of the
/// widest line is fixed. The gloss column is 11, the widest legal socket is a v6 with no
/// compressible group and a five-digit port at 47 (link-locals are filtered one crate down, so no
/// `%zone` can widen one), the mark gutter is 2, and the widest mark is 14 including its
/// parentheses. `11 + 47 + 2 + 14 = 74`, which is why no line here measures itself.
fn direct_lane(dialable: &Dialable, width: usize, gutter: usize) -> String {
    let gloss_col = 2 + width + gutter;
    // Same reach class whatever the tunnel's link name: two overlays are two spellings of one
    // decision, and the cap is one line per DECISION. `class()` rather than `PartialEq`, which
    // would read `Tunnel { link }` pairs as distinct classes on the strength of the name.
    let mut chosen: Vec<&At> = Vec::new();
    for at in dialable.all() {
        let Some(kept) = chosen
            .iter_mut()
            .find(|kept| kept.scope.class() == at.scope.class())
        else {
            chosen.push(at);
            continue;
        };
        // v4 wins its class: `Dialable::all` holds interface order within a class, so without this
        // a host whose v6 happens to enumerate first hands its operator the harder address to paste.
        if kept.socket.is_ipv6() && at.socket.is_ipv4() {
            *kept = at;
        }
    }
    // The two ephemeral binds an unnamed dual-stack bind gets are two ports, and the operator has to
    // take the one that came with the address they picked. Measured over the RENDERED rows, so a
    // v4-only host, quirk, and any same-port bind render byte-identically to a lane with no clause.
    let mixed_ports = chosen
        .windows(2)
        .any(|pair| pair[0].socket.port() != pair[1].socket.port());
    let addrs: Vec<String> = chosen.iter().map(|at| at.socket.to_string()).collect();
    // One column for the marks, measured over the addresses actually being printed rather than a fixed
    // budget: an IPv6 line is far wider than an IPv4 one and a fixed column would either waste the
    // banner's width on every v4-only host or wrap on every v6 one.
    let addr_col = addrs.iter().map(String::len).max().unwrap_or(0);
    let rows: Vec<(String, &'static str)> = addrs
        .into_iter()
        .zip(&chosen)
        .map(|(addr, at)| (addr, mark(at.scope.class())))
        .collect();
    // The class a drop took the last row of, asked only of a drop report: it is the one fact the
    // expiring arm renders, and `emptied` is where the whole of that question lives.
    let emptied = match dialable.missing() {
        Missing::Expiring(dropped) => emptied(dropped, &chosen),
        _ => None,
    };
    // ONE clause, first match wins, loudest first. The lane carries a single gloss because the
    // operator gives it a single glance, so the conditions are ranked rather than concatenated: a
    // list that could not be read outranks one that lost a class, which outranks a list nothing
    // could be checked against, which outranks a port skew every row already answers for itself.
    // `Missing::Expiring` and `Missing::Flags` cannot co-occur (nothing is dropped when nothing
    // was read), so there is no arm for the pair and no order to settle between them.
    let gloss: Cow<'static, str> = match (dialable.missing(), emptied, rows.len()) {
        // Unreachable on any bind that came up (a bound socket answers at loopback at the very least),
        // stated rather than left to render a header over nothing.
        (_, _, 0) => Cow::Borrowed("no address to hand over"),
        // The cause, then the bound: without this a lone `127.0.0.1  (this machine)` row asserts
        // this host is loopback-only when the truth is that nothing could be read. The errno stays
        // in the log, where it is free to be as long as it likes.
        (Missing::Interfaces(_), _, 1) => {
            Cow::Borrowed("could not read this host's addresses; only this one is known:")
        }
        (Missing::Interfaces(_), _, _) => {
            Cow::Borrowed("could not read this host's addresses; only these are known:")
        }
        // Only a drop that took a whole class off the screen; see [`emptied`]. ONE arm at any row
        // count: `what is left:` is count-free, so it is correct over one row and over five, and
        // the mark is the row's own word, so a reader matches the ABSENT line by literal compare
        // against the marks that are still on screen.
        (_, Some(class), _) => Cow::Owned(format!(
            "only expiring addresses reach {}; what is left:",
            mark(class)
        )),
        // WHOLE and unchecked rather than short, so the instruction stays intact and the caveat is a
        // parenthetical: every row still dials, and only how long it will keep dialing is unknown.
        // The misread to kill is an operator who believes we checked.
        (Missing::Flags, _, 1) => {
            Cow::Borrowed("hand a peer this address (could not check for expiry):")
        }
        (Missing::Flags, _, _) => {
            Cow::Borrowed("hand a peer one of these (could not check for expiry):")
        }
        (_, _, 1) => Cow::Borrowed("hand a peer this address:"),
        // One rendered row is one port, so the mixed condition cannot hold at one address and the
        // clause lives on the many arm alone.
        (_, _, _) if mixed_ports => {
            Cow::Borrowed("hand a peer one of these (each address has its own port):")
        }
        (_, _, _) => Cow::Borrowed("hand a peer one of these:"),
    };
    let mut out = reach_line(width, gutter, "direct", &gloss);
    for (addr, mark) in &rows {
        // The address leads each line so a copy starts clean, at the gloss column, the same standard the
        // node id is held to.
        out.push_str(&format!("{:gloss_col$}{addr:<addr_col$}  ({mark})\n", ""));
    }
    out
}

/// How far a class of address reaches, in the words the banner spells it with.
///
/// ONE spelling of each class for the whole lane: the rows carry these, and the expiring gloss
/// interpolates the same word, so a reader who is told `only expiring addresses reach the internet`
/// matches that against the row marks by literal compare. Two spellings of `the internet` in one
/// file would be two strings to keep in step and one of them eventually wrong.
///
/// Four marks that read as one family (a determiner and a noun), so the classes scan against each
/// other, and short on purpose: the widest legal v6 socket is 47 columns and a longer phrasing
/// wraps. A tunnel is `this tunnel` and does NOT name its link. The cap renders one line per class,
/// so at most one tunnel row ever appears and the name has no second overlay to tell it apart from:
/// it was redundant where it informed (the address already said it) and empty where it did not (on
/// macOS every overlay is `utunN`). Dropping it is also what leaves this banner with NO
/// externally-sourced string at all, which is why nothing here guards against control characters or
/// measures a line: there is no longer an input to guard. Re-adding an OS-supplied string here
/// brings both of those back with it.
fn mark(class: ScopeClass) -> &'static str {
    match class {
        ScopeClass::Internet => "the internet",
        ScopeClass::Network => "this network",
        ScopeClass::Tunnel => "this tunnel",
        ScopeClass::ThisMachine => "this machine",
    }
}

/// The reach class that the addresses dropped as expiring took the last row of, if any: the
/// highest-ranked one when a drop emptied several at once.
///
/// The fact an operator can act on is not how MANY addresses went, it is WHICH class went. The
/// cap already renders one line per class, so a drop a class survived is invisible by design and a
/// tally of hidden addresses is noise in a glance: that arm would fire on every laptop that has ever
/// slept and tell its operator nothing to do. A class with no row left is the opposite case, and the
/// one the lane would otherwise lie about: silence where an address used to be reads as "this host
/// has none", when the truth is that this host is losing them and may want to wait or renew.
///
/// Asked over the classes that actually lost an address, by CLASS and never by scope. A tunnel
/// scope carries the link it rides, and the link whose only address expired leaves no surviving row
/// to take that name from, so the drop that most needs saying is the one a question phrased as
/// `Scope::Tunnel` could not even be formed for. Reading the report's own classes is also what
/// keeps this honest as the classes change: a sweep of every class written out here answers for the
/// four that exist today and silently skips the fifth.
///
/// The FIRST emptied class is the highest-ranked one, for free: [`Expiring::classes`] yields in
/// [`ScopeClass`]'s own rank order, so the one gloss the lane can spend goes to the class whose
/// absence costs the operator most. It can never be all four, because a lane with no rows at all is
/// the first arm.
fn emptied(dropped: &Expiring, chosen: &[&At]) -> Option<ScopeClass> {
    dropped
        .classes()
        .find(|class| !chosen.iter().any(|at| at.scope.class() == *class))
}

/// One `how peers reach you` line: `  <label padded>   <gloss>`.
fn reach_line(width: usize, gutter: usize, label: &str, gloss: &str) -> String {
    format!("  {label:<width$}{:gutter$}{gloss}\n", "")
}

/// The `serving` section: services grouped by posture, safest-first, empty groups omitted. `control.*` folds
/// to one line, glossed `never public` (it can never be opened with `--public`, unlike the other gated
/// services). Within a group the gloss column aligns (per group, so a long raw-stream
/// row never widens the tight family block). The danger weight is monotonic on the GROUP headers; a
/// per-service unmetered caveat is quiet inline prose, never a marker louder than the group above it.
fn serving_section(
    manifest: &[ManifestEntry],
    addr_by_name: &HashMap<String, String>,
    fetch_names: &HashSet<String>,
) -> String {
    // (label, gloss, optional quiet caveat) rows per group; the manifest is already name-sorted, so rows keep
    // that order. A BTreeMap keyed by `Group` iterates safest-first (the derived `Ord`).
    let mut rows: BTreeMap<Group, Vec<(String, String, Option<String>)>> = BTreeMap::new();
    let mut has_control = false;
    for entry in manifest {
        // `control.stop` / `control.services` fold into one row: node plumbing an operator never opts into,
        // never a hidden service. Detected by the `control.` prefix, the verbatim wire family. The update
        // route every serve binds is the same kind of plumbing and folds with them.
        if entry.name.starts_with("control.") || entry.name == ROSTER_SERVICE {
            has_control = true;
            continue;
        }
        let (label, gloss) = describe(entry, addr_by_name, fetch_names);
        let caveat = (entry.posture == Posture::Open
            && matches!(entry.metering, Some(Metering::Unmetered)))
        .then(|| "unmetered: a stranger can drain your uplink".to_owned());
        rows.entry(Group::of(entry))
            .or_default()
            .push((label, gloss, caveat));
    }
    if has_control {
        rows.entry(Group::FamilyGated).or_default().push((
            "control.*".to_owned(),
            "node control (never public)".to_owned(),
            None,
        ));
    }

    let mut out = String::from("serving\n");
    for (group, group_rows) in &rows {
        let (name, audience) = group.header();
        // The header carries its audience on a fixed short gutter (so a long raw-stream row never shoves the
        // header audience far to the right); the SERVICE ROWS align their gloss column among THEMSELVES, per
        // group, so the tight family block is never widened by a long `public-UNSAFE` row below it.
        out.push_str(&format!("  {name}   {audience}\n"));
        let col = group_rows
            .iter()
            .map(|(label, _, _)| 4 + label.len())
            .max()
            .unwrap_or(0)
            + 3;
        for (label, gloss, caveat) in group_rows {
            out.push_str(&format!("{:<col$}{gloss}", format!("    {label}")));
            if let Some(caveat) = caveat {
                out.push_str(&format!("   {caveat}"));
            }
            out.push('\n');
        }
    }
    out
}

/// Render a count of seconds as a short human span (`5400` -> `1h 30m`, `3600` -> `1h`), so the
/// `--expires` banner and a status uptime read the way an operator thinks rather than in raw seconds.
/// Coarsest non-zero units only, at most two, so `1d` stays `1d` and `5400` reads `1h 30m`. The one
/// span formatter the serve banner and bare `status` share, so the two can never drift.
pub(crate) fn humanize_secs(mut secs: u64) -> String {
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
    // A zero span renders `0s`: `--expires` cannot be zero (`Lifetime` rejects it), but a status uptime
    // of zero seconds can, so keep the guard rather than indexing an empty `parts`.
    if parts.is_empty() {
        "0s".to_owned()
    } else {
        parts.join(" ")
    }
}

/// Parse the operator's raw `--public`/`--public-unsafe` names into typed [`Service`]s: the Router's overlays
/// take the domain type, so a malformed name fails at the serve edge with its own parse error.
fn parse_services(names: &[String]) -> eyre::Result<Vec<Service>> {
    names
        .iter()
        .map(|name| name.parse::<Service>().map_err(Into::into))
        .collect()
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod serve_tests;
