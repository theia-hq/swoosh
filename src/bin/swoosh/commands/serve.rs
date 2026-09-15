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
//! signet read from swoosh's own store, and derives the ssh host seed from swoosh's secret, so an
//! `ssh=sshd:` service presents the host key a client pins. swoosh assembles the whole route table
//! itself (`fetch`/`recv` instances, `ping`/`speed`, and `sshd` under the `ssh` feature), builds the gate through the shared
//! [`resolve_gate`](tightbeam::tunnel::resolve_gate) policy, and prints its OWN readiness banner. `--public`
//! and `--quiet` live on THIS verb (not root), and reach comes via the shared
//! [`ReachArgs`](swoosh::transport::ReachArgs), flattened like every other reaching verb. `--expires` is a
//! LOCAL timer with no security surface: when its deadline passes the node ends by itself, the same
//! graceful teardown a Ctrl-C gives.
//!
//! This file owns the VERB: its flags, the readiness banner, and the run loop. The node engine it
//! drives (the route-table edges, the `control.*` handlers, the resident arm) is the library's `serve`
//! module, which the integration proofs also assemble their nodes from.

use core::net::SocketAddr;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use eyre::WrapErr as _;
use nauthy::{FileDenylist, Service};
use swoosh::credential::Credential;
use swoosh::home::Home;
use swoosh::identity::Identity;
use swoosh::reaching::{BindRole, ReachCtx, Reaching};
use swoosh::serve::{
    CONTROL_SERVICES_SERVICE, CONTROL_STOP_SERVICE, FetchScope, InstanceLock, RECV_SCHEME, Recv,
    Resident, ServiceList, Stop, StopKind, Stopped, acquire_single, bind_entry, classify_stop,
    extract_recv_services,
};
use swoosh::transport::{MdnsState, ReachArgs};
use tightbeam::duration::Lifetime;
use tightbeam::enabled::FileDisabledList;
use tightbeam::tunnel::{
    self, CancellationToken, Exposer, ManifestEntry, Metering, Posture, RawSource, Router,
    TargetKind,
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
    #[arg(value_name = "name=target")]
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
    /// suppress the readiness banner (for unattended/CI use)
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
    /// `serve` reads its OWN context (Craftsman): it is deliberately NOT a `ReachCtx` field, so the reach
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
}

/// What `serve` needs beyond the bound node: swoosh's ssh host seed, the trusted signet, the revocation
/// denylist the gate honors, and the pre-cut signed roster blob. All resolved in the composition root (the
/// host seed needs the secret before the transport consumes it), then attached to [`ServeCmd`] via
/// [`with_expose`](ServeCmd::with_expose). Moved here from `main.rs` so `serve` reads its own context.
/// The home rides along too: `serve --resident` names its socket/lock off the home, and the SAME `home`
/// value the root resolved (never a re-derive), so the resident paths and the daemon's future clients
/// can never disagree on which home they mean.
pub struct ExposeContext {
    /// swoosh's ssh host key seed, derived from the secret so an `ssh=sshd:` service presents the host
    /// key a client pins.
    pub host_seed: [u8; 32],
    /// The signet the default gate trusts: a provisioned signet if one was adopted, else this node's OWN
    /// key (person-zero self-trusts).
    pub signet: Option<NodeId>,
    /// The revocation denylist the gate honors.
    pub denylist: FileDenylist,
    /// The live enable/disable oracle the exposer's per-stream gate consults (delib-47): a `service disable`
    /// written to `<home>/disabled` refuses the service live, and a `service enable` restores it, both with no
    /// restart. The exact mtime-watch shape as the denylist, loaded beside it in the composition root.
    pub enabled: FileDisabledList,
    /// The signet-signed roster blob the `roster:` handler serves, cut once per `serve` from the
    /// operator's contacts while the secret is still live.
    pub roster_blob: Arc<Vec<u8>>,
    /// The node home this serve runs under: the resident socket/lock derive from it, and the composition
    /// root resolves it ONCE, so a `--resident` serve and its future control clients name the same paths.
    pub home: Home,
}

impl core::fmt::Debug for ExposeContext {
    /// `FileDenylist` and `FileDisabledList` each hold a `Mutex` (not `Debug`), so this impl names the fields
    /// it can and elides those, which is enough for the derived `Debug` on `ServeCmd`/`Command` to compile.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExposeContext")
            .field("host_seed", &self.host_seed)
            .field("signet", &self.signet)
            .field("roster_blob_len", &self.roster_blob.len())
            .finish_non_exhaustive()
    }
}

impl Reaching for ServeCmd {
    fn reach_args(&self) -> &ReachArgs {
        &self.reach
    }

    /// `serve` RECEIVES badges (it is the gate), it never presents one, so it dials as no one:
    /// `Anonymous`. It must bind `Persisted` (a stable address), which is a SEPARATE, non-forgettable
    /// concern, not this credential's derived `Ephemeral`: the composition root's identity override, not
    /// this method, supplies it.
    fn credential(&self) -> Credential {
        Credential::Anonymous
    }

    /// `serve` is the gate: it dials no peer and takes no `--present`, so there is no self-addressing link
    /// peer to conflict with. The check is vacuously satisfied.
    fn reject_redundant_present(&self) -> eyre::Result<()> {
        Ok(())
    }

    /// `serve` MUST be reachable at one stable address across runs, so it declares `Persisted` EXPLICITLY
    /// rather than inheriting the credential's derived `Ephemeral` (which would give a new address every
    /// run: a broken node). This is a written declaration the compiler requires, not a forgettable
    /// override, so a serve verb cannot silently come up ephemeral.
    fn identity(&self) -> Identity {
        Identity::Persisted
    }

    /// Serving: `serve` is the process that accepts connections under the home key, so its bind publishes
    /// the key's address record (n0 pkarr/DNS) for peers to dial. The one `Serving` verb.
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
            signet,
            denylist,
            enabled,
            roster_blob,
            home,
        } = *expose;
        self.run_serve(
            node,
            host_seed,
            signet,
            denylist,
            enabled,
            roster_blob,
            home,
        )
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
}

impl ServeCmd {
    /// Serve the named services (default `ping:` + `speed:`) under swoosh's identity by driving the
    /// tunnel core directly: parse the services, resolve the gate from swoosh's own signet + denylist (through
    /// the shared `resolve_gate` policy, so `--public` opens, else a family gate on the signet), assemble the
    /// route table (`fetch`/`recv` instances, `ping`/`speed`, and `sshd` under the `ssh` feature), print
    /// swoosh's banner, and run the exposer. A `sshd:`/`ping:`/`speed:` service stays gated regardless. The `signet` here is already
    /// resolved by the composition root: a provisioned signet if one was adopted, else this node's OWN key
    /// (person-zero self-trusts), so a plain node gates on itself rather than failing "no signet".
    #[expect(
        clippy::too_many_arguments,
        reason = "run_serve takes the pre-resolved serve inputs one by one (seed, signet, oracles, \
                  roster, home) so each stays a named parameter at the one call site; bundling them \
                  into a struct would only rename the list"
    )]
    async fn run_serve<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        host_seed: [u8; 32],
        signet: Option<NodeId>,
        denylist: FileDenylist,
        enabled: FileDisabledList,
        roster_blob: Arc<Vec<u8>>,
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
        // origins: the SSRF pivot is unrepresentable, not fail-closed-by-convention (delib-39 BLOCKER-3).
        let fetch = FetchScope::extract(&mut requested)?;
        // De-merge the receive services the SAME way (delib-39): every `name=recv:<dir>` becomes its OWN
        // `Recv` instance bound to ONLY its own sink directory, so `a=recv:/x b=recv:/y` writes alice's
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
        // Resolve the node BASE gate before announcing readiness: an unprovisioned node fails HERE, through
        // the ONE shared policy point, rather than ever serving on a permissive default. Opening individual
        // services is the separate `--public`/`--public-unsafe` overlay, never a node-wide value.
        //
        // `Router::catalog` renders the `control.services` read and reads only whether the base gate is
        // whole-node open; `Router` owns its gate with no accessor, so the display render gets a second
        // rooted gate through the same policy on the same authority (the catalog never reads the
        // revocation store). A `Router::base_gate()` accessor would delete this second value.
        let catalog_gate = tunnel::resolve_gate(signet, FileDenylist::empty(PathBuf::new()))?;
        let gate = tunnel::resolve_gate(signet, denylist)?;
        // One `Router`: each route binds a handler VALUE (the engine handlers, roster, stop, the fetch and
        // recv instances) or tightbeam's own primitives (forwards, raw streams, the `echo:` reflector)
        // through the `name=addr` grammar. The public overlays prove at `.expose()` below, so
        // prove-before-announce holds. The operator's `--public` set is parsed ONCE here, before the bind,
        // and drives the overlay, the per-route diagnostic engine (the metered engine for an open name,
        // the owner engine otherwise), and the per-service fetch posture (one source of truth).
        let public = parse_services(&self.public)?;
        let mut router = Router::new(gate);
        for entry in &requested {
            router = bind_entry(router, entry, host_seed, &roster_blob, &public)?;
        }
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
        for service in &recv {
            // One `Recv` instance per receive service, holding ONLY its own sink dir, so a push to one
            // receive service can never land in another's directory.
            router =
                router.service(service.name().parse()?, Recv::new(service.out().to_owned()))?;
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
        let catalog = router.catalog(&catalog_gate, Some(CONTROL_SERVICES_SERVICE.parse()?));
        let router = router.member_service(
            CONTROL_SERVICES_SERVICE.parse()?,
            ServiceList::new(catalog.clone()),
        )?;
        // Wire the live enable/disable oracle (delib-47) alongside the proven public overlay: a stream for a
        // service named in `<home>/disabled` is refused at the gate seam, live, and a re-enable restores it
        // with no restart. `with_enabled` cannot fail (it only stores the oracle), so it tails the chain.
        let exposer = router.expose()?.with_enabled(enabled);
        // Prove the transport can carry this gate BEFORE announcing readiness or binding the resident
        // socket: a rooted gate over a transport that does not prove the peer refuses here with the
        // teaching error, never after a "ready" banner the node cannot honor (and never with a lock or
        // socket taken for a serve that cannot arm).
        exposer
            .prove_security::<T>()
            .wrap_err(
                "bare quirk cannot serve: it does not prove the peer's key; use `--transport quirk+noise`",
            )?;

        // The resident listener arm (S4), after the proven overlay so a refused serve never binds
        // a socket. Order: (1) plain serve acquires nothing (byte-identical, no dir, no lock, no
        // socket); (2) `--resident` acquires single-instance off the THREADED home (flock truth +
        // bound listener, held for life); the LIVE catalog snapshot above plus a CLONE of the node's
        // one teardown token ride the `Resident` state the accept loop serves from. The bound
        // address rides along as the status `addr`, carried with the arm (no second `local_addr`).
        // Snapshot the address only when something reads it (the arm, or the banner): a plain
        // quiet serve performs no new read at all.
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
            Some(self.resident_parts(
                &home,
                &runtime_root,
                tightbeam::tunnel::ServiceCatalog::clone(&catalog),
                addr.node,
                addr.hints.first().copied(),
                &cancel,
            )?)
        } else {
            None
        };

        if !self.quiet {
            // The banner reads its own `local_addr` snapshot beside the one the resident arm already
            // carried: a plain serve (resident `None`) reads exactly once here, as today, and the
            // resident arm carries the status `addr` from the same bound node.
            let addr = node.local_addr();
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
            // direct-only. The live mDNS state is a SEPARATE reachability fact, attached by the
            // composition root from the SAME `advertise` call that composed discovery, so the banner
            // reports what started rather than assuming it.
            let reach = ReachKind::of(self.reach.transport, self.reach.local);
            let Some(mdns) = self.mdns else {
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
            // FLAG(CLI-Architect): the `control` banner line wording is the surface owner's call;
            // picked here as one extra line under `--resident` only, after the reach section.
            let resident_socket = resident.as_ref().map(|(_, _, lock)| lock.socket_path());
            let control_line = self.control_line(resident_socket);
            print!(
                "{}",
                render_ready_banner(
                    &addr.node.to_string(),
                    reach,
                    mdns,
                    &addr.hints,
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
                 `ping=ping:`, `web=127.0.0.1:8080`"
            );
        };
        map.insert(name.to_owned(), addr.to_owned());
    }
    Ok(map)
}

/// How peers reach this node, for the banner's `how peers reach you` section: whether the bound transport
/// routes across the internet (an `internet` channel) or is local/direct-only. Read off the SELECTED
/// transport and bind mode at the composition seam, never inferred from whether hints are present (that
/// would conflate the channel with the hint state, delib-41 CLI-Architect note). An enum, not a bool, so a
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
/// GROUP and escalates monotonically DOWN the list (delib-41 Newcomer fix): `FamilyGated` (no overlay) <
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
    // FLAG(CLI-Architect): the exact marker glyphs (`!` / `!!`) and the audience wording are a banner-format
    // detail; picked here to satisfy the monotonic-loudness rule, open to the owner's final call.
    fn header(self) -> (&'static str, &'static str) {
        match self {
            Self::FamilyGated => ("family-gated", "your devices + peers you've granted"),
            Self::Public => ("public !", "anyone, unauthenticated"),
            Self::PublicUnsafe => ("public-UNSAFE !!", "raw bytes to anyone who connects"),
        }
    }
}

/// The gloss for a bare handler scheme, the terse right-column description (delib-41 CLI-Architect gloss set).
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
/// the built-in forward and the `echo:` reflector from a named handler scheme, because both built-ins are
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
            // tightbeam's built-in local forward (`host:port` / `unix:<path>`): a socket the operator
            // deliberately stood up, glossed as such.
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

/// Whether the operator's typed target is tightbeam's built-in local forward (`host:port` / `unix:<path>`)
/// rather than a named handler scheme. Both forwards and the `echo:` reflector are first-party [`Handler`]s,
/// so the manifest's [`TargetKind`] names only handler-vs-raw-stream; the display map carries the finer
/// render distinction. Mirrors tightbeam's own forward grammar so the two never disagree.
fn is_forward(addr: &str) -> bool {
    addr.starts_with("unix:")
        || addr
            .rsplit_once(':')
            .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
}

/// Render the full readiness banner as ONE string (pure, so it is unit-testable and printed once): the
/// `swoosh ready` header, the copy-clean node id, the `how peers reach you` section, the grouped `serving`
/// section, and the stop line. Every line is a tell (delib-41): no raw dial flags, no split posture, one
/// monotonic danger vocabulary. Blank-line framed so the id (and any direct address) is copy-paste-clean.
#[expect(
    clippy::too_many_arguments,
    reason = "the banner is assembled from independent facts (id, reach kind, mDNS state, hints, the \
              declared manifest, swoosh's display map, the fetch names, the stop line); bundling them into \
              one struct would only move the argument list, not remove it"
)]
fn render_ready_banner(
    node_id: &str,
    reach: ReachKind,
    mdns: MdnsState,
    hints: &[SocketAddr],
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
    out.push_str(&reach_section(reach, mdns, hints));
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
/// The `internet` channel appears only when the transport routes across the internet; `direct` only when the
/// bind is direct-only AND hands out address hints. "automatic" leads both auto channels, and the local mDNS
/// lane is a first-class tell that flips to an off-state naming what to do instead when discovery did not
/// start.
// FLAG(CLI-Architect): the channel glosses (wording, "even across NATs", the off-state next-step) are a
// banner-format detail; picked here to satisfy the Newcomer fixes (no backend name, "automatic" on both, a
// down-state next-step), open to the owner's final call.
fn reach_section(reach: ReachKind, mdns: MdnsState, hints: &[SocketAddr]) -> String {
    let direct = matches!(reach, ReachKind::DirectOnly) && !hints.is_empty();
    // Whether the direct channel below would hold an address a peer could actually dial: a loopback
    // hint resolves to the peer's own machine, so a loopback-only bind has nothing to hand over.
    let handable = hints.iter().any(|addr| !addr.ip().is_loopback());
    // Width the label column to the widest channel label actually shown.
    let mut labels: Vec<&str> = Vec::new();
    if reach == ReachKind::Internet {
        labels.push("internet");
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
    let local = match (mdns, reach) {
        // A direct-only bind resolves on local mDNS or a hand-fed address, and its advertised hints are
        // loopback today (the same-host mDNS defect), so the gloss promises local discovery only. The
        // founder's LAN sentence returns with the advertisement fix (LOOSE-ENDS, two-host Operator gate).
        (MdnsState::Available, ReachKind::DirectOnly) => {
            "automatic; local mDNS, or direct, no NAT traversal".to_owned()
        }
        (MdnsState::Available, ReachKind::Internet) => {
            "automatic; your devices just need the key (mDNS)".to_owned()
        }
        (MdnsState::Blocked, ReachKind::Internet) => {
            "off; mDNS unavailable here, so reach by the key over the internet".to_owned()
        }
        (MdnsState::Blocked, ReachKind::DirectOnly) => {
            // The down-state is what the operator reads when discovery did not start, so it points at
            // a direct address only when one is actually handable; a loopback-only bind has none, and
            // saying otherwise would promise an address the section below contradicts.
            if handable {
                "off; mDNS unavailable here, so hand a peer the address below".to_owned()
            } else {
                "off; mDNS unavailable here, so no address can be handed to a peer".to_owned()
            }
        }
    };
    out.push_str(&reach_line(width, gutter, "local", &local));
    if direct {
        // Loopback hints cannot be handed to a peer (they resolve to the peer's own machine), so a
        // loopback-only bind reads "reachable on this machine only" rather than "hand a peer this address".
        let (routable, loopback): (Vec<&SocketAddr>, Vec<&SocketAddr>) =
            hints.iter().partition(|addr| !addr.ip().is_loopback());
        let (header, addrs): (&str, Vec<&SocketAddr>) = if routable.is_empty() {
            ("reachable on this machine only:", loopback)
        } else if routable.len() == 1 {
            ("hand a peer this address:", routable)
        } else {
            ("hand a peer one of these:", routable)
        };
        out.push_str(&reach_line(width, gutter, "direct", header));
        // Each address on its own line, bare and copy-clean (the same standard as the node id), aligned
        // under the header's gloss column.
        for addr in addrs {
            out.push_str(&format!("{:gloss_col$}{addr}\n", ""));
        }
    }
    out
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
        // never a hidden service. Detected by the `control.` prefix, the verbatim wire family.
        if entry.name.starts_with("control.") {
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
