//! `swoosh serve [<service>...]`: be the one `serve` for this home. Publish the named services behind
//! this machine's gate, hold the home's control socket, then stay reachable so your devices, and anyone
//! you gave a link, reach them.
//!
//! Bare, it serves what this home last started with (the services in `<home>/serve.toml`), or `ping` and
//! `speed` when it never named any. `swoosh serve ssh ping` publishes a shell and the round-trip probe;
//! `ssh`, `ping` and `speed` name themselves, and every other entry is `name=target`. Only the services are remembered:
//! `--public`, `--public-unsafe`, `--admit` and `--expires` apply to the run that types them. It drives
//! tightbeam's tunnel LIBRARY (`Exposer`) directly under swoosh's OWN persisted identity: the node binds
//! the same key `swoosh ssh` and a signed link root at, gates on the pin read live from swoosh's own
//! store and on the links this machine signed, and derives the ssh host seed from swoosh's secret, so an
//! `ssh` service presents the host key a client pins. swoosh assembles the whole route table itself
//! (`fetch`/`recv` instances, `ping`/`speed`, the update route, and `sshd` under the `ssh` feature),
//! takes the gate the composition root built ([`swoosh::gate::anchored`]), and prints its OWN banner.
//! `--expires` is a LOCAL timer with no security surface: when its deadline passes the node ends by
//! itself, the same graceful teardown a Ctrl-C gives.
//!
//! Every `serve` is the one `serve` for its home: before anything binds it takes the home's lock and
//! control socket under the per-user runtime directory, so a second one refuses with the running one's pid
//! and the fix, and bare `stop` and `status` always find it.
//!
//! This file owns the VERB: its flags, the banner, and the run loop. The node engine it drives (the
//! route-table edges, the `control.*` handlers, the control socket) is the library's `serve` module, which
//! the integration proofs also assemble their nodes from.

use core::net::SocketAddr;
use core::time::Duration;
use std::borrow::Cow;
use std::ffi::OsString;
use std::io::IsTerminal as _;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use bifrost_mdns::{At, Dialable, Expiring, Missing, ScopeClass};
use clap::Args;
use eyre::WrapErr as _;
use nauthy::{Gate, Service};
use swoosh::contacts::ContactsStore;
use swoosh::gate::AnchorCut;
use swoosh::home::{Home, HomeWrite, ServeLock};
use swoosh::identity::Identity;
use swoosh::node_client::{ControlClient, NodeClient as _};
use swoosh::reaching::{BindRole, ReachCtx, Reaching};
use swoosh::renewal::PickUp;
use swoosh::serve::{
    Activity, CONTROL_SERVICES_SERVICE, CONTROL_STOP_SERVICE, Exchange, FetchScope, InstanceLock,
    RecvService, Resident, SYNC_SERVICE, ServiceList, SingleError, Started, Stop, StopKind,
    Stopped, acquire_single, bind_entry, bind_recv, bind_renewal, classify_stop,
    extract_recv_services, refuse_recv_into_home,
};
use swoosh::serve_toml::{LiveServeToml, ServeToml};
use swoosh::standing::{Standing, StandingError};
use swoosh::transport::{MdnsState, Reach, ReachArgs, RelayHome, Resolver};
use tightbeam::duration::Lifetime;
use tightbeam::tunnel::{CancellationToken, Exposer, ManifestEntry, Posture, Router};

/// Be a node: publish these services behind your gate, then stay reachable.
#[derive(Debug, Args)]
pub struct ServeCmd {
    /// publish services as `name=target` (bare: the last list, else `ping` and `speed`)
    // The long form lists every target scheme, both halves: the three engines swoosh serves and the six
    // forms the tunnel grammar routes. A refusal from either half points here, so this list is the one a
    // mistyped scheme is sent to and it has to be complete.
    #[arg(
        value_name = "name=target",
        value_parser = swoosh::serve::service_entry,
        long_help = "publish services as `name=target` (bare: the last list, else `ping` and `speed`)\n\
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
        value_parser = swoosh::names::service,
        long_help = "A keyless shell is refused; a raw stream goes to `--public-unsafe`."
    )]
    pub public: Vec<Service>,
    /// open named raw-stream services (file:, fifo:, stdin:) to anyone
    // A raw stream opens only through this flag, and only when named: no bang suffix, no whole-node form.
    #[arg(
        long,
        value_name = "svc",
        value_delimiter = ',',
        value_parser = swoosh::names::service,
        long_help = "A raw stream has no auth of its own; `--public` refuses it and points here."
    )]
    pub public_unsafe: Vec<Service>,
    /// suppress the readiness banner and activity lines
    #[arg(long)]
    pub quiet: bool,
    /// Also print how peers reach this machine, under the banner.
    #[arg(long, hide = true, env = "SWOOSH_VERBOSE")]
    pub verbose: bool,
    /// serve for a bounded time, then stop (`30m`, `2h`, `1d`)
    #[arg(long, value_name = "duration")]
    pub expires: Option<Lifetime>,
    /// For this run, let in the devices of another root without joining it (CI).
    #[arg(long, value_name = "root key", value_parser = admitted_root)]
    pub admit: Option<NodeId>,
    #[command(flatten)]
    pub reach: ReachArgs,
    /// The home's lock and control socket and the services this run starts with, taken by
    /// [`claim`](Self::claim) before anything binds. Not a flag: clap skips it.
    #[arg(skip)]
    pub claim: Option<Box<Claim>>,
    /// What `serve` needs beyond the bound node, resolved by the composition root BEFORE the transport
    /// consumes the secret (the ssh host seed derives from it). Not a flag: clap skips it, and the root
    /// fills it in via [`with_expose`](Self::with_expose) before dispatch. Lives HERE, on `ServeCmd`, so
    /// `serve` reads its OWN context and the reach context stays uniform.
    // Boxed so the runtime context (which embeds a `Denylist`, itself carrying a `Mutex` and its
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
    /// uniform; the transport block reports what started rather than assuming it.
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

/// What a `serve` holds for its whole run, taken before anything binds: the home's single-instance lock
/// and its bound control socket, and the services this run starts with.
pub struct Claim {
    /// `<home>/serve.toml`, read live: the run's one reader of it. The services this run starts with and
    /// the relay and resolver it binds over come from its first read; the gate and the status ask it after.
    serve_toml: LiveServeToml,
    /// The services this run starts with, and where they came from.
    started: Started,
    /// The receive services, each with its output directory checked, taken out of `started`'s entries.
    recv: Vec<RecvService>,
    /// The rest of `started`'s entries, for the router.
    requested: Vec<String>,
    /// The flock that makes this the one `serve` for its home, held for the run.
    lock: InstanceLock,
    /// The control socket, bound under the lock.
    listener: std::os::unix::net::UnixListener,
}

impl core::fmt::Debug for Claim {
    /// The lock and the listener are not `Debug`; the services are what a reader wants.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Claim")
            .field("started", &self.started)
            .finish_non_exhaustive()
    }
}

/// What `serve` needs beyond the bound node: swoosh's ssh host seed, and the gate and the live cut beside
/// it. All resolved in the composition root (the host seed needs the secret before the transport consumes
/// it), then attached to [`ServeCmd`] via [`with_expose`](ServeCmd::with_expose).
pub struct ExposeContext {
    /// swoosh's ssh host key seed, derived from the secret so an `ssh` service presents the host key a
    /// client pins.
    pub host_seed: [u8; 32],
    /// The one gate this node runs in every standing ([`swoosh::gate::anchored`]): the pin read live,
    /// this machine's own key for the links it signed, and the revocations.
    pub gate: Gate,
    /// The live cut over the same pin and revocations the gate reads, wired beside it.
    pub cut: AnchorCut,
    /// The node home this serve runs under, resolved ONCE by the composition root.
    pub home: Home,
}

/// `--admit`'s root key, typed `root:ed01…`.
fn admitted_root(text: &str) -> Result<NodeId, String> {
    swoosh::peer::parse_key(text.strip_prefix("root:").unwrap_or(text))
        .map_err(|error| error.to_string())
}

/// Check that this machine may admit the devices of `root` for this run, and record it in `serve.lock`
/// beside this run's pid: never this machine's own key, a root revoked here, or a person's root, and only on
/// a machine that trusts no root. The pin is read and the root recorded under one `home.lock`, which `join`
/// writes the pin under, so a `join` and a `serve --admit` never both go ahead.
pub(crate) async fn admitting(
    serve_lock: &ServeLock,
    home: &Home,
    own: NodeId,
    root: NodeId,
) -> eyre::Result<()> {
    if root == own {
        eyre::bail!("that is this machine's key, not a root.");
    }
    if swoosh::config::is_revoked(home, root)? {
        eyre::bail!("root:{root} was revoked on this machine; recovery is a new root.");
    }
    let store = ContactsStore::open(home).await?;
    let contacts = store.contacts();
    if let Some(person) = contacts.petnames().find(|person| {
        contacts
            .signet(person)
            .is_some_and(|binding| binding.node == root)
    }) {
        eyre::bail!(
            "root:{root} is {person}'s root: admitting it would admit every one of {person}'s devices. To let \
             {person} use a service: swoosh share <service> {person}"
        );
    }
    let home_lock = HomeWrite::take(home).await?;
    match Standing::read(home).await {
        Ok(standing) => match standing {
            Standing::Unpinned => {}
            Standing::Device { pin, .. } | Standing::HoldsRoot { pin, .. } => eyre::bail!(
                "this machine trusts root:{pin}, and admits its devices already: --admit is for a machine \
                 that trusts no root."
            ),
            Standing::InterruptedMint { .. } => {
                eyre::bail!("{}", swoosh::standing::UNFINISHED_MINT)
            }
        },
        Err(StandingError::Damaged(what)) => {
            eyre::bail!("{}", swoosh::standing::damaged_line(&what))
        }
        Err(other) => return Err(other.into()),
    }
    serve_lock.record(&home_lock, Some(root))?;
    drop(home_lock);
    eprintln!(
        "admitting devices of root root:{root} for this run; this machine does not get your revoked keys."
    );
    Ok(())
}

impl core::fmt::Debug for ExposeContext {
    /// The gate and the cut are not `Debug`, so this impl names the fields it can and
    /// elides those, which is enough for the derived `Debug` on `ServeCmd`/`Command` to compile.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExposeContext")
            .field("host_seed", &self.host_seed)
            .finish_non_exhaustive()
    }
}

impl Reaching for ServeCmd {
    fn reach_args(&self) -> &ReachArgs {
        &self.reach
    }

    /// `serve` dials no peer of its own: its exchanges are its own rounds.
    fn dialed(&self) -> Option<&swoosh::peer::Peer> {
        None
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
    /// that states NO dial credential: it is the gate, so it verifies badges and never presents one.
    fn bind_role(&self) -> BindRole {
        BindRole::Serving
    }

    /// Uniform dispatch: `serve` reads its OWN [`Claim`] and [`ExposeContext`] (attached by the root before
    /// dispatch), so it ignores every `ReachCtx` field.
    async fn run<T: Transport, D: Discovery>(
        mut self,
        node: &Node<T, D>,
        _ctx: ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        // The root always claims the home and attaches the expose context before dispatch (it is the only
        // caller), so a missing one is a composition-root bug, not a user error: surface it as an internal
        // error rather than panicking.
        let (Some(claim), Some(expose)) = (self.claim.take(), self.expose.take()) else {
            eyre::bail!(
                "internal: serve reached run without its claim or expose context (composition-root bug)"
            );
        };
        let ExposeContext {
            host_seed,
            gate,
            cut,
            home,
        } = *expose;
        self.run_serve(node, *claim, host_seed, gate, cut, home)
            .await
    }
}

impl ServeCmd {
    /// Before anything binds or is written: take this home's one lock and control socket, and settle the
    /// services this run starts with (named, resumed from `<home>/serve.toml`, or the default). A second
    /// `serve` for the home refuses here with the running one's pid and the fix, and so does a machine with
    /// no private runtime directory or one whose path a socket cannot hold.
    pub async fn claim(mut self, home: &Home) -> eyre::Result<Self> {
        let root = swoosh::home::runtime_root()?;
        let (lock, listener) = match acquire_single(home, &root).await {
            Ok(held) => held,
            Err(SingleError::AlreadyResident { pid }) => {
                let serving = running_services(home).await;
                eyre::bail!("{}", self.running_refusal(pid, serving.as_deref()));
            }
            Err(other) => return Err(eyre::Report::new(other)),
        };
        let serve_toml = LiveServeToml::load(home)?;
        let cwd = std::env::current_dir().wrap_err("could not read the current directory")?;
        let started = Started::of(&self.services, &serve_toml.held(), home, &cwd)?;
        // A receive service never saves into `$HOME`, the home, or above it, whether named now or resumed:
        // refused here, before anything binds or is written.
        let mut requested = started.entries();
        let recv = extract_recv_services(&mut requested, swoosh::home::inbox)?;
        let user_home = std::env::var_os("HOME")
            .filter(|user_home| !user_home.is_empty())
            .map(std::path::PathBuf::from);
        refuse_recv_into_home(&recv, home, user_home.as_deref())?;
        // The inbox is made here too, so a run that cannot make it stops before the machine key is made.
        for service in &recv {
            service.create_inbox()?;
        }
        self.claim = Some(Box::new(Claim {
            serve_toml,
            started,
            recv,
            requested,
            lock,
            listener,
        }));
        Ok(self)
    }

    /// The refusal a `serve` prints when one already runs for its home: which one, then the one fix that
    /// fits what this run asked for, in order. A service it named that the running one serves is turned on
    /// with `service on`; a flag that changes how the node runs needs a stop first; anything else is a
    /// second node, which needs a home of its own.
    fn running_refusal(&self, pid: u32, serving: Option<&[String]>) -> String {
        let head = match serving {
            Some(names) if !names.is_empty() => format!(
                "swoosh serve is already running for this home (pid {pid}, serving {}).",
                names.join(", ")
            ),
            _ => format!("swoosh serve is already running for this home (pid {pid})."),
        };
        let started = self
            .services
            .iter()
            .filter_map(|entry| entry.split_once('=').map(|(name, _)| name))
            .find(|name| serving.is_some_and(|names| names.iter().any(|served| served == name)));
        let fix = match started {
            Some(name) => format!("To turn {name} on: swoosh service on {name}"),
            None if self.sets_how_it_runs() => {
                "Stop it first to change how it runs: swoosh stop".to_owned()
            }
            None => "A second one needs its own: swoosh --home <dir> serve …".to_owned(),
        };
        format!("{head}\n{fix}")
    }

    /// Whether this run set a flag that changes how the node runs rather than what it serves: exposure,
    /// a lifetime, an admitted root, or anything about the bind.
    fn sets_how_it_runs(&self) -> bool {
        let reach = &self.reach;
        !self.public.is_empty()
            || !self.public_unsafe.is_empty()
            || self.expires.is_some()
            || self.admit.is_some()
            || reach.local
            || !reach.peer.is_empty()
            || reach.relay.is_some()
            || reach.resolver.is_some()
            || reach.transport != swoosh::transport::Transport::default()
    }

    /// `<home>/serve.toml` as this run's one watcher reads it, once the run has claimed its home: the root
    /// binds over the relay and resolver it holds and hands the gate the same watcher, so no two parts of
    /// the run read the file at two different moments.
    pub fn serve_toml(&self) -> Option<&LiveServeToml> {
        self.claim.as_ref().map(|claim| &claim.serve_toml)
    }

    /// Check that this run may admit the devices of `root`, and record it in `serve.lock`, which its claim
    /// holds; see [`admitting`].
    ///
    /// # Errors
    ///
    /// The run was not claimed, or [`admitting`] refused.
    pub(crate) async fn admit(&self, home: &Home, own: NodeId, root: NodeId) -> eyre::Result<()> {
        let Some(claim) = self.claim.as_ref() else {
            eyre::bail!("internal: serve admits before it claimed its home (composition-root bug)");
        };
        admitting(claim.lock.serve_lock(), home, own, root).await
    }

    /// Attach the resolved [`ExposeContext`] the composition root cut while the secret was still live, so
    /// `serve` reads its own context at run time.
    pub fn with_expose(mut self, expose: ExposeContext) -> Self {
        self.expose = Some(Box::new(expose));
        self
    }

    /// Attach the live [`MdnsState`] the composition root read off the composed discovery, so the
    /// transport block reports the discovery that started rather than one it assumed.
    pub fn with_mdns(mut self, mdns: MdnsState) -> Self {
        self.mdns = Some(mdns);
        self
    }

    /// Attach the [`Reach`] the composition root composed for this bind, so the transport block names the
    /// relay this node offers and the resolver it publishes to rather than promising n0's. Called at the
    /// iroh arm only, beside [`with_mdns`](Self::with_mdns).
    pub fn with_bound_reach(mut self, bound_reach: Reach) -> Self {
        self.bound_reach = Box::new(bound_reach);
        self
    }
}

/// The names the `serve` already running for `home` serves, read over its control socket, internal
/// routes left out; `None` when it does not answer.
async fn running_services(home: &Home) -> Option<Vec<String>> {
    let client = ControlClient::resolve(home).ok()?;
    let menu = client.services().await.ok()?;
    Some(
        menu.catalog
            .entries()
            .filter(|entry| !entry.name.starts_with("control."))
            .map(|entry| entry.name.clone())
            .collect(),
    )
}

impl ServeCmd {
    /// Serve the services this run started with under swoosh's identity by driving the tunnel core
    /// directly: parse the services, assemble the route table (`fetch`/`recv` instances, `ping`/`speed`,
    /// the update route, and `sshd` under the `ssh` feature) behind the gate the composition root built,
    /// record what it serves, print swoosh's banner, and run the exposer and the control socket with the
    /// live cut wired. A service stays gated unless `--public` opens it.
    async fn run_serve<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        claim: Claim,
        host_seed: [u8; 32],
        gate: Gate,
        cut: AnchorCut,
        home: Home,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        // The run's one watcher of `<home>/serve.toml`, the one its claim read: the live enable/disable
        // oracle the exposer's per-stream gate consults, so a service turned off is refused live, and
        // turned back on, both with no restart. The status the control socket reports reads the same one.
        let Claim {
            serve_toml: enabled,
            started,
            recv,
            mut requested,
            lock,
            listener,
        } = claim;
        // The served names in the order the person gave them, for the banner and the per-service lines:
        // read from every entry, before the fetch and receive services were pulled out.
        let names: Vec<String> = started
            .entries()
            .iter()
            .filter_map(|entry| entry.split_once('=').map(|(name, _)| name.to_owned()))
            .collect();
        // Every node answers its own `control.stop` and member-only `control.services`, always, whatever
        // else it serves: the node-lifecycle control surface is part of being a node, not a service the
        // operator opts into. Both are MEMBER-only (`.member_service` below): the gate admits a family
        // badge or a service slip, and the route's access floor then refuses anything that is not a
        // whole-node member BEFORE any `Response::Ok`, so a delegate holding a `control.stop` slip cannot
        // stop the node.
        //
        // Pull each fetch service out of the requested set BEFORE the router binds it, and de-merge: every
        // `name=fetch:<origin>` becomes its OWN handler instance holding ONLY its own origin scope. A public
        // fetch handler therefore physically holds only its own origins and cannot reach a gated fetch's
        // origins: the SSRF pivot is unrepresentable, not fail-closed-by-convention.
        let fetch = FetchScope::extract(&mut requested)?;
        // The node's ONE teardown authority. The exposer owns it (it is what acts on the cancel); a local
        // `--expires` timer, the gated `control.stop` handler, and the local socket `Stop` each hold a
        // CLONE as the node-control capability: they may REQUEST the stop, never tear the node down
        // themselves.
        let cancel = CancellationToken::new();
        // The node BASE gate is the one the composition root built, the same in every standing. Opening
        // individual services is the separate `--public`/`--public-unsafe` overlay, never a node-wide value.
        let public = self.public.clone();
        let mut router = Router::new(gate);
        for entry in &requested {
            router = bind_entry(router, entry, host_seed, &public)?;
        }
        // The update route, on every `serve` whatever the standing, member-gated: only this root's devices
        // exchange on it. Bound by the node, never by an entry, and dotted, so no typed name reaches it.
        router = router.member_service(SYNC_SERVICE.parse()?, Exchange::new(home.clone()))?;
        // The pick-up route, proven-only: a device of this root whose standing ended takes its renewal
        // here. Bound on every `serve` so a `join` under a running one needs no restart, but only while
        // this home is a device or holds its root, and its update verifies under the pin, does any key
        // reach the handler: a key the update lists live.
        let (bound, known) = bind_renewal(router, &home).await?;
        router = bound;
        for scoped in fetch.services() {
            // One engine handler per fetch service, holding ONLY its own origin scope. An unconstrained
            // scope is the NEVER engine (the open proof refuses to expose it); a non-empty scope is the
            // OPT-IN engine, which applies the 16 MiB/30s responder bounds by construction.
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
        // sink, so quiet silences every activity line by construction.
        let activity = self.activity(std::io::stderr())?;
        for service in &recv {
            // One `Recv` instance per receive service, holding ONLY its own output dir: de-merged the SAME way
            // as fetch, at the claim, where each dir was checked and the inbox made.
            let name: Service = service.name().parse()?;
            router = bind_recv(router, name, service.out().to_owned(), activity.as_ref())?;
        }
        // The node-lifecycle control verbs are MEMBER-only, not merely gated: tightbeam checks the route's
        // access class after the gate admits and before any `Response::Ok`.
        router = router.member_service(CONTROL_STOP_SERVICE.parse()?, Stop::new(cancel.clone()))?;
        // Refuse an unconstrained PUBLIC fetch per-service at build time (an open egress relay).
        fetch.refuse_open_relay(&self.public)?;
        // Declare both open overlays from the operator's raw names. The proof runs at `.expose()` below,
        // before anything is recorded or a banner advertises a service it will not serve.
        router = router
            .public(public)
            .public_unsafe(self.public_unsafe.clone());
        // Snapshot the served catalog ONCE, here, for the `control.services` read handler AND the control
        // socket read to serve. `self_listing` renders the one row being built: `control.services` itself.
        let catalog = router.catalog(Some(CONTROL_SERVICES_SERVICE.parse()?));
        let router = router.member_service(
            CONTROL_SERVICES_SERVICE.parse()?,
            ServiceList::new(catalog.clone()),
        )?;
        // Wire the live enable/disable oracle and the live cut beside the proven public overlay.
        let exposer = router
            .expose()?
            .with_enabled(enabled.clone())
            .with_live_cuts(cut);
        // Prove the transport can carry this gate BEFORE recording or announcing anything.
        exposer
            .prove_security::<T>()
            .wrap_err(
                "bare quirk cannot serve: it does not prove the peer's key; use `--transport quirk+noise`",
            )?;

        // The routes bound: only now does this run save what it was told, in one write: a named list for the
        // next bare `serve`, with the services it names turned back on, and the relay and resolver it was
        // pointed at. A `serve` that did not start saves nothing. A bare `serve` saves no list, and says
        // which of its services are off.
        let home_lock = HomeWrite::take(&home).await?;
        ServeToml::update(&home_lock, &home, |file| {
            started.record(file);
            self.reach.keep_reach(file);
        })?;
        drop(home_lock);
        if !matches!(started, Started::Named(_)) {
            let off = enabled.off();
            for name in names.iter().filter(|name| off.contains(*name)) {
                eprintln!("{name} is off; to turn it back on: swoosh service enable {name}");
            }
        }

        // ONE expansion of this bind, read by both the control socket's status address and the transport
        // block, so the two can only ever name the same host.
        let dialable = Dialable::of(node.bound_sockets());
        // The status address is the first entry of the bind's own dialable set: a peer elsewhere can route
        // to it where one exists, and it falls back to loopback on a host that has nothing else.
        let status_addr = dialable.all().first().map(|at| at.socket);
        let addr = node.local_addr();
        let resident = std::sync::Arc::new(Resident::new(
            addr.node,
            status_addr,
            tightbeam::tunnel::ServiceCatalog::clone(&catalog),
            enabled,
            cancel.clone(),
        ));

        if !self.quiet {
            let manifest = exposer.manifest();
            let transport = match (self.verbose, self.mdns.as_ref()) {
                (false, _) => None,
                (true, Some(mdns)) => Some(reach_section(
                    ReachKind::of(self.reach.transport, self.reach.local),
                    mdns,
                    &self.bound_reach,
                    &dialable,
                )),
                (true, None) => eyre::bail!(
                    "internal: serve reached its banner without the mDNS state (composition-root bug)"
                ),
            };
            let stop_line = match self.expires {
                Some(lifetime) => format!(
                    "runs for {}, then stops (or ctrl-c)",
                    humanize_secs(lifetime.duration().as_secs())
                ),
                None => "ctrl-c to stop".to_owned(),
            };
            let keeper = keeper_line(
                supervised(|name| std::env::var_os(name)),
                std::io::stderr().is_terminal(),
                Keeper::here,
            );
            print!(
                "{}",
                render_banner(
                    &addr.node.to_string(),
                    &serving_line(&names, &manifest, started.is_resumed()),
                    transport.as_deref(),
                    keeper,
                    &stop_line,
                )
            );
        }

        // An `--expires` deadline is a LOCAL timer with no security surface: after it elapses it cancels the
        // node's teardown token, the same graceful stop a Ctrl-C or a remote `control.stop` gives.
        if let Some(lifetime) = self.expires {
            let cancel = cancel.clone();
            let deadline = lifetime.duration();
            tokio::spawn(async move {
                tokio::time::sleep(deadline).await;
                cancel.cancel();
            });
        }

        // Run until a stop, distinguishing a GRACEFUL stop from an ERRORED teardown: a requested stop is
        // SUCCESS (exit 0, so a CI action reads a clean teardown as green); only a genuine error exits
        // non-zero. Beside the run, this node's own exchanges with your devices: they end when the run does.
        let stopped = tokio::select! {
            stopped = run_until_stopped(exposer, node, cancel, resident, listener, lock) => stopped?,
            () = sync_rounds(node, &home) => unreachable!("the rounds run until the node stops"),
            () = known.watch() => unreachable!("the pick-up route's keys are read until the node stops"),
        };
        // The teardown line is best-effort: a piped consumer may have already closed stdout by the time
        // the node stops, so a broken-pipe write must NOT turn a clean stop into a panic.
        {
            use std::io::Write as _;
            let _ = writeln!(std::io::stdout(), "{}", stopped.message());
        }
        // The bound node's teardown (iroh's graceful `Endpoint::close`) is owned by the composition root,
        // which closes it after every reaching verb returns.
        Ok(())
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
}

/// Drive the exposer and the control socket until the node stops, returning WHY it stopped for a graceful
/// end or propagating the error for a failed teardown.
///
/// The control listener runs beside the exposer and Ctrl-C: it serves the local socket until the same
/// token fires, then the teardown unlinks the socket and drops the lock. Because the socket `Stop` cancels
/// the SAME token the exposer watches, every arm classifies its result from the recorded [`StopKind`]
/// rather than from the arm that won the poll: a socket stop renders [`Stopped::Local`], a wire
/// `control.stop` or a `--expires` deadline renders [`Stopped::Requested`], and a Ctrl-C records itself and
/// renders [`Stopped::Interrupted`], so the kinds never collapse into one.
async fn run_until_stopped<T: Transport, D: Discovery>(
    exposer: Exposer,
    node: &Node<T, D>,
    cancel: CancellationToken,
    resident: std::sync::Arc<Resident>,
    listener: std::os::unix::net::UnixListener,
    lock: InstanceLock,
) -> eyre::Result<Stopped>
where
    <T::Session as Session>::Write: Send + 'static,
    <T::Session as Session>::Read: Send + 'static,
{
    let source = resident.stop_source();
    let control = resident.serve(listener);
    // A service manager stops `serve` with SIGTERM (`brew services stop`, `systemctl --user stop`): it is
    // the same graceful stop as a ctrl-c, so the socket goes with the process.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .wrap_err("could not watch for SIGTERM")?;
    let stopped = tokio::select! {
        result = exposer.run(node, cancel.clone()) => {
            result?;
            lock.release();
            classify_stop(source.first())
        }
        output = control => {
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
        _ = terminate.recv() => {
            source.note(StopKind::Interrupted);
            cancel.cancel();
            lock.release();
            classify_stop(source.first())
        }
    };
    Ok(stopped)
}

/// The `serving:` line's body: each served name in the order it was given, with who reaches it, and
/// " (as last time)" when the list was resumed. A name the run opened to anyone says so, which is how a
/// `--public` typed on a bare `serve` shows on screen. An internal `control.*` route is never listed.
fn serving_line(names: &[String], manifest: &[ManifestEntry], resumed: bool) -> String {
    let mut line = names
        .iter()
        .filter(|name| !name.starts_with("control."))
        .map(|name| {
            let open = manifest
                .iter()
                .any(|entry| entry.name == *name && entry.posture == Posture::Open);
            let who = if open { "anyone" } else { "your devices" };
            format!("{name} ({who})")
        })
        .collect::<Vec<_>>()
        .join(", ");
    if resumed {
        line.push_str(" (as last time)");
    }
    line
}

/// The banner, as ONE string printed once: this machine's key, what it serves, the transport block under
/// `--verbose`, the service-manager line where one applies, and how to stop.
fn render_banner(
    key: &str,
    serving: &str,
    transport: Option<&str>,
    keeper: Option<&str>,
    stop_line: &str,
) -> String {
    let mut out = format!("key: {key}\nserving: {serving}\n");
    if let Some(transport) = transport {
        out.push('\n');
        out.push_str(transport);
        out.push('\n');
    }
    if let Some(keeper) = keeper {
        out.push_str(keeper);
        out.push('\n');
    }
    out.push_str(stop_line);
    out.push('\n');
    out
}

/// Whether a service manager already runs this `serve`: systemd sets `INVOCATION_ID` or `JOURNAL_STREAM`,
/// and launchd sets `XPC_SERVICE_NAME` to something other than `0` (a Terminal session sets it to `0`).
fn supervised(var: impl Fn(&str) -> Option<OsString>) -> bool {
    var("INVOCATION_ID").is_some()
        || var("JOURNAL_STREAM").is_some()
        || var("XPC_SERVICE_NAME").is_some_and(|value| value != "0")
}

/// The line that says how to keep this machine serving after a reboot: printed only by a `serve` that no
/// service manager runs, started from a terminal. `keeper` is asked only then, since on macOS it runs
/// `brew --prefix`.
fn keeper_line(
    supervised: bool,
    stderr_terminal: bool,
    keeper: impl FnOnce() -> Keeper,
) -> Option<&'static str> {
    if supervised || !stderr_terminal {
        return None;
    }
    Some(keeper().line())
}

/// The service manager that keeps a `serve` running on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Keeper {
    /// Homebrew's, for a binary installed under `brew --prefix`.
    Brew,
    /// systemd's user manager, on Linux.
    Systemd,
    /// Anything else: the page that shows how.
    Elsewhere,
}

impl Keeper {
    /// The keeper for this machine and this binary.
    fn here() -> Self {
        if cfg!(target_os = "linux") {
            return Self::Systemd;
        }
        if cfg!(target_os = "macos") && under_brew() {
            return Self::Brew;
        }
        Self::Elsewhere
    }

    /// The line naming how to keep this machine serving after a reboot.
    fn line(self) -> &'static str {
        match self {
            Self::Brew => "to keep this machine serving after a reboot: brew services start swoosh",
            Self::Systemd => {
                "to keep this machine serving after a reboot: systemctl --user enable --now swoosh"
            }
            Self::Elsewhere => {
                "to keep this machine serving after a reboot: see docs/use-cases/run-at-login.md"
            }
        }
    }
}

/// Whether this binary sits under `brew --prefix`, the one install `brew services` can start.
fn under_brew() -> bool {
    let Ok(output) = std::process::Command::new("brew")
        .arg("--prefix")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let prefix = std::path::PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let prefix = std::fs::canonicalize(&prefix).unwrap_or(prefix);
    std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .is_ok_and(|exe| exe.starts_with(prefix))
}

/// When a `serve` first exchanges with your devices after it starts.
const FIRST_ROUND: Duration = Duration::from_secs(60);

/// How often a `serve` exchanges with your devices after its first round, give or take a tenth.
const EVERY_ROUND: Duration = Duration::from_secs(60 * 60);

/// Every `serve`'s own exchanges with your devices: 60 s after start, then hourly with a tenth of jitter
/// either way. Each round reads the standing, the pin, the standing's badge and `me` afresh, runs only on
/// a device of a root, and stops at the first device that gave this machine a newer update. When your
/// devices refuse this machine because its standing has ended or was revoked here, the round picks up its
/// renewal ([`swoosh::renewal`]) and, on a hit, exchanges again. It never returns; it ends when the run
/// beside it does.
async fn sync_rounds<T: Transport, D: Discovery>(node: &Node<T, D>, home: &Home) {
    use rand::Rng as _;

    let dial = swoosh::sync::NodeDial::new(node, home);
    let fetch = swoosh::renewal::NodeFetch::new(node);
    let mut wait = FIRST_ROUND;
    loop {
        tokio::time::sleep(wait).await;
        let devices = if swoosh::sync::is_device(home).await {
            swoosh::sync::devices(home, []).await
        } else {
            Ok(Vec::new())
        };
        match devices {
            Ok(devices) => {
                let round = || {
                    swoosh::sync::round(
                        &dial,
                        &devices,
                        swoosh::sync::Until::Newer,
                        swoosh::sync::EACH * 4,
                    )
                };
                let replies = round().await;
                tracing::debug!(asked = replies.len(), "a sync round finished");
                // Refused for a standing that needs a renewal: pick it up, then exchange again with it.
                if let PickUp::Took(renewed) =
                    swoosh::renewal::after_round(home, &fetch, &replies).await
                {
                    tracing::debug!(from = %renewed.from, "took a renewal");
                    let replies = round().await;
                    tracing::debug!(asked = replies.len(), "a sync round finished");
                }
            }
            Err(error) => tracing::debug!(%error, "no sync round: the devices could not be read"),
        }
        let jitter = rand::thread_rng().gen_range(0.9..=1.1);
        wait = EVERY_ROUND.mul_f64(jitter);
    }
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

#[cfg(test)]
#[path = "serve_tests.rs"]
mod serve_tests;
