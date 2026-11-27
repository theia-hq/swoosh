//! `swoosh serve [<service>...]`: be the one `serve` for this home. Publish the named services behind
//! this machine's gate, hold the home's control socket, then stay reachable so your devices, and anyone
//! you gave a link, reach them.
//!
//! Bare, it uses the saved services in `<home>/serve.toml`, or `ping` and `speed` if no list is saved.
//! `swoosh serve ssh ping` selects a shell and round-trip probe for this run without saving them.
//! `ssh`, `ping` and `speed` name themselves; other entries use `name=target`.
//!
//! `--with DEF` and `--without NAME` add to or omit from the saved services (or ping and speed) for this run.
//! Later saved service additions, removals and target changes do not change this process's selection.
//! Off changes affect new admissions; existing streams may continue. Each restart, including a
//! supervisor restart, captures the then-current saved/default selection again. Launch changes neither
//! saved services nor off settings.
//!
//! `--public`, `--public-unsafe`, `--admit` and `--expires` also apply only to this run. It drives
//! tightbeam's tunnel LIBRARY (`Exposer`) directly under swoosh's OWN persisted identity: the node binds
//! the same key `swoosh ssh` and a signed link root at, gates on the pin read live from swoosh's own
//! store and on the links this machine signed, and derives the ssh host seed from swoosh's secret, so an
//! `ssh` service presents the host key a client pins. swoosh assembles the whole route table itself
//! (`proxy`/`recv` instances, `ping`/`speed`, the update route, and `sshd` under the `ssh` feature),
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

use core::time::Duration;
use std::ffi::OsString;
use std::io::{IsTerminal as _, Write as _};

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use bifrost_mdns::{Dialable, Missing};
use clap::Args;
use eyre::WrapErr as _;
use nauthy::{Gate, Service};
use swoosh::contacts::ContactsStore;
use swoosh::gate::AnchorCut;
use swoosh::grants::LinksForAnother;
use swoosh::home::{Home, HomeWrite, ServeLock};
use swoosh::identity::Identity;
use swoosh::reaching::{BindRole, Reaching};
use swoosh::renewal::PickUp;
use swoosh::serve::{
    Activity, BoundTargets, InstanceLock, Internet, Lan, Network, ProxyScope, ReachSource,
    Reachable, RecvService, Resident, SingleError, Started, StopKind, StopSource, Stopped,
    acquire_single, bind_entry, bind_recv, classify_stop, control, extract_recv_services,
    refuse_recv_into_home,
};
use swoosh::serve_toml::{LiveServeToml, ServeToml};
use swoosh::standing::{Standing, StandingError};
use swoosh::transport::{MdnsState, Reach, ReachArgs, RelayHome, Resolver};
use tightbeam::duration::Lifetime;
use tightbeam::tunnel::{CancellationToken, Exposer, ManifestEntry, Posture, Router};

use crate::commands::service::Running;
use crate::commands::share;
use crate::commands::status::report::own_name;
use crate::screen::{Block, Cell, Paint, Screen, Style};

/// Be a node: publish these services behind your gate, then stay reachable.
#[derive(Debug, Args)]
pub struct ServeCmd {
    /// Serve exactly these for this run, without saving them
    // The long form lists every form both halves take: the services swoosh serves under their own names,
    // and the targets served under a name the person gives. A refusal from either half points here, so this
    // list is the one a mistyped form is sent to and it has to be complete.
    #[arg(
        value_name = "service",
        conflicts_with_all = ["with", "without"],
        long_help = "Serve exactly these for this run, without saving them\n\
                     With none named and no --with or --without, it serves the saved\n\
                     services, or ping and speed if none are saved.\n\
                     \n\
                     Built in, served under their own names:\n\
                     \x20 ssh                   a shell on this machine\n\
                     \x20 ping                  round-trip probe\n\
                     \x20 speed                 throughput test\n\
                     \x20 proxy:<url>           requests to one site, from this machine\n\
                     \x20 recv:<dir>            files sent here, to <dir>, else the inbox\n\
                     \n\
                     Under a name you give (web=tcp:localhost:3000):\n\
                     \x20 tcp:<address>:<port>  a TCP service this machine reaches\n\
                     \x20 unix:<path>           a Unix socket on this machine\n\
                     \x20 file:<path>           a file's bytes\n\
                     \x20 fifo:<path>           a named pipe, live\n\
                     \x20 stdin:                this process's stdin\n\
                     \x20 echo:                 sends back whatever it receives"
    )]
    pub services: Vec<String>,
    /// Also serve this service, for this run
    #[arg(
        long,
        value_name = "service",
        long_help = "Also serve this service, for this run\n\
                     Repeat or combine these flags; positional definitions cannot be\n\
                     used with them.\n\
                     \n\
                     Adding, removing or retargeting a saved service while this runs\n\
                     does not change what it serves.\n\
                     Turning one off does, for new connections; open ones may continue.\n\
                     Each start, including one a service manager makes, reads the saved\n\
                     or default services again.\n\
                     This flag changes neither the saved services nor any off setting."
    )]
    pub with: Vec<String>,
    /// Omit a saved/default service for this run
    #[arg(
        long,
        value_name = "service",
        long_help = "Omit a saved/default service for this run\n\
                     Repeat or combine these flags; positional definitions cannot be\n\
                     used with them.\n\
                     \n\
                     Saved changes made while this runs do not change what it serves;\n\
                     see --with."
    )]
    pub without: Vec<String>,
    /// Open these services to anyone, comma-separated
    #[arg(
        long,
        value_name = "service",
        value_delimiter = ',',
        value_parser = swoosh::names::service,
        long_help = "Open these services to anyone, comma-separated\n\
                     ssh and recv are never opened to anyone.\n\
                     A raw stream needs --public-unsafe."
    )]
    pub public: Vec<Service>,
    /// Open these raw streams to anyone
    // A raw stream opens only through this flag, and only when named: no bang suffix, no whole-node form.
    #[arg(
        long,
        value_name = "service",
        value_delimiter = ',',
        value_parser = swoosh::names::service,
        long_help = "Open these raw streams to anyone\n\
                     A raw stream (file:, fifo: or stdin:) gives its bytes to whoever\n\
                     connects.\n\
                     The --public flag refuses it and points here."
    )]
    pub public_unsafe: Vec<Service>,
    /// suppress the readiness banner and activity lines
    // Hidden and read from `SWOOSH_QUIET`: no flow needs it, and a supervisor or an action sets it once.
    // It withholds stdout and the activity lines only; refusals, warnings and `Stopped by` still print.
    #[arg(
        long,
        env = "SWOOSH_QUIET",
        hide = true,
        value_parser = clap::builder::FalseyValueParser::new()
    )]
    pub quiet: bool,
    /// Serve for this long, then stop (30m, 2h, 1d)
    #[arg(long, value_name = "d")]
    pub expires: Option<Lifetime>,
    /// Admit another root's devices, for this run
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
    /// uniform; the `reach` block reports what started rather than assuming it.
    #[arg(skip)]
    pub mdns: Option<MdnsState>,
    /// The relay and the resolver this bind actually leaned on, attached by the composition root after
    /// it composed them from the flags and the home files. Not a flag: clap skips it, and the root fills
    /// it in via [`with_bound_reach`](Self::with_bound_reach) alongside [`mdns`](Self::mdns). The
    /// default is n0's on both halves, which is what a bind that has no relay or resolver of its own
    /// (`--local`) leans on, so an un-attached value still logs the truth.
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
    /// The first file read supplies saved/default services for a bare start, plus relay and resolver
    /// settings; explicit constructors supply invocation-selected services.
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

/// The refusal for a machine's key typed to `--admit`, through the usage frame so the key is not echoed.
pub const ADMIT_TAKES_A_ROOT: &str = "--admit takes a root key, not a machine's key";

/// The usage line a refused `serve` claim exits 2 with, when it is a usage error: typed services that cannot
/// be one list, or a reserved word in a service slot, typed or in `serve.toml`. `None` for every other
/// refusal, which keeps its own exit.
pub fn usage_of(report: &eyre::Report) -> Option<String> {
    if let Some(mistyped) = report.downcast_ref::<swoosh::serve::Mistyped>() {
        return Some(mistyped.to_string());
    }
    if let Some(serving) = report.downcast_ref::<swoosh::serve::ServingError>() {
        return serving.reserved().map(|_| serving.to_string());
    }
    match report.downcast_ref::<swoosh::serve_toml::ServeTomlError>()? {
        reserved @ swoosh::serve_toml::ServeTomlError::Reserved { .. } => {
            Some(reserved.to_string())
        }
        _ => None,
    }
}

/// A key with no `root:` typed to `--admit`: a machine's, which the parse refuses with
/// [`ADMIT_TAKES_A_ROOT`] instead of clap's frame, which would echo the key.
#[derive(Debug, thiserror::Error)]
#[error("{ADMIT_TAKES_A_ROOT}")]
pub struct MachineAdmitted;

/// `--admit`'s root key, typed `root:ed01…` and only so: a bare key is a machine's, and admitting one
/// machine's devices means nothing.
fn admitted_root(text: &str) -> Result<NodeId, Box<dyn core::error::Error + Send + Sync>> {
    match text.parse::<swoosh::root_key::RootKey>() {
        Ok(root) => Ok(root.key()),
        Err(swoosh::root_key::RootKeyError::NoPrefix) => Err(Box::new(MachineAdmitted)),
        Err(error) => Err(error.into()),
    }
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
}

impl ServeCmd {
    /// Serve on the composed `node`, over its `peers`: the one command that receives a node. It reads its
    /// OWN [`Claim`] and [`ExposeContext`], attached by the root before dispatch.
    pub async fn run<'n: 'p, 'p, T: Transport, D: Discovery>(
        mut self,
        node: &'n Node<T, D>,
        peers: &'p swoosh::peers::Peers<'n, T, D>,
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
        self.run_serve(node, peers, *claim, *expose).await
    }

    /// Capture this invocation's service selection from positional definitions or the saved/default base, applying relative flags when supplied.
    pub async fn claim(mut self, home: &Home) -> eyre::Result<Self> {
        // Typed services that cannot be one list are a usage error: refused before the lock, so it reads
        // the same whether or not a `serve` runs here.
        swoosh::serve::Mistyped::check(&self.services)?;
        let cwd = std::env::current_dir().wrap_err("could not read the current directory")?;
        self.normalize_services(&cwd)?;
        // Additions and exclusions are typed too, so their grammar is refused before the lock as well.
        Started::positional(&self.with, &cwd)?;
        Started::exclusions(&self.without)?;
        // A reserved word saved in `serve.toml` is refused here too, reading only, so its refusal creates no
        // lock and binds nothing; the load after the lock stays the authority for every other refusal.
        ServeToml::refuse_reserved(home, &cwd)?;
        let root = swoosh::home::runtime_root()?;
        let (lock, listener) = match acquire_single(home, &root).await {
            Ok(held) => held,
            Err(SingleError::AlreadyResident { pid }) => {
                let running = Running::ask(home).await;
                eyre::bail!("{}", self.running_refusal(pid, running.as_ref()));
            }
            Err(other) => return Err(eyre::Report::new(other)),
        };
        let serve_toml = LiveServeToml::load_at(home, &cwd)?;
        let started = if self.with.is_empty() && self.without.is_empty() {
            Started::of(&self.services, serve_toml.first_read(), &cwd)?
        } else {
            Started::relative(serve_toml.first_read(), &self.with, &self.without, &cwd)?
        };
        let mut requested = started.entries();
        // An engine that must never face an open gate, bound under a name whose live links were made for
        // something else, is said here, whether named now or resumed. Refusing the start would protect
        // nothing: the gate refuses each of those links when it is presented, and a refusal could hold a
        // name for as long as a lost `anyone` link lives. A ledger that cannot be read is not said here
        // either: the gate logs it when it is built, and admits no link this machine signed until it can.
        match LinksForAnother::in_home(home, requested.iter().map(String::as_str)) {
            Ok(Some(links)) => warn(&links),
            Ok(None) => {}
            Err(error) => tracing::debug!("could not check the services' links: {error:#}"),
        }
        // A receive service never saves into `$HOME`, the home, or above it, whether named now or resumed:
        // refused here, before anything binds or is written.
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

    // Refusal reporting needs normalized names before any runtime resource is acquired.
    pub(crate) fn normalize_services(
        &mut self,
        cwd: &std::path::Path,
    ) -> Result<(), swoosh::serve::ServingError> {
        self.services = Started::positional(&self.services, cwd)?.entries();
        Ok(())
    }

    /// The refusal a `serve` prints when one already runs for its home: which one and what it serves, then
    /// the one fix that fits what this run asked for, in order. A flag that changes how the node runs needs a
    /// stop first, and only a new run meets it, so it comes before the rest: the rerun's start then names any
    /// service it keeps off. A name it typed that the running one serves and has off is turned on with
    /// `service on`. Saving services prepares a later bare start; it does not change the running selection.
    fn running_refusal(&self, pid: u32, running: Option<&Running>) -> String {
        let mut out = format!("swoosh serve is already running here (pid {pid})");
        let serves = running
            .map(|running| running.serves.as_slice())
            .unwrap_or_default();
        if !serves.is_empty() {
            out.push_str(&format!("\n  It serves {}.", serves.join(", ")));
        }
        if running.is_some_and(Running::off_unknown) {
            out.push_str(
                "\n  It cannot read its serve.toml, so it refuses new connections to its services until it can.",
            );
        }
        let named = |entry: &String| entry.split_once('=').map(|(name, _)| name.to_owned());
        let off = self
            .services
            .iter()
            .filter_map(named)
            .find(|name| running.is_some_and(|running| running.has_off(name)));
        let new: Vec<(String, &str)> = self
            .services
            .iter()
            .filter_map(|entry| Some((named(entry)?, swoosh::serve::as_typed(entry))))
            .filter(|(name, _)| !serves.contains(name))
            .collect();
        if self.sets_how_it_runs() {
            out.push_str("\n  To change how it runs, stop it first:\n    swoosh stop");
        } else if let Some(name) = off {
            out.push_str(&format!(
                "\n  To turn {name} on:\n    swoosh service on {name}"
            ));
        } else if !new.is_empty() {
            let typed: Vec<&str> = new.iter().map(|(_, typed)| *typed).collect();
            out.push_str(&format!(
                "\n  To save services for a bare start:\n    swoosh service add {}",
                typed.join(" ")
            ));
        }
        out
    }

    /// Whether this run set a flag that changes how the node runs rather than what it serves: exposure,
    /// a lifetime, an admitted root, or anything about the bind.
    fn sets_how_it_runs(&self) -> bool {
        let reach = &self.reach;
        !self.with.is_empty()
            || !self.without.is_empty()
            || !self.public.is_empty()
            || !self.public_unsafe.is_empty()
            || self.expires.is_some()
            || self.admit.is_some()
            || reach.local
            || !reach.peer.is_empty()
            || reach.relay.is_some()
            || reach.resolver.is_some()
    }

    /// The first file read supplies saved/default services for a bare start, plus relay and resolver
    /// settings; explicit constructors supply invocation-selected services.
    pub fn first_read(&self) -> Option<&ServeToml> {
        self.claim
            .as_ref()
            .map(|claim| claim.serve_toml.first_read())
    }

    /// What this run binds under each of its names, from the services it starts with (receive services
    /// included), for its gate to check each link it signed against.
    ///
    /// # Errors
    ///
    /// The run was not claimed: there is no list to check against, and an empty one would admit every
    /// link, so this fails closed as [`admit`](Self::admit) does.
    pub fn bound_targets(&self) -> eyre::Result<BoundTargets> {
        let Some(claim) = self.claim.as_ref() else {
            eyre::bail!(
                "internal: serve builds its gate before it claimed its home (composition-root bug)"
            );
        };
        Ok(BoundTargets::of(
            claim.started.entries().iter().map(String::as_str),
        ))
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
    /// `reach` block and the bind's log report the discovery that started rather than one it assumed.
    pub fn with_mdns(mut self, mdns: MdnsState) -> Self {
        self.mdns = Some(mdns);
        self
    }

    /// Attach the [`Reach`] the composition root composed for this bind, so the bind's log names the
    /// relay this node offers and the resolver it publishes to rather than promising n0's. Called at the
    /// iroh arm only, beside [`with_mdns`](Self::with_mdns).
    pub fn with_bound_reach(mut self, bound_reach: Reach) -> Self {
        self.bound_reach = Box::new(bound_reach);
        self
    }
}

impl ServeCmd {
    /// Serve the services this run started with under swoosh's identity by driving the tunnel core
    /// directly: parse the services, assemble the route table (`proxy`/`recv` instances, `ping`/`speed`,
    /// the update route, and `sshd` under the `ssh` feature) behind the gate the composition root built,
    /// keep its captured service selection, print swoosh's banner, and run the exposer and the control socket with the
    /// live cut wired. A service stays gated unless `--public` opens it.
    async fn run_serve<'n: 'p, 'p, T: Transport, D: Discovery>(
        self,
        node: &'n Node<T, D>,
        peers: &'p swoosh::peers::Peers<'n, T, D>,
        claim: Claim,
        expose: ExposeContext,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let ExposeContext {
            host_seed,
            gate,
            cut,
            home,
        } = expose;
        // Each Open holds two descriptors for its life; a run that cannot raise the limit still serves,
        // with fewer Opens before the next is refused Busy.
        if let Err(error) = swoosh::serve::raise_open_files() {
            tracing::warn!(%error, "could not raise the open-file limit");
        }
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
        // read from every entry, before the proxy and receive services were pulled out.
        let names = started.names();
        // Every node answers its own `control.serve`, always, whatever else it serves: the node-lifecycle
        // control surface is part of being a node, not a service the operator opts into. It is MEMBER-only
        // (`.member_service` in `control::bind_serve`): the gate admits a family
        // badge or a service slip, and the route's access floor then refuses anything that is not a
        // whole-node member BEFORE any `Response::Ok`, so a delegate holding a `control.serve` slip cannot
        // stop the node.
        //
        // Pull each proxy service out of the requested set BEFORE the router binds it, and de-merge: every
        // `name=proxy:<url>` becomes its OWN handler instance holding ONLY its own origin scope. A public
        // proxy handler therefore physically holds only its own origins and cannot reach a gated proxy's
        // origins: the SSRF pivot is unrepresentable, not fail-closed-by-convention.
        let proxy = ProxyScope::extract(&mut requested)?;
        // The node's ONE teardown authority. The exposer owns it (it is what acts on the cancel); a local
        // `--expires` timer, the gated `control.serve` handler, and the local socket `Stop` each hold a
        // CLONE as the node-control capability: they may REQUEST the stop, never tear the node down
        // themselves.
        let cancel = CancellationToken::new();
        // How the node was asked to stop, noted by whichever path fires `cancel` first: the socket stop,
        // a Ctrl-C, or `control.serve` with the key that asked. Read once more at teardown, to say who.
        let stop_source = std::sync::Arc::new(StopSource::new());
        // The node BASE gate is the one the composition root built, the same in every standing. Opening
        // individual services is the separate `--public`/`--public-unsafe` overlay, never a node-wide value.
        let public = self.public.clone();
        let mut router = Router::new(gate);
        for entry in &requested {
            router = bind_entry(router, entry, host_seed, &public)?;
        }
        // The update, pick-up and root routes, on every `serve` whatever the standing. Bound by the node,
        // never by an entry, and dotted, so no typed name reaches them.
        let (bound, control::Watched { known, devices }) =
            control::bind_exchanges(router, &home).await?;
        router = bound;
        for scoped in proxy.services() {
            // One engine handler per proxy service, holding ONLY its own origin scope. Every scope names an
            // origin (`ProxyScope::extract` refuses one that does not), so each is the OPT-IN engine, which
            // applies the 16 MiB/30s responder bounds by construction.
            let name = scoped.name().parse()?;
            let scoped_fetch = ::fetch::ScopedFetch::new(scoped.allow().clone())
                .map_err(|error| eyre::eyre!(error))?;
            router = router.service(name, scoped_fetch)?;
        }
        // The node's activity renderer, or none at all under `--quiet`: with no renderer no engine gets a
        // sink, so quiet silences every activity line by construction.
        let activity = self.activity(std::io::stderr())?;
        for service in &recv {
            // One `Recv` instance per receive service, holding ONLY its own output dir: de-merged the SAME way
            // as proxy, at the claim, where each dir was checked and the inbox made.
            let name: Service = service.name().parse()?;
            router = bind_recv(router, name, service.out().to_owned(), activity.as_ref())?;
        }
        // Declare both open overlays from the operator's raw names. The proof runs at `.expose()` below,
        // before anything is recorded or a banner advertises a service it will not serve.
        router = router
            .public(public)
            .public_unsafe(self.public_unsafe.clone());
        // `control.serve` cuts the served catalog ONCE, here, after every other route and both overlays,
        // for its own list AND the control socket read to serve. It lists itself. A stop on it waits for
        // the first sync round, and is refused to a key the gate's own revocations now hold, so a device
        // revoked by that round cannot stop this machine on a stream it opened before the round ended.
        let (router, catalog, first_round) = control::bind_serve(
            router,
            cancel.clone(),
            std::sync::Arc::clone(&stop_source),
            &cut,
        )?;
        // The live oracle as it is: a remote stop's hold is `control.serve`'s own, read per request.
        let exposer = router
            .expose()?
            .with_enabled(enabled.clone())
            .with_live_cuts(cut);

        let home_lock = HomeWrite::take(&home).await?;
        ServeToml::update(&home_lock, &home, |file| {
            self.reach.keep_reach(file);
        })?;
        drop(home_lock);
        enabled.serving(&started);
        let off = enabled.off();
        for name in names.iter().filter(|name| off.contains(*name)) {
            off_lines(name).write(&mut std::io::stderr())?;
        }

        let Some(mdns) = self.mdns.as_ref() else {
            eyre::bail!(
                "internal: serve reached its banner without the mDNS state (composition-root bug)"
            );
        };
        // The control socket's reach is re-read from the bound sockets on every status request, so it
        // follows the host to a new network; what `--local` chose and what mDNS managed stay as bound.
        let reach = ReachSource::new(
            node.bound_sockets(),
            Internet::of(self.reach.local),
            Lan::of(mdns),
        );
        // What the `reach` block leaves out goes to the log once, at bind, quiet or not.
        log_bind(
            &Dialable::of(node.bound_sockets()),
            mdns,
            &self.bound_reach,
            self.reach.local,
        );
        // The banner reads the same source the status reply does, so the two screens cannot disagree.
        // Read here, before the resident takes the source, and also where an unreadable host first warns.
        let shown = reach.reachable();
        let addr = node.local_addr();
        let resident = std::sync::Arc::new(Resident::new(
            addr.node,
            reach,
            tightbeam::tunnel::ServiceCatalog::clone(&catalog),
            enabled.clone(),
            cancel.clone(),
            std::sync::Arc::clone(&stop_source),
        ));

        // The rounds and the renewal before an Open ride this run's own sessions, presenting this home's
        // standing as it reads at each open, never a slip.
        let own = swoosh::streams::OwnBind::new(
            peers,
            &home,
            addr.node,
            &swoosh::credential::Credential::Family { present: None },
        );
        let dial = swoosh::sync::SourceDial::new(&own, &home);
        let fetch = swoosh::renewal::SourceFetch::new(&own);
        // The renewal an Open waits for, and what answers Opens on the control socket. Built before the
        // banner, since drawing the epoch for its references can fail, and serve announces only what runs.
        let renewal = swoosh::renewal::OpenRenewal::new(&home, &fetch);
        let opener = swoosh::serve::Opener::new(peers, &renewal, &home, addr.node)?;

        if !self.quiet {
            let manifest = exposer.manifest();
            let rows = ReachRows::of(&shown, Scope::Banner);
            let until = self
                .expires
                .map(|lifetime| Until::from_now(lifetime.duration()));
            let reader = Reader::of(
                supervised(|name| std::env::var_os(name)),
                std::io::stdout().is_terminal(),
            );
            // Named as `status` names it, from the one source both read; with no name, no row.
            let name = own_name(&home, addr.node)
                .await
                .map(|name| format!("me/{name}"));
            let key = addr.node.to_string();
            let serving = Serving::of(&started, enabled.saved_services().as_ref(), &manifest);
            banner(
                if self.reach.local {
                    "swoosh is serving, on this network only"
                } else {
                    "swoosh is serving"
                },
                Head {
                    name: name.as_deref(),
                    key: &key,
                },
                &rows,
                &serving,
                Stop {
                    until: until.map(|until| until.to_string()),
                    reader,
                },
            )
            .write(&mut std::io::stdout())?;
        }

        // An `--expires` deadline is a LOCAL timer with no security surface: after it elapses it cancels the
        // node's teardown token, the same graceful stop a Ctrl-C or a remote `control.serve` stop gives. It is an
        // arm of the run, never a spawned task, so a run that stops first takes the timer with it.
        let expiry = expire(self.expires, cancel.clone());
        // Run until a stop, distinguishing a GRACEFUL stop from an ERRORED teardown: a requested stop is
        // SUCCESS (exit 0, so a CI action reads a clean teardown as green); only a genuine error exits
        // non-zero. Beside the run, this node's own exchanges with your devices: they end when the run does.
        let stopped = tokio::select! {
            stopped = run_until_stopped(exposer, node, cancel, resident, listener, lock, &opener) => stopped?,
            never = expiry => match never {},
            () = sync_rounds(&home, &dial, &fetch, first_round) => unreachable!("the rounds run until the node stops"),
            () = known.watch() => unreachable!("the pick-up route's keys are read until the node stops"),
            () = devices.watch() => unreachable!("the root route's keys are read until the node stops"),
            () = enabled.watch(|waiting| {
                // One write for every warning, so a line logged beside them cannot land inside one.
                let _ = std::io::stderr().write_all(waiting_warnings(waiting, &std::io::stderr()).as_bytes());
                let changed: Vec<String> = waiting.added.iter().chain(&waiting.changed).cloned().collect();
                match LinksForAnother::among_changed(&home, &enabled.held(), &changed) {
                    Ok(Some(links)) => warn(&links),
                    Ok(None) => {}
                    Err(error) => tracing::warn!("could not check the added services: {error:#}"),
                }
            }) => {
                unreachable!("serve.toml is checked until the node stops")
            }
        };
        // One of your devices stopped it over `control.serve`: say which, on stderr and under `--quiet` too,
        // since any of them may stop any other and this line is the trail. Named from the book as it reads
        // now, not as it read at start, so a device that joined since is named; a book that does not read
        // leaves the whole key, never a failed stop.
        if let Some(StopKind::Wire(key)) = stop_source.first() {
            let contacts = match ContactsStore::open(&home).await {
                Ok(store) => store.contacts().clone(),
                Err(error) => {
                    tracing::debug!(%error, "could not read the book to name who stopped this node");
                    swoosh::contacts::Contacts::default()
                }
            };
            eprintln!("{}", control::stopped_by(&contacts, key));
        }
        // The teardown line is best-effort: a piped consumer may have already closed stdout by the time
        // the node stops, so a broken-pipe write must NOT turn a clean stop into a panic. It is stdout, so
        // `--quiet` withholds it with the banner.
        if !self.quiet {
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
/// `control.serve` stop or a `--expires` deadline renders [`Stopped::Requested`], and a Ctrl-C records itself and
/// renders [`Stopped::Interrupted`], so the kinds never collapse into one.
async fn run_until_stopped<T: Transport, D: Discovery>(
    exposer: Exposer,
    node: &Node<T, D>,
    cancel: CancellationToken,
    resident: std::sync::Arc<Resident>,
    listener: std::os::unix::net::UnixListener,
    lock: InstanceLock,
    opens: &impl swoosh::serve::Opens,
) -> eyre::Result<Stopped>
where
    <T::Session as Session>::Write: Send + 'static,
    <T::Session as Session>::Read: Send + 'static,
{
    let source = resident.stop_source();
    let control = resident.serve(listener, opens);
    // A service manager stops `serve` with SIGTERM (`brew services stop`, `systemctl --user stop`): it is
    // the same graceful stop as a ctrl-c, so the socket goes with the process.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .wrap_err("could not watch for SIGTERM")?;
    let stopped = tokio::select! {
        () = exposer.run(node, cancel.clone()) => {
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

/// Cancel `cancel` once `lifetime` has elapsed, then wait forever; with no lifetime, only wait. It never
/// returns, so as an arm of the run's select it can never win it: the exposer still sees the cancel and
/// ends the run gracefully, and the stop is classified exactly as before. Dropping it before the deadline
/// drops the timer, so nothing of this run is left behind to fire later.
async fn expire(
    lifetime: Option<Lifetime>,
    cancel: CancellationToken,
) -> core::convert::Infallible {
    if let Some(lifetime) = lifetime {
        tokio::time::sleep(lifetime.duration()).await;
        cancel.cancel();
    }
    core::future::pending().await
}

fn service_pairs(entries: &[String]) -> impl Iterator<Item = (&str, &str)> {
    entries.iter().filter_map(|entry| entry.split_once('='))
}

/// The services this run binds beside the saved list, as the banner's `serving` block shows them.
struct Serving<'m> {
    selection: &'static str,
    /// This run's services, `name=target`.
    bound: Vec<String>,
    /// The saved list, when this home saved one.
    saved: Option<Vec<String>>,
    manifest: &'m [ManifestEntry],
}

impl<'m> Serving<'m> {
    fn of(started: &Started, saved: Option<&Started>, manifest: &'m [ManifestEntry]) -> Self {
        let selection = match started {
            Started::Named(_) => "this run only (not saved)",
            Started::Adjusted(_) => "saved services, adjusted for this run",
            Started::Resumed(_) => "saved services",
            Started::Default => "default services",
        };
        Self {
            selection,
            bound: started.entries(),
            // A home that never saved a list holds no saved services, so its defaults are never shown as
            // saved.
            saved: saved
                .filter(|saved| !matches!(saved, Started::Default))
                .map(Started::entries),
            manifest,
        }
    }

    /// Each bound service with its audience, a saved target that differs right under it, then the saved
    /// services this run does not bind.
    fn block(&self) -> Block<'_> {
        use std::collections::BTreeMap;

        let bound: BTreeMap<_, _> = service_pairs(&self.bound).collect();
        let saved: Option<BTreeMap<_, _>> = self
            .saved
            .as_ref()
            .map(|entries| service_pairs(entries).collect());
        let saved_for_bare = |name, target| {
            [
                Cell::Token(name),
                Cell::Word("saved for bare start"),
                Cell::Token(target),
            ]
        };
        let mut block =
            Block::titled("serving").row([Cell::Word("selection"), Cell::Word(self.selection)]);
        for (name, target) in service_pairs(&self.bound) {
            let open = self
                .manifest
                .iter()
                .any(|entry| entry.name == name && entry.posture == Posture::Open);
            let audience = if open {
                Cell::Risk("anyone")
            } else {
                Cell::Word("your devices")
            };
            block = block.row([Cell::Token(name), audience, Cell::Token(target)]);
            if let Some(saved) = saved
                .as_ref()
                .and_then(|saved| saved.get(name))
                .filter(|saved| **saved != target)
            {
                block = block.row(saved_for_bare(name, saved));
            }
        }
        for (name, target) in self
            .saved
            .iter()
            .flat_map(|entries| service_pairs(entries))
            .filter(|(name, _)| !bound.contains_key(name))
        {
            block = block.row(saved_for_bare(name, target));
        }
        if saved.as_ref().is_some_and(|saved| *saved != bound) {
            block = block.row([
                Cell::Word("saved services"),
                Cell::Word("apply to the next bare or --with/--without serve"),
            ]);
        }
        if bound.is_empty() {
            block = block
                .text("Serving nothing.".to_owned())
                .text("To save a service for a bare start:".to_owned())
                .command("swoosh service add <service>".to_owned());
        }
        block
    }
}

/// `warning: <fact>` on stderr, in one write, its head styled where stderr shows style. A closed stderr
/// is no reason to stop serving, so a failed write is dropped.
fn warn(fact: &impl core::fmt::Display) {
    let mut err = std::io::stderr();
    let head = Style::WARNING.paint("warning:", &err);
    let _ = err.write_all(format!("{head} {fact}\n").as_bytes());
}

/// Account for the diagnostic prefix here, not in the library's unprefixed description. Each `warning:`
/// is styled where `on` shows style; the width counts only its letters.
fn waiting_warnings(waiting: &swoosh::serve_toml::Waiting, on: &impl Paint) -> String {
    let mut out = String::new();
    for fact in waiting.to_string().lines() {
        out.push_str(&Style::WARNING.paint("warning:", on).to_string());
        let mut column = "warning:".len();
        for word in fact.split_ascii_whitespace() {
            // Validated service names contain no whitespace, so each name remains one whole token.
            if column + 1 + word.len() > 80 {
                out.push_str("\n ");
                column = 1;
            }
            out.push(' ');
            out.push_str(word);
            column += 1 + word.len();
        }
        out.push('\n');
    }
    out
}

/// Keep off notices, including under quiet: temporary selection does not imply enabled service.
fn off_lines(name: &str) -> Screen<'static> {
    Screen::default().block(
        Block::default()
            .text(format!("{name} is off."))
            .text("To turn it on:".to_owned())
            .command(format!("swoosh service on {name}")),
    )
}

/// The banner: its title, this machine's name and key, how peers reach it, what it serves, then when it
/// stops and how to stop it.
fn banner<'a>(
    title: &'static str,
    head: Head<'a>,
    reach: &'a ReachRows,
    serving: &'a Serving<'_>,
    stop: Stop,
) -> Screen<'a> {
    Screen::default()
        .block(Block::titled(title))
        .block(head.block())
        .block(reach.block("reach"))
        .block(serving.block())
        .block(stop.block())
}

/// The banner's head: this machine's name among your devices, when it has one, then its key.
struct Head<'a> {
    /// `me/<name>`, from the one source `status` reads; `None` drops the row.
    name: Option<&'a str>,
    key: &'a str,
}

impl<'a> Head<'a> {
    fn block(&self) -> Block<'a> {
        let block = Block::default().column(17);
        let block = match self.name {
            Some(name) => block.row([Cell::Word("this machine"), Cell::Token(name)]),
            None => block,
        };
        block.row([Cell::Word("key"), Cell::Token(self.key)])
    }
}

/// The banner's closing block: when an `--expires` run stops, then how a person stops it.
struct Stop {
    /// `Serving until ...`, for an `--expires` run.
    until: Option<String>,
    reader: Reader,
}

impl Stop {
    fn block(self) -> Block<'static> {
        let block = self
            .until
            .into_iter()
            .fold(Block::default(), |block, line| block.text(line));
        match self.reader {
            Reader::Person => block.text("Press ctrl-c to stop.".to_owned()),
            Reader::Log => block,
        }
    }
}

/// Who reads the banner as it prints, which decides whether it says how to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reader {
    /// A person at the terminal on stdout, with no service manager running this `serve`: ctrl-c is theirs.
    Person,
    /// A pipe, a file, or a service manager's log: no key to press, so no line that says to.
    Log,
}

impl Reader {
    fn of(supervised: bool, stdout_terminal: bool) -> Self {
        if stdout_terminal && !supervised {
            Self::Person
        } else {
            Self::Log
        }
    }
}

/// When an `--expires` run stops, as its line prints: `Serving until 15:04 (1h 30m).` The end is the local
/// clock time within a day of now and the local date past it, as a link's end prints; the span is what
/// `--expires` took, in days, hours and minutes.
struct Until {
    /// The end, in seconds since the epoch.
    at: u64,
    left: Duration,
}

impl Until {
    /// `left` from now.
    fn from_now(left: Duration) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            at: now.saturating_add(left).as_secs(),
            left,
        }
    }

    /// The line, with the end in `local`, this machine's time zone, or as a date with no zone when the
    /// system cannot say.
    fn line(&self, local: Option<&libc::tm>) -> String {
        let end = match local {
            Some(local) => share::End {
                local,
                within_a_day: self.left <= share::DAY,
            }
            .to_string(),
            None => swoosh::root::Date(self.at).to_string(),
        };
        match span(self.left) {
            Some(span) => format!("Serving until {end} ({span})."),
            None => format!("Serving until {end}."),
        }
    }
}

impl core::fmt::Display for Until {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.line(share::local_time(self.at).as_ref()))
    }
}

/// A span as the `Serving until` line prints it: its two coarsest non-zero units of days, hours and
/// minutes (`1h 30m`, `90d`), with no seconds. `None` under a minute, which has no such span.
fn span(left: Duration) -> Option<String> {
    let mut secs = left.as_secs();
    let mut parts = Vec::new();
    for (unit, per) in [("d", 86_400), ("h", 3_600), ("m", 60)] {
        let n = secs / per;
        if n > 0 {
            parts.push(format!("{n}{unit}"));
            secs %= per;
        }
        if parts.len() == 2 {
            break;
        }
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// Which of the `reach` rows a screen shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// The banner's: `internet`, the address on this network, and the loopback address when this
    /// machine has no network address. A banner is pasted into logs and issues, so it
    /// never shows the public or tunnel address unless `--local` made an address the whole of its reach.
    Banner,
    /// Every class this machine has, as `status` lists them on the person's own terminal: the public,
    /// tunnel and loopback addresses too, the loopback one beside an `unknown` network as well.
    All,
}

/// The `reach` block's rows, from the one [`Reachable`] the banner and the status reply share: a fixed
/// label, then one value. An address is our own formatting of a `SocketAddr`, so it is a token that is
/// never styled and never split.
#[derive(Debug)]
pub(crate) struct ReachRows(Vec<(&'static str, Value)>);

/// One `reach` row's value.
#[derive(Debug)]
enum Value {
    /// Fixed words.
    Word(&'static str),
    /// An address, with its gloss when it has one.
    Address(String),
}

impl ReachRows {
    /// The rows `scope` shows of `reach`, in class order: internet, public, this network, tunnel, this
    /// computer.
    pub(crate) fn of(reach: &Reachable, scope: Scope) -> Self {
        // With no internet channel an address is the whole of how a peer reaches this machine, so a
        // `--local` banner shows every class, one row each.
        let every = scope == Scope::All || reach.internet == Internet::Off;
        let at = &reach.at;
        let internet = match reach.internet {
            Internet::On => "on",
            Internet::Off => "off (--local)",
        };
        let mut rows = vec![("internet", Value::Word(internet))];
        if every && let Some(public) = at.public() {
            rows.push(("public", Value::Address(public.to_string())));
        }
        match at.network() {
            Network::At(socket) => rows.push((
                "this network",
                Value::Address(match reach.lan {
                    Lan::Announced => socket.to_string(),
                    Lan::ByAddressOnly => format!("{socket}, by address only"),
                }),
            )),
            // The host could not read its addresses: the row stays, so the screen never reads offline
            // when the host only could not look. The cause is in the log.
            Network::Unknown => rows.push(("this network", Value::Word("unknown"))),
            Network::Nothing => {}
        }
        if every && let Some(tunnel) = at.tunnel() {
            rows.push(("tunnel", Value::Address(tunnel.to_string())));
        }
        // On the banner by default the loopback address shows only when this machine has no network
        // address, so the banner still names an address to reach it at; `status` and a `--local` banner
        // show every class. The banner never shows it beside `unknown`, where a pasted loopback row would
        // read as the one address the host has, when it only could not look; `status` lists every class
        // it has, so it shows it there too.
        let shows_computer = match at.network() {
            Network::Nothing => true,
            Network::At(_) => every,
            Network::Unknown => scope == Scope::All,
        };
        if shows_computer && let Some(computer) = at.computer() {
            rows.push(("this computer", Value::Address(computer.to_string())));
        }
        Self(rows)
    }

    /// The rows as a block under `title`, their values in column 17 as the head block's are.
    pub(crate) fn block(&self, title: &'static str) -> Block<'_> {
        self.0
            .iter()
            .fold(Block::titled(title).column(17), |block, (label, value)| {
                let value = match value {
                    Value::Word(words) => Cell::Word(words),
                    Value::Address(address) => Cell::Token(address),
                };
                block.row([Cell::Word(label), value])
            })
    }
}

/// Log, once at bind, what the `reach` block leaves out: the degraded causes at `warn` and the channels
/// at `debug`. Causes and class names only, never an address: a `warn` line reaches the journal of a
/// supervised run, and an address there is one the person never chose to show. An unreadable host is
/// not here; [`ReachSource::reachable`] logs it whenever it becomes so.
fn log_bind(dialable: &Dialable, mdns: &MdnsState, bound_reach: &Reach, local: bool) {
    match mdns {
        MdnsState::OnLan(_) | MdnsState::Blocked => {}
        MdnsState::LoopbackOnly => {
            tracing::warn!("mDNS on this host only; another host needs a direct address hint");
        }
        MdnsState::BrowseOnly(cause) => {
            tracing::warn!(%cause, "finding peers, not announcing you");
        }
    }
    match dialable.missing() {
        Missing::Flags => tracing::warn!("could not check for expiry"),
        Missing::Expiring(dropped) => {
            // A class whose every address is expiring has no address left to show.
            for class in dropped
                .classes()
                .filter(|class| !dialable.all().iter().any(|at| at.scope.class() == *class))
            {
                tracing::warn!(?class, "only expiring addresses reach this class");
            }
        }
        Missing::Nothing | Missing::Interfaces(_) => {}
    }
    if local {
        return;
    }
    // Which half is the person's own, never where it is: the URL is in their own flags and files.
    let resolver = match &bound_reach.resolver {
        Resolver::N0 => "n0's public discovery",
        Resolver::Custom(_) => "custom",
    };
    tracing::debug!(resolver, "your addresses, for anyone with your key");
    let relay = match &bound_reach.relay {
        RelayHome::N0 => "n0's public relays",
        RelayHome::Custom(_) => "custom",
    };
    tracing::debug!(relay, "the relay this machine offers");
}

/// `serve --help`'s closing lines: the page on starting `serve` at login, for this build's tag. The link
/// is alone on its line, an unbreakable token.
pub(crate) const AT_LOGIN: &str = concat!(
    "To start serving at login:\n  https://github.com/theia-hq/swoosh/blob/v",
    env!("CARGO_PKG_VERSION"),
    "/docs/use-cases/run-at-login.md"
);

/// Whether a service manager already runs this `serve`: systemd sets `INVOCATION_ID` or `JOURNAL_STREAM`,
/// and launchd sets `XPC_SERVICE_NAME` to something other than `0` (a Terminal session sets it to `0`).
fn supervised(var: impl Fn(&str) -> Option<OsString>) -> bool {
    var("INVOCATION_ID").is_some()
        || var("JOURNAL_STREAM").is_some()
        || var("XPC_SERVICE_NAME").is_some_and(|value| value != "0")
}

/// How often a `serve` exchanges with your devices after its first round, give or take a tenth.
const EVERY_ROUND: Duration = Duration::from_secs(60 * 60);

/// Every `serve`'s own exchanges with your devices: one round at start, then hourly with a tenth of
/// jitter either way. The first round runs at once so a machine that was down folds a revocation before a
/// remote stop can reach it, and `first_round` hears when it has ended, whatever it found, which is what
/// lets a remote stop in. It never returns; it ends when the run beside it does.
async fn sync_rounds(
    home: &Home,
    dial: &impl swoosh::sync::Dial,
    fetch: &impl swoosh::renewal::Fetch,
    first_round: control::FirstRound,
) {
    use rand::Rng as _;

    // The first round asks every device. Stop at the first that hands over a newer list and a revoked
    // device asked first ends the round with a list from before its revocation, so the stop opens before
    // the device holding the revocation is asked.
    let asked = sync_round(home, dial, fetch, swoosh::sync::Until::Every).await;
    // The gate stats `revoked` at most once per debounce, so wait one out: any admission after this either
    // stats afresh or reuses a stat taken after the round's fold was written, and sees a revocation the
    // round took before the stop opens. Any exchange can fold one, a fork passed on beside the same list
    // too; a round that asked no one folded nothing, and opens at once.
    if asked > 0 {
        tokio::time::sleep(nauthy::STAT_DEBOUNCE).await;
    }
    first_round.finished();
    loop {
        let jitter = rand::thread_rng().gen_range(0.9..=1.1);
        tokio::time::sleep(EVERY_ROUND.mul_f64(jitter)).await;
        sync_round(home, dial, fetch, swoosh::sync::Until::Newer).await;
    }
}

/// One round with your devices, stopping as `until` says. It reads the standing, the pin, the standing's
/// badge and `me` afresh, and asks only on a device of a root. When your devices refuse this machine
/// because its standing has ended or was revoked here, the round picks up its renewal
/// ([`swoosh::renewal`]) and, on a hit, exchanges again. Every outcome is logged and none is an error: a
/// device that is not reached now is asked at the next round. How many devices it asked, in both passes.
async fn sync_round(
    home: &Home,
    dial: &impl swoosh::sync::Dial,
    fetch: &impl swoosh::renewal::Fetch,
    until: swoosh::sync::Until,
) -> usize {
    let devices = if swoosh::sync::is_device(home).await {
        swoosh::sync::devices(home, []).await
    } else {
        Ok(Vec::new())
    };
    let devices = match devices {
        Ok(devices) => devices,
        Err(error) => {
            tracing::debug!(%error, "no sync round: the devices could not be read");
            return 0;
        }
    };
    let round = || swoosh::sync::round(dial, &devices, until, swoosh::sync::EACH * 4);
    let replies = round().await;
    tracing::debug!(asked = replies.len(), "a sync round finished");
    // Refused for a standing that needs a renewal: pick it up, then exchange again with it.
    let PickUp::Took(renewed) = swoosh::renewal::after_round(home, fetch, &replies).await else {
        return replies.len();
    };
    tracing::debug!(from = %renewed.from, "took a renewal");
    let again = round().await;
    tracing::debug!(asked = again.len(), "a sync round finished");
    replies.len() + again.len()
}

#[cfg(test)]
#[path = "serve_tests.rs"]
pub(crate) mod serve_tests;
