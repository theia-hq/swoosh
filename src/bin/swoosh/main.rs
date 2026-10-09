//! swoosh: work with a machine addressed by its public key, not its address.
//!
//! You give swoosh a peer's public key and it dials that peer directly, wherever the peer is on the
//! internet, across NATs, without you knowing the peer's address: no lookup, no account.
//! From that one connection swoosh does whatever you ask of the machine: today it stays reachable and
//! measures the link; as it grows, the same primitive carries files, tunnels, shared access, and
//! fetches. Under the hood every job is one cap-gated byte-stream to a key, behind a thin front door
//! per job, so the surface is broad while the core stays one thing.
//!
//! Today's verbs: `swoosh serve` prints this machine's key and stays reachable; `swoosh ping <peer>`
//! measures the round-trip time to a key; `swoosh speed <peer>` measures throughput; `swoosh status
//! <peer>` reports whether the link is direct or relayed; `swoosh contact add alice/laptop <key>` saves
//! a petname so `swoosh ping alice/laptop` works; `swoosh tree` prints the command tree. A peer is a raw key or
//! a saved petname, interchangeably.
//!
//! Each command runs under a key of its own. `serve` must be reachable at one address, so it persists a
//! key and keeps a stable address across runs (and across transports: `--transport iroh|quirk|quirk+noise`
//! swaps the backend without changing the key). The outward verbs only dial out, so they mint a throwaway
//! key each run unless you pin a home with `--home`/`SWOOSH_HOME` (the key then lives at `<home>/machine/key`).
//! The full verb arc (send, tunnel, share, fetch, run, cluster, MagicDNS names) is tracked in the README's
//! Roadmap; it ticks as it ships.

use std::path::PathBuf;

use bifrost::{Discovery, Node, Transport};
use clap::{CommandFactory, Parser, Subcommand};
use swoosh::contacts::{Contacts, ContactsStore};
use swoosh::home::Home;
use swoosh::identity::Identity;
use swoosh::reaching::{BindRole, Reaching};
use swoosh::transport::{MdnsState, PeerHint};
use swoosh::{credential, reaching, transport};

// The verb modules this binary dispatches to, each its own tree beside the composition root. The
// library (`swoosh::`) keeps only the node engine and the domain modules the verbs drive.
use crate::commands::{
    contact, forward, invite, join, leave, lock, ping, proxy, revoke, root, send, serve, service,
    share, speed, ssh, status, stop, sync, tree,
};

mod commands;

/// `--home`'s help line, naming the default home of the platform this binary was built for
/// ([`swoosh::home::Home::resolve`]).
#[cfg(target_os = "macos")]
const HOME_HELP: &str = "home (default ~/Library/Application Support/swoosh)";

/// `--home`'s help line, naming the default home of the platform this binary was built for
/// ([`swoosh::home::Home::resolve`]).
#[cfg(not(target_os = "macos"))]
const HOME_HELP: &str = "home (default ~/.local/state/swoosh; honors $XDG_STATE_HOME)";

#[derive(Debug, Parser)]
#[command(
    name = "swoosh",
    // Every usage line says `swoosh` whatever the program file is called (a release asset is
    // `swoosh-aarch64-macos`, a symlink may be `sw`): the docs teach `swoosh`, and the stop line's link
    // refusal reads `swoosh stop` in clap's usage to know the line was `stop`'s.
    bin_name = "swoosh",
    version,
    about = "Work with a machine addressed by its public key: reach it, measure it, and more.",
    // A bare `swoosh` is a mistake, not a default action: print the help on stderr and exit 2. This
    // must hold even with `SWOOSH_HOME` set, but an env-backed global `--home` counts as an arg to clap,
    // so `arg_required_else_help` would fall to a terse "subcommand required" line there instead of the
    // help. So the subcommand is `Option` and the no-verb case is handled in `run`, one behavior whether
    // or not the env var is set.
    arg_required_else_help = true
)]
struct Cli {
    // clap appends the `[env: SWOOSH_HOME]` annotation itself from `env` below, so the help must NOT
    // spell the env var again (doing so double-prints it). The default is a runtime path clap cannot
    // render, so the line names the one for the platform this binary was built for.
    #[arg(
        help = HOME_HELP,
        long = "home",
        id = "node-home",
        value_name = "dir",
        env = "SWOOSH_HOME",
        // Help names the variable, never its value: a home the user set is not printed back.
        hide_env_values = true,
        global = true
    )]
    home: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve services on this machine; peers you admit reach them.
    Serve(serve::ServeCmd),
    /// Stop swoosh serve here or on one of your own devices
    Stop(stop::StopCmd),
    /// Change what this machine serves
    #[command(subcommand)]
    Service(service::ServiceCmd),
    /// Measure the round-trip time to a peer, addressed by a petname or their public key.
    Ping(ping::PingCmd),
    /// Measure throughput to a peer: iperf, but over the overlay.
    Speed(speed::SpeedCmd),
    /// Show this machine: its key, lock, root, devices, contacts, links and services.
    ///
    /// `status <machine>` shows how you reach one.
    Status(status::StatusCmd),
    /// Forward a machine's service to a local port or stdout
    Forward(forward::ForwardCmd),
    /// Mint a local URL that reaches an origin through a machine you name.
    Proxy(proxy::ProxyCmd),
    /// Push a file or directory to a peer.
    #[command(name = "send")]
    Send(send::SendCmd),
    /// Bring your device list up to date with your other devices, both ways.
    Sync(sync::SyncCmd),
    /// Save or remove another person's key under a name.
    #[command(subcommand)]
    Contact(contact::ContactCmd),
    /// set, change or remove the lock on this machine's key
    Lock(lock::LockCmd),
    /// copy, restore or forget your root, or change its locks
    #[command(
        subcommand,
        subcommand_required = true,
        arg_required_else_help = true,
        after_help = "To end a root for good: swoosh revoke --help"
    )]
    Root(root::RootCmd),
    /// Add one of your devices, or renew it. Bare `invite` lists what is due.
    Invite(invite::InviteCmd),
    /// Make this machine one of your devices, from an invite.
    Join(join::JoinCmd),
    /// Stop being one of your devices. `--new-key` also gives this machine a new key.
    Leave(leave::LeaveCmd),
    /// Take back a link, a device, or everything you shared with a contact; or end a root for good.
    Revoke(revoke::RevokeCmd),
    /// Reach a peer's sshd over the overlay; runs the system ssh.
    Ssh(ssh::SshCmd),
    /// Make a link to a service for a person, a device, a key, or anyone
    Share(share::ShareCmd),
    /// Print this command tree (spec vs binary).
    Tree(tree::TreeCmd),
}

/// Declare the reaching verbs ONCE: the list below becomes both the [`Reach`] enum and its whole
/// [`Reaching`] impl, so a verb joins the reach family by adding one line rather than an arm in each of
/// five parallel matches. Five hand-written arm lists is the shape the retired `self_badge()` drifted in:
/// nothing keeps them in step but the author's eye, and a `_` wildcard in any one of them silently admits
/// a verb that never stated its auth need. Generated, the five cannot disagree, and a verb missing from the
/// list is a compile error at [`Command::split`] rather than a verb that reaches a gate carrying nothing.
///
/// Earned by that invariant, not by the keystrokes: the forwarding is mechanical, identical per arm, and
/// there is no way to express "these five matches share one arm list" in the type system, because
/// [`Reaching::run`] is generic over the transport and cannot be a `dyn` object.
macro_rules! reaching_verbs {
    ($($(#[$note:meta])* $verb:ident($cmd:ty)),+ $(,)?) => {
        /// A verb that reaches a peer: it binds a transport and dials. Split from the local `contact` group,
        /// which touches only the address book and never composes a transport.
        enum Outward {
            $($(#[$note])* $verb($cmd),)+
        }

        impl Reaching for Outward {
            /// The reach-family flags this verb carries (`--transport`, `--local`, `--peer`). Shared by every
            /// reaching verb and no local one, so they are flattened into each reach command rather than made
            /// a root global; the composition root reads them here to pick the backend, the bind mode, and
            /// the discovery seed.
            fn reach_args(&self) -> &transport::ReachArgs {
                match self {
                    $(Self::$verb(cmd) => cmd.reach_args(),)+
                }
            }

            /// The peer the selected verb dials, for the stale-list exchange beside it.
            fn dialed(&self) -> Option<&swoosh::peer::Peer> {
                match self {
                    $(Self::$verb(cmd) => cmd.dialed(),)+
                }
            }

            /// The identity this verb binds under. For the reach-outward verbs it derives from the bind
            /// role's credential (`Family -> PersistedIfPresent`), so identity and badge cannot disagree;
            /// `serve` declares `Persisted` explicitly, because a stable address is its whole job.
            fn identity(&self) -> Identity {
                match self {
                    $(Self::$verb(cmd) => cmd.identity(),)+
                }
            }

            /// What this verb's bind is for, and (when it dials) what it presents. Read BEFORE the bind,
            /// since it selects the iroh constructor: only `serve` publishes, so a short-lived command
            /// cannot overwrite the live record (0.9.0 F1), and only a dialing verb resolves slots.
            fn bind_role(&self) -> BindRole {
                match self {
                    $(Self::$verb(cmd) => cmd.bind_role(),)+
                }
            }

            /// Run the selected verb against the composed node with ONE uniform [`reaching::ReachCtx`], not
            /// a per-verb argument-threading match. Every verb is generic over `Node<T, D>`, so this stays
            /// transport-blind: the concrete transport was chosen once, at the seam below. A verb reads the
            /// ctx fields it needs and ignores the rest; `serve` reads its own attached
            /// [`serve::ExposeContext`] instead.
            async fn run<T: Transport, D: Discovery>(
                self,
                node: &Node<T, D>,
                ctx: reaching::ReachCtx<'_>,
            ) -> eyre::Result<()>
            where
                <T::Session as bifrost::Session>::Write: Send + 'static,
                <T::Session as bifrost::Session>::Read: Send + 'static,
            {
                match self {
                    $(Self::$verb(cmd) => cmd.run(node, ctx).await,)+
                }
            }
        }
    };
}

reaching_verbs! {
    Serve(serve::ServeCmd),
    Ping(ping::PingCmd),
    Speed(speed::SpeedCmd),
    Status(status::StatusCmd),
    Proxy(proxy::ProxyCmd),
    /// `swoosh forward`: the generic dial, any service, any local end. Presents a membership badge (like
    /// `ping`/`send`), which a link typed as the peer overrides, so it rides the reach path under the
    /// persisted identity when one exists.
    Forward(forward::ForwardCmd),
    /// `swoosh send`: push files to a peer's gated `recv:` service. Presents a membership badge (like
    /// `ping`/`speed`), so it rides the reach path under the persisted identity when one exists.
    Send(send::SendCmd),
    /// `swoosh stop me/<name>` for another of your devices, once resolved locally: reach its member-only
    /// `control.stop` and trigger a graceful stop. Presents this device's membership badge, so it rides the
    /// reach path under the persisted identity when one exists.
    Stop(stop::StopDevice),
    /// `swoosh sync`: exchange with every live device of your root. Presents this machine's standing and
    /// binds its own key, so each device's gate admits it as one of your devices.
    Sync(sync::SyncCmd),
    /// `swoosh invite <name> …`: a root act that syncs with your devices before it signs and offers them
    /// its cut after. Presents this machine's standing, like `sync`. A bare `invite` splits to a local read.
    Invite(invite::InviteCmd),
    /// `swoosh join`'s first exchange, with the machine that made the invite: it presents the standing the
    /// join just stored, under this machine's key.
    Join(join::JoinPull),
    /// `swoosh revoke me/<name>` with your root, once this machine's block is written: a root act that
    /// syncs with your devices before it signs and offers them its cut after, like `invite`.
    Revoke(revoke::RevokeRoot),
    /// `swoosh root restore <dir>`'s exchange, once the root is written: it presents the standing the
    /// restore just wrote, under this machine's key, to bring the restored root up to date.
    RootRestore(Box<root::restore::RestoreSync>),
}

impl Command {
    /// Split the parsed verb into the local `contact` group (no transport) or a reaching verb (binds
    /// one). The two paths diverge before any transport is composed, so `contact add` never spins up an
    /// endpoint it does not need.
    fn split(self) -> Verb {
        match self {
            Self::Contact(cmd) => Verb::Contact(cmd),
            Self::Lock(cmd) => Verb::Lock(cmd),
            Self::Root(cmd) => match cmd.split() {
                root::Split::Local(local) => Verb::Root(local),
                root::Split::Restore(restore) => Verb::RootRestore(Box::new(restore)),
            },
            // A bare `invite` lists what is due from the root's records and dials nothing; a named one is a
            // root act that syncs and offers, so it binds a transport.
            Self::Invite(cmd) => match cmd.name {
                Some(_) => Verb::Outward(Outward::Invite(cmd)),
                None => Verb::Invite(cmd),
            },
            Self::Join(cmd) => Verb::Join(cmd),
            Self::Leave(cmd) => Verb::Leave(cmd),
            Self::Revoke(cmd) => Verb::Revoke(cmd),
            Self::Ssh(cmd) => Verb::Ssh(cmd),
            Self::Tree(cmd) => Verb::Tree(cmd),
            Self::Share(cmd) => Verb::Share(cmd),
            Self::Forward(cmd) => Verb::Outward(Outward::Forward(cmd)),
            Self::Send(cmd) => Verb::Outward(Outward::Send(cmd)),
            Self::Sync(cmd) => Verb::Outward(Outward::Sync(cmd)),
            // `stop` resolves its machine against the list of your devices first, with no transport: only
            // another of your devices goes on to dial.
            Self::Stop(cmd) => Verb::Stop(cmd),
            // The `service` group: every leaf is a LOCAL file-write on `<home>/serve.toml`, so none composes a
            // transport.
            Self::Service(cmd) => Verb::Service(cmd),
            Self::Serve(cmd) => Verb::Outward(Outward::Serve(cmd)),
            Self::Ping(cmd) => Verb::Outward(Outward::Ping(cmd)),
            Self::Speed(cmd) => Verb::Outward(Outward::Speed(cmd)),
            // A bare `status` (no peer) reports THIS machine from its own files; with a peer it reaches out
            // and reports its path. Split here so the bare case never composes a transport.
            Self::Status(cmd) => match cmd.peer {
                Some(_) => Verb::Outward(Outward::Status(cmd)),
                None => Verb::Status(cmd),
            },
            Self::Proxy(cmd) => Verb::Outward(Outward::Proxy(cmd)),
        }
    }
}

/// The three kinds of verb, once split: purely local, a launcher, or reaching outward over a transport.
enum Verb {
    /// Edits the address book; needs no transport.
    Contact(contact::ContactCmd),
    /// Sets, changes or removes the passphrase on this machine's key; needs only the home.
    Lock(lock::LockCmd),
    /// `root backup`, `forget` or `lock`: needs only the home.
    Root(root::Local),
    /// `root restore`: checks, asks and writes locally, then exchanges as a reaching verb.
    RootRestore(Box<root::restore::RestoreCmd>),
    /// A bare `swoosh invite`: what is due, from the root's records; it binds no transport. With a name it is
    /// a reaching verb instead.
    Invite(invite::InviteCmd),
    /// Joins a root from an invite: checks and writes locally, then makes one exchange as a reaching verb.
    Join(join::JoinCmd),
    /// Leaves the root this machine trusts; needs only the home.
    Leave(leave::LeaveCmd),
    /// Takes back a link, a device, or what was shared with a contact: blocks here first, with no
    /// transport; a device's part that needs your root then runs as a reaching verb.
    Revoke(revoke::RevokeCmd),
    /// Reads the address book to resolve a peer, then execs the system `ssh` over the overlay. A launcher:
    /// it reaches a peer, but binds no transport of its own (tightbeam, run as ssh's `ProxyCommand`, does),
    /// so it dispatches beside the local verbs, off the store, before any transport is composed.
    Ssh(ssh::SshCmd),
    /// `swoosh service add|rm|on|off`: a LOCAL file-write on `<home>/serve.toml`, no transport.
    Service(service::ServiceCmd),
    /// `swoosh stop [me/<name>]`: resolves the machine against the list of your devices with no transport,
    /// and stops this machine over its control socket; another of your devices goes on as a reaching verb.
    Stop(stop::StopCmd),
    /// A bare `swoosh status` (no peer): this machine, read from its own files; it binds no transport.
    /// With a peer it is a reaching verb instead.
    Status(status::StatusCmd),
    /// Prints the command tree; needs no transport and no store.
    Tree(tree::TreeCmd),
    /// Makes a link with this machine's key, or a shorter copy of a link, wholly offline. Binds no
    /// transport.
    Share(share::ShareCmd),
    /// Reaches a peer; binds a transport.
    Outward(Outward),
}

impl Outward {
    /// Claim the home for a `serve` (a no-op for every other verb): its lock and control socket, and the
    /// services it starts with, taken before anything else is opened, written or bound.
    async fn claim(self, home: &Home) -> eyre::Result<Self> {
        match self {
            Self::Serve(cmd) => Ok(Self::Serve(cmd.claim(home).await?)),
            verb => Ok(verb),
        }
    }

    /// `<home>/serve.toml` as a claimed `serve`'s one watcher first read it; `None` for every other verb,
    /// which reads the file itself.
    fn serve_toml(&self) -> Option<&swoosh::serve_toml::ServeToml> {
        match self {
            Self::Serve(cmd) => cmd.first_read(),
            _ => None,
        }
    }

    /// Attach the resolved [`serve::ExposeContext`] to the `serve` verb (a no-op for every other verb, which
    /// carries no expose context), so `serve` reads its OWN context at run time. Called once in the root
    /// after the context is cut (while the secret is still live), before dispatch. This is why the reach
    /// [`ReachCtx`] stays uniform: the one verb that needs more than the shared context gets it on ITSELF
    /// here, not as an `Option` field threaded through every verb's dispatch.
    fn attach_expose(self, expose: Option<serve::ExposeContext>) -> Self {
        match (self, expose) {
            (Self::Serve(cmd), Some(expose)) => Self::Serve(cmd.with_expose(expose)),
            // A non-serve verb resolves `expose` to `None` (see `expose_context`), so there is nothing to
            // attach; a `serve` with no context is a root bug caught at its own `run`, not here.
            (reach, _) => reach,
        }
    }

    /// Attach the composed discovery's live [`MdnsState`] to the `serve` verb (a no-op for every other
    /// verb), so `serve`'s banner reports the discovery that started instead of assuming one. Called
    /// once per bind, at the seam that composed discovery, beside
    /// [`attach_expose`](Self::attach_expose); a `serve` that reaches its banner without one is a root
    /// bug caught there, not here.
    fn attach_mdns(self, mdns: MdnsState) -> Self {
        match self {
            Self::Serve(cmd) => Self::Serve(cmd.with_mdns(mdns)),
            reach => reach,
        }
    }

    /// Attach the composed [`transport::Reach`] to the `serve` verb (a no-op for every other verb), so
    /// its banner names the relay it offers and the resolver it publishes to instead of promising n0's.
    /// Called at the iroh arm only, beside [`attach_mdns`](Self::attach_mdns): every other bind leans on
    /// neither, and its banner says the same thing it always did.
    fn attach_bound_reach(self, bound: &transport::Reach) -> Self {
        match self {
            Self::Serve(cmd) => Self::Serve(cmd.with_bound_reach(transport::Reach::clone(bound))),
            verb => verb,
        }
    }

    /// The exposer context `serve` needs, resolved before the secret is consumed by the transport bind:
    /// swoosh's ssh host seed (derived from the secret), and the one gate `serve` runs in every standing
    /// with its live cut ([`swoosh::gate::anchored`]). All read from swoosh's OWN store, the node home.
    /// Every other verb returns `None`. Async because the gate's files are read from disk.
    ///
    /// The gate never treats this machine's own key as a root: with no pin it admits no member, and the
    /// own key admits only the links this machine recorded signing.
    async fn expose_context(
        &self,
        secret: &swoosh::identity::Secret,
        home: &Home,
    ) -> eyre::Result<Option<serve::ExposeContext>> {
        match self {
            // `serve` drives the gated exposer, so it resolves the exposer context; every other verb
            // returns `None`. Nothing is signed here (or anywhere in `serve`): an update it gives or
            // takes was signed by the root.
            Self::Serve(cmd) => {
                if let Some(root) = cmd.admit {
                    cmd.admit(home, secret.node_id(), root).await?;
                }
                let admitted = cmd
                    .admit
                    .map(|root| tightbeam::identity::AsVerifyKey::verify_key(&root))
                    .transpose()?;
                let (gate, cut) = swoosh::gate::anchored_admitting(
                    home,
                    secret.node_id(),
                    admitted,
                    cmd.bound_targets()?,
                )
                .await?;
                Ok(Some(serve::ExposeContext {
                    #[cfg(feature = "ssh")]
                    host_seed: secret.ssh_host_seed(),
                    #[cfg(not(feature = "ssh"))]
                    host_seed: [0u8; 32],
                    gate,
                    cut,
                    // The SAME home the root resolved once, so the serve and its control clients name
                    // the same paths.
                    home: home.clone(),
                }))
            }
            _ => Ok(None),
        }
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Print the error's message chain, not eyre's `Debug` form: returning `eyre::Result` from `main`
    // trails a source `Location:` (and a spantrace) that is noise to a user and reads as "go read our
    // source". `{:#}` renders the full `cause: cause` chain with no location; the backtrace stays behind
    // `RUST_BACKTRACE` for anyone debugging. See STYLE.md, Error handling.
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(report) => {
            eprintln!("error: {report:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Parse `argv`. A `forward` missing only its local end is refused with [`forward::NO_LOCAL_END`], which says
/// what `-` means where clap's own required-argument line shows only the metavar; a `stop` given more than
/// one machine is refused with [`stop::ONE_MACHINE`], and one given a link or a path with
/// [`stop::A_LINK_STOPS_NOTHING`]. Every other error is clap's own. Refused here, at parse, so nothing is
/// read, opened or bound first, the home included.
fn parse_from<I, T>(argv: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString>,
{
    let argv: Vec<std::ffi::OsString> = argv.into_iter().map(Into::into).collect();
    match Cli::try_parse_from(&argv) {
        Err(error) if error.kind() == clap::error::ErrorKind::MissingRequiredArgument => {
            // The model again with only `forward`'s local end optional: a line it accepts was missing that
            // slot and nothing else. A line it refuses too was missing something else, and clap's own
            // error stands.
            let lenient = Cli::command().mut_subcommand("forward", |forward| {
                forward.mut_arg(forward::LOCAL_END, |end| end.required(false))
            });
            match lenient.try_get_matches_from(&argv) {
                Ok(_) => Err(usage(&["forward"], forward::NO_LOCAL_END)),
                Err(_) => Err(error),
            }
        }
        Err(error) if error.kind() == clap::error::ErrorKind::UnknownArgument => {
            // The model again with `stop` taking any number of plain words: a line it accepts was refused
            // only for its extra machines. A line it refuses too stays clap's own error, unless the
            // argument clap names is a link typed as a second machine: refused with the fixed line
            // instead, so its token is never printed back.
            let lenient = Cli::command().mut_subcommand("stop", |stop| {
                stop.mut_arg(stop::MACHINE, |machine| {
                    machine
                        .num_args(1..)
                        .action(clap::ArgAction::Append)
                        .value_parser(clap::builder::NonEmptyStringValueParser::new())
                })
            });
            match lenient.try_get_matches_from(&argv) {
                Ok(_) => Err(usage(&["stop"], stop::ONE_MACHINE)),
                Err(_) if stop_link_unexpected(&error) => {
                    Err(usage(&["stop"], stop::A_LINK_STOPS_NOTHING))
                }
                Err(_) => Err(error),
            }
        }
        // A link or a path where `stop`'s machine goes, refused here with no echo of what was typed, so a
        // pasted link's token is never printed back.
        Ok(Cli {
            command:
                Some(Command::Stop(stop::StopCmd {
                    machine: Some(stop::Aim::Link),
                    ..
                })),
            ..
        }) => Err(usage(&["stop"], stop::A_LINK_STOPS_NOTHING)),
        parsed => parsed,
    }
}

/// Whether `error`, an unexpected argument, is a link or a path typed on a `stop` line: the argument clap
/// names sorts as a link, and the usage clap shows is `stop`'s. Read from clap's own error rather than argv,
/// so a path given to another flag (`--home ./x`) never reads as a machine.
fn stop_link_unexpected(error: &clap::Error) -> bool {
    use clap::error::{ContextKind, ContextValue};

    let Some(ContextValue::String(unexpected)) = error.get(ContextKind::InvalidArg) else {
        return false;
    };
    let Some(ContextValue::StyledStr(usage)) = error.get(ContextKind::Usage) else {
        return false;
    };
    usage.to_string().contains("swoosh stop")
        && matches!(stop::Aim::parse(unexpected), Ok(stop::Aim::Link))
}

/// Run a `service` leaf against `home`, exiting 2 on a usage error found once the line is parsed: a machine
/// or a second service typed to `on` or `off`, an entry with no name, or a name typed twice.
async fn run_service(cmd: service::ServiceCmd, home: &Home) -> eyre::Result<()> {
    use service::toggle::Way;

    let (leaf, done) = match cmd {
        service::ServiceCmd::Add(add) => ("add", add.run(home).await),
        service::ServiceCmd::Rm(rm) => ("rm", rm.run(home).await),
        service::ServiceCmd::On(on) => ("on", on.run(home, Way::On).await),
        service::ServiceCmd::Off(off) => ("off", off.run(home, Way::Off).await),
    };
    let Err(report) = done else {
        return Ok(());
    };
    match report.downcast_ref::<service::Usage>() {
        Some(service::Usage(usage)) => usage_error(&["service", leaf], usage),
        None => Err(report),
    }
}

/// Exit as clap does on a usage error of the command at `path` (`["root", "lock"]`): `error: <message>`, its
/// usage line, and exit 2. For a usage error found only once the verb runs, such as stdin that held no link.
fn usage_error(path: &[&str], message: &str) -> ! {
    usage(path, message).exit()
}

/// The usage error [`usage_error`] exits with: the command `path` names, walked one word at a time, so a
/// leaf prints its own usage and never its parent's. A word that names no subcommand stops the walk there.
fn usage(path: &[&str], message: &str) -> clap::Error {
    let mut command = Cli::command();
    // Built first, so each subcommand carries its full name (`swoosh root lock`) into its usage line.
    command.build();
    for word in path {
        match command.find_subcommand(word) {
            // A clone, on the way to an exit: a borrow taken in one arm would outlive the walk.
            Some(sub) => command = sub.clone(),
            None => break,
        }
    }
    command.error(clap::error::ErrorKind::InvalidValue, message)
}

/// The default `RUST_LOG` directive: ERROR everywhere. Activity lines do not ride the log at all (a
/// serving node renders them itself, and `--quiet` withholds them), so no target needs a raised default,
/// and a dependency's info events never reach a stock node's stderr.
const DEFAULT_LOG: &str = "error";

/// The subscriber filter: `RUST_LOG` when set, else the default directives. The ERROR default
/// directive still covers an empty or all-invalid `RUST_LOG`, where no directive parses. `parse_lossy`
/// never fails, so a malformed directive is ignored rather than aborting the binary.
fn log_filter(directives: Option<String>) -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::ERROR.into())
        .parse_lossy(directives.unwrap_or_else(|| DEFAULT_LOG.to_owned()))
}

/// The real entry point, split from `main` so a failure prints its clean message chain rather than
/// eyre's `Debug` form (see the note in `main`).
async fn run() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(log_filter(
            std::env::var(tracing_subscriber::EnvFilter::DEFAULT_ENV).ok(),
        ))
        // Diagnostics ride stderr, never stdout: stdout is a verb's product (`swoosh forward -` writes the
        // stream there) and the action's public log, so a log line must not interleave. The action holds
        // serve's stderr in a file and echoes it only on failure, redacted.
        .with_writer(std::io::stderr)
        .init();

    let cli = parse_from(std::env::args_os()).unwrap_or_else(|error| error.exit());

    // No verb given (a bare `swoosh`, even with `SWOOSH_HOME` set): a mistake, so the help goes to stderr
    // with exit 2, as clap's own `arg_required_else_help` does (stdout stays empty, no `error:` line).
    // See the note on `Cli` for why this is handled here rather than by that attribute alone.
    let Some(command) = cli.command else {
        eprint!("{}", Cli::command().render_help());
        std::process::exit(2);
    };
    let verb = command.split();

    // The node home, resolved ONCE from `--home`/`SWOOSH_HOME` (else the platform default): every
    // node path (identity key, signet, badge, contacts, denylist, ledger) derives from it, so a verb never
    // re-derives one and two verbs can never disagree on where the store is.
    let home = Home::resolve(cli.home)?;
    // Before any verb reads it: a trust file another user could have written is never loaded.
    home.check_trust_files()?;
    // And a key file others can read, this machine's or a root kept here, is refused with its own line,
    // never the key store's.
    home.check_key_file()?;

    // Local verbs run here, before any transport is composed and (for `tree`) before the store is even
    // opened: `tree` is pure introspection over clap's own model, and `contact` only edits the address
    // book. A reaching verb falls through to bind a transport below.
    let reach = match verb {
        Verb::Tree(cmd) => return cmd.run(&Cli::command()),
        // A bare `swoosh status` (no peer): this machine, from its own files. It never dials; with a
        // peer it is a reach verb.
        Verb::Status(cmd) => return cmd.run_local(&home).await,
        // `swoosh stop`: every shape the list of your devices refuses exits 2 here, before any transport
        // is composed, and this machine stops over its control socket. Only another of your devices binds.
        Verb::Stop(cmd) => match cmd.run_local(&home).await {
            Ok(Some(device)) => Outward::Stop(device),
            Ok(None) => return Ok(()),
            Err(report) => match report.downcast_ref::<stop::Usage>() {
                Some(usage) => usage_error(&["stop"], &usage.0),
                None => return Err(report),
            },
        },
        // `service add|rm|on|off`: LOCAL file-writes on `<home>/serve.toml`; `on` and `off` are honored live
        // by a running `serve` via the watched set its gate reads. Need only the home; bind no transport and
        // touch no store. A machine typed to `on` or `off`, or a name typed twice, exits 2 here.
        Verb::Service(cmd) => return run_service(cmd, &home).await,
        // Each `contact` verb opens the book itself, holding `home.lock` from its read to its save. A root
        // key given for a machine is found only once `contact add` runs, and exits 2, as clap's own do.
        Verb::Contact(cmd) => {
            return match cmd.run(&home).await {
                Err(report) => match report.downcast_ref::<contact::add::Usage>() {
                    Some(usage) => usage_error(&["contact", "add"], &usage.0),
                    None => Err(report),
                },
                done => done,
            };
        }
        // The passphrase on this machine's key, and the `root` leaves that need only the home: no store and
        // no transport, so they dispatch here beside the other local verbs.
        Verb::Lock(cmd) => return cmd.run(&home).await,
        Verb::Root(cmd) => {
            return match cmd.run(&home).await {
                Err(report) => match report.downcast_ref::<root::lock::Usage>() {
                    Some(usage) => usage_error(&["root", "lock"], &usage.0),
                    None => Err(report),
                },
                done => done,
            };
        }
        // `root restore`: every check, the passphrase and the writes are local and come first; only the
        // exchange that brings the restored root up to date binds a transport, under the key it wrote for.
        Verb::RootRestore(cmd) => {
            cmd.reach.reject_unused_reach()?;
            Outward::RootRestore(Box::new(cmd.run_local(&home).await?))
        }
        // A bare `swoosh invite`: what is due, read from the root's records with no lock and no prompt.
        Verb::Invite(cmd) => return cmd.run_due(&home).await,
        // Joins a root from an invite: every check and write is local; only the first exchange with the
        // machine that made the invite binds a transport, under the key the join may just have written. A
        // reach flag that exchange would never read is refused first, before the join writes anything.
        Verb::Join(cmd) => {
            cmd.reach.reject_unused_reach()?;
            match cmd.run_local(&home).await? {
                Some(from) => Outward::Join(join::JoinPull {
                    from,
                    reach: cmd.reach,
                }),
                None => return Ok(()),
            }
        }
        Verb::Leave(cmd) => return cmd.run(&home).await,
        // Revokes: the block and its lines are local and come first, before any transport is composed,
        // so nothing a bind does can delay or stop them. Only a device's part that your root publishes
        // goes on to bind, to sync and to offer the cut. A root's revoke runs whole here: it dials nobody.
        Verb::Revoke(cmd) => {
            cmd.reach.reject_unused_reach()?;
            match cmd
                .block(
                    &home,
                    std::io::stdin().lock(),
                    &mut swoosh::passphrase::Terminal,
                    &revoke::Undialed,
                    &mut std::io::stderr(),
                )
                .await
            {
                Ok(Some(publish)) => Outward::Revoke(revoke::RevokeRoot {
                    publish,
                    reach: cmd.reach,
                }),
                Ok(None) => return Ok(()),
                Err(report) => match report.downcast_ref::<revoke::Usage>() {
                    Some(usage) => usage_error(&["revoke"], &usage.0),
                    None => return Err(report),
                },
            }
        }
        // `share` signs with this machine's key and reads the address book to resolve who a link is for;
        // `share <link>` is wholly offline. Neither binds a transport, so it dispatches here beside the
        // local verbs. A usage error found once it runs (no recipient) exits 2, as clap's own do.
        Verb::Share(cmd) => {
            let done = cmd
                .run(
                    &home,
                    std::io::stdin().lock(),
                    &mut std::io::stdout(),
                    &mut std::io::stderr(),
                )
                .await;
            return match done {
                Err(report) => match report.downcast_ref::<share::Usage>() {
                    Some(usage) => usage_error(&["share"], &usage.0),
                    None => Err(report),
                },
                done => done,
            };
        }
        // A launcher: read the store to resolve the peer, then hand off to the system `ssh` (which runs
        // tightbeam as its `ProxyCommand`). swoosh binds no transport here; on unix `run` execs and does
        // not return on success.
        Verb::Ssh(cmd) => {
            let store = ContactsStore::open(&home).await?;
            return cmd.run(store.contacts(), &home);
        }
        Verb::Outward(outward) => {
            // Before anything is opened or minted: a flag the selected bind would never read is refused
            // here, not after the store is loaded and a key provisioned, so a refused
            // `serve --local --relay` on a fresh home leaves that home exactly as it found it.
            outward.reach_args().reject_unused_reach()?;
            // A `serve` takes its home's lock and control socket before anything is opened or bound, so a
            // second one for the home refuses leaving everything as the running one has it. Its typed
            // services that cannot be one list exit 2 first, as clap's own errors do.
            match outward.claim(&home).await {
                Ok(claimed) => claimed,
                Err(report) => match report.downcast_ref::<swoosh::serve::Mistyped>() {
                    Some(mistyped) => usage_error(&["serve"], &mistyped.to_string()),
                    None => return Err(report),
                },
            }
        }
    };

    // The address book lives in the node home, `<home>/contacts.toml`. A reach verb reads it to resolve a
    // petname in its peer slot.
    let store = ContactsStore::open(&home).await?;

    // The verb decides its identity: `serve` persists so it is reachable at one address, a reach-outward
    // verb binds the home's key where one exists (its badge roots there) and a throwaway where none does,
    // writing nothing. Resolve it before binding, since the secret is what the transport is bound under.
    // A serving node took `serve.lock` with its claim, before its key is read, so a key replacement can
    // never replace the key it is serving as.
    let secret = swoosh::identity::resolve(reach.identity(), &home).await?;
    let contacts = Contacts::clone(store.contacts());

    // The one and only place a concrete transport is named. Everything downstream speaks `bifrost`. The
    // same secret yields the same NodeId whether bound under iroh or quirk, which is what makes the
    // transport swap a swap and not a new node. The reach-family flags travel on the verb itself now, so
    // the backend and the dial hints are read off the chosen reaching verb, not a root global.
    let transport = reach.reach_args().transport;
    let local = reach.reach_args().local;
    // The verb's bind role, read BEFORE the bind selects a constructor: only a `Serving` verb publishes
    // the home key's address record, so a dial-only command never overwrites the live `serve` record
    // (0.9.0 F1). It carries the dialing verb's credential too, so the one read below answers both what
    // this bind publishes and what it presents. Read here, before `reach` is consumed by dispatch.
    let bind_role = reach.bind_role();
    let peers = reach.reach_args().peer.clone();
    // What this run bound, as ONE value: every consumer (a verb reporting its backend, a failed dial's
    // teaching line, `serve`'s banner) reads all three facts, so they travel together from here. The
    // relay and the resolver come from the flags and the home files, over the ONE bind that reads them
    // (the guard at the arm above refused the flags on every other), so a stale file can never refuse a
    // quirk or `--local` bind that would not have opened it.
    let bound = transport::Bound {
        transport,
        local,
        reach: match reach.reach_args().unused_reach_bind() {
            Some(_unused) => transport::Reach::default(),
            // A serving verb keeps the two servers it was pointed at in the home once its routes bind
            // (`serve`'s own write); a dialing verb's flag is this run only. Nothing is written here.
            // A `serve` binds over what its one watcher of `serve.toml` first read, when it claimed the
            // home: the same read its services came from.
            None => match reach.serve_toml() {
                Some(kept) => reach.reach_args().reach_over(kept),
                None => reach.reach_args().reach(&home).await?,
            },
        },
    };
    // Resolve the membership badge to present BEFORE the secret is consumed by the transport bind: a
    // device presents its STORED badge (bound to this key, which the dial then binds under, so the far
    // gate's device-binding matches), and a machine that is not a device presents none. The exposer
    // context (`serve`) is resolved before the bind too: its ssh host seed derives from the secret
    // before the bind consumes it.
    //
    // The SERVING verb resolves nothing: it is the gate, so it presents no credential and never mints or
    // loads a badge it would not send. There is no wildcard here and no "present nothing" credential for a
    // dialing verb to reach for: the role it declared decides, and only one of its arms carries slots.
    //
    // Only a verb that dials a peer of its own resolves slots. `sync`, `invite` and `join` dial your
    // devices themselves and present this home's standing on each exchange, so they resolve nothing
    // here: a standing that has passed its date must reach their exchange, whose refusal is what sends
    // them to the pick-up route.
    //
    // A verb that dials its own peer and presents this home's standing, when that standing has passed
    // its date or was revoked here, first tries the pick-up route at your own devices, once the node is
    // bound; its slots are resolved after that, so the standing it presents is the one it may just have
    // taken. An `anyone` link dials under a throwaway key, which must never reach your devices, and a
    // slip presents its own authority, so neither tries it.
    let own_peer = reach.dialed().is_some();
    let renew = match &bind_role {
        BindRole::Dialing(dial @ credential::Credential::Family { present: None })
            if own_peer && swoosh::renewal::is_due(&home, std::time::SystemTime::now()).await =>
        {
            Some(Renew {
                credential: credential::Credential::clone(dial),
                secret: &secret,
            })
        }
        BindRole::Serving | BindRole::Dialing(_) => None,
    };
    let (present, membership) = match (&bind_role, &renew) {
        (BindRole::Dialing(dial), None) if own_peer => {
            reaching::resolve(credential::Credential::clone(dial), &secret, &home)
                .await?
                .into_slots()
        }
        (BindRole::Serving | BindRole::Dialing(_), _) => (None, None),
    };
    let expose = reach.expose_context(&secret, &home).await?;
    // Attach the resolved exposer context to the `serve` verb (a no-op otherwise), so `serve` reads its OWN
    // context and every verb dispatches through the uniform `ReachCtx` below.
    let reach = reach.attach_expose(expose);
    // The one uniform context every verb runs against: the badge is already resolved, so the dispatch is
    // `cmd.run(node, ctx)` per verb, not a per-verb argument-threading match.
    let ctx = reaching::ReachCtx {
        contacts: &contacts,
        bound: &bound,
        present,
        membership,
        home: &home,
    };
    // Each transport bind borrows the seed through `with_bytes` and returns a future that holds only
    // what it derived, so the seed never leaves its wiping owner.
    match transport {
        // iroh self-discovers (n0 pkarr/DNS + relays) AND honors explicit hints: the composed
        // discovery feeds it the `--peer` addresses and any LAN peer heard over mDNS as direct
        // addresses, so a same-network dial goes straight there instead of relaying. With nothing
        // known locally the resolve is empty and iroh self-discovers exactly as before. The verb's bind
        // role picks the n0 constructor (serving publishes the address record, dialing does not);
        // `--local` keeps the same arm and swaps in the persisted key with no n0, no relays.
        transport::Transport::Iroh => {
            let endpoint = match IrohBind::of(local, &bind_role) {
                IrohBind::Reachable => {
                    secret
                        .with_bytes(|seed| {
                            bifrost_iroh::Endpoint::bind_reachable_with_secret_via(
                                seed,
                                transport::Reach::clone(&bound.reach),
                            )
                        })
                        .await?
                }
                IrohBind::Dialing => {
                    secret
                        .with_bytes(|seed| {
                            bifrost_iroh::Endpoint::bind_dialing_with_secret_via(
                                seed,
                                transport::Reach::clone(&bound.reach),
                            )
                        })
                        .await?
                }
                IrohBind::Local => {
                    secret
                        .with_bytes(bifrost_iroh::Endpoint::bind_local_with_secret)
                        .await?
                }
            };
            let composed = PeerHint::discovery(&endpoint, peers, &bind_role);
            let node = Node::new(endpoint, composed.discovery);
            let reach = reach.attach_bound_reach(&bound.reach);
            run_and_close(reach.attach_mdns(composed.mdns), &node, ctx, renew).await
        }
        // quirk is direct-only with no internal discovery, so the composed discovery is its only way
        // to learn a peer's address: the `--peer` hints, plus any peer heard over mDNS on the LAN.
        transport::Transport::Quirk => {
            let endpoint = secret
                .with_bytes(bifrost_quirk::Endpoint::bind_with_secret)
                .await?;
            let composed = PeerHint::discovery(&endpoint, peers, &bind_role);
            let node = Node::new(endpoint, composed.discovery);
            run_and_close(reach.attach_mdns(composed.mdns), &node, ctx, renew).await
        }
        // The sealed spelling: quirk under the wrapper, still one node under one key. The wrapper runs
        // its own Noise handshake over quirk's one stream and proves the peer's `NodeId`, so a
        // signet-rooted gate arms (where bare quirk refuses); both ends must spell `quirk+noise`, and a
        // bare quirk peer fails the wrapper tag with no fallback. One seed binds both layers, and
        // `Noise::new` refuses an inner bound under any other identity, so the two can never disagree.
        transport::Transport::QuirkNoise => {
            let endpoint = secret
                .with_bytes(bifrost_quirk::Endpoint::bind_with_secret)
                .await?;
            let endpoint = secret.with_bytes(|seed| bifrost_noise::Noise::new(endpoint, seed))?;
            let composed = PeerHint::discovery(&endpoint, peers, &bind_role);
            let node = Node::new(endpoint, composed.discovery);
            run_and_close(reach.attach_mdns(composed.mdns), &node, ctx, renew).await
        }
    }
}

/// Which iroh constructor the bind selects, the flags' one mechanism. A named choice instead of an
/// inline `if local`, so the composition root's match has an arm per mode with no wildcard to fall
/// through, and the mapping is a pure value a unit test can pin without binding a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IrohBind {
    /// The n0 default under a SERVING verb: discovery (pkarr/DNS) plus relays, and the address-record
    /// write peers resolve.
    Reachable,
    /// The n0 default under a DIALING verb: the same resolvers and relays, no publisher, so a
    /// short-lived command never overwrites the live `serve` record (0.9.0 F1).
    Dialing,
    /// `--local`: the persisted key with no n0 discovery, no relays, and no NAT traversal.
    Local,
}

impl IrohBind {
    /// Map the `--local` bit and the verb's [`BindRole`] to the constructor they select. `--local` wins:
    /// it removes n0 entirely, so there is no discovery to resolve and no record to write either way.
    fn of(local: bool, role: &BindRole) -> Self {
        if local {
            Self::Local
        } else {
            match role {
                BindRole::Serving => Self::Reachable,
                BindRole::Dialing(_) => Self::Dialing,
            }
        }
    }
}

/// The device a dialing verb's peer is, when this machine's list is stale and that peer is one of your
/// devices: the one to make the stale-list exchange with.
async fn stale_device(
    home: &Home,
    contacts: &Contacts,
    peer: &swoosh::peer::Peer,
) -> Option<bifrost::NodeId> {
    if !swoosh::sync::is_stale(home).await {
        return None;
    }
    let device = peer.candidates(contacts).ok()?.into_iter().next()?;
    swoosh::sync::is_own_device(home, device.node)
        .await
        .then_some(device.node)
}

/// Run a reaching verb, and beside it, from the moment it starts, the stale-list exchange with the device
/// it dials (through `dial`). The exchange never waits for the verb, never depends on it succeeding, and
/// ends with it: whatever the exchange has not finished when the verb returns is dropped, before the node
/// closes. It is never printed; a failure logs at debug.
async fn run_verb<T: Transport, D: Discovery>(
    outward: Outward,
    node: &Node<T, D>,
    ctx: reaching::ReachCtx<'_>,
    dial: &impl swoosh::sync::Dial,
) -> eyre::Result<()>
where
    <T::Session as bifrost::Session>::Write: Send + 'static,
    <T::Session as bifrost::Session>::Read: Send + 'static,
{
    // A dial under a throwaway key is none of your devices, so it makes no exchange.
    let device = match outward.dialed() {
        Some(peer) if outward.identity() != Identity::Ephemeral => {
            stale_device(ctx.home, ctx.contacts, peer).await
        }
        _ => None,
    };
    let verb = outward.run(node, ctx);
    let Some(device) = device else {
        return verb.await;
    };
    let exchange = swoosh::sync::once(dial, device);
    tokio::pin!(verb, exchange);
    tokio::select! {
        biased;
        _ = &mut exchange => verb.await,
        result = &mut verb => result,
    }
}

/// Run a reaching verb against the bound node, then CLOSE the node on the way out on EVERY path (a clean
/// return and an error alike). The composition root owns the node's lifetime, so teardown lives here in one
/// place for the whole reaching family: iroh's `Endpoint` logs a red "Aborting ungracefully" if it drops
/// without an awaited close, so a verb that binds iroh must close it before the node drops (quirk's close is
/// a no-op). One owner of teardown, so no verb re-implements it; `serve`'s own graceful-drain still returns
/// first, and this is the single close that follows it.
async fn run_and_close<T: Transport, D: Discovery>(
    outward: Outward,
    node: &Node<T, D>,
    mut ctx: reaching::ReachCtx<'_>,
    renew: Option<Renew<'_>>,
) -> eyre::Result<()>
where
    <T::Session as bifrost::Session>::Write: Send + 'static,
    <T::Session as bifrost::Session>::Read: Send + 'static,
{
    let home = ctx.home;
    let result = async {
        if let Some(renew) = renew {
            let fetch = swoosh::renewal::NodeFetch::new(node);
            reaching::renew_before_dial(home, &fetch, &mut std::io::stderr()).await;
            (ctx.present, ctx.membership) = reaching::resolve(renew.credential, renew.secret, home)
                .await?
                .into_slots();
        }
        run_verb(outward, node, ctx, &swoosh::sync::NodeDial::new(node, home)).await
    }
    .await;
    node.close().await;
    result
}

/// What a dialing verb that tries the pick-up route first resolves its slots from, after the try.
struct Renew<'a> {
    /// The credential the verb declared.
    credential: credential::Credential,
    /// The key the verb binds under.
    secret: &'a swoosh::identity::Secret,
}

// The CLI-surface proofs that drive a real verb (clap-parsed, exactly as the binary dispatches it):
// they live with the binary because they exercise its command types, and the library only sees the
// core those verbs call.
#[cfg(test)]
#[path = "bearer_dial_tests.rs"]
mod bearer_dial_tests;
#[cfg(test)]
#[path = "revoke_by_key_tests.rs"]
mod revoke_by_key_tests;
#[cfg(test)]
#[path = "signet_dial_verb_tests.rs"]
mod signet_dial_verb_tests;
#[cfg(test)]
#[path = "stale_exchange_tests.rs"]
mod stale_exchange_tests;

#[cfg(test)]
mod tests {
    use bifrost::NodeId;
    use clap::Parser;

    use super::*;

    /// One `share` makes and copies links: it is a top-level verb, and the `grant` group it replaced, with
    /// its `issue` and `narrow` leaves, resolves nowhere.
    #[test]
    fn share_is_the_one_verb_for_links() {
        let cli = Cli::try_parse_from(["swoosh", "share", "ssh", "anyone"]).expect("share parses");
        assert!(matches!(cli.command, Some(Command::Share(_))));
        for argv in [
            ["swoosh", "grant", "issue", "ssh"].as_slice(),
            ["swoosh", "grant", "narrow", "swoosh:x"].as_slice(),
            ["swoosh", "issue", "ssh"].as_slice(),
            ["swoosh", "narrow", "swoosh:x"].as_slice(),
        ] {
            assert!(Cli::try_parse_from(argv).is_err(), "{argv:?} resolves");
        }
    }

    /// I.2 (no aliases, one spelling per act): the five retired spellings do not resolve, and the
    /// canonical spelling of each act still does. The retired alias stays retired, pinned so a
    /// convenience alias cannot reappear unnoticed.
    #[test]
    fn retired_aliases_do_not_resolve() {
        for argv in [
            vec!["swoosh", "id"],
            vec!["swoosh", "service", "list"],
            vec!["swoosh", "service", "ls"],
            vec!["swoosh", "service", "enable", "ssh"],
            vec!["swoosh", "service", "disable", "ssh"],
            vec!["swoosh", "grant", "list"],
            vec!["swoosh", "contact", "list"],
            vec!["swoosh", "contact", "remove"],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_err(),
                "{argv:?} must not resolve: one spelling per act (I.2)"
            );
        }
        for argv in [
            vec!["swoosh", "status"],
            vec!["swoosh", "status", "--key"],
            vec!["swoosh", "service", "rm", "ssh"],
            vec!["swoosh", "contact", "rm", "alice"],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_ok(),
                "{argv:?} is the canonical spelling and must resolve"
            );
        }
    }

    /// The `tunnel` noun is retired: its two leaves are the flat top-level verbs `serve` (publish
    /// services) and `forward` (the generic dial). `swoosh tunnel ...` does not resolve; `serve` and
    /// `forward` do.
    #[test]
    fn tunnel_is_gone_and_serve_and_forward_are_flat() {
        let peer = NodeId::from_ed25519_secret(&[2u8; 32]).to_string();

        // The retired noun and both old paths are unknown commands.
        assert!(Cli::try_parse_from(["swoosh", "tunnel"]).is_err());
        assert!(Cli::try_parse_from(["swoosh", "tunnel", "expose", "ping=ping:"]).is_err());
        assert!(Cli::try_parse_from(["swoosh", "tunnel", "connect", &peer, "22"]).is_err());

        // `serve` is the primary publish verb: bare (default `ping` + `speed`) and with an
        // explicit service set.
        assert!(matches!(
            Cli::try_parse_from(["swoosh", "serve"])
                .expect("bare serve parses")
                .command,
            Some(Command::Serve(_))
        ));
        assert!(matches!(
            Cli::try_parse_from(["swoosh", "serve", "ssh=sshd:", "ping=ping:"])
                .expect("serve with services parses")
                .command,
            Some(Command::Serve(_))
        ));

        // `forward` is the flat generic dial; its local end is a port, `-` (stdout), or `unix:<path>`.
        for end in ["5432", "-", "unix:/run/x.sock"] {
            assert!(
                matches!(
                    Cli::try_parse_from(["swoosh", "forward", &peer, "web", end])
                        .expect("forward parses each local end")
                        .command,
                    Some(Command::Forward(_))
                ),
                "forward {end} parses to the forward verb"
            );
        }
        // A bare path or a source-only scheme is a hard parse error, never a silent misparse.
        for bad in ["/tmp/out", "fifo:/tmp/x", "0"] {
            assert!(
                Cli::try_parse_from(["swoosh", "forward", &peer, "web", bad]).is_err(),
                "forward {bad} must be rejected"
            );
        }
        // The local end is a positional: neither `--to` nor the retired `--stdio` boolean resolves.
        for flag in [["--to", "-"].as_slice(), ["--stdio"].as_slice()] {
            let mut argv = vec!["swoosh", "forward", peer.as_str(), "web"];
            argv.extend_from_slice(flag);
            assert!(
                Cli::try_parse_from(&argv).is_err(),
                "{argv:?} must not resolve"
            );
        }
    }

    /// `reach` is no command, not even a hidden alias: one spelling per act, and the act is `forward`.
    /// clap refuses it as an unknown subcommand, a usage error.
    #[test]
    fn reach_is_not_a_command() {
        let peer = NodeId::from_ed25519_secret(&[2u8; 32]).to_string();
        for argv in [
            vec!["swoosh", "reach"],
            vec!["swoosh", "reach", peer.as_str(), "web", "-"],
            vec!["swoosh", "reach", peer.as_str(), "web", "--to", "-"],
        ] {
            let error = Cli::try_parse_from(&argv).expect_err("reach is no command");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::InvalidSubcommand,
                "{argv:?}"
            );
            assert_eq!(error.exit_code(), 2, "{argv:?}");
        }
        assert!(
            Cli::command().find_subcommand("reach").is_none(),
            "no subcommand, visible or hidden, is named reach"
        );
    }

    /// `fetch` is no command either: its act is `proxy`, with the machine first.
    #[test]
    fn fetch_is_not_a_command_and_proxy_takes_the_machine_first() {
        let peer = NodeId::from_ed25519_secret(&[2u8; 32]).to_string();
        let error = Cli::try_parse_from(["swoosh", "fetch", "https://example.com", "--via", &peer])
            .expect_err("fetch is no command");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
        let Some(Command::Proxy(cmd)) =
            Cli::try_parse_from(["swoosh", "proxy", &peer, "https://example.com"])
                .expect("proxy parses")
                .command
        else {
            panic!("proxy parses to the proxy verb");
        };
        assert_eq!(cmd.url.as_str(), "https://example.com/");
        assert!(
            Cli::try_parse_from(["swoosh", "proxy", "https://example.com", "--via", &peer])
                .is_err(),
            "`--via` is gone: the machine is the first positional"
        );
    }

    /// The generic dial's slots, pinned: the SERVICE has no default, and the LOCAL END has none either.
    /// A `forward` with no local end is a usage error, exit 2, whose line names the three local ends and
    /// neither the machine nor the service, under forward's own usage line.
    ///
    /// Default the local end to `-` and the line parses instead: the bytes would silently go to the
    /// terminal, which is the default the surface rules out.
    #[test]
    fn forward_without_a_local_end_is_a_usage_error() {
        assert!(
            Cli::try_parse_from(["swoosh", "forward", "me/nas"]).is_err(),
            "the service slot is required: a dial with no service is clap's own error here"
        );
        assert!(
            Cli::try_parse_from(["swoosh", "forward", "me/nas", "--service", "db", "5432"])
                .is_err(),
            "the service is a positional, not a flag: `--service` is not a spelling of it"
        );
        // A line missing more than the local end keeps clap's own error, never the local-end line.
        let other = parse_from(["swoosh", "forward", "me/nas"])
            .expect_err("a forward with no service refuses");
        assert_eq!(
            other.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );

        let error = parse_from(["swoosh", "forward", "me/nas", "db"])
            .expect_err("a forward with no local end refuses at parse");
        assert_eq!(error.exit_code(), 2, "a usage error exits 2");
        let printed = error.to_string();
        assert!(
            printed.starts_with(
                "error: forward needs a local end: a port (5432), unix:<path>, or - for stdout\n"
            ),
            "the line names the three ends and nothing typed: {printed}"
        );
        assert!(
            printed.contains("Usage: swoosh forward"),
            "it prints forward's own usage line: {printed}"
        );
    }

    /// The `swoosh ssh` ProxyCommand ABI, which is the PUBLIC `forward` verb: ssh re-invokes
    /// `<self> forward <peer> <service> -`, so the exact line that carries an ssh session is one an
    /// operator can run by hand to debug a launch that fails.
    ///
    /// This is the PARSING half of that ABI; `ssh_argv`'s tests are the writing half. Every token the
    /// launcher may append rides one line, in the order it writes them: the global `--home`, then one
    /// `--peer <key>=<addr>` per hint. No link rides beside the peer: a link is given where the machine
    /// goes, or not at all.
    #[test]
    fn the_ssh_proxycommand_line_parses_as_a_public_forward() {
        let peer = NodeId::from_ed25519_secret(&[1u8; 32]).to_string();
        let hint = format!("{peer}=127.0.0.1:9000");
        let cli = Cli::try_parse_from([
            "swoosh", "forward", &peer, "ssh", "-", "--home", "/tmp/yah", "--peer", &hint,
        ])
        .expect("the ProxyCommand line parses as a forward");
        assert_eq!(cli.home, Some(PathBuf::from("/tmp/yah")));
        let Some(Command::Forward(cmd)) = cli.command else {
            panic!("the ProxyCommand line is a `forward`");
        };
        assert_eq!(cmd.service.as_str(), "ssh");
        assert_eq!(
            cmd.to,
            commands::connect::To::Stdout,
            "the bridge streams the single service over stdin/stdout"
        );
        assert_eq!(cmd.reach.peer.len(), 1, "each `--peer` hint rides verbatim");

        // The retired spellings are gone: a stale `swoosh ssh` launched from an older binary's config, or
        // a hand-typed guess, gets clap's unknown-subcommand error rather than a hidden verb.
        for retired in ["tunnel-connect", "reach"] {
            assert!(
                Cli::try_parse_from(["swoosh", retired, &peer, "ssh", "-"]).is_err(),
                "`{retired}` is no spelling of this act"
            );
        }
    }

    /// No verb takes `--present`: a link is given where the machine goes. Walked over the real command
    /// tree, hidden flags included, so a verb added later with the flag fails here.
    #[test]
    fn no_verb_has_a_present_flag() {
        fn walk(command: &clap::Command, path: &str, found: &mut Vec<String>) {
            for arg in command.get_arguments() {
                if arg.get_long() == Some("present") {
                    found.push(format!("{path} --present"));
                }
            }
            for sub in command.get_subcommands() {
                walk(sub, &format!("{path} {}", sub.get_name()), found);
            }
        }
        let mut found = Vec::new();
        let mut root = Cli::command();
        root.build();
        walk(&root, "swoosh", &mut found);
        assert!(
            found.is_empty(),
            "verbs that still take --present: {found:?}"
        );
        // And every `--help` reads the same: the word appears in none of them.
        for sub in root.get_subcommands_mut() {
            let help = sub.render_long_help().to_string();
            assert!(
                !help.contains("--present"),
                "`swoosh {}` --help names --present",
                sub.get_name()
            );
        }
    }

    /// No verb takes `--at` or `--on`: a machine is a positional. Walked over the real command tree, hidden
    /// flags included, so a verb added later with either flag fails here, and every `--help` is read too.
    #[test]
    fn no_verb_has_a_machine_flag() {
        fn walk(command: &clap::Command, path: &str, found: &mut Vec<String>) {
            for arg in command.get_arguments() {
                if let Some(long) = arg.get_long().filter(|long| ["at", "on"].contains(long)) {
                    found.push(format!("{path} --{long}"));
                }
            }
            for sub in command.get_subcommands() {
                walk(sub, &format!("{path} {}", sub.get_name()), found);
            }
        }
        let mut found = Vec::new();
        let mut root = Cli::command();
        root.build();
        walk(&root, "swoosh", &mut found);
        assert!(
            found.is_empty(),
            "verbs that take a machine flag: {found:?}"
        );
        fn helps(command: &mut clap::Command, path: &str, found: &mut Vec<String>) {
            let help = command.render_long_help().to_string();
            for flag in ["--at ", "--on "] {
                if help.contains(flag) {
                    found.push(format!("{path} names {flag}"));
                }
            }
            for sub in command.get_subcommands_mut() {
                let path = format!("{path} {}", sub.get_name());
                helps(sub, &path, found);
            }
        }
        helps(&mut root, "swoosh", &mut found);
        assert!(
            found.is_empty(),
            "help that names a machine flag: {found:?}"
        );
    }

    /// A `serve` asked for its gate before it claimed its home has no list of what it binds to check each
    /// link against, so it builds no gate rather than one that admits every link.
    #[tokio::test]
    async fn an_unclaimed_serve_builds_no_gate() {
        let dir = std::env::temp_dir().join(format!("swoosh-unclaimed-ctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create an empty config dir");
        let home = Home::resolve(Some(dir.clone())).expect("resolve an explicit home");
        let secret = swoosh::identity::Secret::ephemeral();
        let serve = match Cli::try_parse_from(["swoosh", "serve"])
            .expect("bare serve parses")
            .command
            .expect("serve is a command")
            .split()
        {
            Verb::Outward(outward) => outward,
            _ => panic!("serve splits to a reaching verb"),
        };
        let built = serve.expose_context(&secret, &home).await;
        let _ = std::fs::remove_dir_all(&dir);
        let Err(error) = built else {
            panic!("no gate before the claim");
        };
        assert!(
            error.to_string().contains("before it claimed its home"),
            "{error:#}"
        );
    }

    /// The gate `serve` builds refuses a pin to a root this home revoked, as if there were no pin, and
    /// fails to build at all over a `revoked` it cannot read, rather than serving as if nothing were
    /// revoked.
    #[tokio::test]
    async fn the_serve_gate_honors_the_homes_revoked_roots() {
        let dir = std::env::temp_dir().join(format!("swoosh-latch-ctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create an empty config dir");
        let home = Home::resolve(Some(dir.clone())).expect("resolve an explicit home");
        let secret = swoosh::identity::Secret::ephemeral();
        // The call `expose_context` makes for a claimed `serve`, which takes this machine's runtime
        // directory and so is not made here.
        let build = || {
            swoosh::gate::anchored(
                &home,
                secret.node_id(),
                swoosh::serve::BoundTargets::default(),
            )
        };
        let disabled = swoosh::testkit::TestRoot::seeded(41);
        let live = swoosh::testkit::TestRoot::seeded(42);
        let device = swoosh::testkit::TestNode::seeded(43).verify_key();
        let hour = nauthy::Request::expires_in(core::time::Duration::from_secs(3600));
        let service: nauthy::Service = "ssh".parse().expect("valid service");
        let admits = |gate: &nauthy::Gate, root: &swoosh::testkit::TestRoot| {
            matches!(
                gate.admit(
                    nauthy::ProvenPeer::from_handshake(device),
                    Some(&root.member_badge(device, hour).expect("mint")),
                    &service,
                ),
                nauthy::Decision::Admit
            )
        };
        swoosh::revoked::add(
            &swoosh::testkit::lock(),
            &home,
            [nauthy::Revocation::Key(disabled.verify_key())],
        )
        .expect("revoke a root");

        swoosh::config::write_signet(&swoosh::testkit::lock(), &home, disabled.node_id())
            .expect("pin the disabled root");
        let (built, _cut) = build().await.expect("the gate builds");
        assert!(
            !admits(&built, &disabled),
            "a pin to a disabled root admits none of its devices"
        );

        swoosh::config::write_signet(&swoosh::testkit::lock(), &home, live.node_id())
            .expect("pin a live root");
        let (built, _cut) = build().await.expect("the gate builds");
        assert!(admits(&built, &live), "a live pin admits its devices");

        std::fs::write(home.revoked(), "not a key\n").expect("corrupt the revocations");
        assert!(
            build().await.is_err(),
            "an unreadable revoked stops the serve rather than trusting every root"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A real `swoosh:` capability link, minted through the library so a parse test exercises the true
    /// boundary (a `Peer::Capability` arm), not a fake token a lenient parser would wave through.
    fn shown_link() -> String {
        let link = swoosh::testkit::TestNode::seeded(3)
            .fleet_slip(
                &"ssh".parse().expect("valid service"),
                swoosh::testkit::TestRoot::seeded(4).verify_key(),
                nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
            )
            .expect("mint a swoosh: link");
        swoosh::link::Link::from(link).to_string()
    }

    /// Every DIALING verb that may reach any machine takes a unified `<peer>`: a saved petname, a raw key,
    /// and a `swoosh:` link all parse in its peer slot, uniform across `ping`/`speed`/`status`/`forward`/
    /// `send`/`proxy`/`ssh`, each positionally. `stop` takes only your own devices, so it is not here.
    #[test]
    fn every_dialing_verb_takes_a_petname_a_key_and_a_link() {
        let key = NodeId::from_ed25519_secret(&[8u8; 32]).to_string();
        let link = shown_link();
        for peer in ["alice", key.as_str(), link.as_str()] {
            let cases: [&[&str]; 7] = [
                &["swoosh", "ping", peer],
                &["swoosh", "speed", peer],
                &["swoosh", "status", peer],
                &["swoosh", "forward", peer, "web", "5432"],
                &["swoosh", "send", "afile", peer],
                &["swoosh", "proxy", peer, "http://example.com/x"],
                &["swoosh", "ssh", peer],
            ];
            for argv in cases {
                assert!(
                    Cli::try_parse_from(argv).is_ok(),
                    "{argv:?} should accept the peer form {peer:?}"
                );
            }
        }
    }

    /// At the root, an ssh passthrough token can no longer swallow `--home`. After `--` everything is
    /// ssh's (including a literal `--home`); without the separator an ssh-shaped token is a parse error,
    /// so `swoosh ssh alice -p 2222 --home <dir>` can never silently dial the default home again.
    #[test]
    fn ssh_passthrough_args_do_not_swallow_root_flags() {
        let cli = Cli::try_parse_from([
            "swoosh",
            "--home",
            "/tmp/right",
            "ssh",
            "alice",
            "--",
            "-p",
            "2222",
            "--home",
            "/tmp/is-ssh-arg",
        ])
        .expect("the separated form parses");
        assert_eq!(cli.home, Some(PathBuf::from("/tmp/right")));
        let Some(Command::Ssh(cmd)) = cli.command else {
            panic!("ssh parses to the ssh verb");
        };
        assert_eq!(cmd.args, ["-p", "2222", "--home", "/tmp/is-ssh-arg"]);

        assert!(
            Cli::try_parse_from(["swoosh", "ssh", "alice", "-p", "2222", "--home", "/tmp/x"])
                .is_err(),
            "an ssh-shaped token before `--` must be a parse error, never a silent capture"
        );
    }

    /// The `--peer` HINT flag still parses, now under its de-collided clap id `peer-hint`, alongside a
    /// verb's positional `<peer>` with no clap id collision.
    #[test]
    fn the_peer_hint_flag_still_parses() {
        let key = NodeId::from_ed25519_secret(&[8u8; 32]).to_string();
        let cli = Cli::try_parse_from([
            "swoosh",
            "ping",
            "alice",
            "--peer",
            &format!("{key}=127.0.0.1:9000"),
        ])
        .expect("the --peer hint parses under its new id peer-hint");
        assert!(matches!(cli.command, Some(Command::Ping(_))));
    }

    /// The sealed quirk spelling resolves: `--transport quirk+noise` selects the wrapped composition
    /// under the same identity, while bare `quirk` stays its own choice (the profile enforcement, not
    /// the parser, refuses it a rooted gate). The label is what `ping`/`status` print and a failed dial
    /// names.
    #[test]
    fn the_sealed_quirk_transport_spelling_resolves() {
        let sealed = Cli::try_parse_from(["swoosh", "ping", "alice", "--transport", "quirk+noise"])
            .expect("the sealed quirk spelling parses");
        assert!(matches!(
            sealed.command,
            Some(Command::Ping(ping::PingCmd {
                reach: transport::ReachArgs {
                    transport: transport::Transport::QuirkNoise,
                    ..
                },
                ..
            }))
        ));
        assert_eq!(transport::Transport::QuirkNoise.name(), "quirk+noise");

        // The bare spelling is unchanged and a DIFFERENT choice: the enforcement refuses it a rooted
        // gate, it never silently resolves to the wrapper.
        let bare = Cli::try_parse_from(["swoosh", "ping", "alice", "--transport", "quirk"])
            .expect("the bare quirk spelling parses");
        assert!(matches!(
            bare.command,
            Some(Command::Ping(ping::PingCmd {
                reach: transport::ReachArgs {
                    transport: transport::Transport::Quirk,
                    ..
                },
                ..
            }))
        ));
        assert_ne!(
            transport::Transport::Quirk,
            transport::Transport::QuirkNoise
        );

        // The default remains iroh.
        let defaulted = Cli::try_parse_from(["swoosh", "ping", "alice"])
            .expect("a bare ping parses on the default transport");
        assert!(matches!(
            defaulted.command,
            Some(Command::Ping(ping::PingCmd {
                reach: transport::ReachArgs {
                    transport: transport::Transport::Iroh,
                    ..
                },
                ..
            }))
        ));
    }

    /// The `--local` flag is a reach-family bind knob: it parses on the reaching verbs (the dial half
    /// rides the same bind), nowhere else, and is accepted idempotently on the already-direct-only quirk
    /// spellings. Placement is the reach group's, not a root global's.
    #[test]
    fn the_local_flag_lives_on_the_reach_family_only() {
        let parsed = Cli::try_parse_from(["swoosh", "ping", "alice", "--local"])
            .expect("ping --local parses");
        assert!(matches!(
            parsed.command,
            Some(Command::Ping(ping::PingCmd {
                reach: transport::ReachArgs { local: true, .. },
                ..
            }))
        ));

        // Accepted idempotently on the direct-only quirk spellings: the flag states a bind property
        // quirk already has, so it is a no-op, never a conflict refusal.
        for quirk in ["quirk", "quirk+noise"] {
            let cli = Cli::try_parse_from(["swoosh", "serve", "--local", "--transport", quirk])
                .unwrap_or_else(|err| panic!("serve --local --transport {quirk} parses: {err}"));
            assert!(matches!(
                cli.command,
                Some(Command::Serve(serve::ServeCmd {
                    reach: transport::ReachArgs { local: true, .. },
                    ..
                }))
            ));
        }

        // Placement: the flag rides `ReachArgs`, so a root or a transport-free verb never takes it.
        assert!(
            Cli::try_parse_from(["swoosh", "--local", "serve"]).is_err(),
            "`--local` is not a root global"
        );
        assert!(
            Cli::try_parse_from(["swoosh", "contact", "rm", "alice", "--local"]).is_err(),
            "`contact rm` binds no transport"
        );
    }

    /// The bind's one mechanism is constructor selection: `--local` picks the persisted-minimal iroh
    /// bind, else the verb's bind role picks between the serving (publishing) and the dialing
    /// (non-publishing) n0 constructors. A pure mapping, so every branch is covered without a socket,
    /// and the composition root's match has an arm per mode with no wildcard.
    #[test]
    fn the_local_flag_and_bind_role_select_the_iroh_constructor() {
        let dialing = || BindRole::Dialing(credential::Credential::Family { present: None });
        assert_eq!(IrohBind::of(false, &BindRole::Serving), IrohBind::Reachable);
        assert_eq!(IrohBind::of(false, &dialing()), IrohBind::Dialing);
        assert_eq!(IrohBind::of(true, &BindRole::Serving), IrohBind::Local);
        assert_eq!(IrohBind::of(true, &dialing()), IrohBind::Local);
    }

    /// F1 (0.9.1): only `serve` writes the home key's address record. A dialing verb on the serving
    /// machine must not touch what other machines resolve, and the table fails on the old switch (every
    /// verb selected the publishing constructor). Asserted through the constructor each role selects,
    /// which is the observable consequence the bind acts on. One parseable argv per reach verb, split to
    /// its [`Verb::Outward`] arm.
    #[test]
    fn only_serve_registers_the_node_record() {
        let key = NodeId::from_ed25519_secret(&[7u8; 32]).to_string();
        let cases: Vec<(Vec<&str>, IrohBind)> = vec![
            (vec!["swoosh", "serve"], IrohBind::Reachable),
            (vec!["swoosh", "ping", &key], IrohBind::Dialing),
            (vec!["swoosh", "speed", &key], IrohBind::Dialing),
            (vec!["swoosh", "status", &key], IrohBind::Dialing),
            (
                vec!["swoosh", "proxy", &key, "https://example.com"],
                IrohBind::Dialing,
            ),
            (
                vec!["swoosh", "forward", &key, "web", "-"],
                IrohBind::Dialing,
            ),
            (vec!["swoosh", "send", "notes.md", &key], IrohBind::Dialing),
            (vec!["swoosh", "sync"], IrohBind::Dialing),
        ];

        for (argv, expected) in cases {
            let cli = Cli::try_parse_from(argv.iter().copied())
                .unwrap_or_else(|err| panic!("{argv:?} parses: {err}"));
            let Some(command) = cli.command else {
                panic!("{argv:?} selects a verb");
            };
            let Verb::Outward(outward) = command.split() else {
                panic!("{argv:?} must split to the reach path");
            };
            assert_eq!(
                IrohBind::of(false, &outward.bind_role()),
                expected,
                "{argv:?} must select the {expected:?} constructor"
            );
        }
    }

    /// `--local` is a bind knob, not an auth knob: it must not change what `serve` gates or what
    /// `--public` opens. The parsed shape carries the same opened set and the same credential/identity
    /// declaration as the unflagged serve; the flag never enters the gate path.
    #[test]
    fn the_local_flag_leaves_the_gate_and_public_shape_alone() {
        let cli = Cli::try_parse_from(["swoosh", "serve", "--local", "--public", "speed"])
            .expect("serve --local --public parses");
        let Some(Command::Serve(cmd)) = cli.command else {
            panic!("serve parses to the serve verb");
        };
        assert!(cmd.reach.local, "the flag is set");
        assert_eq!(
            cmd.public,
            vec!["speed".parse::<nauthy::Service>().expect("a service")],
            "--public names the same opened set"
        );
        assert!(
            matches!(cmd.bind_role(), BindRole::Serving),
            "serve still serves, and states no dial credential"
        );
        assert_eq!(
            cmd.identity(),
            swoosh::identity::Identity::Persisted,
            "serve still binds the persisted key"
        );
    }

    /// `stop` resolves its machine before any transport: bare and `me/<name>` both split to the local verb,
    /// which binds only for another of your devices once the list of your devices names it. `--at` is gone:
    /// a machine is a positional.
    #[test]
    fn stop_resolves_locally_and_takes_no_at() {
        for argv in [vec!["swoosh", "stop"], vec!["swoosh", "stop", "me/nas"]] {
            let cli = Cli::try_parse_from(&argv).expect("stop parses");
            assert!(
                matches!(cli.command.expect("a command").split(), Verb::Stop(_)),
                "{argv:?} resolves locally first"
            );
        }
        let error = Cli::try_parse_from(["swoosh", "stop", "--at", "me/nas"])
            .expect_err("--at is no flag of stop");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    /// `stop` takes one machine: a second is a usage error, exit 2, naming the rule, whatever the second
    /// one is, before the home is read. Accept two and the first one stops.
    #[test]
    fn stop_takes_one_machine() {
        for second in ["me/pi", "./nas.link", "bob"] {
            let error = parse_from(["swoosh", "stop", "me/nas", second])
                .expect_err("two machines refuse at parse");
            assert_eq!(error.exit_code(), 2, "a usage error exits 2");
            let printed = error.to_string();
            assert!(
                printed.starts_with("error: swoosh stop takes one machine\n"),
                "{printed}"
            );
            assert!(printed.contains("Usage: swoosh stop"), "{printed}");
        }
        // A line wrong for another reason keeps clap's own error.
        let other = parse_from(["swoosh", "stop", "me/nas", "--bogus"])
            .expect_err("an unknown flag refuses");
        assert!(!other.to_string().contains("takes one machine"), "{other}");
    }

    /// The `service` group: `add`, `rm`, `on` and `off` are local leaves, each split to the one local verb
    /// with no transport. `ls`, `enable`, `disable` and the flat `service --at <peer>` are gone, and no leaf
    /// takes `--at`.
    #[test]
    fn service_group_is_add_rm_on_off() {
        for argv in [
            ["swoosh", "service", "add", "ssh"].as_slice(),
            ["swoosh", "service", "add", "ssh", "web=tcp:localhost:3000"].as_slice(),
            ["swoosh", "service", "rm", "ssh", "web"].as_slice(),
            ["swoosh", "service", "on", "ssh"].as_slice(),
            ["swoosh", "service", "off", "ssh"].as_slice(),
            ["swoosh", "service", "off", "ssh", "me/nas"].as_slice(),
            ["swoosh", "service", "off", "me/nas"].as_slice(),
        ] {
            let cli = Cli::try_parse_from(argv).unwrap_or_else(|error| panic!("{argv:?}: {error}"));
            assert!(
                matches!(cli.command.expect("a command").split(), Verb::Service(_)),
                "{argv:?} is a local verb"
            );
        }
        let key = NodeId::from_ed25519_secret(&[6u8; 32]).to_string();
        for argv in [
            ["swoosh", "service", "--at", &key].as_slice(),
            ["swoosh", "service", "add"].as_slice(),
            ["swoosh", "service", "rm"].as_slice(),
            ["swoosh", "service", "on"].as_slice(),
            ["swoosh", "service", "off", "ssh", "--at", &key].as_slice(),
        ] {
            assert!(Cli::try_parse_from(argv).is_err(), "{argv:?} resolves");
        }
    }

    /// A synthetic callsite backing the probe metadata below. The filter's static target directives
    /// read only an event's target and level, so this callsite is never consulted; it exists because
    /// `FieldSet`'s only constructor takes one.
    struct ProbeCallsite;

    impl tracing::Callsite for ProbeCallsite {
        fn set_interest(&self, _interest: tracing::subscriber::Interest) {}
        fn metadata(&self) -> &tracing::Metadata<'_> {
            &PROBE_TRANSFER_INFO
        }
    }

    static PROBE_CALLSITE: ProbeCallsite = ProbeCallsite;

    /// Synthetic event metadata for the filter probes: the receive engine's target at INFO, plus a
    /// NON-transfer target at INFO and at ERROR. `Metadata::new` is const, so each probe is a static.
    static PROBE_TRANSFER_INFO: tracing::Metadata<'static> =
        probe_meta("transfer", tracing::Level::INFO);
    static PROBE_OTHER_INFO: tracing::Metadata<'static> =
        probe_meta("swoosh", tracing::Level::INFO);
    static PROBE_OTHER_ERROR: tracing::Metadata<'static> =
        probe_meta("swoosh", tracing::Level::ERROR);

    const fn probe_meta(target: &'static str, level: tracing::Level) -> tracing::Metadata<'static> {
        tracing::Metadata::new(
            "swoosh-log-filter-probe",
            target,
            level,
            None,
            None,
            None,
            tracing::field::FieldSet::new(&[], tracing::callsite::Identifier(&PROBE_CALLSITE)),
            tracing::metadata::Kind::EVENT,
        )
    }

    /// Whether `filter` would surface a synthetic event carrying `meta`, with no subscriber installed
    /// and nothing emitted. The register-side verdict is `Interest::never` for a target the static
    /// directives do not enable, and `always` for one they do.
    fn filter_enables(
        filter: &tracing_subscriber::EnvFilter,
        meta: &'static tracing::Metadata<'static>,
    ) -> bool {
        use tracing_subscriber::Layer;

        !Layer::<tracing_subscriber::Registry>::register_callsite(filter, meta).is_never()
    }

    /// The default filter shows errors and nothing below them, for every target: the receive engine's
    /// target gets no raised default, because an arrival is an activity line the serving root renders,
    /// never a log event. An explicit `RUST_LOG` replaces the default.
    #[test]
    fn the_default_log_filter_is_errors_only() {
        use tracing_subscriber::filter::LevelFilter;

        let default = log_filter(None);
        assert!(!filter_enables(&default, &PROBE_TRANSFER_INFO));
        assert!(!filter_enables(&default, &PROBE_OTHER_INFO));
        assert!(filter_enables(&default, &PROBE_OTHER_ERROR));
        assert_eq!(default.max_level_hint(), Some(LevelFilter::ERROR));

        // `RUST_LOG` wins, in both directions.
        let info = log_filter(Some("transfer=info".to_owned()));
        assert!(filter_enables(&info, &PROBE_TRANSFER_INFO));
        let warn = log_filter(Some("warn".to_owned()));
        assert_eq!(warn.max_level_hint(), Some(LevelFilter::WARN));
        assert!(filter_enables(&warn, &PROBE_OTHER_ERROR));
    }

    /// A key nobody can hold is refused where it enters: typed (as a contact's root or device) with the
    /// one line that names the check it failed, and stored (as the pin) as the damaged home, naming the
    /// file, from the read every verb that loads the pin goes through.
    #[tokio::test]
    async fn a_malformed_key_is_refused_where_it_enters() {
        let key = swoosh::testkit::torsioned_text();
        let line = format!("{key} is not a usable key: carries a torsion component");
        for typed in [
            ["swoosh", "contact", "add", "alice", key.as_str()],
            ["swoosh", "contact", "add", "alice/laptop", key.as_str()],
        ] {
            let error = Cli::try_parse_from(typed).expect_err("a torsioned key is refused");
            assert_eq!(error.exit_code(), 2, "a typed bad key is a usage error");
            assert!(
                error.to_string().contains(&line),
                "the typed refusal names the check: {error}"
            );
        }

        let dir = std::env::temp_dir().join(format!("swoosh-malformed-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        swoosh::config::create_store_dir(&dir).expect("create the home");
        let home = Home::resolve(Some(dir.clone())).expect("resolve an explicit home");
        std::fs::write(home.root_pub(), format!("{key}\n")).expect("write the pin");
        let error = swoosh::config::load_signet(&home)
            .await
            .expect_err("a torsioned pin is refused");
        assert_eq!(
            error.to_string(),
            swoosh::standing::damaged_line(&swoosh::standing::Disagreement::UnreadablePin {
                path: home.root_pub()
            }),
            "the stored bad key reads as the damaged home"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `mint` is no command: clap refuses it as an unknown subcommand, a usage error.
    #[test]
    fn mint_is_not_a_command() {
        let error = Cli::try_parse_from(["swoosh", "mint"]).expect_err("mint is no command");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
        assert_eq!(error.exit_code(), 2);
    }

    /// The pick-up route is `control.renewal`: every `serve`'s catalog names it, and like every internal
    /// route it is dotted, so no service name a person types can be it.
    #[tokio::test]
    async fn the_pick_up_route_is_control_renewal() {
        assert_eq!(swoosh::serve::RENEWAL_SERVICE, "control.renewal");
        let dir = std::env::temp_dir().join(format!("swoosh-pick-up-name-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        swoosh::config::create_store_dir(&dir).expect("a scratch home");
        let home = Home::resolve(Some(dir.clone())).expect("the scratch home resolves");
        let own = swoosh::testkit::TestNode::seeded(0x61).node_id();
        let (gate, _cut) =
            swoosh::gate::anchored(&home, own, swoosh::serve::BoundTargets::default())
                .await
                .expect("the gate builds");
        let (router, _known) =
            swoosh::serve::bind_renewal(tightbeam::tunnel::Router::new(gate), &home)
                .await
                .expect("the route binds");
        assert!(
            router
                .catalog(None)
                .entries()
                .any(|entry| entry.name == swoosh::serve::RENEWAL_SERVICE),
            "the catalog names the route"
        );
        for argv in [
            vec!["swoosh", "serve", "control.renewal=tcp:localhost:1"],
            vec!["swoosh", "serve", "--public", "control.renewal"],
        ] {
            let error = Cli::try_parse_from(&argv).expect_err("the route's name is never typed");
            assert_eq!(error.exit_code(), 2, "{argv:?} is a usage error");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A typed service name follows the one name rule, so a dotted internal route (`control.stop`) can never
    /// be typed: the entry refuses at parse, exit 2, before anything binds. A capital folds.
    #[test]
    fn a_typed_service_name_cannot_be_an_internal_route() {
        let error = Cli::try_parse_from(["swoosh", "serve", "control.stop=tcp:localhost:1"])
            .expect_err("a dotted service name refuses");
        assert_eq!(error.exit_code(), 2, "a bad name is a usage error");
        assert!(
            error.to_string().contains(
                "control.stop is not a name: a name uses a-z, 0-9 and -, and starts with a letter or digit."
            ),
            "the refusal states the rule: {error}"
        );
        // A `:` in the name is no exception: the entry is still read as `name=target`.
        let error = Cli::try_parse_from(["swoosh", "serve", "a:b=tcp:127.0.0.1:1"])
            .expect_err("a name holding a colon refuses");
        assert_eq!(error.exit_code(), 2, "a bad name is a usage error");
        assert!(
            error.to_string().contains("a:b is not a name"),
            "the refusal states the rule: {error}"
        );
        let Some(Command::Serve(cmd)) =
            Cli::try_parse_from(["swoosh", "serve", "Web=tcp:localhost:1"])
                .expect("a capital name parses")
                .command
        else {
            panic!("serve parses to the serve verb");
        };
        assert_eq!(cmd.services, ["web=tcp:localhost:1"]);

        // Every service name a person types takes the same rule: a dotted route refuses at parse, exit 2,
        // wherever it is typed.
        let key = bifrost::NodeId::from_ed25519_secret(&[3u8; 32]).to_string();
        for argv in [
            vec!["swoosh", "serve", "control.stop"],
            vec!["swoosh", "serve", "--public", "control.stop"],
            vec!["swoosh", "serve", "--public-unsafe", "control.stop"],
            vec!["swoosh", "share", "control.stop", "anyone"],
            vec!["swoosh", "service", "off", "control.stop"],
            vec!["swoosh", "service", "on", "control.stop"],
            vec!["swoosh", "service", "rm", "control.stop"],
            vec!["swoosh", "service", "add", "control.stop"],
            vec!["swoosh", "forward", key.as_str(), "control.stop", "-"],
            vec!["swoosh", "ssh", key.as_str(), "--service", "control.stop"],
            vec![
                "swoosh",
                "send",
                "f",
                key.as_str(),
                "--service",
                "control.stop",
            ],
        ] {
            let error = Cli::try_parse_from(&argv).expect_err("a dotted service name refuses");
            assert_eq!(error.exit_code(), 2, "{argv:?} is a usage error");
            assert!(
                error.to_string().contains("control.stop is not a name"),
                "{argv:?} states the rule: {error}"
            );
        }

        // And a capital folds to the one spelling the node serves.
        let parsed = |argv: &[&str]| Cli::try_parse_from(argv).expect("a capital parses").command;
        let Some(Command::Serve(cmd)) =
            parsed(&["swoosh", "serve", "Web=tcp:localhost:1", "--public", "Web"])
        else {
            panic!("serve parses to the serve verb");
        };
        assert_eq!(
            cmd.public,
            ["web".parse::<nauthy::Service>().expect("a service")]
        );
        let Some(Command::Share(share::ShareCmd {
            what: share::Shared::Service(service),
            ..
        })) = parsed(&["swoosh", "share", "Web", "anyone"])
        else {
            panic!("share parses to a service");
        };
        assert_eq!(service.as_str(), "web");
        let Some(Command::Forward(args)) = parsed(&["swoosh", "forward", key.as_str(), "Web", "-"])
        else {
            panic!("forward parses");
        };
        assert_eq!(args.service.as_str(), "web");
    }

    /// A device typed as an address follows the one name rule, and its refusal is the rule's own line, not a
    /// generic wrapper.
    #[test]
    fn a_typed_address_refuses_with_the_name_rule() {
        for (argv, bad) in [
            (vec!["swoosh", "ssh", "me/La.ptop"], "La.ptop"),
            (vec!["swoosh", "share", "ssh", "a.b/x"], "a.b"),
        ] {
            let error = Cli::try_parse_from(&argv).expect_err("a bad name refuses");
            assert_eq!(error.exit_code(), 2, "{argv:?} is a usage error");
            assert!(
                error.to_string().contains(&format!(
                    "{bad} is not a name: a name uses a-z, 0-9 and -, and starts with a letter or digit."
                )),
                "{argv:?} states the rule: {error}"
            );
        }
    }
}
