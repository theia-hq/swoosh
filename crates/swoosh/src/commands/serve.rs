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

use core::sync::atomic::{AtomicU64, Ordering};
use std::path::PathBuf;
use std::sync::Arc;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use nauthy::{Admitted, Denylist, Epoch, Member, RosterDoc, RosterLabel, VerifyKey};
use tightbeam::duration::Lifetime;
use tightbeam::open_policy::{Never, OptIn};
use tightbeam::tunnel::{
    self, BoxRead, BoxWrite, CancellationToken, Exposer, Handler, Registry, Services,
};
use tokio::io::AsyncWriteExt as _;

use crate::contacts::{Contacts, Petname};
use crate::identity::Secret;
use crate::transport::ReachArgs;

/// The node-control service that stops this node: an admitted caller reaching it triggers a graceful
/// teardown (the remote twin of a local Ctrl-C or a `--for` deadline). The client verb is `swoosh stop`.
///
/// SETTLED name (delib-23, Principal-ruled): one unified `control.*` family over both the reads
/// (`control.status`) and the mutations (`control.stop`); the dotted scheme is the verbatim registry key,
/// gated exact-name, so a grant for one method can never open another. Public so the `swoosh stop` client
/// verb requests the SAME name the served handler is keyed under, one source of truth for the wire string.
pub const CONTROL_STOP_SERVICE: &str = "control.stop";

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
    /// Serve to ANYONE, unauthenticated: the one deliberate opt-out from the signet gate. Refused for a
    /// keyless shell (`sshd:`, remote code execution) or a raw diagnostics service (`ping:`/
    /// `speed:`, no responder-side bound yet), which have no safe public form until that bound lands.
    #[arg(long)]
    pub public: bool,
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
            eyre::bail!("internal: serve reached run without its expose context (composition-root bug)");
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
        let services = Services::parse(&requested)?;
        // Resolve the gate before announcing readiness: an unprovisioned node with no `--public` fails
        // HERE, through the ONE shared policy point, rather than ever serving on a permissive default.
        let gate = tunnel::resolve_gate(self.public, signet, denylist)?;
        // The node's ONE teardown authority. The exposer owns it (it is what acts on the cancel); a local
        // `--for` timer and the gated `control.stop` handler each hold a CLONE as the node-control
        // capability -- they may REQUEST the stop, never tear the node down themselves. So this one token is
        // the join point for every way the node can stop: a Ctrl-C, a `--for` deadline, or a remote
        // `swoosh stop`.
        let cancel = CancellationToken::new();
        // The core assembles the exposer, enforcing the sshd-cannot-be-public (and ping/speed-cannot-be-public)
        // invariant before any banner is printed, so a refused pairing never advertises a service it will
        // not serve. The `control.stop` handler is added over the shared base registry with a CLONE of the
        // cancel token, so an admitted caller that reaches it requests the same graceful teardown.
        let registry = registry(host_seed, self.out.clone())?
            .with("roster", Roster::new(roster_blob))
            .with(CONTROL_STOP_SERVICE, Stop::new(cancel.clone()));
        let exposer = Exposer::new(services.clone(), registry, gate)?;

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

        // The exposer owns the teardown: it returns when the token fires (a `--for` deadline, or an admitted
        // `control.stop` caller). A Ctrl-C is the same graceful stop, driven here by cancelling the token so
        // there is ONE stop path, then letting the run finish. Either way the node is closed after.
        tokio::select! {
            result = exposer.run(node, cancel.clone()) => result?,
            signalled = tokio::signal::ctrl_c() => {
                signalled?;
                cancel.cancel();
            }
        }
        println!("\nshutting down.");
        node.close().await;
        Ok(())
    }

    /// A one-line description of the effective gate, for the readiness banner: trust made visible. `self_id`
    /// is this node's own id, so the banner can say "self" when the gate roots at the node's OWN key (a
    /// person-zero node with no provisioned signet self-trusts) rather than naming its own id as a "signet".
    fn gate_description(&self, signet: Option<NodeId>, self_id: NodeId) -> String {
        if self.public {
            "public (anyone, unauthenticated)".to_owned()
        } else {
            match signet {
                Some(root) if root == self_id => {
                    "self (person-zero: this node and its devices)".to_owned()
                }
                Some(root) => format!("signet {}", root.short()),
                None => "unprovisioned".to_owned(),
            }
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

/// Assemble the whole handler registry swoosh serves: the HTTP egress `fetch:`, the two gated diagnostic
/// services `ping:` and `speed:`, the gated file-receive `beam:`, and (under the `ssh` feature) the keyless
/// shell `sshd:`. swoosh is the one crate that depends on every service crate, so it is the one place these
/// are wired: tightbeam names no service crate and ships no built-in, and this function injects them all
/// with `.with(...)`. `extend` stays available for add-only merges, but swoosh builds one registry directly
/// here.
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
/// identical registry swoosh serves rather than a hand-rolled near-copy.
pub fn registry(host_seed: [u8; 32], beam_out: PathBuf) -> eyre::Result<Registry> {
    let registry = Registry::new()
        .with("fetch", Fetch)
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
/// B1 ships epoch 0: a single hand-repointed coordination node needs no ordering yet, and the epoch counter
/// rides B2's `fleet` re-cut. A `me` device whose label is not a valid roster label is skipped rather than
/// aborting the whole roster.
pub fn cut_roster(contacts: &Contacts, secret: &Secret) -> eyre::Result<Vec<u8>> {
    let me: Petname = "me".parse()?;
    let members: Vec<Member> = contacts
        .devices(&me)
        .into_iter()
        .flatten()
        .filter_map(|(label, node)| {
            let label = label.as_str().parse::<RosterLabel>().ok()?;
            Some(Member {
                node: VerifyKey::new(*node.key()),
                label,
            })
        })
        .collect();
    let doc = RosterDoc::new(Epoch(0), members)?;
    Ok(secret.cap_identity()?.sign_roster(&doc).encode())
}

/// The `roster:` handler: serve the signet-signed membership snapshot to an admitted member, then close.
/// GATED (a stranger must never read the member set: delib-28 containment). Only the signet SIGNED the blob;
/// this node merely serves a pre-cut snapshot, so a popped courier leaks a read of a member-known set, never
/// authority (the signing secret is not needed to serve, only to have signed). The blob is self-delimiting
/// and signature-validated by the puller, so the handler just writes it and closes the write half.
pub struct Roster {
    blob: Arc<Vec<u8>>,
}

impl Roster {
    /// Build the `roster:` handler over the pre-cut, signet-signed membership snapshot it serves.
    pub fn new(blob: Arc<Vec<u8>>) -> Self {
        Self { blob }
    }
}

impl Handler for Roster {
    // GATED (a stranger must never read the member set: delib-28 containment): no legitimate public use.
    type Public = Never;

    async fn serve(
        &self,
        _admitted: Admitted,
        mut writer: BoxWrite,
        _reader: BoxRead,
    ) -> eyre::Result<()> {
        writer.write_all(&self.blob).await?;
        writer.shutdown().await?;
        Ok(())
    }
}

/// The `control.stop` handler swoosh injects: the remote node-lifecycle stop. It holds a CLONE of the
/// node's teardown token as the node-control CAPABILITY (never a node handle), so when an admitted caller
/// reaches it, it REQUESTS the graceful teardown by cancelling that token; the exposer (the one owner of
/// teardown) sees the cancel and stops the node. GATED, because stopping the node is a mutation with no
/// safe public form: the family gate is its authentication, so only an admitted member (this node's own
/// devices, for a single-owner node) can stop it. An open gate over it is refused at [`Exposer::new`].
///
/// SAFE FIRST SLICE (delib-18): this ships the FAMILY-GATED stop, correct for a single-owner qat node.
/// The HARDENED lifecycle (an arm->confirm nonce + a single-use device-bound DESTROY-CAP, ideally
/// OWNER-only so a delegate cannot casually shut the node down) is the FOLLOW, and needs an Adversary
/// gating-review before `control.stop` is trusted on a multi-delegate node; the open question there is
/// whether the `Admitted` witness can distinguish an owner device from a delegate.
///
/// On admission the handler cancels the token, then writes ONE ack byte so the client can confirm the stop
/// was actioned (not merely that the dial was admitted): a positive, explicit confirmation, the honest
/// counterpart to the loud typed refusal a non-admitted caller gets at the gate.
///
/// Public so the `gated_stop` proof drives the SAME handler `serve` injects, not a hand-rolled near-copy,
/// exactly as the `gated_measure` proof reuses `registry`.
pub struct Stop {
    cancel: CancellationToken,
}

impl Stop {
    /// Build the `control.stop` handler holding a CLONE of the node's teardown token as the node-control
    /// capability (never a node handle): an admitted caller REQUESTS the graceful teardown by cancelling it.
    pub fn new(cancel: CancellationToken) -> Self {
        Self { cancel }
    }
}

impl Handler for Stop {
    // GATED: stopping the node is a mutation with no safe public form; the family gate is its authentication.
    type Public = Never;

    async fn serve(
        &self,
        _admitted: Admitted,
        mut writer: BoxWrite,
        _reader: BoxRead,
    ) -> eyre::Result<()> {
        self.cancel.cancel();
        // The ack byte: proof to the client that the stop landed. Written after the cancel so a client
        // reading it knows the teardown was requested, then flushed since the node is about to close.
        writer.write_all(&[STOP_ACK]).await?;
        writer.flush().await?;
        Ok(())
    }
}

/// The single byte `control.stop` writes to confirm the stop was actioned. Any value works (the client only
/// needs to read one byte on an admitted stream); a printable `.` keeps a raw wire dump legible.
pub const STOP_ACK: u8 = b'.';

/// The `beam:` handler swoosh injects: the receive half of PUSH file transfer. It takes one admitted stream
/// carrying one pushed file, drives `bifrost-wire`'s verified receive into a temp file under `beam_out`, and
/// moves it into place at the safe relative path the sender named. GATED, because a receive service with no
/// auth of its own would let anyone write files into the node's output directory; the gate IS its
/// authentication. Each stream gets a unique tag from a shared counter, so concurrent pushes never contend
/// for the same temp file.
struct Beam {
    out: PathBuf,
    next_tag: AtomicU64,
}

impl Beam {
    fn new(out: PathBuf) -> Self {
        Self {
            out,
            next_tag: AtomicU64::new(0),
        }
    }
}

impl Handler for Beam {
    // GATED: a receive service with no auth of its own would let anyone write files into the node's output
    // directory; the gate IS its authentication.
    type Public = Never;

    async fn serve(
        &self,
        _admitted: Admitted,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> eyre::Result<()> {
        // Each stream gets a unique tag from the shared counter, so concurrent pushes never contend for the
        // same temp file.
        let tag = self.next_tag.fetch_add(1, Ordering::Relaxed);
        let received = beam::receive_file(writer, reader, &self.out, tag).await?;
        println!(
            "received {} ({} bytes)",
            received.path.display(),
            received.bytes
        );
        Ok(())
    }
}

/// The `fetch:` handler swoosh injects: the node acts as an HTTP client and streams an origin response back
/// over the admitted stream. It carries its own SSRF guard, so it does not require the gate (a `--public
/// fetch:` is a deliberate choice, not an accidental keyless shell).
struct Fetch;

impl Handler for Fetch {
    // OPT-IN: `fetch:` carries its own SSRF guard, so a `--public fetch:` is a deliberate choice, not an
    // accidental keyless shell.
    type Public = OptIn;

    async fn serve(
        &self,
        _admitted: Admitted,
        mut writer: BoxWrite,
        mut reader: BoxRead,
    ) -> eyre::Result<()> {
        fetch::serve_fetch(&mut writer, &mut reader).await?;
        Ok(())
    }
}

/// The `ping:` handler swoosh injects: the cheap RTT half of reach diagnostics, behind the node's
/// gate. It answers one ping run over the admitted stream and REFUSES a speed frame at the wire, so a grant
/// for `ping` can never open the speed drain. GATED for now (an open gate over it, `--public
/// ping:`, is a deliberate opt-out a node makes to advertise as a public ping responder); a member is
/// admitted whole-node.
struct Ping;

impl Handler for Ping {
    // OPT-IN: an open gate over it (`--public ping:`) is a deliberate opt-out a node makes to advertise as a
    // public ping responder; a member is otherwise admitted whole-node.
    type Public = OptIn;

    async fn serve(
        &self,
        _admitted: Admitted,
        mut writer: BoxWrite,
        mut reader: BoxRead,
    ) -> eyre::Result<()> {
        measure::answer_ping(&mut writer, &mut reader).await?;
        Ok(())
    }
}

/// The `speed:` handler swoosh injects: the bandwidth-eating throughput half of reach diagnostics,
/// behind the node's gate. It answers one speed transfer over the admitted stream and REFUSES a ping frame
/// at the wire. GATED: `SpeedSource{None}` is a raw diagnostics drain with no responder-side bound yet, so
/// an open gate over it is a saturable uplink handed to anyone; a node that DELIBERATELY wants to advertise
/// as a public speedtest server opts in with `--public speed:`. The family gate is the terminator
/// until the responder-side bound lands.
struct Speed;

impl Handler for Speed {
    // OPT-IN: a node that DELIBERATELY wants to advertise as a public speedtest server opts in with
    // `--public speed:`; otherwise the family gate is the terminator.
    type Public = OptIn;

    async fn serve(
        &self,
        _admitted: Admitted,
        mut writer: BoxWrite,
        mut reader: BoxRead,
    ) -> eyre::Result<()> {
        measure::answer_speed(&mut writer, &mut reader).await?;
        Ok(())
    }
}

/// The `sshd:` handler swoosh injects under the `ssh` feature: a keyless shell. GATED, because a keyless
/// shell is remote code execution with no legitimate public use, so the gate IS its authentication; an open
/// gate over it is refused at [`Exposer::new`]. Captures the ssh host-key seed the caller derived from
/// swoosh's identity.
#[cfg(feature = "ssh")]
struct Sshd {
    host_seed: [u8; 32],
}

#[cfg(feature = "ssh")]
impl Handler for Sshd {
    // NEVER: a keyless shell is remote code execution with no legitimate public use, so the gate IS its
    // authentication; an open gate over it is refused at `Exposer::new`.
    type Public = Never;

    async fn serve(
        &self,
        admitted: Admitted,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> eyre::Result<()> {
        sshh::serve(admitted, self.host_seed, writer, reader).await?;
        Ok(())
    }
}
