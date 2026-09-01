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
use futures::FutureExt as _;
use nauthy::Denylist;
use tightbeam::duration::Lifetime;
use tightbeam::tunnel::{self, CancellationToken, Exposer, Handler, Registry, ServeFn, Services};
use tokio::io::AsyncWriteExt as _;

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
}

impl ServeCmd {
    /// Serve the named services (default `ping:` + `speed:`) under swoosh's identity by driving the
    /// tunnel core directly: parse the services, resolve the gate from swoosh's own signet + denylist (through
    /// the shared `resolve_gate` policy, so `--public` opens, else a family gate on the signet), assemble the
    /// handler registry (`fetch:`, `ping:`/`speed:`, and `sshd:` under the `ssh` feature), print
    /// swoosh's banner, and run the exposer. A `sshd:`/`ping:`/`speed:` service stays gated regardless. The `signet` here is already
    /// resolved by the composition root: a provisioned signet if one was adopted, else this node's OWN key
    /// (person-zero self-trusts), so a plain node gates on itself rather than failing "no signet".
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        host_seed: [u8; 32],
        signet: Option<NodeId>,
        denylist: Denylist,
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
            .with(CONTROL_STOP_SERVICE, stop_handler(cancel.clone()));
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
        .with("fetch", fetch_handler())
        .with("ping", ping_handler())
        .with("speed", speed_handler())
        .with("beam", beam_handler(beam_out));
    #[cfg(feature = "ssh")]
    let registry = registry.with("sshd", sshd_handler(host_seed));
    #[cfg(not(feature = "ssh"))]
    let _ = host_seed;
    Ok(registry)
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
pub fn stop_handler(cancel: CancellationToken) -> Handler {
    let serve: ServeFn = Arc::new(move |_admitted, mut writer, _reader| {
        let cancel = cancel.clone();
        async move {
            cancel.cancel();
            // The ack byte: proof to the client that the stop landed. Written after the cancel so a client
            // reading it knows the teardown was requested, then flushed since the node is about to close.
            writer.write_all(&[STOP_ACK]).await?;
            writer.flush().await?;
            Ok(())
        }
        .boxed()
    });
    Handler::gated(serve)
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
fn beam_handler(out: PathBuf) -> Handler {
    let out = Arc::new(out);
    let next_tag = Arc::new(AtomicU64::new(0));
    let serve: ServeFn = Arc::new(move |_admitted, writer, reader| {
        let out = Arc::clone(&out);
        let tag = next_tag.fetch_add(1, Ordering::Relaxed);
        async move {
            let received = beam::receive_file(writer, reader, &out, tag).await?;
            println!(
                "received {} ({} bytes)",
                received.path.display(),
                received.bytes
            );
            Ok(())
        }
        .boxed()
    });
    Handler::gated(serve)
}

/// The `fetch:` handler swoosh injects: the node acts as an HTTP client and streams an origin response back
/// over the admitted stream. It carries its own SSRF guard, so it does not require the gate (a `--public
/// fetch:` is a deliberate choice, not an accidental keyless shell).
fn fetch_handler() -> Handler {
    let serve: ServeFn = Arc::new(|_admitted, mut writer, mut reader| {
        async move {
            fetch::serve_fetch(&mut writer, &mut reader).await?;
            Ok(())
        }
        .boxed()
    });
    Handler::open(serve)
}

/// The `ping:` handler swoosh injects: the cheap RTT half of reach diagnostics, behind the node's
/// gate. It answers one ping run over the admitted stream and REFUSES a speed frame at the wire, so a grant
/// for `ping` can never open the speed drain. GATED for now (an open gate over it, `--public
/// ping:`, is a deliberate opt-out a node makes to advertise as a public ping responder); a member is
/// admitted whole-node.
fn ping_handler() -> Handler {
    let serve: ServeFn = Arc::new(|_admitted, mut writer, mut reader| {
        async move {
            measure::answer_ping(&mut writer, &mut reader).await?;
            Ok(())
        }
        .boxed()
    });
    Handler::gated(serve)
}

/// The `speed:` handler swoosh injects: the bandwidth-eating throughput half of reach diagnostics,
/// behind the node's gate. It answers one speed transfer over the admitted stream and REFUSES a ping frame
/// at the wire. GATED: `SpeedSource{None}` is a raw diagnostics drain with no responder-side bound yet, so
/// an open gate over it is a saturable uplink handed to anyone; a node that DELIBERATELY wants to advertise
/// as a public speedtest server opts in with `--public speed:`. The family gate is the terminator
/// until the responder-side bound lands.
fn speed_handler() -> Handler {
    let serve: ServeFn = Arc::new(|_admitted, mut writer, mut reader| {
        async move {
            measure::answer_speed(&mut writer, &mut reader).await?;
            Ok(())
        }
        .boxed()
    });
    Handler::gated(serve)
}

/// The `sshd:` handler swoosh injects under the `ssh` feature: a keyless shell. GATED, because a keyless
/// shell is remote code execution with no legitimate public use, so the gate IS its authentication; an open
/// gate over it is refused at [`Exposer::new`]. Captures the ssh host-key seed the caller derived from
/// swoosh's identity.
#[cfg(feature = "ssh")]
fn sshd_handler(host_seed: [u8; 32]) -> Handler {
    let serve: ServeFn = Arc::new(move |admitted, writer, reader| {
        async move {
            sshh::serve(admitted, host_seed, writer, reader).await?;
            Ok(())
        }
        .boxed()
    });
    Handler::gated(serve)
}
