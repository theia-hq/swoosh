//! `swoosh send <path>... <machine>`: PUSH a file or directory to a machine.
//!
//! The sender-initiates half of file transfer: you dial a waiting receiver (a node serving `recv:`), open
//! one stream per file, and drive [`transfer::wire`]'s [`Transfer`](transfer::wire::Transfer) directly,
//! the same wire `swoosh serve recv=recv:` receives with. A directory expands to every file under it, and
//! files pipeline over concurrent streams (capped so one connection is not flooded); a file that cannot be
//! read is skipped and reported, not fatal, so a courier sends what it can.
//!
//! The `recv:` service is family-gated like `ping`/`speed`, so send presents the same
//! membership badge (or the link typed as the peer) to prove membership before the receiver admits a
//! stream. The sender hashes each file with BLAKE3 and the receiver re-hashes as bytes arrive, which
//! catches a fault on the way and a file that changed while it was sent. It stops no lying sender, who
//! names the root of whatever it sends: who sent the bytes is the gate's proof, and the receiver's line
//! names that key.

use std::path::{Path, PathBuf};

use bifrost::{Discovery, Node, Session, Transport};
use clap::Args;
use eyre::WrapErr as _;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use nauthy::{Link, Service};
use swoosh::escape::{Escaped, EscapedPath, causes, escaped_report};
use swoosh::peer::{Machine, Peer};
use swoosh::transport::ReachArgs;
use swoosh::unbound::Unbound;
use transfer::wire::{Blob, Transfer};

use crate::commands::machine;

/// The service name a receiver publishes and `swoosh send` reaches: a peer serving `recv:` receives,
/// `swoosh send` pushes.
///
/// Taken FROM the table that knows a bare `swoosh serve` does not bind it (a receive service's sink
/// directory is the operator's to name, so there is no default to inherit).
pub const RECV_SERVICE: &str = Unbound::RECV.name();

/// Files send concurrently over separate streams, capped so one connection is not flooded. Matches iris's
/// pipeline depth; a receiver's exposer accepts these streams concurrently too, so both sides fan out.
const MAX_INFLIGHT: usize = 16;

/// Push a file or directory to a peer, addressed by their public key.
#[derive(Debug, Args)]
pub struct SendCmd {
    /// The files or directories to push.
    #[arg(required = true, value_name = "path")]
    pub paths: Vec<PathBuf>,
    #[arg(value_name = "machine", help = machine::HELP)]
    pub peer: Peer,
    /// the peer's file-receiving service
    // Hidden, with no variable: each verb's default differs, so one variable would retarget three verbs.
    #[arg(long, value_name = "service", default_value = RECV_SERVICE, value_parser = swoosh::names::service, hide = true)]
    pub service: Service,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl swoosh::reaching::Reaching for SendCmd {
    fn reach_args(&self) -> &swoosh::transport::ReachArgs {
        &self.reach
    }

    /// The peer this verb dials, for the stale-list exchange after it runs.
    fn dialed(&self) -> Option<&swoosh::peer::Peer> {
        Some(&self.peer)
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, and what it dials as. It reaches a peer and never accepts connections under the
    /// home key, so its bind must not write the key's address record (0.9.0 F1).
    ///
    /// `send` pushes to the peer's family-gated `recv:` service, so it presents the member badge rooted
    /// at the dialing key. `Family` fuses the identity to `PersistedIfPresent`. A self-addressing
    /// `swoosh:` link-as-peer is threaded INTO the credential so the ONE resolver owns both slots (so a
    /// signet-bound link-as-peer computes its slot-2 badge there).
    ///
    /// An `anyone` link typed as the peer presents alone, under a throwaway key (`Credential::dialing`).
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::dialing(
            &self.peer,
            self.service.as_str(),
        ))
    }

    /// Uniform dispatch: unpack the reach context and run. `send` reads the resolved `present` badge and
    /// the machine resolved before the bind; it ignores `transport` and `key`.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let Some(machine) = ctx.machine else {
            eyre::bail!("internal: `send` ran without its machine resolved (root-dispatch bug)");
        };
        self.run_send(node, machine, ctx.present, ctx.membership)
            .await
    }
}

impl SendCmd {
    /// Reach the peer's `recv:` service and push every named file over its own gated stream, expanding
    /// directories first. Presents the resolved `present` (this device's membership badge, or the link typed
    /// as the peer) so the receiver's family gate admits each stream. A file that cannot be read is
    /// skipped and reported; the run ends non-zero if any item failed. A stream the receiver refuses
    /// `NotAdmitted` ends the run with the one dial refusal, never a `skip:` per file.
    async fn run_send<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        machine: &Machine,
        present: Option<Link>,
        membership: Option<Link>,
    ) -> eyre::Result<()> {
        // Slots 1 and 2 are ALREADY resolved by the composition root's ONE resolver (link-or-badge in
        // slot 1, a fleet badge in slot 2 only for a signet-bound slip); the fold in `bind_role()` routed a
        // link-as-peer through that same resolver, so the verb never threads a slip itself.
        let connector = swoosh::reach::gated(
            machine.key(),
            self.service.clone(),
            Option::clone(&present),
            Option::clone(&membership),
        );
        let dial = connector.dial();
        println!("sending to {dial}...");
        // A service-scoped session: each `open_bi` speaks the `recv:` request and presents the badge, so
        // every per-file stream is admitted by the receiver's gate on its own merits. The connect chain can
        // carry the peer's text (the reason it gave for closing), so it prints through the escaper.
        let session = connector.open_service(node).await.map_err(escaped_report)?;

        // Expand directories, then pipeline up to MAX_INFLIGHT files over concurrent streams.
        let mut files = Vec::new();
        let mut failures = 0usize;
        for path in &self.paths {
            match collect_files(path).await {
                Ok(collected) => files.extend(collected),
                Err(error) => {
                    eprintln!("skip {}: {error:#}", render_path(path));
                    failures += 1;
                }
            }
        }

        let mut pending = files.into_iter();
        let mut sending = FuturesUnordered::new();
        for _ in 0..MAX_INFLIGHT {
            match pending.next() {
                Some((name, path)) => sending.push(send_one(&session, name, path)),
                None => break,
            }
        }
        while let Some(result) = sending.next().await {
            match result {
                Ok(()) => {}
                // The receiver refused this machine the service: no other file would be admitted, so the
                // run ends here with one refusal, and the files still in flight are dropped.
                Err(error) if error.is::<NotAdmitted>() => {
                    drop(sending);
                    let diagnosis = swoosh::reach::diagnose_over(
                        node,
                        machine,
                        &self.service,
                        present,
                        membership,
                    )
                    .await;
                    node.close().await;
                    return Err(machine::refused(machine, &self.service, diagnosis));
                }
                Err(error) => {
                    eprintln!("skip: {error:#}");
                    failures += 1;
                }
            }
            if let Some((name, path)) = pending.next() {
                sending.push(send_one(&session, name, path));
            }
        }

        node.close().await;
        if failures > 0 {
            eyre::bail!("{failures} item(s) could not be sent");
        }
        Ok(())
    }
}

/// Push one file over its own admitted stream: hash it, open a gated stream, and drive the transfer,
/// naming the file by its relative name so the receiver saves it under that name.
async fn send_one<S: Session>(session: &S, name: String, path: PathBuf) -> eyre::Result<()> {
    let blob = {
        let mut file = tokio::fs::File::open(&path)
            .await
            .wrap_err_with(|| format!("open {}", render_path(&path)))?;
        Blob::hash(&mut file).await?
    };

    let (send, recv) = session.open_bi().await.map_err(|error| match error {
        bifrost::Error::Refused(bifrost::Refusal::NotAdmitted) => eyre::Report::new(NotAdmitted),
        error => peer_error(&error),
    })?;
    let mut source = tokio::fs::File::open(&path)
        .await
        .wrap_err_with(|| format!("open {}", render_path(&path)))?;
    Transfer::new(send, recv)
        .send(name.as_bytes(), &blob, &mut source)
        .await
        .map_err(|error| peer_error(&error))?;

    println!("sent {} ({} bytes)", Escaped(&name), blob.len());
    Ok(())
}

/// A stream the receiver refused `NotAdmitted`: the run's one refusal, which ends it rather than skipping
/// the file.
#[derive(Debug, thiserror::Error)]
#[error("the receiver refused the stream")]
struct NotAdmitted;

/// A failed stream or transfer as the skip line prints it: the cause chain, `outer: inner`, through the
/// shared escaper. The chain can carry the receiver's text (a refusal detail, the reason it gave for
/// closing), so it is escaped here, where it enters, and not on the skip line, which would escape the
/// paths [`render_path`] already escaped a second time.
fn peer_error(error: &dyn core::error::Error) -> eyre::Report {
    eyre::eyre!("{}", Escaped(&causes(error)))
}

/// Render a path for a line or an error context through the shared escaper, as the `sent` line renders
/// a file's name. Every path this verb prints or wraps comes through here, including the paths inside an
/// error context: the skip line renders its own prefix escaped and then prints the whole error chain, so a
/// context built with a raw `Path::display` would leak the newline or ESC the prefix just escaped.
fn render_path(path: &Path) -> String {
    EscapedPath(path).to_string()
}

/// Collect `(relative name, path)` pairs to send: a file yields itself; a directory yields every file
/// under it, named by its path relative to the directory's parent (so the directory name is kept). Ported
/// from iris.
async fn collect_files(root: &Path) -> eyre::Result<Vec<(String, PathBuf)>> {
    let meta = tokio::fs::metadata(root)
        .await
        .wrap_err_with(|| format!("stat {}", render_path(root)))?;

    if meta.is_file() {
        let name = file_name(root)?;
        return Ok(vec![(name, root.to_path_buf())]);
    }

    let base = root.parent().unwrap_or(root);
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = tokio::fs::read_dir(&dir)
            .await
            .wrap_err_with(|| format!("read {}", render_path(&dir)))?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_type = entry.file_type().await?;
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                let relative = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push((relative, path));
            }
        }
    }
    Ok(files)
}

/// The file's own name, for a single-file push. A path with no final component (`.`/`..`/`/`) is a hard
/// error rather than a silent misname.
fn file_name(path: &Path) -> eyre::Result<String> {
    path.file_name()
        .and_then(|component| component.to_str())
        .map(str::to_owned)
        .ok_or_else(|| eyre::eyre!("path has no file name: {}", render_path(path)))
}

#[cfg(test)]
#[path = "send_tests.rs"]
mod send_tests;
