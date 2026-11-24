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

use core::cell::Cell;
use std::path::{Path, PathBuf};

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use eyre::WrapErr as _;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use nauthy::Service;
use swoosh::escape::{Escaped, EscapedPath};
use swoosh::learn::Admitted;
use swoosh::peer::{Machine, Peer};
use swoosh::peers::Hints;
use swoosh::serve::control_codec::OpenLane;
use swoosh::streams::{Ask, OwnBind, Resident, StreamSource, Tracked, Unopened};
use swoosh::transport::ReachArgs;
use swoosh::unbound::Unbound;
use transfer::wire::{Blob, Transfer};

use crate::commands::machine;
use crate::commands::route::{Route, peer_error};
use crate::commands::through_serve::{ServeStopped, Unresponsive};

/// The service name a receiver publishes and `swoosh send` reaches: a peer serving `recv:` receives,
/// `swoosh send` pushes.
///
/// Taken FROM the table that knows a bare `swoosh serve` does not bind it (a receive service's sink
/// directory is the operator's to name, so there is no default to inherit).
pub const RECV_SERVICE: &str = Unbound::RECV.name();

/// Files send concurrently over separate streams, capped so one connection is not flooded. Matches iris's
/// pipeline depth; a receiver's exposer accepts these streams concurrently too, so both sides fan out.
pub(crate) const MAX_INFLIGHT: usize = 16;

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
        swoosh::reaching::BindRole::Dialing(self.credential())
    }

    /// Uniform dispatch: each file is a stream on the run's own Bulk session to the machine resolved
    /// before the bind, presenting what each open reads from the home, or an `anyone` link alone.
    async fn run<'n: 'p, 'p, T: Transport, D: Discovery>(
        self,
        node: &'n Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'p>,
        peers: &'p swoosh::peers::Peers<'n, T, D>,
    ) -> eyre::Result<()>
    where
        T::Session: 'static,
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let Some(machine) = ctx.machine else {
            eyre::bail!("internal: `send` ran without its machine resolved (root-dispatch bug)");
        };
        let route = Route::Own {
            peer: &self.peer,
            bound: ctx.bound,
            this: node.node_id(),
        };
        self.run_send(
            OwnBind::new(peers, ctx.home, node.node_id(), &self.credential()),
            &route,
            machine,
            self.ask(machine),
            ctx.admitted,
            // By own bind no `serve` can stop under the run, so nothing reads it.
            &Cell::new(false),
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        )
        .await
    }
}

/// The lane `send`'s file streams ride: a fan-out of long transfers, so a slow one never holds the Main
/// session the run's exchanges ride past its open deadline.
const SEND_LANE: OpenLane = OpenLane::Bulk;

impl SendCmd {
    /// What this run dials as: the one value that picks its bind and what each of its streams presents.
    fn credential(&self) -> swoosh::credential::Credential {
        swoosh::credential::Credential::dialing(&self.peer, self.service.as_str())
    }

    /// Each file's Open to `machine`, on both paths. It carries no addresses: by own bind the typed ones
    /// reach the run's dials through its discovery, and through `serve` the source fills them in.
    fn ask(&self, machine: &Machine) -> Ask {
        Ask {
            peer: machine.key(),
            hints: Hints::NONE,
            service: self.service.clone(),
            lane: SEND_LANE,
            slip: self.peer.self_present(),
        }
    }

    /// Run through `serve` as `route` words it, each file one Open from `source`, printing on `out` and
    /// `err`. The first admitted file gives `admitted` its question, asked through `source`. `sent` is set
    /// once a file prints `sent`, so a line for `serve` stopping after the run can say what is left.
    ///
    /// # Errors
    ///
    /// The run's line, or how many files could not be sent.
    #[expect(
        clippy::too_many_arguments,
        reason = "the run's two writers and what it sent ride beside its source"
    )]
    pub async fn through<'s>(
        &self,
        source: &'s Tracked<Resident>,
        route: &Route<'_>,
        machine: &Machine,
        admitted: Admitted<'s>,
        sent: &Cell<bool>,
        out: &mut impl std::io::Write,
        err: &mut impl std::io::Write,
    ) -> eyre::Result<()> {
        self.run_send(
            source,
            route,
            machine,
            self.ask(machine),
            admitted,
            sent,
            out,
            err,
        )
        .await
    }

    /// Push every named file to `machine`, each over its own stream from `source` as `ask` asks for it,
    /// expanding directories first, and printing on `out` and `err`. Up to [`MAX_INFLIGHT`] files go at
    /// once. A file that cannot be read, or whose stream alone fails, is skipped and reported; the run
    /// ends non-zero if any was. An outcome every later stream would repeat ends the run with its one
    /// line, never a `skip` per file: for `NotAdmitted`, after asking the machine why, and for a `serve`
    /// confirmed stalled, whose stall every file would meet. A transfer cut after its stream attached
    /// ends the run on `serve`'s line when `serve` went under it, and is that file's skip otherwise.
    /// The first admitted stream gives `admitted` its question, asked through `source`. `sent` is set at each
    /// `sent` line; a run that ends on `serve` stopping after one says not to send those files again.
    #[expect(
        clippy::too_many_arguments,
        reason = "the run's two writers and what it sent ride beside its source"
    )]
    async fn run_send<'s, S: StreamSource + Copy + 's>(
        &self,
        source: S,
        route: &Route<'_>,
        machine: &Machine,
        ask: Ask,
        admitted: Admitted<'s>,
        sent: &Cell<bool>,
        out: &mut impl std::io::Write,
        err: &mut impl std::io::Write,
    ) -> eyre::Result<()> {
        writeln!(out, "sending to {}...", machine.key())?;

        // Expand directories, then pipeline up to MAX_INFLIGHT files over concurrent streams.
        let mut files = Vec::new();
        let mut failures = 0usize;
        for path in &self.paths {
            match collect_files(path).await {
                Ok(collected) => files.extend(collected),
                Err(error) => {
                    writeln!(err, "skip {}: {error:#}", render_path(path))?;
                    failures += 1;
                }
            }
        }

        // A `Cell`: the file streams open through a shared borrow on one task, and whichever is admitted
        // first takes the signal.
        let admitted = Cell::new(Some(admitted));
        let first = First {
            admitted: &admitted,
            admitted_any: Cell::new(false),
            source,
            key: machine.key(),
        };
        let mut pending = files.into_iter();
        let mut sending = FuturesUnordered::new();
        for _ in 0..MAX_INFLIGHT {
            match pending.next() {
                Some((name, path)) => sending.push(send_one(&first, &ask, name, path)),
                None => break,
            }
        }
        while let Some(result) = sending.next().await {
            match result {
                Ok((name, len)) => {
                    writeln!(out, "sent {} ({len} bytes)", Escaped(&name))?;
                    sent.set(true);
                }
                // No later file would be admitted: the run ends here with one line, and the files still
                // in flight are dropped.
                Err((_, Unsent::Unopened(unopened))) if first.ends(&unopened) => {
                    drop(sending);
                    let line = route.ending(unopened, &source, &ask, machine).await;
                    return Err(left_unsent(line, sent));
                }
                Err((name, Unsent::Unopened(unopened))) => {
                    let line = route.line(unopened, machine).await;
                    // A stalled `serve` stalls every file: the run ends with its line, once.
                    if line.is::<Unresponsive>() {
                        drop(sending);
                        return Err(line);
                    }
                    writeln!(err, "skip {}: {line:#}", Escaped(&name))?;
                    failures += 1;
                }
                // `serve` going cuts every stream it carries, so the run ends with its line once; a cut
                // it answers through is the file's own, and the run goes on. Asked before the files in
                // flight are dropped: a live `serve` answers at once, and by own bind nothing is asked.
                Err((name, Unsent::Cut(error))) => {
                    if let Some(line) = route.stopped().await {
                        drop(sending);
                        return Err(left_unsent(line, sent));
                    }
                    writeln!(err, "skip {}: {error:#}", Escaped(&name))?;
                    failures += 1;
                }
                Err((name, Unsent::Failed(error))) => {
                    writeln!(err, "skip {}: {error:#}", Escaped(&name))?;
                    failures += 1;
                }
            }
            if let Some((name, path)) = pending.next() {
                sending.push(send_one(&first, &ask, name, path));
            }
        }

        if failures > 0 {
            eyre::bail!("{failures} item(s) could not be sent");
        }
        Ok(())
    }
}

/// `line`, a run's ending met by a file left unsent: `serve` stopping says, after a `sent` line, to leave
/// the sent files out of the rerun, since a bare rerun would send them again. Any other line is unchanged.
fn left_unsent(line: eyre::Report, sent: &Cell<bool>) -> eyre::Report {
    match line.downcast::<ServeStopped>() {
        Ok(stopped) if sent.get() => stopped.after_sent().into(),
        Ok(stopped) => stopped.into(),
        Err(line) => line,
    }
}

/// What a run holds to hand over its root question once a file stream is admitted: the signal, taken
/// by the first, and the source and key the question asks through. It also knows whether any file was
/// admitted, which decides what a machine not reached means.
struct First<'a, 's, S> {
    admitted: &'a Cell<Option<Admitted<'s>>>,
    /// Whether a file stream of this run was admitted. Apart from the signal, which the question takes
    /// and so cannot be read in place.
    // A `Cell`: the file streams open through a shared borrow on one task.
    admitted_any: Cell<bool>,
    source: S,
    key: NodeId,
}

impl<'s, S: StreamSource + Copy + 's> First<'_, 's, S> {
    /// Whether `unopened` ends this run: an outcome every later open repeats (the shared table), one this
    /// run's fixed ask and home repeat, or a machine not reached before any file was admitted.
    ///
    /// The home and a resident's Error reply belong to the run's fixed inputs: every Error reply an
    /// unobserved Open can get (a home it cannot read, a request it cannot decode) repeats for this ask,
    /// and a passing fault comes back as a typed refusal or no reply at all. A machine not reached before
    /// any admission is a fact about the machine, so every file would repeat it; after one, the path
    /// dropped, and the next file redials.
    fn ends(&self, unopened: &Unopened) -> bool {
        unopened.ends_run()
            || matches!(unopened, Unopened::Home(_) | Unopened::ServeError(_))
            || (unopened.unreached() && !self.admitted_any.get())
    }

    /// A file stream was admitted: the first gives the signal, so the question is asked from now, and
    /// never ahead of it.
    fn admitted(&self) {
        self.admitted_any.set(true);
        let Some(admitted) = self.admitted.take() else {
            return;
        };
        admitted.asked_through(self.source, self.key);
    }
}

/// Why one file was not sent: its stream was not opened, kept typed for the run to sort; its transfer
/// broke after the stream attached, which `serve` stopping under it does; or it failed some other way.
/// Each failure carries its line.
enum Unsent {
    Unopened(Unopened),
    /// The transfer broke after the open: the run asks whether `serve` went before it skips the file.
    Cut(eyre::Report),
    Failed(eyre::Report),
}

/// Push one file over its own admitted stream, opened through `first`'s source as `ask` asks: hash it,
/// open the stream, and drive the transfer, naming the file by its relative name so the receiver saves
/// it under that name. The file's name and length once it is sent, else its name and why not, so the
/// skip line names the file.
async fn send_one<'s, S: StreamSource + Copy + 's>(
    first: &First<'_, 's, S>,
    ask: &Ask,
    name: String,
    path: PathBuf,
) -> Result<(String, u64), (String, Unsent)> {
    match send_named(first, ask, &name, &path).await {
        Ok(len) => Ok((name, len)),
        Err(unsent) => Err((name, unsent)),
    }
}

/// [`send_one`]'s body: the file's length once it is sent.
async fn send_named<'s, S: StreamSource + Copy + 's>(
    first: &First<'_, 's, S>,
    ask: &Ask,
    name: &str,
    path: &Path,
) -> Result<u64, Unsent> {
    let blob = {
        let mut file = tokio::fs::File::open(path)
            .await
            .wrap_err("open")
            .map_err(Unsent::Failed)?;
        Blob::hash(&mut file)
            .await
            .map_err(|error| Unsent::Failed(error.into()))?
    };

    let opened = first.source.open(ask).await.map_err(Unsent::Unopened)?;
    first.admitted();
    let mut source = tokio::fs::File::open(path)
        .await
        .wrap_err("open")
        .map_err(Unsent::Failed)?;
    Transfer::new(opened.write, opened.read)
        .send(name.as_bytes(), &blob, &mut source)
        .await
        .map_err(|error| Unsent::Cut(peer_error(&error)))?;
    Ok(blob.len())
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
    let meta = tokio::fs::metadata(root).await.wrap_err("stat")?;

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
