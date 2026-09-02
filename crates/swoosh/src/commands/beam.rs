//! `swoosh beam <path>... <peer>`: PUSH a file or directory to a peer, verified end to end.
//!
//! The sender-initiates half of file transfer: you dial a waiting receiver (a node serving `beam:`), open
//! one stream per file, and drive [`bifrost::wire`]'s verified [`Transfer`](bifrost::wire::Transfer)
//! directly, the same engine `swoosh serve beam=beam:` receives with. A directory expands to every file
//! under it, and files pipeline over concurrent streams (capped so one connection is not flooded); a file
//! that cannot be read is skipped and reported, not fatal, so a courier sends what it can.
//!
//! The `beam:` service is family-gated like `ping`/`speed`, so beam presents the same self-signed
//! membership badge (or an explicit `--present` link) to prove membership before the receiver admits a
//! stream. Integrity is checked end to end by `bifrost-wire`: the sender hashes each file with BLAKE3 and
//! the receiver re-hashes as bytes arrive, so a truncated or tampered transfer is rejected, never written.

use std::path::{Path, PathBuf};

use bifrost::wire::{Blob, Transfer};
use bifrost::{Discovery, Node, Session, Transport};
use clap::Args;
use eyre::WrapErr as _;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;

use crate::commands::tunnel_connect::Dial;
use crate::contacts::Contacts;
use crate::transport::ReachArgs;

/// The service name a receiver publishes and beam reaches: `swoosh serve beam=beam:` receives, `swoosh
/// beam` pushes.
pub const BEAM_SERVICE: &str = "beam";

/// Files send concurrently over separate streams, capped so one connection is not flooded. Matches iris's
/// pipeline depth; a receiver's exposer accepts these streams concurrently too, so both sides fan out.
const MAX_INFLIGHT: usize = 16;

/// Push a file or directory to a peer, addressed by their public key, verified end to end.
#[derive(Debug, Args)]
pub struct BeamCmd {
    /// The files or directories to push.
    #[arg(required = true, value_name = "path")]
    pub paths: Vec<PathBuf>,
    /// who to reach: a saved petname (`alice`, `alice/box`), a raw node id, or a `sheer:` capability link
    // Named `target`, not `peer`: the flattened `ReachArgs` already owns a `--peer` arg (its clap id is
    // `peer`), so a positional field named `peer` collides two args under one clap id (a panic at --help).
    // The help still reads `<peer>` via `value_name`.
    #[arg(value_name = "peer")]
    pub target: Dial,
    /// present a `sheer:` capability link alongside a raw node id
    #[arg(long, value_name = "link")]
    pub present: Option<String>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl crate::reaching::Reaching for BeamCmd {
    fn reach_args(&self) -> &crate::transport::ReachArgs {
        &self.reach
    }

    /// `beam` pushes to the peer's family-gated `beam:` service, so it presents the member badge rooted
    /// at the dialing key. `Family` fuses the identity to `PersistedIfPresent`.
    fn credential(&self) -> crate::credential::Credential {
        crate::credential::Credential::Family { present: None }
    }

    fn identity(&self) -> crate::identity::Identity {
        self.credential().identity()
    }

    /// Uniform dispatch: unpack the reach context and run. `beam` reads the resolved `present` badge and
    /// `contacts` (to resolve a petname in its peer slot); it ignores `transport` and `key`.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: crate::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        self.run_beam(node, ctx.contacts, ctx.present).await
    }
}

impl BeamCmd {
    /// Reach the peer's `beam:` service and push every named file over its own gated stream, expanding
    /// directories first. Presents `self_badge` (the self-signed membership badge, or an explicit
    /// `--present` link) so the receiver's family gate admits each stream. A file that cannot be read is
    /// skipped and reported; the run ends non-zero if any item failed.
    async fn run_beam<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        self_badge: Option<String>,
    ) -> eyre::Result<()> {
        // Present an explicit `--present` link if given, else the self-signed badge minted from this
        // identity: the peer's `beam` service is gated, so each stream must prove membership to be admitted.
        let present = self.present.or(self_badge);
        let connector = self
            .target
            .connector(contacts, BEAM_SERVICE.to_owned(), present)?;
        let dial = connector.dial();
        println!("beaming to {dial}...");
        // A service-scoped session: each `open_bi` speaks the `beam:` request and presents the badge, so
        // every per-file stream is admitted by the receiver's gate on its own merits.
        let session = connector.open_service(node).await?;

        // Expand directories, then pipeline up to MAX_INFLIGHT files over concurrent streams.
        let mut files = Vec::new();
        let mut failures = 0usize;
        for path in &self.paths {
            match collect_files(path).await {
                Ok(collected) => files.extend(collected),
                Err(error) => {
                    eprintln!("skip {}: {error:#}", path.display());
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
            if let Err(error) = result {
                eprintln!("skip: {error:#}");
                failures += 1;
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

/// Push one file over its own admitted stream: hash it, open a gated stream, and drive the verified
/// transfer, naming the file by its relative name so the receiver saves it under that name.
async fn send_one<S: Session>(session: &S, name: String, path: PathBuf) -> eyre::Result<()> {
    let blob = {
        let mut file = tokio::fs::File::open(&path)
            .await
            .wrap_err_with(|| format!("open {}", path.display()))?;
        Blob::hash(&mut file).await?
    };

    let (send, recv) = session.open_bi().await?;
    let mut source = tokio::fs::File::open(&path)
        .await
        .wrap_err_with(|| format!("open {}", path.display()))?;
    Transfer::new(send, recv)
        .send(name.as_bytes(), &blob, &mut source)
        .await?;

    println!("sent {name} ({} bytes)", blob.len());
    Ok(())
}

/// Collect `(relative name, path)` pairs to send: a file yields itself; a directory yields every file
/// under it, named by its path relative to the directory's parent (so the directory name is kept). Ported
/// from iris.
async fn collect_files(root: &Path) -> eyre::Result<Vec<(String, PathBuf)>> {
    let meta = tokio::fs::metadata(root)
        .await
        .wrap_err_with(|| format!("stat {}", root.display()))?;

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
            .wrap_err_with(|| format!("read {}", dir.display()))?;
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
        .ok_or_else(|| eyre::eyre!("path has no file name: {}", path.display()))
}
