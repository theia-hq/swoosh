//! `swoosh send <path>... <peer>`: PUSH a file or directory to a peer, verified end to end.
//!
//! The sender-initiates half of file transfer: you dial a waiting receiver (a node serving `recv:`), open
//! one stream per file, and drive [`bifrost::wire`]'s verified [`Transfer`](bifrost::wire::Transfer)
//! directly, the same engine `swoosh serve recv=recv:` receives with. A directory expands to every file
//! under it, and files pipeline over concurrent streams (capped so one connection is not flooded); a file
//! that cannot be read is skipped and reported, not fatal, so a courier sends what it can.
//!
//! The `recv:` service is family-gated like `ping`/`speed`, so send presents the same self-signed
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
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::peer::Peer;
use swoosh::transport::ReachArgs;

/// The service name a receiver publishes and `swoosh send` reaches: `swoosh serve recv=recv:` receives,
/// `swoosh send` pushes.
pub const RECV_SERVICE: &str = "recv";

/// Files send concurrently over separate streams, capped so one connection is not flooded. Matches iris's
/// pipeline depth; a receiver's exposer accepts these streams concurrently too, so both sides fan out.
const MAX_INFLIGHT: usize = 16;

/// The longest a pushed file's name may render on the sender's own `sent` line, in characters. Mirrors
/// the receiver's cap for a peer-supplied path (`services/crates/transfer/src/handler.rs`,
/// `MAX_RENDERED_PATH`), so both ends of one transfer render a hostile name in the same bounded shape.
const MAX_RENDERED_NAME: usize = 256;

/// Push a file or directory to a peer, addressed by their public key, verified end to end.
#[derive(Debug, Args)]
pub struct SendCmd {
    /// The files or directories to push.
    #[arg(required = true, value_name = "path")]
    pub paths: Vec<PathBuf>,
    /// the peer to reach: a petname (`alice`, `alice/desk`), a raw node id, or a `sheer:` link
    #[arg(value_name = "peer")]
    pub peer: Peer,
    /// the peer's file-receiving service
    #[arg(long, value_name = "service", default_value = RECV_SERVICE)]
    pub service: String,
    /// present a `sheer:` link to reach as a delegate
    #[arg(
        long,
        value_name = "link",
        long_help = "Optional: your own devices need no link; this machine's membership badge is \
                     presented automatically. Pass a `sheer:` link only to reach as a delegate."
    )]
    pub present: Option<Link>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl swoosh::reaching::Reaching for SendCmd {
    fn reach_args(&self) -> &swoosh::transport::ReachArgs {
        &self.reach
    }

    /// `send` pushes to the peer's family-gated `recv:` service, so it presents the member badge rooted
    /// at the dialing key. `Family` fuses the identity to `PersistedIfPresent`. The effective slip is the
    /// FOLD of a self-addressing `sheer:` link-as-peer with an explicit `--present`, threaded INTO the
    /// credential so the ONE resolver owns both slots (so a signet-bound link-as-peer computes its slot-2
    /// badge exactly as a `--present` link does).
    fn credential(&self) -> swoosh::credential::Credential {
        swoosh::credential::Credential::family(
            self.peer.self_present().or_else(|| self.present.clone()),
        )
    }

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        self.peer.reject_redundant_present(self.present.as_ref())
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.credential().identity()
    }

    /// Dialing only: this verb reaches a peer, it never accepts connections under the home key, so its
    /// bind must not write the key's address record (0.9.0 F1).
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing
    }

    /// Uniform dispatch: unpack the reach context and run. `send` reads the resolved `present` badge and
    /// `contacts` (to resolve a petname in its peer slot); it ignores `transport` and `key`.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        self.run_send(node, ctx.contacts, ctx.present, ctx.membership)
            .await
    }
}

impl SendCmd {
    /// Reach the peer's `recv:` service and push every named file over its own gated stream, expanding
    /// directories first. Presents the resolved `present` (the self-signed membership badge, or an explicit
    /// `--present` link) so the receiver's family gate admits each stream. A file that cannot be read is
    /// skipped and reported; the run ends non-zero if any item failed.
    async fn run_send<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        present: Option<Link>,
        membership: Option<Link>,
    ) -> eyre::Result<()> {
        // Slots 1 and 2 are ALREADY resolved by the composition root's ONE resolver (present-or-badge in
        // slot 1, a fleet badge in slot 2 only for a signet-bound slip); the fold in `credential()` routed a
        // link-as-peer through that same resolver, and the redundant-present conflict was rejected there too
        // (`Reaching::reject_redundant_present`), so the verb never threads `--present` itself.
        let service = self.service.parse::<Service>()?;
        let connector = self
            .peer
            .connector(contacts, service, present, membership)?;
        let dial = connector.dial();
        println!("sending to {dial}...");
        // A service-scoped session: each `open_bi` speaks the `recv:` request and presents the badge, so
        // every per-file stream is admitted by the receiver's gate on its own merits.
        let session = connector.open_service(node).await?;

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
            .wrap_err_with(|| format!("open {}", render_path(&path)))?;
        Blob::hash(&mut file).await?
    };

    let (send, recv) = session.open_bi().await?;
    let mut source = tokio::fs::File::open(&path)
        .await
        .wrap_err_with(|| format!("open {}", render_path(&path)))?;
    Transfer::new(send, recv)
        .send(name.as_bytes(), &blob, &mut source)
        .await?;

    println!("sent {} ({} bytes)", render_name(&name), blob.len());
    Ok(())
}

/// Render a pushed file's name for the sender's own `sent` line: escape control characters and cap the
/// rendered length, the same rule the receive engine applies to a peer-supplied path
/// (`services/crates/transfer/src/handler.rs`, `render_path`). A raw newline forges a line, a carriage
/// return rewrites one, and ESC drives a terminal, so a directory holding a hostile name must not echo
/// it raw. That helper is crate-private to the services repo's transfer engine, so the rule is stated
/// here in the same shape and the two ends of one transfer render a name alike.
fn render_name(name: &str) -> String {
    // The cap plus the `...` cut marker: allocation is bounded whatever the file is named.
    let mut rendered = String::with_capacity(MAX_RENDERED_NAME + 3);
    let mut written = 0usize;
    for ch in name.chars() {
        let width = ch.escape_debug().count();
        if written + width > MAX_RENDERED_NAME {
            rendered.push_str("...");
            break;
        }
        rendered.extend(ch.escape_debug());
        written += width;
    }
    rendered
}

/// Render a PATH for a line or an error context through the SAME escape discipline as a file name.
/// Every path this verb prints or wraps must come through here, including the paths inside an error
/// context: the skip line renders its own prefix escaped and then prints the whole error chain, so a
/// context built with a raw `Path::display` leaks the newline or ESC the prefix just escaped.
fn render_path(path: &Path) -> String {
    render_name(&path.display().to_string())
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
