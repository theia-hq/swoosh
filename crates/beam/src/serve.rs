//! The receive handler: take one admitted stream, receive one verified blob into
//! a temp file, then move it into place under the output directory, named by a peer-supplied header reduced
//! to a safe relative path.

use std::path::{Path, PathBuf};

use bifrost::wire::Transfer;
use tokio::io::{self, AsyncWriteExt as _};

/// Receive one pushed file over an admitted stream: stream it into a temp file under `out`, verify it end
/// to end (`bifrost-wire` checks every byte against the sender's BLAKE3 root), then move it into place at
/// the safe relative path the sender named. On any failure the temp file is removed, so a rejected or
/// truncated transfer never leaves a partial file behind.
///
/// The handler the composing consumer injects into the tunnel's handler registry calls this with one
/// admitted stream's halves and the node's configured output directory; the exposer hands each of the sender's per-file
/// streams here concurrently, so a directory's files are received in parallel.
///
/// `tag` distinguishes concurrent temp files on one node (the caller passes a per-stream value), so two
/// files arriving at once never contend for the same temp path.
pub async fn receive_file<W, R>(
    writer: W,
    reader: R,
    out: &Path,
    tag: u64,
) -> eyre::Result<Received>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    let temp = out.join(format!(".beam-{}-{tag}.part", std::process::id()));
    let received = {
        let file = tokio::fs::File::create(&temp).await?;
        let mut sink = file;
        match Transfer::new(writer, reader).recv(&mut sink).await {
            Ok(received) => {
                sink.flush().await?;
                received
            }
            Err(err) => {
                drop(sink);
                let _ = tokio::fs::remove_file(&temp).await;
                return Err(err.into());
            }
        }
    };

    let relative = safe_relative_path(&received.header);
    let final_path = out.join(&relative);
    if let Some(parent) = final_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::rename(&temp, &final_path)
        .await
        .map_err(|err| eyre::eyre!("save to {}: {err}", final_path.display()))?;

    Ok(Received {
        path: relative,
        bytes: received.blob.len(),
    })
}

/// One received file: the safe relative path it was saved at under the output directory, and its verified
/// byte length. Returned so the caller can report what landed.
#[derive(Debug, Clone)]
pub struct Received {
    /// The path the file was saved at, relative to the output directory.
    pub path: PathBuf,
    /// The verified length of the received bytes.
    pub bytes: u64,
}

/// Reduce a peer-supplied header to a safe relative path under the output directory: keep only normal
/// components, dropping roots, prefixes, and `..`, so a peer cannot write outside it. An all-stripped or
/// empty header falls back to `download`, so a pushed blob always lands somewhere nameable.
///
/// LOAD-BEARING: this is the path-traversal guard on the receive side. Without it a sender could name
/// `../../etc/authorized_keys` and write outside the output directory. Ported verbatim from iris; keep it.
pub fn safe_relative_path(header: &[u8]) -> PathBuf {
    let raw = String::from_utf8_lossy(header);
    let mut safe = PathBuf::new();
    for component in Path::new(raw.as_ref()).components() {
        if let std::path::Component::Normal(part) = component {
            safe.push(part);
        }
    }
    if safe.as_os_str().is_empty() {
        safe.push("download");
    }
    safe
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod serve_tests;
