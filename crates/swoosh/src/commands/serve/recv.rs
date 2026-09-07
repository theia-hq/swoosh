use core::sync::atomic::{AtomicU64, Ordering};
use std::path::PathBuf;

use nauthy::Admitted;
use tightbeam::open_policy::Never;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler};

/// The `recv:` handler swoosh injects: the receive half of PUSH file transfer. It takes one admitted stream
/// carrying one pushed file, drives `bifrost-wire`'s verified receive into a temp file under `out`, and
/// moves it into place at the safe relative path the sender named. GATED, because a receive service with no
/// auth of its own would let anyone write files into the node's output directory; the gate IS its
/// authentication. Each stream gets a unique tag from a shared counter, so concurrent pushes never contend
/// for the same temp file.
pub struct Recv {
    out: PathBuf,
    next_tag: AtomicU64,
}

impl Recv {
    /// Build a receiver that saves pushed files into `out`. Each de-merged `name=recv:<dir>` service holds
    /// its OWN `Recv` bound to its OWN `out`, so two receive services never share a sink directory.
    pub fn new(out: PathBuf) -> Self {
        Self {
            out,
            next_tag: AtomicU64::new(0),
        }
    }
}

impl Handler for Recv {
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
        let received = transfer::receive_file(writer, reader, &self.out, tag).await?;
        println!(
            "received {} ({} bytes)",
            received.path.display(),
            received.bytes
        );
        Ok(())
    }
}
