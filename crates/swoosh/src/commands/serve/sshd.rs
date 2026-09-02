use nauthy::Admitted;
use tightbeam::open_policy::Never;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler};

/// The `sshd:` handler swoosh injects under the `ssh` feature: a keyless shell. GATED, because a keyless
/// shell is remote code execution with no legitimate public use, so the gate IS its authentication; an open
/// gate over it is refused at [`Exposer::new`](tightbeam::tunnel::Exposer::new). Captures the ssh host-key
/// seed the caller derived from swoosh's identity.
pub(super) struct Sshd {
    pub(super) host_seed: [u8; 32],
}

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
