use tightbeam::open_policy::Never;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, ServeError, Served};

use super::engine_failure;

/// The `sshd:` handler swoosh injects under the `ssh` feature: a keyless shell. GATED, because a keyless
/// shell is remote code execution with no legitimate public use, so the gate IS its authentication; an open
/// gate over it is refused at [`Router::expose`](tightbeam::tunnel::Router::expose). Captures the ssh
/// host-key seed the caller derived from swoosh's identity.
pub(super) struct Sshd {
    pub(super) host_seed: [u8; 32],
}

impl Handler for Sshd {
    // NEVER: a keyless shell is remote code execution with no legitimate public use, so the gate IS its
    // authentication; an open gate over it is refused at `Router::expose`.
    type Exposure = Never;

    async fn serve(
        &self,
        served: Served<Self>,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> Result<(), ServeError> {
        // The one narrowing seam: an engine whose safety precondition is a verified peer can never be
        // handed an open witness, so `into_rooted` refuses the open case here, before `Response::Ok`. The
        // transitional `into_admitted` hands today's `sshh::serve` the rooted witness it takes; the
        // engine move (pass 3) makes `sshh::serve` take the rooted proof directly and deletes it.
        let rooted = served.into_rooted()?.into_admitted();
        sshh::serve(rooted, self.host_seed, writer, reader)
            .await
            .map_err(engine_failure)
    }
}
