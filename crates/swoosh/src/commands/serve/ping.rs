use tightbeam::open_policy::OptIn;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, Metering, ServeError, Served};

use super::engine_failure;

/// The `ping:` handler swoosh injects: the cheap RTT half of reach diagnostics, behind the node's
/// gate. It answers one ping run over the admitted stream and REFUSES a speed frame at the wire, so a grant
/// for `ping` can never open the speed drain. OPT-IN for now (an open gate over it, `--public
/// ping`, is a deliberate opt-out a node makes to advertise as a public ping responder); a member is
/// admitted whole-node.
pub(super) struct Ping;

impl Handler for Ping {
    // OPT-IN: an open gate over it (`--public ping`) is a deliberate opt-out a node makes to advertise as
    // a public ping responder; a member is otherwise admitted whole-node.
    type Exposure = OptIn;

    // No responder-side rate limit yet, so the fail-safe default (`Unmetered`) stands and the readiness
    // banner narrates the caveat when the service is open. The service-owned limiter (rate-limit-spec)
    // lands with the engine move and overrides this to `Metered`.
    fn metering(&self) -> Metering {
        Metering::Unmetered
    }

    async fn serve(
        &self,
        _served: Served<Self>,
        mut writer: BoxWrite,
        mut reader: BoxRead,
    ) -> Result<(), ServeError> {
        measure::answer_ping(&mut writer, &mut reader)
            .await
            .map_err(engine_failure)
    }
}
