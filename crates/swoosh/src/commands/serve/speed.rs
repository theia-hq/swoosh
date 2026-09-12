use tightbeam::open_policy::OptIn;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, Metering, ServeError, Served};

use super::engine_failure;

/// The `speed:` handler swoosh injects: the bandwidth-eating throughput half of reach diagnostics,
/// behind the node's gate. It answers one speed transfer over the admitted stream and REFUSES a ping frame
/// at the wire. OPT-IN: a raw diagnostics drain with no responder-side bound yet, so an open gate over it
/// is a saturable uplink handed to anyone; a node that DELIBERATELY wants to advertise as a public
/// speedtest server opts in with `--public speed`.
pub(super) struct Speed;

impl Handler for Speed {
    // OPT-IN: a node that DELIBERATELY wants to advertise as a public speedtest server opts in with
    // `--public speed`; otherwise the family gate is the terminator.
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
        measure::answer_speed(&mut writer, &mut reader)
            .await
            .map_err(engine_failure)
    }
}
