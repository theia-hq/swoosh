use nauthy::Admitted;
use tightbeam::open_policy::OptIn;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler};

/// The `speed:` handler swoosh injects: the bandwidth-eating throughput half of reach diagnostics,
/// behind the node's gate. It answers one speed transfer over the admitted stream and REFUSES a ping frame
/// at the wire. GATED: `SpeedSource{None}` is a raw diagnostics drain with no responder-side bound yet, so
/// an open gate over it is a saturable uplink handed to anyone; a node that DELIBERATELY wants to advertise
/// as a public speedtest server opts in with `--public speed:`. The family gate is the terminator
/// until the responder-side bound lands.
pub(super) struct Speed;

impl Handler for Speed {
    // OPT-IN: a node that DELIBERATELY wants to advertise as a public speedtest server opts in with
    // `--public speed:`; otherwise the family gate is the terminator.
    type Public = OptIn;

    async fn serve(
        &self,
        _admitted: Admitted,
        mut writer: BoxWrite,
        mut reader: BoxRead,
    ) -> eyre::Result<()> {
        measure::answer_speed(&mut writer, &mut reader).await?;
        Ok(())
    }
}
