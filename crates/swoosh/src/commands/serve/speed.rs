use std::sync::Arc;

use measure::{Limits, MethodRefusal};
use tightbeam::open_policy::OptIn;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, Metering, ServeError, Served};
use tokio::sync::{Semaphore, SemaphorePermit};

use super::engine_failure;

/// The `speed:` handler swoosh injects: the bandwidth-eating throughput half of reach diagnostics,
/// behind the node's gate. It answers one speed transfer over the admitted stream and REFUSES a ping frame
/// at the wire. OPT-IN: a raw diagnostics drain, so an open gate over it is a saturable uplink handed to
/// anyone unless the route is metered; a node that DELIBERATELY wants to advertise as a public speedtest
/// server opts in with `--public speed`.
///
/// The route's [`Limits`] decide whether the transfer bound applies. Metered, one transfer runs at a
/// time (a second concurrent caller is refused with the typed busy frame, never queued or given a share
/// of the uplink) and the responder clamps each direction to the byte cap and the wall clock; unmetered,
/// the transfer mirrors the client and the handler reports `Unmetered`, which an open route narrates on
/// the banner. Interior mutability because every stream shares one handler instance through the registry.
pub(super) struct Speed {
    limits: Limits,
    /// The transfer slots, shared across streams; `None` when the concurrency bound is off.
    slot: Option<Arc<Semaphore>>,
}

impl Speed {
    /// Serve transfers under `limits`: metered admits one at a time under the responder caps, unmetered
    /// mirrors the client.
    pub(super) fn new(limits: &Limits) -> Self {
        Self {
            limits: *limits,
            slot: limits
                .speed_slots()
                .map(|slots| Arc::new(Semaphore::new(slots))),
        }
    }

    /// Take the one transfer slot, or refuse because another transfer holds it. `None` when the caller
    /// configured no slot bound.
    fn acquire_slot(&self) -> Result<Option<SemaphorePermit<'_>>, ()> {
        match &self.slot {
            Some(slot) => slot.try_acquire().map(Some).map_err(|_| ()),
            None => Ok(None),
        }
    }
}

impl Handler for Speed {
    // OPT-IN: a node that DELIBERATELY wants to advertise as a public speedtest server opts in with
    // `--public speed`; otherwise the family gate is the terminator.
    type Exposure = OptIn;

    /// The route's bound, read back from what it actually applies: a metered route is a priced unit, an
    /// unmetered one warns when it is open.
    fn metering(&self) -> Metering {
        if self.limits.is_metered() {
            Metering::Metered
        } else {
            Metering::Unmetered
        }
    }

    async fn serve(
        &self,
        _served: Served<Self>,
        mut writer: BoxWrite,
        mut reader: BoxRead,
    ) -> Result<(), ServeError> {
        let _permit = match self.acquire_slot() {
            Ok(permit) => permit,
            Err(()) => {
                return measure::responder::refuse(
                    &mut writer,
                    MethodRefusal::Busy,
                    "speed busy, try again shortly",
                )
                .await
                .map_err(engine_failure);
            }
        };
        measure::answer_speed(&mut writer, &mut reader, self.limits)
            .await
            .map_err(engine_failure)
    }
}

#[cfg(test)]
mod speed_tests {
    use measure::Limits;

    use super::Speed;

    /// The speed slot admits exactly one transfer at a time and refuses the second immediately.
    #[test]
    fn speed_slot_refuses_a_second_transfer() {
        let speed = Speed::new(&Limits::metered());
        let held = speed
            .acquire_slot()
            .expect("the first transfer takes the slot");
        assert!(held.is_some(), "a metered speed holds a slot");
        assert!(
            speed.acquire_slot().is_err(),
            "a second concurrent transfer is refused, never queued"
        );
        drop(held);
        assert!(
            speed.acquire_slot().is_ok(),
            "dropping the transfer frees the slot"
        );
        assert!(Speed::new(&Limits::unmetered()).acquire_slot().is_ok());
    }

    /// The metering a banner reads is the configuration the handler applies, never a frozen flag.
    #[test]
    fn metering_reads_the_limits() {
        use tightbeam::tunnel::{Handler as _, Metering};
        assert_eq!(Speed::new(&Limits::metered()).metering(), Metering::Metered);
        assert_eq!(
            Speed::new(&Limits::unmetered()).metering(),
            Metering::Unmetered
        );
    }
}
