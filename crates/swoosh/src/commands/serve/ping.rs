use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use measure::{Limits, MethodRefusal};
use nauthy::VerifyKey;
use tightbeam::open_policy::OptIn;
use tightbeam::tunnel::{BoxRead, BoxWrite, Handler, Metering, ServeError, Served};

use super::engine_failure;

/// The `ping:` handler swoosh injects: the cheap RTT half of reach diagnostics, behind the node's
/// gate. It answers one ping run over the admitted stream and REFUSES a speed frame at the wire, so a grant
/// for `ping` can never open the speed drain. OPT-IN (an open gate over it, `--public ping`, is a
/// deliberate opt-out a node makes to advertise as a public ping responder); a member is admitted
/// whole-node.
///
/// The route's [`Limits`] decide whether the per-caller rate bound applies. Metered, one verified
/// caller's probes are spaced by the configured interval and the map is pruned on refusal and over its
/// cap, so a peer-churn flood cannot grow it without bound; unmetered, every probe is admitted and the
/// handler reports `Unmetered`, which an open route narrates on the banner. Interior mutability because
/// every stream shares one handler instance through the registry.
pub(super) struct Ping {
    limits: Limits,
    /// The last admitted probe per verified caller.
    last: Arc<Mutex<HashMap<VerifyKey, Instant>>>,
}

/// The largest number of distinct callers the ping limiter remembers before it prunes, bounding the map a
/// peer-churn flood can grow.
const PING_MAP_MAX: usize = 8192;

impl Ping {
    /// Serve probes under `limits`: metered spaces one caller's probes, unmetered admits every probe.
    pub(super) fn new(limits: &Limits) -> Self {
        Self {
            limits: *limits,
            last: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Whether this caller may probe now: records the probe when admitted, prunes stale entries on the
    /// refusal path and over the retention cap. A poisoned lock (a panic in another stream's check) admits
    /// rather than wedging the service closed; the per-caller spacing is a floor, not an authority.
    fn admits(&self, peer: VerifyKey) -> bool {
        let Some(interval) = self.limits.ping_interval() else {
            return true;
        };
        let Ok(mut last) = self.last.lock() else {
            return true;
        };
        let now = Instant::now();
        if last
            .get(&peer)
            .is_some_and(|at| now.duration_since(*at) < interval)
        {
            last.retain(|_, at| now.duration_since(*at) < interval);
            return false;
        }
        if last.len() > PING_MAP_MAX {
            last.retain(|_, at| now.duration_since(*at) < interval);
        }
        last.insert(peer, now);
        true
    }
}

impl Handler for Ping {
    // OPT-IN: an open gate over it (`--public ping`) is a deliberate opt-out a node makes to advertise as
    // a public ping responder; a member is otherwise admitted whole-node.
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
        served: Served<Self>,
        mut writer: BoxWrite,
        mut reader: BoxRead,
    ) -> Result<(), ServeError> {
        if !self.admits(served.peer()) {
            return measure::responder::refuse(
                &mut writer,
                MethodRefusal::RateLimited,
                "ping rate limited, try again shortly",
            )
            .await
            .map_err(engine_failure);
        }
        measure::answer_ping(&mut writer, &mut reader)
            .await
            .map_err(engine_failure)
    }
}

#[cfg(test)]
mod ping_tests {
    use measure::Limits;

    use super::Ping;

    /// A deterministic caller key.
    fn peer(byte: u8) -> nauthy::VerifyKey {
        nauthy::Identity::from_secret(&[byte; 32])
            .expect("valid secret")
            .verifying_key()
    }

    /// The ping bound is per caller: the first probe is admitted, a second inside the interval is refused,
    /// and a different caller is unaffected.
    #[test]
    fn ping_spaces_one_callers_probes() {
        let ping = Ping::new(&Limits::metered());
        assert!(ping.admits(peer(1)), "the first probe is admitted");
        assert!(
            !ping.admits(peer(1)),
            "a second probe inside the interval is refused"
        );
        assert!(
            ping.admits(peer(2)),
            "another caller's probe is not blocked by the first caller"
        );
    }

    /// An unmetered ping admits every probe: the bound is off, not merely wide.
    #[test]
    fn unmetered_ping_admits_every_probe() {
        let ping = Ping::new(&Limits::unmetered());
        assert!(ping.admits(peer(1)));
        assert!(ping.admits(peer(1)));
    }

    /// The metering a banner reads is the configuration the handler applies, never a frozen flag.
    #[test]
    fn metering_reads_the_limits() {
        use tightbeam::tunnel::{Handler as _, Metering};
        assert_eq!(Ping::new(&Limits::metered()).metering(), Metering::Metered);
        assert_eq!(
            Ping::new(&Limits::unmetered()).metering(),
            Metering::Unmetered
        );
    }
}
