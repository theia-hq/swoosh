//! Reach diagnostics over two in-process bifrost nodes: one runs the responder, the other pings and
//! speed-tests it. Hermetic and instant (mem transport, no sockets), and the strongest proof of
//! transport-blindness: the exact client and responder that run over iroh also run here unchanged.

use core::time::Duration;

use bifrost::{Error, NoDiscovery, Node};
use bifrost_mem::MemTransport;
use measure::{Limit, Mode, Ping, Responder, Speedtest};

/// A responder node serving in the background, and a live client session to it, over one mem process.
type Paired = (tokio::task::JoinHandle<()>, bifrost_mem::MemSession);

/// Bring up a responder node and a client session to it, sharing one mem-transport process.
async fn paired() -> Result<Paired, Error> {
    let responder = Node::new(MemTransport::bind(), NoDiscovery);
    let responder_id = responder.node_id();
    let client = Node::new(MemTransport::bind(), NoDiscovery);

    let serving = tokio::spawn(async move {
        if let Ok(session) = responder.accept().await {
            Responder::serve(session).await;
        }
    });

    let session = client.connect(responder_id).await?;
    Ok((serving, session))
}

#[tokio::test]
async fn ping_measures_round_trips_with_no_loss() {
    let (serving, session) = paired().await.expect("client should reach the responder");

    let report = Ping {
        count: 3,
        interval: Duration::from_millis(1),
    }
    .run(&session)
    .await
    .expect("ping run should succeed over the mem transport");

    assert_eq!(report.sent(), 3);
    assert_eq!(report.received(), 3, "every probe should be echoed");
    assert_eq!(report.loss(), 0.0);
    let avg = report.avg().expect("an average rtt with replies");
    assert!(avg < Duration::from_secs(1), "in-process rtt is tiny");

    drop(session);
    serving.abort();
}

#[tokio::test]
async fn observing_reports_every_probe_in_order_as_it_lands() {
    // The live-view path: `observing` must call back once per probe, in sequence order, each carrying a
    // round-trip time (no loss over mem). This is what the `-v` ping surface watches to print a line per
    // pong and sample the path beside each.
    let (serving, session) = paired().await.expect("client should reach the responder");

    let mut seen = Vec::new();
    let report = Ping {
        count: 3,
        interval: Duration::from_millis(1),
    }
    .observing(&session, |probe| {
        seen.push((probe.seq, probe.rtt.is_some()))
    })
    .await
    .expect("observed ping run should succeed over the mem transport");

    assert_eq!(
        seen,
        vec![(0, true), (1, true), (2, true)],
        "every probe is observed once, in order, with a measured rtt"
    );
    assert_eq!(report.received(), 3, "the report still gathers every reply");

    drop(session);
    serving.abort();
}

#[tokio::test]
async fn speed_moves_bytes_in_each_direction() {
    for mode in [Mode::Up, Mode::Down] {
        let (serving, session) = paired().await.expect("client should reach the responder");
        let limit_bytes = 4 * 1024 * 1024;

        let report = Speedtest::new(mode, Limit::ByBytes(limit_bytes))
            .run(&session)
            .await
            .expect("speed run should succeed over the mem transport");

        // A one-way run fills exactly the measured leg and leaves the other empty.
        let (measured, empty) = match mode {
            Mode::Up => (report.up(), report.down()),
            Mode::Down => (report.down(), report.up()),
            Mode::Bidir => unreachable!("only one-way modes in this case"),
        };
        assert!(empty.is_none(), "a one-way run measures a single direction");
        let leg = measured.expect("the measured direction has a throughput");
        assert_eq!(leg.bytes(), limit_bytes, "the whole payload should move");
        assert!(
            leg.mib_per_sec() > 0.0,
            "throughput should be non-zero, got {}",
            leg.mib_per_sec()
        );

        drop(session);
        serving.abort();
    }
}

#[tokio::test]
async fn bidir_moves_bytes_in_both_directions_at_once() {
    // Full-duplex on the one stream: both legs move counted bytes over the same window. This is the
    // path that must also work over a single-stream transport (quirk); mem proves the mechanism.
    let (serving, session) = paired().await.expect("client should reach the responder");
    let limit_bytes = 4 * 1024 * 1024;

    let report = Speedtest::new(Mode::Bidir, Limit::ByBytes(limit_bytes))
        .run(&session)
        .await
        .expect("bidir speed run should succeed over the mem transport");

    let up = report.up().expect("bidir measures the upload leg");
    let down = report.down().expect("bidir measures the download leg");
    assert_eq!(up.bytes(), limit_bytes, "the whole upload should move");
    assert_eq!(down.bytes(), limit_bytes, "the whole download should move");
    assert!(
        up.mib_per_sec() > 0.0 && down.mib_per_sec() > 0.0,
        "both directions should have non-zero throughput, got up {} down {}",
        up.mib_per_sec(),
        down.mib_per_sec()
    );

    drop(session);
    serving.abort();
}

#[tokio::test]
async fn time_bounded_speed_respects_the_duration_not_a_byte_count() {
    // The riskiest path: a time bound must end the run on the wall clock, never a fixed byte budget.
    // Over mem (far faster than any assumed rate) a short window still moves millions of bytes, which a
    // stale byte-budget heuristic would have truncated well before the deadline.
    let requested = Duration::from_millis(250);
    for mode in [Mode::Up, Mode::Down, Mode::Bidir] {
        let (serving, session) = paired().await.expect("client should reach the responder");

        let report = Speedtest::new(mode, Limit::ByTime(requested))
            .run(&session)
            .await
            .expect("time-bounded speed run should succeed over the mem transport");

        // Every measured leg moved bytes at a non-zero rate; bidir measures two, one-way measures one.
        let legs = [report.up(), report.down()].into_iter().flatten();
        let mut measured = 0u32;
        for leg in legs {
            measured += 1;
            assert!(
                leg.bytes() > 0 && leg.mib_per_sec() > 0.0,
                "throughput should be non-zero, got {} bytes at {} MiB/s",
                leg.bytes(),
                leg.mib_per_sec()
            );
        }
        let expected_legs = if mode == Mode::Bidir { 2 } else { 1 };
        assert_eq!(measured, expected_legs, "leg count matches the mode");
        // The run honors the requested duration: it does not stop early on a byte count, and overshoot
        // is bounded to one 64 KiB chunk plus scheduling, so the window brackets the request.
        assert!(
            report.elapsed() >= requested,
            "a time bound must run for at least the requested {requested:?}, ran {:?}",
            report.elapsed()
        );
        assert!(
            report.elapsed() < requested * 4,
            "the run should end near the deadline, not stream on, took {:?}",
            report.elapsed()
        );

        drop(session);
        serving.abort();
    }
}
