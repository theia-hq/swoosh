//! Reach diagnostics over two in-process bifrost nodes: one runs the responder, the other pings and
//! speed-tests it. Hermetic and instant (mem transport, no sockets), and the strongest proof of
//! transport-blindness: the exact client and responder that run over iroh also run here unchanged.

use core::time::Duration;

use bifrost::{Error, NoDiscovery, Node};
use bifrost_mem::MemTransport;
use diag::{Direction, Limit, Ping, Responder, Speedtest};

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
async fn speed_moves_bytes_in_both_directions() {
    for direction in [Direction::Up, Direction::Down] {
        let (serving, session) = paired().await.expect("client should reach the responder");
        let limit_bytes = 4 * 1024 * 1024;

        let report = Speedtest {
            direction,
            limit: Limit::ByBytes(limit_bytes),
        }
        .run(&session)
        .await
        .expect("speed run should succeed over the mem transport");

        assert_eq!(report.direction(), direction);
        assert_eq!(report.bytes(), limit_bytes, "the whole payload should move");
        assert!(
            report.mib_per_sec() > 0.0,
            "throughput should be non-zero, got {}",
            report.mib_per_sec()
        );

        drop(session);
        serving.abort();
    }
}
