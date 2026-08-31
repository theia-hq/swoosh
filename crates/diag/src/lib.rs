//! diag: reach diagnostics over the bifrost overlay.
//!
//! Ping and speed are diagnostics on reach itself, the cheapest high-signal proofs of the thesis: an
//! RTT to a peer addressed by their public key, and throughput over the session that reaches them.
//! Both ride a tiny versioned protocol on bifrost streams and are transport-blind (generic over
//! `bifrost::Session`), so the identical test runs over iroh, mem, and any future transport. That is
//! the payoff: speed is iperf, but over any transport, a built-in transport dyno.
//!
//! diag is TWO services, so a node may advertise one without the other: `diag.ping` (cheap RTT) and
//! `diag.speed` (bandwidth-eating throughput). A node answers them with [`answer_ping`]/[`answer_speed`]
//! (each refuses the other's method at the wire), or serves both over one session with a [`Responder`].
//! A client constructs a [`Ping`] or [`Speedtest`], runs it against a session, and reads back a report.

pub mod ping;
pub mod protocol;
pub mod responder;
pub mod speed;

mod payload;

pub use ping::{Ping, PingReport, Probe};
pub use responder::{Responder, answer, answer_ping, answer_speed};
pub use speed::{Limit, Mode, Progress, SpeedReport, Speedtest, Throughput};
