//! diag: reach diagnostics over the bifrost overlay.
//!
//! Ping and speed are diagnostics on reach itself, the cheapest high-signal proofs of the thesis: an
//! RTT to a peer addressed by their public key, and throughput over the session that reaches them.
//! Both ride a tiny versioned protocol on bifrost streams and are transport-blind (generic over
//! `bifrost::Session`), so the identical test runs over iroh, mem, and any future transport. That is
//! the payoff: speed is iperf, but over any transport, a built-in transport dyno.
//!
//! A node answers these by running a [`Responder`] on each session it accepts. A client constructs a
//! [`Ping`] or [`Speedtest`], runs it against a session, and reads back a report.

pub mod ping;
pub mod protocol;
pub mod responder;
pub mod speed;

mod payload;

pub use ping::{Ping, PingReport};
pub use responder::{Responder, answer};
pub use speed::{Limit, Mode, Progress, SpeedReport, Speedtest, Throughput};
