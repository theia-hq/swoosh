//! beam: receive a pushed file at a keyed node, off an admitted stream.
//!
//! The PUSH half of file transfer: a sender dials, opens one stream per file, and drives
//! [`bifrost::wire`]'s verified [`Transfer`](bifrost::wire::Transfer) to a waiting receiver. This crate is
//! that receiver's per-stream work: read one blob off an admitted stream, verify it end to end (BLAKE3, by
//! `bifrost-wire`), and save it under an output directory, reducing the sender-supplied name to a safe
//! relative path so a peer can never write outside that directory.
//!
//! It is a service crate: it knows what to DO with an admitted stream, never how the peer was reached or
//! gated. The composing consumer wraps [`receive_file`] in a gated handler and injects it
//! into the tunnel's handler registry, so every pushed file rides the same family gate as every other
//! service; the sender side (dial, expand directories, pipeline concurrent streams) is a client verb driving
//! `bifrost-wire` directly.
//!
//! One stream carries one file. The exposer accepts a sender's per-file streams concurrently, so a
//! directory's files land in parallel with no fan-out logic here: each invocation is one file, start to
//! finish.

mod serve;

pub use crate::serve::{receive_file, safe_relative_path};
