//! swoosh: work with a machine addressed by its public key, not its address.
//!
//! The library half of swoosh: the node engine and the domain modules the `swoosh` binary composes.
//! The binary (`src/bin/swoosh/main.rs`) owns the CLI surface (the clap tree, the verb modules, and the
//! composition root); everything a verb drives lives here. The engine pieces are public so an integration
//! test can drive the SAME pieces the product path does (notably the shared `serve::diagnostics` and
//! `serve::bind_entry` edges the `gated_measure` proof builds its exposer from).

pub mod badge;
pub mod config;
pub mod contacts;
pub mod credential;
pub mod gate;
pub mod grants;
pub mod home;
pub mod identity;
pub mod invite;
pub mod link;
pub mod names;
pub mod node_client;
pub mod node_signer;
pub mod passphrase;
pub mod peer;
pub mod reach;
pub mod reaching;
pub mod roster;
pub mod secret;
pub mod serve;
pub mod standing;
#[cfg(any(test, feature = "test-support"))]
pub mod testkit;
pub mod transport;
pub mod unbound;
