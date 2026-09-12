//! swoosh: work with a machine addressed by its public key, not its address.
//!
//! The library half of swoosh: the modules the `swoosh` binary composes, exposed so an integration test
//! can drive the SAME pieces the product path does (notably the shared `commands::serve::diagnostics`
//! and `commands::serve::bind_entry` edges the `gated_measure` proof builds its exposer from). The binary
//! (`main.rs`) owns only the CLI surface (the clap tree and the composition root); everything a verb needs
//! lives here, in these modules.

pub mod authkey;
pub mod commands;
pub mod config;
pub mod contacts;
pub mod credential;
pub mod grants;
pub mod home;
pub mod identity;
pub mod node_client;
pub mod peer;
pub mod reach;
pub mod reaching;
pub mod roster;
pub mod secret;
pub mod transport;
