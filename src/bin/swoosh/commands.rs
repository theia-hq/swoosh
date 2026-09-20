//! The verb tree. `main` dispatches to a leaf command's `run`; each leaf lives in its own file and owns
//! an `async fn run(self, ...)` that consumes it.

pub mod adopt;
pub mod attenuate;
pub mod contact;
pub mod fetch;
pub mod fleet;
pub mod grant;
pub mod grant_ls;
pub mod identity;
pub mod invite;
pub mod ping;
pub mod reach;
pub mod recut;
pub mod revoke;
pub mod send;
pub mod serve;
pub mod service;
pub mod share;
pub mod speed;
pub mod ssh;
pub mod status;
pub mod stop;
pub mod tree;
pub mod tunnel_connect;
