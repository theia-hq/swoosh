//! The verb tree. `main` dispatches to a leaf command's `run`; each leaf lives in its own file and owns
//! an `async fn run(self, ...)` that consumes it.

pub mod adopt;
pub mod attenuate;
pub mod contact;
pub mod fetch;
pub mod grant;
pub mod identity;
pub mod mint;
pub mod ping;
pub mod revoke;
pub mod serve;
pub mod share;
pub mod speed;
pub mod ssh;
pub mod status;
pub mod tree;
pub mod tunnel;
pub mod tunnel_connect;
