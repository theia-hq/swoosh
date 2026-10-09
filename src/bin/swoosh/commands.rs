//! The verb tree. `main` dispatches to a leaf command's `run`; each leaf lives in its own file and owns
//! an `async fn run(self, ...)` that consumes it.

pub mod connect;
pub mod contact;
pub mod forward;
pub mod invite;
pub mod join;
pub mod leave;
pub mod lock;
pub mod machine;
pub mod ping;
pub mod proxy;
pub mod revoke;
pub mod root;
pub mod send;
pub mod serve;
pub mod service;
pub mod share;
pub mod speed;
pub mod ssh;
pub mod status;
pub mod stop;
pub mod sync;
pub mod tree;
