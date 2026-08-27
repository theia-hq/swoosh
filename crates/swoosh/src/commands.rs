//! The verb tree. `main` dispatches to a leaf command's `run`; each leaf lives in its own file and owns
//! an `async fn run(self, ...)` that consumes it.

pub mod contact;
pub mod ping;
pub mod serve;
pub mod speed;
pub mod status;
pub mod tree;
