//! The routes every `serve` binds that answer other roots' machines, not only this root's devices: a sibling
//! of the family-only [`control`](super::control) group, never in it. Each route's handler lives in the file
//! named for the route, and is reached by its path (`lookup::Root`).

mod root;

#[cfg(test)]
pub(crate) use root::answer;
pub use root::{Devices, Root};
