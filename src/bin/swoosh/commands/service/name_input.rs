use core::convert::Infallible;

use nauthy::Service;

/// Identifies an invalid service name by its one-based position in the input list. Contains no input text or underlying parser error.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("invalid service name at index {index}")]
pub(super) struct NameError {
    /// The service name's one-based position within the input list.
    pub(super) index: usize,
}

// A total clap parser avoids clap retaining the invalid operand in its own error.
pub(super) fn parse(text: &str) -> Result<Option<Service>, Infallible> {
    Ok(swoosh::names::service(text).ok())
}
