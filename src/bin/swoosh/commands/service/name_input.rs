use nauthy::Service;
use swoosh::names::{NameError as Refused, ReservedService};

/// Identifies an invalid service name by its one-based position in the input list. Contains no input text or underlying parser error.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("invalid service name at index {index}")]
pub(super) struct NameError {
    /// The service name's one-based position within the input list.
    pub(super) index: usize,
}

// Total but for a reserved word, so clap never retains an invalid operand in its own error; a reserved word
// is one of five fixed ones, refused at parse with its own line.
pub(super) fn parse(text: &str) -> Result<Option<Service>, ReservedService> {
    match swoosh::names::service(text) {
        Ok(service) => Ok(Some(service)),
        Err(Refused::ReservedService(reserved)) => Err(reserved),
        Err(Refused::NotAName(_) | Refused::Reserved(_)) => Ok(None),
    }
}
