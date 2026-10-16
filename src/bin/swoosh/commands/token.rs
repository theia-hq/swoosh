//! The typed token an act that cannot be undone on a root asks for, one helper for every such act
//! (`revoke root:` and replacing a person's root): the 8 characters after the root's `ed01`, shown in the
//! question, typed back once.
//!
//! It is an intent gate, not a secret: the question prints it, so its job is to make the person read the
//! key the act is about. The same 8 every short form shows, so it is one they have seen.

use swoosh::passphrase::Prompt;
use swoosh::root_key::RootKey;

/// What the person typed back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Typed {
    /// The token, exactly (whitespace around it aside).
    Matched,
    /// Anything else: one try, so the act does not go ahead.
    Other,
}

/// Ask for `root`'s token at `prompt`, in a question that names `act` ("revoke this root for good"): "Type
/// <token> to <act>:". The caller checks for a terminal first and words its own refusals.
///
/// # Errors
///
/// The prompt could not ask or read: the terminal went away, or a read or write on it failed.
pub fn ask(prompt: &mut impl Prompt, root: RootKey, act: &str) -> eyre::Result<Typed> {
    let token = root.token();
    let typed = prompt.confirm(&format!("Type {token} to {act}:"))?;
    Ok(if typed.trim() == token {
        Typed::Matched
    } else {
        Typed::Other
    })
}
