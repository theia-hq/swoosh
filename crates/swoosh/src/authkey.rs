//! The `authkey:` token: a device secret plus the signet that vouches for it.
//!
//! `swoosh mint <label>` emits one; a machine adopts it to become the derived device identity AND to
//! trust the signet that minted it. Shape: `authkey:<base32(child-seed)>.<signet-node-id>`. The seed is
//! SECRET (adopting it IS becoming that device); the signet is PUBLIC (the key the machine's gate will
//! trust). Sibling to the `sheer:` capability link: one scheme per kind of thing you hand a machine, so
//! a glance at the prefix says what it is.

use bifrost::{NodeId, NodeIdParseError};
use data_encoding::BASE32_NOPAD;
use zeroize::Zeroize as _;

/// The `authkey:` scheme prefix.
pub const SCHEME: &str = "authkey:";

/// Separates the encoded child seed from the signet node id.
const SEPARATOR: char = '.';

/// Encode an authkey from a device `child_seed` and the `signet` it derives from and trusts.
pub fn encode(child_seed: &[u8; 32], signet: NodeId) -> String {
    format!(
        "{SCHEME}{}{SEPARATOR}{signet}",
        BASE32_NOPAD.encode(child_seed).to_lowercase()
    )
}

/// Parse an authkey into the device child seed and the signet node id.
///
/// parse-don't-validate at the edge: a caller receives a `[u8; 32]` seed and a [`NodeId`] or a typed
/// error, never a half-parsed string. The decoded byte buffer is wiped before returning, so a malformed
/// or short seed does not linger in freed memory.
pub fn parse(token: &str) -> Result<([u8; 32], NodeId), AuthkeyError> {
    let body = token.strip_prefix(SCHEME).ok_or(AuthkeyError::Scheme)?;
    let (seed, signet) = body.split_once(SEPARATOR).ok_or(AuthkeyError::Malformed)?;
    let signet = signet.parse::<NodeId>().map_err(AuthkeyError::Signet)?;
    let mut bytes = BASE32_NOPAD
        .decode(seed.to_uppercase().as_bytes())
        .map_err(|_| AuthkeyError::Encoding)?;
    let seed = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| AuthkeyError::Length);
    bytes.zeroize();
    Ok((seed?, signet))
}

/// Why a string was not a valid [`authkey`](self) token.
#[derive(Debug, thiserror::Error)]
pub enum AuthkeyError {
    /// The token did not start with the `authkey:` scheme.
    #[error("not an authkey (expected the `authkey:` prefix)")]
    Scheme,
    /// The token had no `.` separating the seed from the signet.
    #[error("malformed authkey (expected `authkey:<seed>.<signet>`)")]
    Malformed,
    /// The seed part was not valid base32.
    #[error("invalid base32 in authkey seed")]
    Encoding,
    /// The seed decoded to the wrong length (not 32 bytes).
    #[error("authkey seed is not 32 bytes")]
    Length,
    /// The signet part was not a valid node id.
    #[error("invalid signet in authkey")]
    Signet(#[source] NodeIdParseError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_seed_and_signet() {
        let seed = [7u8; 32];
        let signet = NodeId::from_ed25519_secret(&[9u8; 32]);
        let token = encode(&seed, signet);
        assert!(token.starts_with("authkey:"));
        let (parsed_seed, parsed_signet) = parse(&token).expect("round-trips");
        assert_eq!(parsed_seed, seed);
        assert_eq!(parsed_signet, signet);
    }

    #[test]
    fn rejects_a_non_authkey_and_a_short_seed() {
        assert!(matches!(parse("sheer:whatever"), Err(AuthkeyError::Scheme)));
        let signet = NodeId::from_ed25519_secret(&[1u8; 32]);
        let short = format!(
            "{SCHEME}{}{SEPARATOR}{signet}",
            BASE32_NOPAD.encode(&[0u8; 8])
        );
        assert!(matches!(parse(&short), Err(AuthkeyError::Length)));
    }
}
