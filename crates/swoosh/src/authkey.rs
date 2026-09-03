//! The `authkey:` token: a device secret, the signet that vouches for it, and the badge it carries.
//!
//! `swoosh mint <label>` emits one; a machine adopts it to become the derived device identity AND to
//! trust the signet that minted it. Shape: `authkey:<base32(child-seed)>.<signet-node-id>.<badge>`. The
//! seed is SECRET (adopting it IS becoming that device); the signet is PUBLIC (the key the machine's gate
//! will trust); the badge is PUBLIC (a `sheer:` link the signet signed, rooted at the signet and bound to
//! the device, proving membership when the device dials). Sibling to the `sheer:` capability link: one
//! scheme per kind of thing you hand a machine, so a glance at the prefix says what it is.
//!
//! The badge is the whole fix for device-reach: a device does NOT self-sign (its self-sign roots at its
//! own child key, which a signet-rooted gate refuses). Instead the signet signs a `member(true)` badge FOR
//! the device at mint time (rooted at the signet, `bound_device` = the device's pubkey), the device stores
//! it, and presents that STORED badge on connect. The signet SECRET is never in the authkey: only the
//! child seed, the signet's PUBLIC node id, and the already-signed public badge travel. A signet holder
//! (person-zero) needs no badge here -- it IS the root and self-signs -- so a two-field authkey (no badge)
//! still parses for backward compatibility.

use bifrost::{NodeId, NodeIdParseError};
use data_encoding::BASE32_NOPAD;
use zeroize::{Zeroize as _, Zeroizing};

/// The `authkey:` scheme prefix.
pub const SCHEME: &str = "authkey:";

/// Separates the encoded child seed, the signet node id, and the badge.
const SEPARATOR: char = '.';

/// Encode an authkey from a device `child_seed`, the `signet` it derives from and trusts, and the signed
/// membership `badge` the signet minted for it. The badge is a `sheer:` link (already public, already
/// signed by the signet); it is carried verbatim as the third field.
pub fn encode(child_seed: &[u8; 32], signet: NodeId, badge: &str) -> String {
    format!(
        "{SCHEME}{}{SEPARATOR}{signet}{SEPARATOR}{badge}",
        BASE32_NOPAD.encode(child_seed).to_lowercase()
    )
}

/// The three fields an authkey carries: the device child seed, the signet it trusts, and the signet-signed
/// membership badge the device presents on connect (absent only for a legacy two-field authkey).
pub struct Authkey {
    /// The device's derived child seed. SECRET: adopting it IS becoming that device.
    pub seed: [u8; 32],
    /// The signet's PUBLIC node id, the root the device's gate trusts.
    pub signet: NodeId,
    /// The signet-signed, device-bound membership badge (a `sheer:` link), or `None` for a legacy
    /// two-field authkey minted before badges were carried.
    pub badge: Option<String>,
}

/// Parse an authkey into its device child seed, signet node id, and (if present) membership badge.
///
/// parse-don't-validate at the edge: a caller receives an [`Authkey`] or a typed error, never a
/// half-parsed string. The decoded seed buffer is wiped before returning, so a malformed or short seed
/// does not linger in freed memory. A two-field token (no badge) parses with `badge: None`, so an authkey
/// minted before badges were carried still adopts (backward-compatible); the badge is the third field
/// when present, and is not split further so a `sheer:` link containing no `.` is carried verbatim.
pub fn parse(token: &str) -> Result<Authkey, AuthkeyError> {
    let body = token.strip_prefix(SCHEME).ok_or(AuthkeyError::Scheme)?;
    let (seed, rest) = body.split_once(SEPARATOR).ok_or(AuthkeyError::Malformed)?;
    // The badge (a `sheer:` link) may itself be arbitrary base-N with no `.`, so split only ONCE more:
    // the signet is up to the next `.`, and everything after is the badge carried verbatim. A two-field
    // token has no second `.`, so the badge is absent.
    let (signet, badge) = match rest.split_once(SEPARATOR) {
        Some((signet, badge)) => (signet, Some(badge.to_owned())),
        None => (rest, None),
    };
    let signet = signet.parse::<NodeId>().map_err(AuthkeyError::Signet)?;
    // `BASE32_NOPAD` decodes uppercase only, but the encoded seed is lowercase (see `encode`), so it must be
    // uppercased first. That uppercase copy IS secret-equivalent material (the base32 of the child seed), so
    // hold it in a zeroizing buffer that wipes on drop rather than leaving it in freed heap.
    let upper = Zeroizing::new(seed.to_uppercase());
    let mut bytes = BASE32_NOPAD
        .decode(upper.as_bytes())
        .map_err(|_| AuthkeyError::Encoding)?;
    let seed = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| AuthkeyError::Length);
    bytes.zeroize();
    Ok(Authkey {
        seed: seed?,
        signet,
        badge,
    })
}

/// Why a string was not a valid [`authkey`](self) token.
#[derive(Debug, thiserror::Error)]
pub enum AuthkeyError {
    /// The token did not start with the `authkey:` scheme.
    #[error("not an authkey (expected the `authkey:` prefix)")]
    Scheme,
    /// The token had no `.` separating the seed from the signet.
    #[error("malformed authkey (expected `authkey:<seed>.<signet>.<badge>`)")]
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
    fn round_trips_seed_signet_and_badge() {
        let seed = [7u8; 32];
        let signet = NodeId::from_ed25519_secret(&[9u8; 32]);
        // A badge is a `sheer:` link, which contains no `.`; carry a representative one verbatim.
        let badge = "sheer:AAAABBBBCCCCDDDD";
        let token = encode(&seed, signet, badge);
        assert!(token.starts_with("authkey:"));
        let parsed = parse(&token).expect("round-trips");
        assert_eq!(parsed.seed, seed);
        assert_eq!(parsed.signet, signet);
        assert_eq!(parsed.badge.as_deref(), Some(badge));
    }

    #[test]
    fn parses_a_legacy_two_field_authkey_with_no_badge() {
        // An authkey minted before badges were carried has only seed + signet; it must still adopt, with
        // no badge (the device then self-signs as before, which is the person-zero fallback path).
        let seed = [4u8; 32];
        let signet = NodeId::from_ed25519_secret(&[5u8; 32]);
        let legacy = format!(
            "{SCHEME}{}{SEPARATOR}{signet}",
            BASE32_NOPAD.encode(&seed).to_lowercase()
        );
        let parsed = parse(&legacy).expect("legacy two-field authkey parses");
        assert_eq!(parsed.seed, seed);
        assert_eq!(parsed.signet, signet);
        assert!(parsed.badge.is_none());
    }

    #[test]
    fn rejects_a_non_authkey_and_a_short_seed() {
        assert!(matches!(parse("sheer:whatever"), Err(AuthkeyError::Scheme)));
        let signet = NodeId::from_ed25519_secret(&[1u8; 32]);
        let short = format!(
            "{SCHEME}{}{SEPARATOR}{signet}{SEPARATOR}sheer:badge",
            BASE32_NOPAD.encode(&[0u8; 8])
        );
        assert!(matches!(parse(&short), Err(AuthkeyError::Length)));
    }
}
