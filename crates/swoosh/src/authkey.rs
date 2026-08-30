//! The `authkey:` token: a device secret, the signet that vouches for it, and its membership badge.
//!
//! `swoosh mint <label>` emits one; a machine adopts it to become the derived device identity, to trust
//! the signet that minted it, AND to carry the badge that proves its membership on connect. Shape:
//! `authkey:<base32(child-seed)>.<signet-node-id>.<base32(badge-link)>`. The seed is SECRET (adopting it
//! IS becoming that device); the signet is PUBLIC (the key the machine's gate trusts); the badge is a
//! `sheer:` membership cap the signet signed for this device, base32-encoded so it carries no `.` of its
//! own and the dot-separated fields stay unambiguous. The badge is OPTIONAL: a two-field token (no badge)
//! still parses, for a device that only needs an identity + anchor. Sibling to the `sheer:` link: one
//! scheme per kind of thing you hand a machine, so a glance at the prefix says what it is.

use bifrost::{NodeId, NodeIdParseError};
use data_encoding::BASE32_NOPAD;
use zeroize::Zeroize as _;

/// The `authkey:` scheme prefix.
pub const SCHEME: &str = "authkey:";

/// Separates the seed, the signet node id, and the badge. None of the three fields contains one (all are
/// base32 or a base32 node id), so a plain split is unambiguous.
const SEPARATOR: char = '.';

/// Encode an authkey from a device `child_seed`, the `signet` it derives from and trusts, and — for a
/// provisioned device — the membership `badge` (a `sheer:` link) the signet signed for it.
///
/// The badge is base32-encoded so the whole token is dot-delimited into exactly two or three fields. A
/// `None` badge yields the two-field form (identity + anchor only).
pub fn encode(child_seed: &[u8; 32], signet: NodeId, badge: Option<&str>) -> String {
    let seed = BASE32_NOPAD.encode(child_seed).to_lowercase();
    match badge {
        Some(link) => {
            let badge = BASE32_NOPAD.encode(link.as_bytes()).to_lowercase();
            format!("{SCHEME}{seed}{SEPARATOR}{signet}{SEPARATOR}{badge}")
        }
        None => format!("{SCHEME}{seed}{SEPARATOR}{signet}"),
    }
}

/// Parse an authkey into the device child seed, the signet node id, and (if present) the membership badge
/// link.
///
/// parse-don't-validate at the edge: a caller receives a `[u8; 32]` seed, a [`NodeId`], and an optional
/// badge link — or a typed error, never a half-parsed string. The decoded seed buffer is wiped before
/// returning, so a malformed or short seed does not linger in freed memory.
pub fn parse(token: &str) -> Result<([u8; 32], NodeId, Option<String>), AuthkeyError> {
    let body = token.strip_prefix(SCHEME).ok_or(AuthkeyError::Scheme)?;
    let mut fields = body.splitn(3, SEPARATOR);
    let seed = fields.next().ok_or(AuthkeyError::Malformed)?;
    let signet = fields.next().ok_or(AuthkeyError::Malformed)?;
    let badge = fields.next();

    let signet = signet.parse::<NodeId>().map_err(AuthkeyError::Signet)?;
    let mut bytes = BASE32_NOPAD
        .decode(seed.to_uppercase().as_bytes())
        .map_err(|_| AuthkeyError::Encoding)?;
    let seed = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| AuthkeyError::Length);
    bytes.zeroize();
    let seed = seed?;

    let badge = match badge {
        Some(field) if !field.is_empty() => {
            let decoded = BASE32_NOPAD
                .decode(field.to_uppercase().as_bytes())
                .map_err(|_| AuthkeyError::BadgeEncoding)?;
            Some(String::from_utf8(decoded).map_err(|_| AuthkeyError::BadgeEncoding)?)
        }
        _ => None,
    };
    Ok((seed, signet, badge))
}

/// Why a string was not a valid [`authkey`](self) token.
#[derive(Debug, thiserror::Error)]
pub enum AuthkeyError {
    /// The token did not start with the `authkey:` scheme.
    #[error("not an authkey (expected the `authkey:` prefix)")]
    Scheme,
    /// The token had no `.` separating the seed from the signet.
    #[error("malformed authkey (expected `authkey:<seed>.<signet>[.<badge>]`)")]
    Malformed,
    /// The seed part was not valid base32.
    #[error("invalid base32 in authkey seed")]
    Encoding,
    /// The seed decoded to the wrong length (not 32 bytes).
    #[error("authkey seed is not 32 bytes")]
    Length,
    /// The badge part was not valid base32, or not valid UTF-8 once decoded.
    #[error("invalid badge in authkey")]
    BadgeEncoding,
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
        let badge = "sheer:bf01aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq.abc23def";
        let token = encode(&seed, signet, Some(badge));
        assert!(token.starts_with("authkey:"));
        let (parsed_seed, parsed_signet, parsed_badge) = parse(&token).expect("round-trips");
        assert_eq!(parsed_seed, seed);
        assert_eq!(parsed_signet, signet);
        assert_eq!(parsed_badge.as_deref(), Some(badge));
    }

    #[test]
    fn round_trips_without_a_badge() {
        // The two-field form (identity + anchor, no badge) still parses, badge None.
        let seed = [3u8; 32];
        let signet = NodeId::from_ed25519_secret(&[4u8; 32]);
        let token = encode(&seed, signet, None);
        let (parsed_seed, parsed_signet, parsed_badge) = parse(&token).expect("round-trips");
        assert_eq!(parsed_seed, seed);
        assert_eq!(parsed_signet, signet);
        assert_eq!(parsed_badge, None);
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
