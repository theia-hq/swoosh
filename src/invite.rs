//! The `invite:` token: a membership authorization for one device key.
//!
//! An owner creates an invite with `swoosh invite add`; a machine adopts it to join the owner's family.
//! Two shapes share the one scheme:
//!
//! - **Bound**: `invite:<signet>.<badge>`. The owner signed a device-bound badge for a key the DEVICE
//!   made and printed (`invite add <label> --for <key>`), so the token carries no secret and is safe in
//!   transit. It is NOT authenticated: anyone can name any signet, so the device verifies the badge binds
//!   its own key and trusts the signet only after comparing the full signet with the owner out of band.
//! - **Derived**: `invite:<seed>.<signet>.<badge>`. The owner derived a child identity and hands over its
//!   seed (`invite add <label>`, the CI case): adopting it BECOMES that identity. The seed is a device
//!   SECRET, so this shape is handed over a private channel only.
//!
//! The signet SECRET never travels in either shape: only the child seed (derived), the signet's PUBLIC
//! node id, and the already-signed public badge (a `sheer:` link). `invite:` is the one accepted scheme:
//! there is no legacy spelling, so a retired token fails loudly instead of parsing as a second shape.
//! Sibling to the `sheer:` capability link: one scheme per kind of thing you hand a machine, so a glance
//! at the prefix says what it is.

use core::fmt;

use bifrost::{NodeId, NodeIdParseError};
use data_encoding::BASE32_NOPAD;
use nauthy::Link;
use zeroize::{Zeroize as _, Zeroizing};

/// The `invite:` scheme prefix.
pub const SCHEME: &str = "invite:";

/// Separates the encoded fields. A base32 seed, a node id, and a `sheer:` link all lack one, so it
/// delimits unambiguously.
const SEPARATOR: char = '.';

/// A parsed invite: the signet it trusts plus, for the derived shape, the device seed it carries.
///
/// The derived seed never renders in `{:?}`: the manual [`fmt::Debug`] below prints it as `<redacted>`,
/// mirroring [`SecretSource`](crate::secret::SecretSource)'s redacting Debug. A debug line, a panic
/// message, or a future `tracing` field must never leak the device identity.
pub enum Invite {
    /// `invite:<signet>.<badge>`: the machine already holds the key the badge binds; adopting trusts the
    /// signet and stores the badge, keeping that identity.
    Bound {
        /// The signet's PUBLIC node id, the root the device's gate trusts.
        signet: NodeId,
        /// The signet-signed, device-bound membership badge (a `sheer:` link).
        badge: Link,
    },
    /// `invite:<seed>.<signet>.<badge>`: adopting writes the seed as the device identity.
    Derived {
        /// The device's derived child seed. SECRET: adopting it IS becoming that device.
        seed: Zeroizing<[u8; 32]>,
        /// The signet's PUBLIC node id, the root the device's gate trusts.
        signet: NodeId,
        /// The signet-signed, device-bound membership badge.
        badge: Link,
    },
}

impl Invite {
    /// A bound invite: a signed badge for a key the device made, no secret carried.
    pub fn bound(signet: NodeId, badge: Link) -> Self {
        Self::Bound { signet, badge }
    }

    /// A derived invite: the child `seed` plus the signet-signed badge for the child's node.
    pub fn derived(seed: [u8; 32], signet: NodeId, badge: Link) -> Self {
        Self::Derived {
            seed: Zeroizing::new(seed),
            signet,
            badge,
        }
    }

    /// Parse an `invite:` token into its shape.
    ///
    /// The badge is a `sheer:` link, which itself contains a `.` (the root and the token), so the field
    /// count cannot decide the shape: the badge's `sheer:` scheme marks where it starts, and the fields
    /// before it (one for bound, two for derived) decide the shape. Any other scheme is refused: a token
    /// parses under `invite:` or not at all. The decoded seed buffer is wiped before returning, and the
    /// returned seed zeroizes on drop, so no key material lingers in freed memory.
    ///
    /// Every field lands as its own type here, the badge included: a token that carries something other
    /// than a decodable `sheer:` link is an [`InviteError::Badge`], so a parsed `Invite` holds a credential
    /// that verified against its root and no caller downstream re-parses it. The badge is decoded LAST, so
    /// a token whose seed or signet is also wrong still names the field a reader typed wrong first.
    ///
    /// [`Derived`]: Invite::Derived
    pub fn parse(token: &str) -> Result<Self, InviteError> {
        if let Some(body) = token.strip_prefix(SCHEME) {
            // The signed badge always starts at `sheer:`; everything before it is `.`-terminated:
            // `<signet>.` (bound) or `<seed>.<signet>.` (derived).
            let (head, rest) = body.split_once("sheer:").ok_or(InviteError::Malformed)?;
            if rest.is_empty() {
                return Err(InviteError::Malformed);
            }
            let badge = format!("sheer:{rest}");
            let head = head.strip_suffix(SEPARATOR).ok_or(InviteError::Malformed)?;
            return match head.split(SEPARATOR).collect::<Vec<_>>().as_slice() {
                [signet] => Ok(Self::Bound {
                    signet: parse_signet(signet)?,
                    badge: parse_badge(&badge)?,
                }),
                [seed, signet] => Ok(Self::Derived {
                    seed: parse_seed(seed)?,
                    signet: parse_signet(signet)?,
                    badge: parse_badge(&badge)?,
                }),
                _ => Err(InviteError::Malformed),
            };
        }
        Err(InviteError::Scheme)
    }
}

impl fmt::Debug for Invite {
    /// Redact the derived seed, the one secret an invite can carry: the shape, the signet, and the
    /// badge's presence (with its byte length) are safe to print. The seed prints as `<redacted>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bound { signet, badge } => f
                .debug_struct("Invite::Bound")
                .field("signet", signet)
                .field("badge", &badge.as_str().len())
                .finish(),
            Self::Derived { signet, badge, .. } => f
                .debug_struct("Invite::Derived")
                .field("seed", &"<redacted>")
                .field("signet", signet)
                .field("badge", &badge.as_str().len())
                .finish(),
        }
    }
}

impl fmt::Display for Invite {
    /// The canonical token for this shape: both shapes render under `invite:`, so re-encoding is stable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bound { signet, badge } => write!(f, "{SCHEME}{signet}{SEPARATOR}{badge}"),
            Self::Derived {
                seed,
                signet,
                badge,
            } => write!(
                f,
                "{SCHEME}{}{SEPARATOR}{signet}{SEPARATOR}{badge}",
                encode_seed(seed).as_str()
            ),
        }
    }
}

/// Encode a device seed as lowercase unpadded base32. Both allocations zeroize: the uppercase
/// intermediate is wiped after lowercasing, and the returned wrapper wipes the lowercase form on drop,
/// so the seed's encoding does not linger in freed memory either.
fn encode_seed(seed: &[u8; 32]) -> Zeroizing<String> {
    let mut upper = Zeroizing::new(BASE32_NOPAD.encode(seed));
    let lower = upper.to_lowercase();
    upper.zeroize();
    Zeroizing::new(lower)
}

/// Decode a base32 seed of exactly 32 bytes. The uppercase copy and the decoded buffer both zeroize on
/// drop, so neither lingers in freed memory.
fn parse_seed(text: &str) -> Result<Zeroizing<[u8; 32]>, InviteError> {
    let upper = Zeroizing::new(text.to_uppercase());
    let mut bytes = Zeroizing::new(
        BASE32_NOPAD
            .decode(upper.as_bytes())
            .map_err(|_| InviteError::Encoding)?,
    );
    let seed = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| InviteError::Length)?;
    bytes.zeroize();
    Ok(Zeroizing::new(seed))
}

/// Parse the signet field as a node id, with a typed error.
fn parse_signet(text: &str) -> Result<NodeId, InviteError> {
    text.parse::<NodeId>().map_err(InviteError::Signet)
}

/// Parse the badge field as a `sheer:` link, with a typed error. The scheme was already matched to find
/// the field boundary, so what this adds is the decode and the signature check against the embedded root:
/// a token carrying a truncated or forged badge is refused here rather than stored and presented.
fn parse_badge(text: &str) -> Result<Link, InviteError> {
    text.parse::<Link>().map_err(InviteError::Badge)
}

/// Why a string was not a valid [`Invite`] token.
#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    /// The token did not carry the `invite:` prefix.
    #[error("not an invite (expected the `invite:` prefix)")]
    Scheme,
    /// The token had the wrong number of fields.
    #[error(
        "malformed invite (expected `invite:<signet>.<badge>` or `invite:<seed>.<signet>.<badge>`)"
    )]
    Malformed,
    /// The seed part was not valid base32.
    #[error("invalid base32 in the invite seed")]
    Encoding,
    /// The seed decoded to the wrong length (not 32 bytes).
    #[error("invite seed is not 32 bytes")]
    Length,
    /// The signet part was not a valid node id.
    #[error("invalid signet in invite")]
    Signet(#[source] NodeIdParseError),
    /// The badge part was not a decodable `sheer:` capability link.
    #[error("invalid membership badge in invite")]
    Badge(#[source] nauthy::CapError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signet() -> NodeId {
        NodeId::from_ed25519_secret(&[9u8; 32])
    }

    /// A real signet-signed membership badge, so a token test carries what the product carries: the badge
    /// field is a parsed `sheer:` link now, and a stand-in string would only prove the parser is lenient.
    fn badge() -> Link {
        crate::identity::Secret::ephemeral()
            .member_badge()
            .expect("mint a membership badge")
    }

    /// The bound shape round-trips through the one scheme with no seed in the token.
    #[test]
    fn bound_invite_round_trips_and_carries_no_seed() {
        let badge = badge();
        let token = Invite::bound(signet(), Link::clone(&badge)).to_string();
        assert!(token.starts_with("invite:"));
        let parsed = Invite::parse(&token).expect("a bound invite round-trips");
        match parsed {
            Invite::Bound {
                signet: root,
                badge: carried,
            } => {
                assert_eq!(root, signet());
                assert_eq!(carried.as_str(), badge.as_str());
            }
            other => panic!("expected the bound shape, got {other:?}"),
        }
    }

    /// The derived shape round-trips with the seed, signet, and badge fields intact.
    #[test]
    fn derived_invite_round_trips() {
        let minted = badge();
        let token = Invite::derived([7u8; 32], signet(), Link::clone(&minted)).to_string();
        assert!(token.starts_with("invite:"));
        let parsed = Invite::parse(&token).expect("a derived invite round-trips");
        match parsed {
            Invite::Derived {
                seed,
                signet: root,
                badge,
            } => {
                assert_eq!(&*seed, &[7u8; 32]);
                assert_eq!(root, signet());
                assert_eq!(badge.as_str(), minted.as_str());
            }
            other => panic!("expected the derived shape, got {other:?}"),
        }
    }

    /// The manual Debug redacts the derived seed, the one secret an invite can carry: a device seed IS
    /// an identity, so no `{:?}` (a log line, a panic message, a future trace) may print it. The shape,
    /// the signet, and the badge's presence stay.
    #[test]
    fn derived_debug_redacts_the_seed() {
        let seed = [7u8; 32];
        let invite = Invite::derived(seed, signet(), badge());
        let shown = format!("{invite:?}");
        assert!(
            shown.contains("Invite::Derived"),
            "the shape is still named: {shown}"
        );
        assert!(
            shown.contains("<redacted>"),
            "the seed renders as redacted: {shown}"
        );
        assert!(
            !shown.contains("7, 7"),
            "the seed's bytes never render: {shown}"
        );
        assert!(
            !shown.contains(&BASE32_NOPAD.encode(&seed).to_lowercase()),
            "the seed's base32 form never renders: {shown}"
        );
    }

    /// A pre-rename `authkey:` token is REFUSED, both shapes: `invite:` is the one scheme, with no
    /// aliasing, so a token carrying the retired prefix fails loudly instead of half-working as a
    /// legacy shape.
    #[test]
    fn a_pre_rename_token_is_refused() {
        let two_field = format!(
            "authkey:{}.{}",
            BASE32_NOPAD.encode(&[4u8; 32]).to_lowercase(),
            signet()
        );
        assert!(matches!(
            Invite::parse(&two_field),
            Err(InviteError::Scheme)
        ));

        let three_field = format!("{two_field}.sheer:BADGE");
        assert!(matches!(
            Invite::parse(&three_field),
            Err(InviteError::Scheme)
        ));
    }

    /// The scheme and the shape markers are the whole grammar: a foreign scheme, a missing or empty
    /// badge, a short seed, bad base32, a bad signet, and a badge that does not decode are each a typed
    /// refusal, never a silent default.
    #[test]
    fn malformed_tokens_are_refused() {
        assert!(matches!(Invite::parse("sheer:x"), Err(InviteError::Scheme)));
        assert!(matches!(
            Invite::parse("invite:"),
            Err(InviteError::Malformed)
        ));
        assert!(matches!(
            Invite::parse(&format!("invite:{}", signet())),
            Err(InviteError::Malformed)
        ));
        let short = BASE32_NOPAD.encode(&[0u8; 8]).to_lowercase();
        assert!(matches!(
            Invite::parse(&format!("invite:{short}.{}.sheer:B", signet())),
            Err(InviteError::Length)
        ));
        assert!(matches!(
            Invite::parse(&format!("invite:not-base32.{}.sheer:B", signet())),
            Err(InviteError::Encoding)
        ));
        assert!(matches!(
            Invite::parse("invite:not-a-node.sheer:B"),
            Err(InviteError::Signet(_))
        ));
        assert!(matches!(
            Invite::parse(&format!("invite:{}.", signet())),
            Err(InviteError::Malformed)
        ));
        assert!(matches!(
            Invite::parse(&format!("invite:{}.sheer:not-a-link", signet())),
            Err(InviteError::Badge(_))
        ));
    }
}
