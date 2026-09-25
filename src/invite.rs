//! The `invite:` token: a device's standing, with what `join` needs to find its root's devices.
//!
//! ```text
//! invite:<from>.<name>.<root>.<token>           bound: 4 fields, no secret
//! invite:<seed>.<from>.<name>.<root>.<token>    carries a key: 5 fields
//! ```
//!
//! `<root>.<token>` is the device's standing: nauthy's bare link, whose key is the root, so the root rides
//! once. `<from>` is the inviting machine's key and `<name>` the device's name without `me/`. Both are
//! unsigned hints: neither feeds an admission, a pin or a revocation. `<seed>` is the device key a keyed
//! invite hands over, so that shape is a secret.
//!
//! Every field is dot-free by construction (a name follows the one name rule; keys and the seed are base32;
//! the token is nauthy's), so the field count alone decides the shape. There is no version field and no
//! kind letter.

use core::fmt;

use bifrost::{NodeId, NodeIdParseError};
use data_encoding::BASE32_NOPAD;
use nauthy::Link;
use zeroize::{Zeroize as _, Zeroizing};

use crate::contacts::DeviceLabel;
use crate::names::NameError;

/// The mark every invite starts with.
pub const PREFIX: &str = "invite:";

/// Separates the fields.
const SEPARATOR: char = '.';

/// A parsed invite.
///
/// The seed never renders in `{:?}`: the manual [`fmt::Debug`] below prints it as `<redacted>`. A debug
/// line, a panic message, or a future `tracing` field must never leak a device key.
pub struct Invite {
    /// The device key a keyed invite hands over, or `None` for a bound invite. SECRET: holding it IS being
    /// that device.
    pub seed: Option<Zeroizing<[u8; 32]>>,
    /// The inviting machine's key: a hint for where to sync first.
    pub from: NodeId,
    /// The device's name, without `me/`: a hint until the first sync.
    pub name: DeviceLabel,
    /// The device's standing: a link whose key is the root.
    pub standing: Link,
}

impl Invite {
    /// A bound invite: the standing for a key the device made, no secret carried.
    pub fn bound(from: NodeId, name: DeviceLabel, standing: Link) -> Self {
        Self {
            seed: None,
            from,
            name,
            standing,
        }
    }

    /// A keyed invite: the device key `seed`, plus the standing for the key it derives.
    pub fn keyed(seed: [u8; 32], from: NodeId, name: DeviceLabel, standing: Link) -> Self {
        Self {
            seed: Some(Zeroizing::new(seed)),
            from,
            name,
            standing,
        }
    }

    /// Parse an invite: require the prefix (ASCII case-insensitive, surrounding whitespace trimmed), split
    /// on `.`, and read 4 fields as bound and 5 as keyed. Each field parses as its own type, the standing
    /// last, so an invite with two bad fields names the one typed first. The decoded seed zeroizes on drop.
    pub fn parse(token: &str) -> Result<Self, InviteError> {
        let token = token.trim();
        let body = token
            .get(..PREFIX.len())
            .filter(|head| head.eq_ignore_ascii_case(PREFIX))
            .and_then(|_| token.get(PREFIX.len()..))
            .ok_or(InviteError::NotAnInvite)?;
        let fields: Vec<&str> = body.split(SEPARATOR).collect();
        let (seed, rest) = match fields.as_slice() {
            [from, name, root, token] => (None, [*from, *name, *root, *token]),
            [seed, from, name, root, token] => {
                (Some(parse_seed(seed)?), [*from, *name, *root, *token])
            }
            _ => return Err(InviteError::NotAnInvite),
        };
        let [from, name, root, token] = rest;
        let from = from.parse::<NodeId>().map_err(InviteError::From)?;
        let name = name.parse::<DeviceLabel>().map_err(InviteError::Name)?;
        let standing = format!("{root}{SEPARATOR}{token}")
            .parse::<Link>()
            .map_err(InviteError::Standing)?;
        Ok(Self {
            seed,
            from,
            name,
            standing,
        })
    }
}

impl fmt::Debug for Invite {
    /// Everything but the seed, which prints as `<redacted>` when there is one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("seed", &self.seed.as_ref().map(|_| "<redacted>"))
            .field("from", &self.from)
            .field("name", &self.name)
            .field("standing", &self.standing)
            .finish()
    }
}

impl fmt::Display for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PREFIX)?;
        if let Some(seed) = &self.seed {
            write!(f, "{}{SEPARATOR}", encode_seed(seed).as_str())?;
        }
        write!(
            f,
            "{}{SEPARATOR}{}{SEPARATOR}{}",
            self.from,
            self.name,
            self.standing.as_str()
        )
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
///
/// Only ASCII is folded to uppercase. Unicode folding maps `ſ` to `S` and `ı` to `I`, which would give
/// one seed a second spelling.
fn parse_seed(text: &str) -> Result<Zeroizing<[u8; 32]>, InviteError> {
    if !text.is_ascii() {
        return Err(InviteError::Encoding);
    }
    let upper = Zeroizing::new(text.to_ascii_uppercase());
    let mut bytes = Zeroizing::new(
        BASE32_NOPAD
            .decode(upper.as_bytes())
            .map_err(|_| InviteError::Encoding)?,
    );
    let seed = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| InviteError::Length)?;
    bytes.zeroize();
    Ok(Zeroizing::new(seed))
}

/// Why a string was not a valid [`Invite`].
///
/// Every variant prints the same one line, and none carries a source, so the printed error chain is that
/// line alone. The variant and its inner error stay for tests and `Debug`.
#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    /// No `invite:` prefix, or neither 4 nor 5 fields.
    #[error("this is not a swoosh invite")]
    NotAnInvite,
    /// The seed was not valid base32.
    #[error("this is not a swoosh invite")]
    Encoding,
    /// The seed decoded to the wrong length (not 32 bytes).
    #[error("this is not a swoosh invite")]
    Length,
    /// The inviting machine's key was not a key.
    #[error("this is not a swoosh invite")]
    From(NodeIdParseError),
    /// The device's name broke the name rule.
    #[error("this is not a swoosh invite")]
    Name(NameError),
    /// The last field was not a link.
    #[error("this is not a swoosh invite")]
    Standing(nauthy::CapError),
}

#[cfg(test)]
#[path = "invite_tests.rs"]
mod invite_tests;
