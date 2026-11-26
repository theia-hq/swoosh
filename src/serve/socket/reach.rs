//! A status reply's [`Reachable`], in bytes.
//!
//! Private to the control socket: this is the only codec the reach record has, and the socket is the
//! only wire that carries it. `control.serve`'s list on the network writes a catalog and nothing else.
//!
//! ```text
//!   internet  u8   0 on, 1 off
//!   lan       u8   0 announced, 1 by address only
//!   present   u8   bit 0 public, 1 network, 2 tunnel, 3 computer, 4 network unknown; bits 5-7 zero;
//!                  bits 1 and 4 never both
//!   per address bit, in bit order:
//!     family  u8   4 or 6
//!     ip      [u8; 4 | 16]
//!     port    u16
//! ```
//!
//! At most 3 + 4 x 19 = 79 bytes, bounded by the mask, so there is no count to check. Decode refuses
//! every byte value it does not name, and an address that could not stand for its class, so a reply
//! holds only what [`Picks::of`] could have picked.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{ControlError, take_array, take_byte};
use crate::serve::reachable::{Internet, Lan, Network, Picks, Reachable};

/// The presence bit that says the network is unknown, above the four address bits.
const NETWORK_UNKNOWN: u8 = 1 << 4;

/// Every bit `present` may set.
const KNOWN_BITS: u8 = 0b1_1111;

impl Reachable {
    /// Append this reach to a status reply. Total: every [`Picks`] that exists passed the check decode
    /// applies, so there is nothing here to fail.
    pub(super) fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(match self.internet {
            Internet::On => 0,
            Internet::Off => 1,
        });
        out.push(match self.lan {
            Lan::Announced => 0,
            Lan::ByAddressOnly => 1,
        });
        let (network, unknown) = match self.at.network() {
            Network::At(socket) => (Some(socket), false),
            Network::Nothing => (None, false),
            Network::Unknown => (None, true),
        };
        let slots = [
            self.at.public(),
            network,
            self.at.tunnel(),
            self.at.computer(),
        ];
        let mut present = if unknown { NETWORK_UNKNOWN } else { 0 };
        for (bit, slot) in slots.iter().enumerate() {
            if slot.is_some() {
                present |= 1 << bit;
            }
        }
        out.push(present);
        for socket in slots.into_iter().flatten() {
            match socket.ip() {
                IpAddr::V4(ip) => {
                    out.push(4);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(6);
                    out.extend_from_slice(&ip.octets());
                }
            }
            out.extend_from_slice(&socket.port().to_be_bytes());
        }
    }

    /// Read a reach at `cursor`, advancing it. Strict: a reply from this user's own `serve` that does
    /// not read cleanly is a bug to show, never a field to drop.
    pub(super) fn decode_at(bytes: &[u8], cursor: &mut usize) -> Result<Self, ControlError> {
        let internet = match take_byte(bytes, cursor)? {
            0 => Internet::On,
            1 => Internet::Off,
            other => return Err(refused(format!("unknown reach internet {other:#04x}"))),
        };
        let lan = match take_byte(bytes, cursor)? {
            0 => Lan::Announced,
            1 => Lan::ByAddressOnly,
            other => return Err(refused(format!("unknown reach lan {other:#04x}"))),
        };
        let present = take_byte(bytes, cursor)?;
        if present & !KNOWN_BITS != 0 {
            return Err(refused(format!("unknown reach presence {present:#04x}")));
        }
        let mut slots: [Option<SocketAddr>; 4] = [None; 4];
        for (bit, slot) in slots.iter_mut().enumerate() {
            if present & (1 << bit) != 0 {
                *slot = Some(socket_at(bytes, cursor)?);
            }
        }
        let [public, network, tunnel, computer] = slots;
        let network = match (network, present & NETWORK_UNKNOWN != 0) {
            (Some(socket), false) => Network::At(socket),
            (None, false) => Network::Nothing,
            (None, true) => Network::Unknown,
            // An address and "could not read" at once is two answers to one question.
            (Some(_), true) => {
                return Err(refused("reach network is both known and unknown"));
            }
        };
        let at = Picks::checked(public, network, tunnel, computer)
            .ok_or_else(|| refused("reach address does not fit its class"))?;
        Ok(Self { internet, lan, at })
    }
}

/// One address: its family, its ip and its port.
fn socket_at(bytes: &[u8], cursor: &mut usize) -> Result<SocketAddr, ControlError> {
    let ip = match take_byte(bytes, cursor)? {
        4 => IpAddr::V4(Ipv4Addr::from(take_array::<4>(bytes, cursor)?)),
        6 => IpAddr::V6(Ipv6Addr::from(take_array::<16>(bytes, cursor)?)),
        other => return Err(refused(format!("unknown reach family {other:#04x}"))),
    };
    let port = u16::from_be_bytes(take_array(bytes, cursor)?);
    Ok(SocketAddr::new(ip, port))
}

/// A refusal in the codec's own words: fixed text and a byte value, never an address.
fn refused(reason: impl Into<String>) -> ControlError {
    ControlError::Protocol(reason.into())
}

#[cfg(test)]
#[path = "reach_tests.rs"]
mod tests;
