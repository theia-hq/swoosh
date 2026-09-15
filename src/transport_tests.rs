//! The composed discovery's mDNS state: the one `advertise` call that starts mDNS is also the one
//! source of the bit a surface reports, so a bind whose mDNS cannot start reads as unavailable
//! instead of being assumed live.

use bifrost_mem::MemTransport;

use super::{MdnsState, PeerHint};

/// A bind with no local addresses to advertise (the in-process transport's shape) cannot start mDNS,
/// so the composed discovery reports the layer unavailable: a caller that reports discovery reads
/// this bit rather than assuming it.
#[test]
fn a_bind_without_advertisable_addresses_reports_mdns_unavailable() {
    let transport = MemTransport::bind();
    let composed = PeerHint::discovery(&transport, []);
    assert_eq!(
        composed.mdns,
        MdnsState::Blocked,
        "no addresses to advertise is a disabled mDNS layer"
    );
}
