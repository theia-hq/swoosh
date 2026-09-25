use bifrost::NodeId;
use swoosh::contacts::DeviceLabel;

use super::{SIGNET_ROW, block_lines};

/// A device may be named `signet`, so the signet row prints under a word no device can take: a device named
/// `signet` keeps its own label, and only the recorded signet prints as the person's root.
#[test]
fn a_device_named_signet_never_renders_as_the_signet_row() {
    let device: DeviceLabel = "signet".parse().expect("signet is a device name");
    let (device_key, signet_key) = (
        NodeId::from_ed25519_secret(&[1u8; 32]),
        NodeId::from_ed25519_secret(&[2u8; 32]),
    );
    assert!(
        SIGNET_ROW.parse::<DeviceLabel>().is_err(),
        "no device can take the signet row's label"
    );
    let lines = block_lines(None, &[(&device, &device_key)], NodeId::to_string);
    assert_eq!(lines, [format!("  signet  {device_key}")]);
    let lines = block_lines(
        Some(&signet_key),
        &[(&device, &device_key)],
        NodeId::to_string,
    );
    assert_eq!(
        lines,
        [
            format!("  root    {signet_key}"),
            format!("  signet  {device_key}"),
        ],
        "the signet and the device named signet read apart"
    );
}
