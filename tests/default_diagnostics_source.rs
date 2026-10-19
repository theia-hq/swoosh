//! Source coordinates are safe only while the resolved registry package and both callsites stay pinned.
//! This guard does source I/O in tests, never in the production subscriber.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

const VERSION: &str = "0.6.3";
const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";
const CHECKSUM: &str = "1b4877f20f064de34b77d79237c9caa37c393590af8ef5a2f3253d59be5a338b";
const SOCKET_SHA256: &str = "a5806df89a2029a38c9c45d5a38afabdca5cc369297ad9df4a32c78f2c17d3c3";

#[test]
fn the_resolved_discovery_source_and_diagnostic_callsites_have_not_drifted() {
    let lock: toml::Value = include_str!("../Cargo.lock")
        .parse()
        .expect("shipping lock parses");
    let packages: Vec<_> = lock["package"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|package| package["name"].as_str() == Some("swarm-discovery"))
        .collect();
    assert_eq!(packages.len(), 1, "one registry package owns the exception");
    let package = packages[0];
    assert_eq!(package["version"].as_str(), Some(VERSION));
    assert_eq!(package["source"].as_str(), Some(REGISTRY));
    assert_eq!(package["checksum"].as_str(), Some(CHECKSUM));

    // Cargo identifies the source actually resolved, rather than whichever cached checkout a glob
    // finds first. Python supplies only standard-library JSON and SHA-256, with imports isolated.
    let output = Command::new("python3")
        .args(["-I", "-c", SOURCE_GUARD])
        .args([
            env!("CARGO"),
            env!("CARGO_MANIFEST_DIR"),
            VERSION,
            REGISTRY,
            CHECKSUM,
            SOCKET_SHA256,
        ])
        .output()
        .expect("installed Python runs the test-only source guard");
    assert!(
        output.status.success(),
        "resolved source drift: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

const SOURCE_GUARD: &str = r#"
import hashlib
import json
from pathlib import Path
import subprocess
import sys

cargo, root, version, registry, checksum, digest = sys.argv[1:]
# A host build need not fetch source archives for unbuilt foreign-target dependencies.
cargo_version = subprocess.check_output([cargo, '-vV'], cwd=root, text=True)
host = next(line.split(': ', 1)[1] for line in cargo_version.splitlines() if line.startswith('host: '))
metadata = json.loads(subprocess.check_output(
    [cargo, 'metadata', '--format-version', '1', '--locked', '--offline', '--filter-platform', host], cwd=root))
packages = [p for p in metadata['packages'] if p['name'] == 'swarm-discovery']
assert len(packages) == 1, 'resolved package count changed'
package = packages[0]
assert package['version'] == version, 'resolved version changed'
assert package['source'] == registry, 'resolved registry changed'
assert any(n['id'] == package['id'] for n in metadata['resolve']['nodes']), 'package not resolved'
source = Path(package['manifest_path']).parent
assert source.name == 'swarm-discovery-' + version, 'registry source path changed'
socket = source / 'src' / 'socket.rs'
assert hashlib.sha256(socket.read_bytes()).hexdigest() == digest, 'socket source digest changed'
archive = source.parent.parent.parent / 'cache' / source.parent.name / (source.name + '.crate')
assert hashlib.sha256(archive.read_bytes()).hexdigest() == checksum, 'registry archive checksum changed'
lines = socket.read_text().splitlines()
assert lines[473].strip() == 'tracing::error!("error sending mDNS on interface {}: {}", addr, e);', 'line 474 changed'
assert lines[488].strip() == 'tracing::error!("failed to send mDNS on any IPv4 interface in multi-interface mode");', 'line 489 changed'
"#;
