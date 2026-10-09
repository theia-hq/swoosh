// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `join` through the compiled binary: what it refuses, it refuses before it writes.

use core::time::Duration;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::SystemTime;

use bifrost::NodeId;
use swoosh::invite::Invite;
use swoosh::testkit::{TestNode, TestRoot};

/// A reach flag the first exchange would never read is refused before the join writes anything.
#[test]
fn join_refuses_an_unused_reach_flag_before_writing() {
    let home = std::env::temp_dir().join(format!("swoosh-join-reach-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let swoosh = |args: &[&str], stdin: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
            .arg("--home")
            .arg(&home)
            .args(args)
            .env_remove("SWOOSH_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the binary runs");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let status = swoosh(&["leave", "--new-key"], "");
    assert!(status.status.success());
    let key: NodeId = String::from_utf8(status.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let standing = TestRoot::seeded(0x21)
        .device_badge(
            key,
            SystemTime::now() + Duration::from_secs(90 * 24 * 60 * 60),
        )
        .unwrap();
    let invite = Invite::bound(
        TestNode::seeded(0x41).node_id(),
        "laptop".parse().unwrap(),
        standing,
    );

    let output = swoosh(
        &["join", "--local", "--relay", "https://relay.example"],
        &format!("{invite}\n"),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "refused: {stderr}");
    assert_eq!(output.status.code(), Some(2), "a usage error: {stderr}");
    assert!(
        stderr.contains("--relay or SWOOSH_RELAY has no effect"),
        "{stderr}"
    );
    assert!(!stderr.contains("joined root"), "{stderr}");
    for file in ["key.cert", "root.pub", "invited-by"] {
        assert!(!home.join(file).exists(), "{file} is not written");
    }
    let _ = std::fs::remove_dir_all(&home);
}
