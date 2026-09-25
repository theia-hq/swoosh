// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `invite` through the real binary, where only the binary can tell: how clap reads its flags.

use std::process::{Command, Stdio};

/// `--new-key` is spelled in full: `--new` is a usage error that runs nothing, never read as
/// `--new-key`, and clap's tip names the full flag.
#[test]
fn invite_new_is_a_usage_error_not_new_key() {
    let home = std::env::temp_dir().join(format!("swoosh-invite-new-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(&home)
        .args(["invite", "runner", "--new"])
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "a usage error: {stderr}");
    assert!(output.stdout.is_empty(), "nothing on stdout");
    assert!(
        stderr.contains("--new-key"),
        "the tip names the full flag: {stderr}"
    );
    assert_eq!(
        std::fs::read_dir(&home).unwrap().count(),
        0,
        "the home is unchanged"
    );
    let _ = std::fs::remove_dir_all(&home);
}
