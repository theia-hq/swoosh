// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `leave` through the compiled binary: `--new-key` is spelled in full.

use std::process::{Command, Stdio};

/// `leave --new` is a usage error, never read as `--new-key`: exit 2, nothing on stdout, the key kept.
#[test]
fn leave_new_is_a_usage_error_not_new_key() {
    let home = std::env::temp_dir().join(format!("swoosh-leave-new-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let swoosh = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_swoosh"))
            .arg("--home")
            .arg(&home)
            .args(args)
            .env_remove("SWOOSH_HOME")
            .stdin(Stdio::null())
            .output()
            .expect("the binary runs")
    };
    assert!(swoosh(&["status", "--key"]).status.success());
    let key = std::fs::read(home.join("key")).unwrap();

    let output = swoosh(&["leave", "--new"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "a usage error: {stderr}");
    assert!(output.stdout.is_empty(), "nothing on stdout");
    assert!(
        stderr.contains("--new-key"),
        "the tip names the full flag: {stderr}"
    );
    assert_eq!(
        std::fs::read(home.join("key")).unwrap(),
        key,
        "the key is unchanged"
    );
    let _ = std::fs::remove_dir_all(&home);
}
