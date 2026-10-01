// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `<home>/serve.toml` end to end, through the compiled binary: a `serve` saves its relay only once its
//! routes bind, and a relay the file keeps is read when the file is, by every verb that reads it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// A scratch home removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        let home = std::env::temp_dir().join(format!("sw-serve-toml-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("scratch home");
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).expect("0700");
        Self(home)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `swoosh --home <home> <args>`, run to its end with nothing to read.
fn swoosh(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(args)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .output()
        .expect("swoosh runs")
}

/// A `serve --relay` that refuses after its bind, before its routes bind, saves nothing: the next verb
/// under the home is not pointed at a relay no `serve` ever ran with.
#[test]
fn a_serve_that_did_not_start_saves_no_relay() {
    let scratch = Scratch::new("no-start");
    let out = swoosh(
        &scratch.0,
        &[
            "serve",
            "--relay",
            "https://relay.example/",
            "--public",
            "web",
            "web=fetch:",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let kept = std::fs::read_to_string(scratch.0.join("serve.toml")).unwrap_or_default();
    assert!(!kept.contains("relay"), "nothing saved: {kept}");
}

/// A relay `serve.toml` keeps that is not a usable one is damage the file is read with: `service disable`
/// refuses on it, naming the key, before it writes anything.
#[test]
fn a_bad_relay_in_serve_toml_is_refused_where_the_file_is_read() {
    use std::os::unix::fs::OpenOptionsExt as _;

    let scratch = Scratch::new("bad-relay");
    let path = scratch.0.join("serve.toml");
    let text = "relay = \"http://relay.example\"\n";
    std::io::Write::write_all(
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap(),
        text.as_bytes(),
    )
    .unwrap();
    let out = swoosh(&scratch.0, &["service", "disable", "speed"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!(
            "error: the relay in {} is not a usable relay, and swoosh will not fall back to the default one\n",
            path.display()
        )
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text, "unchanged");
}
