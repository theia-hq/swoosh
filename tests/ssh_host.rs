// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The system ssh accepts the host `swoosh ssh` gives it, for every way a peer is typed.
//!
//! The bug (FLAWS F20): a raw key, a link or a link file gave ssh the key's short form as its host, which
//! ends in `…`, and OpenSSH on macOS refuses such a host under a UTF-8 locale (`hostname contains invalid
//! characters`) before the `ProxyCommand` ever runs. The `host` line from `ssh -G` is what catches a
//! regression on any OS. These tests drive the compiled binary with a
//! stand-in `ssh` first on PATH to record the argv it builds, swap the `ProxyCommand` for `false` so
//! nothing dials, and hand that argv to the real ssh under a UTF-8 locale: `ssh -G` names the host and
//! the alias it would use, and `ssh -v` shows ssh got past its host check to the proxy command.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The stand-in `ssh`: record the argv, one argument per line, and exit.
const FAKE_SSH: &str = r#"#!/bin/sh
printf '%s\n' "$@" > "$SWOOSH_TEST_SSH_LOG"
exit 0
"#;

/// The locale that shows the bug: on macOS, ssh's host check reads `…` as invalid only under UTF-8. Both
/// variables, since a CI runner often sets `LC_ALL=C`, which would hide it.
const UTF8: &str = "en_US.UTF-8";

/// One scratch tree: a home, a bin dir holding the stand-in `ssh`, and the argv log. Drop removes exactly
/// the base it created.
struct Scratch {
    base: PathBuf,
    home: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        let base = std::env::temp_dir().join(format!("swoosh-ssh-host-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let bin = base.join("bin");
        let log = base.join("ssh-argv.log");
        std::fs::create_dir_all(&bin).expect("the stand-in bin");
        let fake = bin.join("ssh");
        std::fs::write(&fake, FAKE_SSH).expect("write the stand-in ssh");
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
            .expect("0755 the stand-in ssh");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
            .expect("0700 the scratch base");
        Self {
            base,
            home,
            bin,
            log,
        }
    }

    /// `swoosh --home <home> <args>`, with the stand-in ssh as the only PATH entry.
    fn swoosh(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_swoosh"))
            .arg("--home")
            .arg(&self.home)
            .args(args)
            .env("PATH", &self.bin)
            .env("SWOOSH_TEST_SSH_LOG", &self.log)
            .env_remove("SWOOSH_HOME")
            .output()
            .expect("the swoosh binary runs")
    }

    /// The argv `swoosh ssh <peer>` hands ssh, with the `ProxyCommand` replaced by `false`.
    fn ssh_argv(&self, peer: &str) -> Vec<String> {
        let _ = std::fs::remove_file(&self.log);
        let out = self.swoosh(&["ssh", peer]);
        assert!(
            out.status.success(),
            "`swoosh ssh {peer}` launches: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        std::fs::read_to_string(&self.log)
            .expect("the stand-in ssh recorded its argv")
            .lines()
            .map(|arg| {
                if arg.starts_with("ProxyCommand=") {
                    "ProxyCommand=false".to_owned()
                } else {
                    arg.to_owned()
                }
            })
            .collect()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// The system ssh on this PATH, or `None` (with the reason printed) when there is none. On CI (`CI` set)
/// a missing ssh fails instead, so the check can never pass there by not running.
fn system_ssh() -> Option<PathBuf> {
    let found = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join("ssh"))
            .find(|path| path.is_file())
    });
    if found.is_none() {
        assert!(
            std::env::var_os("CI").is_none(),
            "no `ssh` on PATH on CI: the real-ssh host check must run there"
        );
        eprintln!("note: no `ssh` on PATH; skipping the real-ssh host check");
    }
    found
}

/// The real ssh run with `options`, then `argv`, under a UTF-8 locale. `-F none` keeps the config of
/// whoever runs the tests out of it: ssh reads `~/.ssh/config` from the password database, not `$HOME`.
fn run_ssh(ssh: &Path, options: &[&str], argv: &[String]) -> Output {
    Command::new(ssh)
        .args(["-F", "none"])
        .args(options)
        .args(argv)
        .env("LANG", UTF8)
        .env("LC_ALL", UTF8)
        .output()
        .expect("the system ssh runs")
}

/// For every way a peer is typed, the real ssh takes the host as given (a petname as typed, anything
/// else the full key of the machine dialed) with the alias on that key, and gets past its host check to
/// the proxy command.
#[test]
fn ssh_accepts_the_host_for_every_kind_of_peer() {
    let Some(ssh) = system_ssh() else {
        return;
    };
    let scratch = Scratch::new();
    let desk = swoosh::testkit::TestNode::seeded(3).node_id().to_string();
    let saved = scratch.swoosh(&["contact", "add", "alice/desk", &desk]);
    assert!(
        saved.status.success(),
        "save alice/desk: {}",
        String::from_utf8_lossy(&saved.stderr)
    );

    // A link's machine is its root, the node that minted it.
    let minter = swoosh::testkit::TestNode::seeded(1);
    let root = minter.node_id().to_string();
    let slip = minter
        .slip(
            &"ssh".parse().expect("valid service"),
            nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
        )
        .expect("mint an anyone slip")
        .seal()
        .expect("seal")
        .link()
        .expect("a link");
    let link = swoosh::link::Link::from(slip).to_string();
    // A file name with a space and a non-ASCII letter, which must never become the host.
    let file = scratch.base.join("nas \u{e9}.link");
    std::fs::write(&file, format!("{link}\n")).expect("write the link file");
    let raw = swoosh::testkit::TestNode::seeded(2).node_id().to_string();

    let cases = [
        ("alice", "alice", desk.as_str()),
        ("alice/desk", "alice/desk", desk.as_str()),
        (raw.as_str(), raw.as_str(), raw.as_str()),
        (link.as_str(), root.as_str(), root.as_str()),
        (
            file.to_str().expect("a UTF-8 path"),
            root.as_str(),
            root.as_str(),
        ),
    ];
    for (peer, host, alias) in cases {
        let argv = scratch.ssh_argv(peer);

        // `-G` prints the options ssh would use and connects to nothing, after its host check.
        let config = run_ssh(&ssh, &["-G"], &argv);
        let stdout = String::from_utf8_lossy(&config.stdout);
        let stderr = String::from_utf8_lossy(&config.stderr);
        assert!(
            !stderr.contains("invalid characters"),
            "ssh refuses the host for {peer}: {stderr}"
        );
        assert!(
            config.status.success(),
            "ssh -G for {peer} exits 0: {stderr}"
        );
        let lines = stdout.lines().collect::<Vec<_>>();
        assert!(
            lines.contains(&format!("host {host}").as_str()),
            "ssh's host for {peer} is {host}: {stdout}"
        );
        assert!(
            lines.contains(&format!("hostkeyalias {alias}").as_str()),
            "ssh's alias for {peer} is {alias}: {stdout}"
        );

        // A real launch reaches the proxy command (`false`, so it ends there) instead of stopping at the
        // host check.
        let launch = run_ssh(&ssh, &["-v", "-o", "BatchMode=yes"], &argv);
        let stderr = String::from_utf8_lossy(&launch.stderr);
        assert!(
            !stderr.contains("invalid characters"),
            "ssh refuses the host for {peer}: {stderr}"
        );
        assert!(
            stderr.contains("Executing proxy command: exec false"),
            "ssh gets past its host check for {peer}: {stderr}"
        );
        assert_eq!(launch.status.code(), Some(255), "{peer}: {stderr}");
    }
}
