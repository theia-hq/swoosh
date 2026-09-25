// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `swoosh ssh` pins into the RESOLVED home's known_hosts, not `$HOME`'s.
//!
//! The live bug (the 0.9.0 operator cut, finding 1): `ssh` derived its private book from `$HOME`
//! (`~/.config/swoosh/known_hosts`) regardless of `--home`/`SWOOSH_HOME`, so an isolated run appended its
//! pins to the live store, and with `HOME` unset the launcher errored `HOME is not set` before dialing.
//! These tests drive the compiled binary with a stand-in `ssh` first on PATH and read the argv it
//! receives, so the assertion sits at the seam the system ssh actually sees rather than on an internal
//! path helper. A decoy `$HOME` is seeded with the peer's key line, so a run that still read `$HOME`
//! would skip the first-pin notice and a run that still wrote `$HOME` would move its bytes (the live
//! store the bug appended to).
//!
//! The stand-in ssh records its argv, then emulates ssh's own `accept-new` write into the book it was
//! handed: ssh (not swoosh) creates the file, so one run exercises the read path (the first-pin notice)
//! and the write path (the selected home's book) end to end.

use std::path::{Path, PathBuf};
use std::process::Command;

use swoosh::identity::Secret;

/// The stand-in `ssh`: record the argv, then emulate ssh's `accept-new` pin write into the file named by
/// `UserKnownHostsFile` (the book swoosh handed it), so the test can observe which book is touched.
const FAKE_SSH: &str = r#"#!/bin/sh
printf '%s\n' "$@" > "$SWOOSH_TEST_SSH_LOG"
book=''
host_key_alias=''
for arg in "$@"; do
  case "$arg" in
    UserKnownHostsFile=*) book="${arg#UserKnownHostsFile=}" ;;
    HostKeyAlias=*) host_key_alias="${arg#HostKeyAlias=}" ;;
  esac
done
book="${book#\"}"
book="${book%\"}"
if [ -n "$book" ] && [ -n "$host_key_alias" ]; then
  printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZha2U=\n' "$host_key_alias" >> "$book"
fi
exit 0
"#;

/// One scratch tree per test: the selected home, a decoy `$HOME`, and a bin dir holding the stand-in
/// `ssh`. Drop removes exactly the base it created.
struct Scratch {
    base: PathBuf,
    selected: PathBuf,
    decoy: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        let base =
            std::env::temp_dir().join(format!("swoosh-ssh-home-{tag}-{}", std::process::id()));
        let selected = base.join("selected-home");
        let decoy = base.join("decoy-home");
        let bin = base.join("bin");
        let log = base.join("ssh-argv.log");
        std::fs::create_dir_all(&selected).expect("the selected home");
        std::fs::create_dir_all(decoy.join(".config").join("swoosh")).expect("the decoy home");
        std::fs::create_dir_all(&bin).expect("the stand-in bin");
        let fake = bin.join("ssh");
        std::fs::write(&fake, FAKE_SSH).expect("write the stand-in ssh");
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
            .expect("0755 the stand-in ssh");
        // 0700 on the base (a shared /tmp base would otherwise be world-readable), so the private-book
        // guard sees a private tree on the second run, as it does for a real home.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
            .expect("0700 the scratch base");
        Self {
            base,
            selected,
            decoy,
            bin,
            log,
        }
    }

    /// The selected home's book, the path the resolved home derives.
    fn selected_book(&self) -> PathBuf {
        self.selected.join("known_hosts")
    }

    /// The decoy `$HOME`'s book: the live-store path the bug wrote to.
    fn decoy_book(&self) -> PathBuf {
        self.decoy
            .join(".config")
            .join("swoosh")
            .join("known_hosts")
    }

    /// Run the compiled binary as `swoosh --home <selected> ssh <key>`, with the stand-in ssh as the ONLY
    /// PATH entry (a miss fails fast instead of falling through to the system ssh), `HOME` set to the decoy
    /// (`None` removes it, the environment the bug could not run in at all).
    fn ssh(&self, key: &str, home_env: Option<&Path>) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_swoosh"));
        command
            .arg("--home")
            .arg(&self.selected)
            .arg("ssh")
            .arg(key)
            .env("PATH", &self.bin)
            .env("SWOOSH_TEST_SSH_LOG", &self.log)
            .env_remove("SWOOSH_HOME")
            .env_remove("SWOOSH_KEY");
        match home_env {
            Some(dir) => command.env("HOME", dir),
            None => command.env_remove("HOME"),
        };
        command.output().expect("the swoosh binary runs")
    }

    /// The argv the stand-in ssh recorded, one argument per line.
    fn recorded_argv(&self) -> String {
        std::fs::read_to_string(&self.log).expect("the stand-in ssh recorded its argv")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// The write path and the read path: ssh is handed the SELECTED home's book and the pin write lands
/// there, the decoy `$HOME`'s book keeps its bytes, and the first-pin notice follows the selected book
/// (seeded with the key, so a run that read the decoy would go silent).
#[test]
fn pins_into_the_selected_home_and_leaves_home_alone() {
    let scratch = Scratch::new("selected");
    let key = Secret::ephemeral().node_id().to_string();

    std::fs::write(
        scratch.decoy_book(),
        format!("{key} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIseed\n"),
    )
    .expect("seed the decoy book");
    let decoy_before = std::fs::read(scratch.decoy_book()).expect("read the decoy book");

    let first = scratch.ssh(&key, Some(&scratch.decoy));
    let first_err = String::from_utf8_lossy(&first.stderr).into_owned();
    assert!(first.status.success(), "ssh exits 0: {first_err}");
    assert!(
        first_err.contains(&format!("pinning {key} on first connection")),
        "the first-pin notice reads the selected home's book, not the seeded decoy: {first_err}"
    );

    let expected = format!(
        "UserKnownHostsFile=\"{}\"",
        scratch.selected_book().display()
    );
    let argv = scratch.recorded_argv();
    assert!(
        argv.lines().any(|line| line == expected),
        "ssh is handed the selected home's book ({expected}): {argv}"
    );
    let pinned = std::fs::read_to_string(scratch.selected_book()).expect("the selected book");
    assert!(
        pinned.starts_with(&format!("{key} ")),
        "the stand-in ssh's pin write lands in the selected home's book: {pinned}"
    );
    assert_eq!(
        std::fs::read(scratch.decoy_book()).expect("read the decoy book"),
        decoy_before,
        "the decoy $HOME's book is untouched: the old $HOME-derived write is gone"
    );

    // Run 2: the pin the first run wrote is read back from the same book, so the notice is gone. ssh
    // writes the file 0600 itself; the stand-in's `>>` inherits the umask, so pin it the way ssh would
    // and keep the private-book guard honest rather than umask-dependent.
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            scratch.selected_book(),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("0600 the selected book, as ssh would");
    }
    let second = scratch.ssh(&key, Some(&scratch.decoy));
    let second_err = String::from_utf8_lossy(&second.stderr).into_owned();
    assert!(
        second.status.success(),
        "the second ssh exits 0: {second_err}"
    );
    assert!(
        !second_err.contains("pinning"),
        "the pin written into the selected book is read back on the next run: {second_err}"
    );
}

/// The `HOME`-unset path: with `HOME` removed and `--home` explicit, the launcher dials (the bug errored
/// `HOME is not set` before ssh) and pins into the selected home's book.
#[test]
fn runs_with_home_unset() {
    let scratch = Scratch::new("home-unset");
    let key = Secret::ephemeral().node_id().to_string();

    let out = scratch.ssh(&key, None);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "ssh with HOME unset exits 0: {err}");

    let expected = format!(
        "UserKnownHostsFile=\"{}\"",
        scratch.selected_book().display()
    );
    let argv = scratch.recorded_argv();
    assert!(
        argv.lines().any(|line| line == expected),
        "ssh is handed the selected home's book ({expected}): {argv}"
    );
    let pinned = std::fs::read_to_string(scratch.selected_book()).expect("the selected book");
    assert!(
        pinned.starts_with(&format!("{key} ")),
        "the pin write lands in the selected home's book with HOME unset: {pinned}"
    );
}

/// A home whose path ssh would read as another file (here `%d`, which ssh expands to the local home)
/// refuses before ssh runs: exit 1, one line naming the path and the character, no book prepared.
#[test]
fn a_home_path_ssh_reads_specially_exits_1_in_one_line() {
    let scratch = Scratch::new("special");
    let home = scratch.base.join("a%db");
    let key = Secret::ephemeral().node_id().to_string();

    let out = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(&home)
        .arg("ssh")
        .arg(&key)
        .env("PATH", &scratch.bin)
        .env("SWOOSH_TEST_SSH_LOG", &scratch.log)
        .env("HOME", &scratch.decoy)
        .env_remove("SWOOSH_HOME")
        .env_remove("SWOOSH_KEY")
        .output()
        .expect("the swoosh binary runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "a refusal exits 1: {stderr}");
    assert_eq!(stderr.lines().count(), 1, "one line: {stderr}");
    assert!(
        stderr.contains(&home.display().to_string()) && stderr.contains("a '%'"),
        "names the path and the character: {stderr}"
    );
    assert!(!scratch.log.exists(), "ssh never ran");
    assert!(!home.exists(), "no book prepared");
}
