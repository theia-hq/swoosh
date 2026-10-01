// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Where the home is and how its key is kept, through the compiled binary: the default home is the
//! platform's per-user state place, `--help` names it, the key's directory is marked for backups to leave
//! out and the home is not, and a key file others can read is refused with swoosh's own line.

use core::sync::atomic::{AtomicU32, Ordering};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

/// A scratch directory standing in for `$HOME`, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "swoosh-home-layout-{tag}-{}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        Self(base)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `swoosh <args>` run in `user` with `HOME` set to it, `XDG_STATE_HOME` set to `state` or unset, and no
/// home named.
fn swoosh(user: &Path, state: Option<&str>, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_swoosh"));
    command
        .args(args)
        .current_dir(user)
        .env("HOME", user)
        .env_remove("SWOOSH_HOME")
        .env_remove("XDG_STATE_HOME")
        .stdin(Stdio::null());
    if let Some(state) = state {
        command.env("XDG_STATE_HOME", state);
    }
    command.output().unwrap()
}

/// `swoosh --home <home> <args>`.
fn swoosh_at(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(args)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// With no home named, the key is made in the platform's per-user state place: on macOS under
/// `~/Library/Application Support/swoosh` whatever `XDG_STATE_HOME` says; elsewhere under
/// `$XDG_STATE_HOME/swoosh` when it is absolute, and `~/.local/state/swoosh` when it is unset or relative.
#[test]
fn the_default_home_is_the_platform_state_place() {
    let scratch = Scratch::new("default");
    let state = scratch.0.join("state");
    let absolute = state.to_str().unwrap();
    for (case, xdg) in [
        ("unset", None),
        ("absolute", Some(absolute)),
        ("relative", Some("relative/state")),
    ] {
        let user = scratch.0.join(case);
        std::fs::create_dir_all(&user).unwrap();
        let out = swoosh(&user, xdg, &["status", "--key"]);
        assert!(out.status.success(), "{case}: {}", text(&out.stderr));

        #[cfg(target_os = "macos")]
        let home = user
            .join("Library")
            .join("Application Support")
            .join("swoosh");
        #[cfg(not(target_os = "macos"))]
        let home = match case {
            "absolute" => state.join("swoosh"),
            _ => user.join(".local").join("state").join("swoosh"),
        };
        assert!(
            home.join("machine").join("key").is_file(),
            "{case}: the key is made in {}",
            home.display()
        );
        assert!(
            !user.join(".config").exists(),
            "{case}: nothing is made under ~/.config"
        );
        assert!(
            !user.join("relative").exists(),
            "{case}: a relative XDG_STATE_HOME is never used"
        );
    }
}

/// `--home`'s help names the default home of the platform the binary was built for.
#[test]
fn home_help_names_the_platform_default() {
    let scratch = Scratch::new("help");
    let out = swoosh(&scratch.0, None, &["--help"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let help = text(&out.stdout);
    #[cfg(target_os = "macos")]
    let line = "home (default ~/Library/Application Support/swoosh)";
    #[cfg(not(target_os = "macos"))]
    let line = "home (default ~/.local/state/swoosh; honors $XDG_STATE_HOME)";
    let flat = help.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains(line), "{help}");
}

/// The extended attribute `tmutil addexclusion` sets on a directory, if `path` carries it.
#[cfg(target_os = "macos")]
fn time_machine_exclusion(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt as _;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = std::ffi::CString::new("com.apple.metadata:com_apple_backup_excludeItem").unwrap();
    let mut value = vec![0_u8; 256];
    // SAFETY: `path` and `name` are live NUL-terminated strings and `value` a live buffer of the length
    // passed; `getxattr` writes at most that many bytes into it.
    let len = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
            0,
            0,
        )
    };
    let len = usize::try_from(len).ok()?;
    value.truncate(len);
    Some(value)
}

/// The first verb that makes the key marks `machine/` for backups to leave out, and only `machine/`: the
/// Time Machine exclusion on macOS, a `CACHEDIR.TAG` elsewhere; the home itself carries neither.
#[test]
fn machine_dir_carries_both_backup_markers() {
    let scratch = Scratch::new("markers");
    let home = scratch.0.join("home");
    let out = swoosh_at(&home, &["status", "--key"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let machine = home.join("machine");
    assert!(machine.join("key").is_file(), "the key is in machine/");

    #[cfg(target_os = "macos")]
    {
        // What `tmutil addexclusion` writes: the binary property list of `com.apple.backupd`.
        let mut excluded = b"bplist00_\x10\x11com.apple.backupd\x08".to_vec();
        excluded.extend([0, 0, 0, 0, 0, 0, 1, 1]);
        excluded.extend([0, 0, 0, 0, 0, 0, 0, 1]);
        excluded.extend([0; 8]);
        excluded.extend([0, 0, 0, 0, 0, 0, 0, 0x1c]);
        assert_eq!(
            time_machine_exclusion(&machine).as_deref(),
            Some(excluded.as_slice()),
            "machine/ is excluded from Time Machine"
        );
        assert_eq!(time_machine_exclusion(&home), None, "the home is backed up");
        assert_eq!(
            time_machine_exclusion(&machine.join("key")),
            None,
            "the mark is on the directory, not the key"
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        let tag = std::fs::read_to_string(machine.join("CACHEDIR.TAG"))
            .expect("machine/ holds a CACHEDIR.TAG");
        assert!(
            tag.starts_with("Signature: 8a477f597d28d172789f06886806bc55"),
            "{tag}"
        );
        assert!(!home.join("CACHEDIR.TAG").exists(), "the home is backed up");
    }
}

/// A key file others can read stops every verb with exit 1 and swoosh's own line, which names the file by
/// its full path and gives the command that fixes it; the key is left as it was.
#[test]
fn a_key_file_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = Scratch::new("readable");
    let home = scratch.0.join("home");
    let made = swoosh_at(&home, &["status", "--key"]);
    assert!(made.status.success(), "{}", text(&made.stderr));
    let key = std::fs::canonicalize(home.join("machine").join("key")).unwrap();
    let before = std::fs::read(&key).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

    let refused = swoosh_at(&std::fs::canonicalize(&home).unwrap(), &["status", "--key"]);
    assert_eq!(refused.status.code(), Some(1), "{}", text(&refused.stderr));
    let path = key.display();
    assert_eq!(
        text(&refused.stderr),
        format!("error: {path} can be read by others: chmod 600 {path}\n")
    );
    assert!(refused.stdout.is_empty(), "no key is printed");
    assert_eq!(std::fs::read(&key).unwrap(), before, "the key is untouched");
}
