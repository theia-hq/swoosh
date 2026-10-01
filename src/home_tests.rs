//! The runtime root's rule: a private, absolute `XDG_RUNTIME_DIR`, or a refusal that names the fix.

use std::ffi::OsString;
use std::path::PathBuf;

use super::{macos_state_home, xdg_runtime_root, xdg_state_home};
use crate::escape::Escaped;

/// Both platforms' default homes, whichever platform runs the test: macOS's under `Application Support`,
/// and the XDG rule, which takes `XDG_STATE_HOME` only when it is absolute. The binary's own platform is
/// driven end to end in `tests/home_layout.rs`.
#[test]
fn the_default_home_rule_holds_on_each_platform() {
    let user = PathBuf::from("/home/you");
    assert_eq!(
        macos_state_home(&user),
        PathBuf::from("/home/you/Library/Application Support/swoosh")
    );
    assert_eq!(
        xdg_state_home(&user, None),
        PathBuf::from("/home/you/.local/state/swoosh")
    );
    assert_eq!(
        xdg_state_home(&user, Some(OsString::from("/var/state"))),
        PathBuf::from("/var/state/swoosh")
    );
    for ignored in ["", "state", "./state"] {
        assert_eq!(
            xdg_state_home(&user, Some(OsString::from(ignored))),
            PathBuf::from("/home/you/.local/state/swoosh"),
            "a relative XDG_STATE_HOME {ignored:?} is ignored"
        );
    }
}

/// The refusal a `serve` prints where no private runtime directory resolves.
const NO_RUNTIME_DIR: &str = "swoosh serve needs a private runtime directory. Set XDG_RUNTIME_DIR to a \
                              directory only you can use (for example /run/user/$(id -u)), or run it as \
                              a systemd --user service.";

/// Unset or relative is refused, never rooted at the cwd, `/tmp` or the home; an absolute one roots at
/// its `swoosh` child.
#[test]
fn an_unset_or_relative_runtime_dir_is_refused_with_the_fix() {
    for value in [
        None,
        Some(OsString::from("run/user/1000")),
        Some(OsString::new()),
    ] {
        let refused = xdg_runtime_root(value.clone());
        let Err(error) = refused else {
            panic!("{value:?} must refuse, not root somewhere: {refused:?}");
        };
        assert_eq!(error.to_string(), NO_RUNTIME_DIR);
    }
    assert_eq!(
        xdg_runtime_root(Some(OsString::from("/run/user/1000"))).expect("an absolute dir roots"),
        PathBuf::from("/run/user/1000/swoosh")
    );
}

/// A fresh home reached through a symlink hashes the same before it is made as after, so the `serve` that
/// claims it first and every later `serve`, `stop` or `status` look for one lock.
#[test]
fn a_fresh_home_keys_the_same_before_and_after_it_is_made() {
    let base = std::env::temp_dir().join(format!("swoosh-home-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("real")).expect("the real dir");
    std::os::unix::fs::symlink(base.join("real"), base.join("link")).expect("the link");
    let dir = base.join("link").join("fresh").join("home");
    let home = super::Home::resolve(Some(dir.clone())).expect("the home resolves");
    let before = home.home_key();
    std::fs::create_dir_all(&dir).expect("the home is made");
    let after = home.home_key();
    let _ = std::fs::remove_dir_all(&base);
    assert_eq!(before, after, "one home, one key");
}

/// Each trust file is checked: one group or other can write is refused by name with the fix, while an
/// owner-only one, or one others may only read, passes.
#[test]
fn every_trust_file_is_refused_when_others_can_write_it() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = std::env::temp_dir().join(format!("swoosh-home-trust-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the home");
    let home = super::Home::resolve(Some(dir.clone())).expect("the home resolves");
    let set = |path: &PathBuf, mode: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("set the mode");
    };
    for path in home.trust_files() {
        std::fs::write(&path, "").expect("the file");
        set(&path, 0o600);
    }
    home.check_trust_files().expect("owner-only files load");
    for path in home.trust_files() {
        set(&path, 0o644);
        home.check_trust_files()
            .expect("a file others may only read loads");
        for mode in [0o620, 0o602] {
            set(&path, mode);
            let refused = home.check_trust_files();
            let Err(
                error @ super::LooseFile {
                    why: super::Loose::Writable,
                    ..
                },
            ) = refused
            else {
                panic!("{} at {mode:o} must refuse: {refused:?}", path.display());
            };
            assert_eq!(
                error.to_string(),
                format!(
                    "{} can be written by others: chmod 600 {}",
                    path.display(),
                    path.display()
                )
            );
        }
        set(&path, 0o600);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A trust file is checked on the handle its bytes are read from: group or other write refuses the read
/// with the file and the fix, and a file others may only read is read.
// `core::io::ErrorKind` is still unstable, so the error kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
#[test]
fn a_trust_file_is_checked_on_the_handle_it_is_read_from() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = std::env::temp_dir().join(format!("swoosh-home-read-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the dir");
    let path = dir.join("links");
    std::fs::write(&path, "a row\n").expect("the file");
    for mode in [0o620, 0o602] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("set the mode");
        let error = super::read_trust_file(&path).expect_err("a loose file is refused");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(super::loose_in(&error), Some(super::Loose::Writable));
        assert_eq!(
            error.to_string(),
            format!(
                "{} can be written by others: chmod 600 {}",
                path.display(),
                path.display()
            )
        );
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("set the mode");
    assert_eq!(super::read_trust_file(&path).expect("read"), "a row\n");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The owner line names the file's owner and this process's user by name, or as `uid <n>` when the uid has
/// no name here, and names no command.
#[test]
fn the_owner_line_names_both_users_and_no_command() {
    // Root is named on every unix; a uid this high is in no passwd database.
    let unnamed = 3_999_999_999;
    let line = |owner, euid| {
        super::LooseFile {
            path: PathBuf::from("/h/links"),
            why: super::Loose::Owner { owner, euid },
        }
        .to_string()
    };
    assert_eq!(
        line(unnamed, 0),
        "/h/links is owned by uid 3999999999, and swoosh is running as root; it will not load another \
         user's file"
    );
    assert_eq!(
        line(0, unnamed),
        "/h/links is owned by root, and swoosh is running as uid 3999999999; it will not load another \
         user's file"
    );
}

/// The path in the `chmod` is shell-quoted when it needs it, and reads back through every shell as the
/// path; the path that leads the line stays bare (through the shared escaper), and a path that needs no
/// quoting prints bare in both places. A path no single-quoted word holds in every shell (fish reads `\'`,
/// tcsh expands `!!`, a newline ends a csh line) gets the lead alone and no command.
#[test]
fn the_chmod_path_is_quoted_only_when_it_needs_it() {
    let base = PathBuf::from("/tmp/f5-quote");
    for (name, command) in [
        ("plain", Some(false)),
        ("my home", Some(true)),
        ("$HOME `x` * \"q\" ~", Some(true)),
        (r"x\'; touch /tmp/pwned-by-fish #", None),
        ("a!!b", None),
        ("a\nb", None),
        ("a'b", None),
        ("a\u{202e}b", None),
    ] {
        let path = base.join(name).join("links");
        let line = super::LooseFile {
            path: path.clone(),
            why: super::Loose::Writable,
        }
        .to_string();
        let lead = format!(
            "{} can be written by others",
            Escaped(&path.to_string_lossy())
        );
        let Some(quoted) = command else {
            assert_eq!(line, lead, "{name:?} names no command");
            continue;
        };
        let word = line
            .strip_prefix(&format!("{lead}: chmod 600 "))
            .unwrap_or_else(|| panic!("the line leads with the bare path: {line}"));
        assert_eq!(word.starts_with('\''), quoted, "{line}");
        if !quoted {
            assert_eq!(word, path.display().to_string());
        }
        for shell in ["sh", "bash", "zsh", "fish", "csh", "tcsh"] {
            // A shell not installed here is skipped; CI installs fish, csh and tcsh.
            let Ok(read) = std::process::Command::new(shell)
                .arg("-c")
                .arg(format!("printf %s {word}"))
                .output()
            else {
                continue;
            };
            assert_eq!(
                String::from_utf8_lossy(&read.stdout),
                path.display().to_string(),
                "{shell} reads {word} back"
            );
        }
    }

    // A non-UTF-8 path has no byte-for-byte word any shell reads back, so the line names no command.
    use std::os::unix::ffi::OsStrExt as _;
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/a\xffb/links"));
    let line = super::LooseFile {
        path: path.clone(),
        why: super::Loose::Writable,
    }
    .to_string();
    assert_eq!(
        line,
        format!("{} can be written by others", path.display()),
        "a non-UTF-8 path names no command"
    );
}

/// A relative home keeps its path as given in the lead, and the `chmod` names the absolute path, so a home
/// that starts with `-` is never read as an option.
#[test]
fn the_chmod_path_is_absolute() {
    let path = PathBuf::from("-x/links");
    let line = super::LooseFile {
        path: path.clone(),
        why: super::Loose::Writable,
    }
    .to_string();
    let lead = "-x/links can be written by others: chmod 600 ";
    let word = line
        .strip_prefix(lead)
        .unwrap_or_else(|| panic!("the line leads with the bare path and a command: {line}"));
    let full = std::path::absolute(&path).expect("the path resolves against the cwd");
    assert_eq!(
        word,
        super::shell_word(&full).expect("a cwd-joined path is a plain or quotable word"),
        "the chmod names the absolute path, however the cwd is spelled"
    );
}

/// A passwd name prints as itself, and one holding a control, format or bidi character, a blank letter,
/// a leading or trailing space, or none at all, prints as its uid.
#[test]
fn a_user_name_that_would_not_print_as_itself_is_its_uid() {
    assert_eq!(super::shown_name("alice", 501), "alice");
    assert_eq!(super::shown_name("jos\u{e9}", 501), "jos\u{e9}");
    for name in [
        "a\u{1b}[2Jb",
        "a\rb",
        "a\nb",
        "a\u{202e}b",
        "a\u{200b}b",
        "\u{115f}",
        "\u{1160}",
        "\u{3164}",
        "\u{ffa0}",
        "\u{2800}",
        " root",
        "root ",
        "",
    ] {
        assert_eq!(super::shown_name(name, 501), "uid 501", "{name:?}");
    }
}

/// The rule over owner, mode and this process's user: this user's or root's file loads unless group or
/// other can write it; another user's file is refused for its owner, whatever its mode, even to root.
#[test]
fn a_trust_file_loads_only_when_its_owner_and_mode_are_sound() {
    use super::Loose::{Owner, Writable};

    let (me, other, root) = (501, 502, 0);
    for (owner, mode, euid, want) in [
        (me, 0o600, me, None),
        (me, 0o644, me, None),
        (me, 0o620, me, Some(Writable)),
        (me, 0o602, me, Some(Writable)),
        (root, 0o644, me, None),
        (root, 0o666, me, Some(Writable)),
        (
            other,
            0o600,
            me,
            Some(Owner {
                owner: other,
                euid: me,
            }),
        ),
        (
            other,
            0o666,
            me,
            Some(Owner {
                owner: other,
                euid: me,
            }),
        ),
        (
            me,
            0o600,
            root,
            Some(Owner {
                owner: me,
                euid: root,
            }),
        ),
    ] {
        assert_eq!(
            super::loose_by(owner, mode, euid),
            want,
            "owner {owner}, mode {mode:o}, euid {euid}"
        );
    }
}

/// known_hosts is a trust file: one group can write is refused by the check every command makes when the
/// home resolves, by its own path; a missing one is not.
#[test]
fn a_loose_known_hosts_is_on_the_trust_list() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = std::env::temp_dir().join(format!("swoosh-home-hosts-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the home");
    let home = super::Home::resolve(Some(dir.clone())).expect("the home resolves");
    home.check_trust_files()
        .expect("a missing known_hosts is not a refusal");
    std::fs::write(home.known_hosts(), "").expect("the file");
    std::fs::set_permissions(home.known_hosts(), std::fs::Permissions::from_mode(0o620))
        .expect("set the mode");
    let refused = home.check_trust_files();
    let Err(super::LooseFile {
        path,
        why: super::Loose::Writable,
    }) = refused
    else {
        panic!("a known_hosts group can write must refuse: {refused:?}");
    };
    assert_eq!(path, home.known_hosts());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A key file is loose when another user owns it, or group or other can read or write it; reading is named
/// first, since the key is a secret.
#[test]
fn a_key_file_is_loose_when_others_can_read_or_write_it() {
    use super::Loose::{Owner, Readable, Writable};

    let me = 501;
    for (owner, mode, want) in [
        (me, 0o100_600, None),
        (me, 0o100_640, Some(Readable)),
        (me, 0o100_604, Some(Readable)),
        (me, 0o100_666, Some(Readable)),
        (me, 0o100_620, Some(Writable)),
        (0, 0o100_600, None),
        (
            502,
            0o100_600,
            Some(Owner {
                owner: 502,
                euid: me,
            }),
        ),
    ] {
        assert_eq!(
            super::loose_key_by(owner, mode, me),
            want,
            "owner {owner}, mode {mode:o}"
        );
    }
}

/// A `--home` that names the key file is refused, and the line names no directory to pass instead: the
/// key's own directory is not the home, and a home there would make a second key.
#[test]
fn a_home_that_is_the_key_file_names_no_directory_to_pass() {
    let home = std::env::temp_dir().join(format!("swoosh-home-file-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join("machine")).unwrap();
    let key = home.join("machine").join("key");
    std::fs::write(&key, b"a key").unwrap();

    let error = super::Home::resolve(Some(key.clone())).expect_err("a file is not a home");
    assert_eq!(
        format!("{error:#}"),
        format!("--home wants a directory, not a file: {}", key.display()),
        "only the file is named"
    );
    std::fs::remove_dir_all(&home).unwrap();
}
