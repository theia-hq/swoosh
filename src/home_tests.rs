//! The runtime root's rule: a private, absolute `XDG_RUNTIME_DIR`, or a refusal that names the fix.

use std::ffi::OsString;
use std::path::PathBuf;

use super::xdg_runtime_root;

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

/// The path in the `chmod` is shell-quoted when it needs it, and reads back through `sh` as the path; the
/// path that leads the line stays bare, and a path that needs no quoting prints bare in both places.
#[test]
fn the_chmod_path_is_quoted_only_when_it_needs_it() {
    use std::os::unix::fs::PermissionsExt as _;

    let base = std::env::temp_dir().join(format!("swoosh-home-quote-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    for (name, quoted) in [
        ("plain", false),
        ("my home", true),
        ("it's $HOME `x` *", true),
    ] {
        let dir = base.join(name);
        std::fs::create_dir_all(&dir).expect("the home");
        let home = super::Home::resolve(Some(dir.clone())).expect("the home resolves");
        let path = home.links();
        std::fs::write(&path, "").expect("the file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620))
            .expect("set the mode");
        let line = home
            .check_trust_files()
            .expect_err("a loose file is refused")
            .to_string();
        let lead = format!("{} can be written by others: chmod 600 ", path.display());
        let word = line
            .strip_prefix(&lead)
            .unwrap_or_else(|| panic!("the line leads with the bare path: {line}"));
        assert_eq!(word.starts_with('\''), quoted, "{line}");
        if !quoted {
            assert_eq!(word, path.display().to_string());
        }
        let read = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf %s {word}"))
            .output()
            .expect("sh runs");
        assert_eq!(
            String::from_utf8_lossy(&read.stdout),
            path.display().to_string()
        );
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// A known_hosts another user owns is refused by the check every command makes when the home resolves,
/// with the owner line; a missing one is not. The file is a link to a path another user owns, since a test
/// cannot make a file owned by someone else, and the check follows links as the read does.
#[test]
fn a_known_hosts_another_user_owns_is_refused() {
    let dir = std::env::temp_dir().join(format!("swoosh-home-hosts-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the home");
    let home = super::Home::resolve(Some(dir.clone())).expect("the home resolves");
    home.check_trust_files()
        .expect("a missing known_hosts is not a refusal");
    let foreign = owned_by_another_user();
    std::os::unix::fs::symlink(&foreign, home.known_hosts()).expect("the link");
    let refused = home.check_trust_files();
    let Err(
        error @ super::LooseFile {
            why: super::Loose::Owner { .. },
            ..
        },
    ) = refused
    else {
        panic!("a known_hosts another user owns must refuse: {refused:?}");
    };
    assert_eq!(error.path, home.known_hosts());
    assert!(
        error
            .to_string()
            .ends_with("; it will not load another user's file"),
        "{error}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A path on this machine owned by neither this process's user nor root, found under the system's own
/// state directories (a service user's), which every test machine has.
fn owned_by_another_user() -> PathBuf {
    use std::os::unix::fs::MetadataExt as _;

    // SAFETY: `geteuid` takes no arguments and touches no memory.
    let euid = unsafe { libc::geteuid() };
    let mut level = vec![PathBuf::from("/var"), PathBuf::from("/run")];
    for _ in 0..3 {
        let mut next = Vec::new();
        for dir in level {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = std::fs::metadata(&path) else {
                    continue;
                };
                if meta.uid() != euid && meta.uid() != 0 {
                    return path;
                }
                if meta.is_dir() {
                    next.push(path);
                }
            }
        }
        level = next;
    }
    panic!(
        "no path under /var or /run is owned by another user, so the owner check cannot be tried"
    );
}
