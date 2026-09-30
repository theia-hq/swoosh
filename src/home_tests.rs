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
            let Err(error @ super::LooseFile::Writable { .. }) = refused else {
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
