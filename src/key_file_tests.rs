//! The keystore boundary: every refusal of a key file prints swoosh's words and swoosh's own path, never the
//! key store's text, its chain, or the path it acted on.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use keystore::{Error, Method, NewLock, Protection, Secret, Stored, Unlock};
use zeroize::Zeroizing;

use super::{KeyFile, Kind, Refused, Whose, chmod_operand, key_store_errors, path_cell};
use crate::home::Home;

/// The keystore rev the words for every variant were read at. Moves only with a re-read of each refusal
/// against the key store's `error.rs` at the new rev.
const READ_AT: &str = "301c6535c344c21b4ef6694a55c6b9c628663cbb";

/// A home under the temp dir, empty, unique to this test.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-key-file-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("machine")).unwrap();
    dir
}

fn passphrase(text: &str) -> keystore::Passphrase {
    keystore::Passphrase::try_from(Zeroizing::new(text.to_owned())).unwrap()
}

/// A path the key store might name that swoosh never does: a link's target.
fn elsewhere() -> PathBuf {
    PathBuf::from("/elsewhere/link-target")
}

/// The path row a refusal prints.
#[derive(Debug, Clone, Copy)]
enum Row {
    /// `file`, the key file swoosh named.
    File,
    /// `home`, the home holding it.
    Home,
}

/// The path row `error`'s refusal of `file` prints: only an access, a type, a mode and an owner refusal
/// name the file, and a disk refusal names the home, but for a copy, whose `copy` row already names it.
fn row(error: &Error, file: &KeyFile) -> Option<Row> {
    match error {
        Error::Io { .. }
        | Error::NotAFile { .. }
        | Error::Permissive { .. }
        | Error::Owner { .. } => Some(Row::File),
        Error::NoHardLinks { .. } => match file.whose() {
            Whose::Copy(_) => None,
            Whose::Machine | Whose::Root => Some(Row::Home),
        },
        _ => None,
    }
}

/// Every sentence the key store would print for `error`: its own message and each cause under it.
fn key_store_sentences(error: &Error) -> Vec<String> {
    let mut said = vec![error.to_string()];
    let mut next = core::error::Error::source(error);
    while let Some(cause) = next {
        said.push(cause.to_string());
        next = cause.source();
    }
    said
}

/// The words of the three files a refusal can be for, in one home and one typed directory.
fn files(tag: &str) -> (PathBuf, Vec<KeyFile>) {
    let dir = scratch(tag);
    let home = Home::resolve(Some(dir.clone())).unwrap();
    let files = vec![
        KeyFile::machine(&home),
        KeyFile::root(&home),
        KeyFile::copy(&dir.join("stick")),
    ];
    (dir, files)
}

/// Each refusal the key store answers, for each whose, prints none of the key store's sentences, none of its
/// vocabulary, and a path only on the rows that need one, and only swoosh's own. The ruled `warning:` head of
/// an unsynced write is swoosh's, so its `failure` row is held to the same. Red when any variant's text or
/// chain reaches the line, or a path prints where none should.
#[test]
fn keystore_text_never_reaches_stderr() {
    let (dir, files) = files("never-reaches");
    for file in &files {
        // The key store's templates name the path they acted on; a refusal that printed one with swoosh's
        // own path in it, raw or as a row prints it, is the same leak.
        let own_forms = [file.path().display().to_string(), path_cell(file.path())];
        for error in key_store_errors() {
            let row = row(&error, file);
            let said = key_store_sentences(&error);
            let refused = file.refuse(error);
            let printed = format!("{:#}", eyre::Report::new(refused));
            let line = format!("error: {printed}");
            for sentence in &said {
                assert!(
                    !line.contains(sentence.as_str()),
                    "{sentence:?} in {line:?}"
                );
                for own in &own_forms {
                    let as_if_named_here = sentence.replace("/elsewhere/link-target", own);
                    assert!(
                        !line.contains(&as_if_named_here),
                        "{as_if_named_here:?} in {line:?}"
                    );
                }
            }
            for word in [
                "strict key",
                "standard key",
                "touch-id lock",
                "owned by uid",
                "/elsewhere",
            ] {
                assert!(!line.contains(word), "{word:?} in {line:?}");
            }
            let own = path_cell(file.path());
            let home = path_cell(home_of(file));
            match row {
                Some(Row::File) => assert!(line.contains(&format!("\n  file   {own}")), "{line}"),
                Some(Row::Home) => assert!(line.contains(&format!("\n  home   {home}")), "{line}"),
                None => {
                    // The whole path: a cut cell of it can equal the cut `copy` row above it.
                    assert!(!line.contains(&file.path().display().to_string()), "{line}");
                    assert!(!line.contains("\n  file   "), "{line}");
                    assert!(!line.contains("\n  home   "), "{line}");
                }
            }
        }
        let unsynced = file.refuse(Error::Unsynced {
            path: elsewhere(),
            source: io::Error::other("the disk went away"),
        });
        assert_eq!(
            unsynced.unsynced().as_deref(),
            Some(
                "the directory holding the key file could not be synced to disk: the disk went away"
            )
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The home a file's `home` row names.
fn home_of(file: &KeyFile) -> &Path {
    let dir = file.path().parent().unwrap();
    match file.whose() {
        super::Whose::Machine => dir.parent().unwrap(),
        super::Whose::Root | super::Whose::Copy(_) => dir,
    }
}

/// A home's `root.key` that is a link to a file whose name holds terminal escapes: a lock change resolves the
/// link and the key store names the target, but the line names only the file swoosh named. (A copy's link is
/// refused before the key store is asked, below.) Red when the target's name, or any escape, reaches the line.
#[test]
fn a_link_to_an_escape_named_target_prints_only_the_named_file() {
    let dir = scratch("link-target");
    let home = Home::resolve(Some(dir.clone())).unwrap();
    let target = dir.join("\u{1b}[2J\u{1b}[Hrun this");
    let under = passphrase("the root's own passphrase");
    keystore::KeyFile::strict(&target)
        .write(
            &Secret::take(&mut [0x22; 32]),
            Protection::Passphrase(&under),
        )
        .unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink(&target, home.root_key()).unwrap();

    let file = KeyFile::root(&home);
    let new = passphrase("a new passphrase for it");
    let raw = keystore::KeyFile::strict(file.path())
        .add_lock(Some(Unlock::Passphrase(&under)), NewLock::Passphrase(&new))
        .unwrap_err();
    // The fixture reaches the case: the key store's own text names the link's target.
    assert!(raw.to_string().contains("run this"), "{raw}");
    let refused = file
        .add_lock(Some(Unlock::Passphrase(&under)), NewLock::Passphrase(&new))
        .unwrap_err();
    assert_eq!(refused.kind(), Kind::Permissive);
    let line = format!("{:#}", eyre::Report::new(refused));
    assert!(!line.contains("run this"), "{line:?}");
    assert!(!line.contains('\u{1b}'), "{line:?}");
    assert!(
        line.starts_with(&format!(
            "your root's key file gives other users access\n  file   {}",
            path_cell(file.path())
        )),
        "{line:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A copy whose `root.key` is a link is refused before the key store reads or writes it, by every act: a
/// lock change follows a link, so a copy linked to the home's root would change the home's while the line
/// said the copy. The line names the typed directory and the file in it, never the link's target. Red when
/// any act reaches the key store through the link, or the target is named.
#[test]
fn a_copy_whose_key_file_is_a_link_is_refused() {
    let dir = scratch("copy-link");
    let home = Home::resolve(Some(dir.clone())).unwrap();
    let under = passphrase("the root's own passphrase");
    let secret = || Secret::take(&mut [0x44; 32]);
    KeyFile::root(&home)
        .write(&secret(), Protection::Passphrase(&under))
        .unwrap();
    let kept = std::fs::read(home.root_key()).unwrap();
    let stick = dir.join("stick");
    std::fs::create_dir_all(&stick).unwrap();
    std::os::unix::fs::symlink(home.root_key(), stick.join("root.key")).unwrap();

    let file = KeyFile::copy(&stick);
    let new = passphrase("a new passphrase for it");
    let refusals = [
        file.load().map(drop).unwrap_err(),
        file.write(&secret(), Protection::Passphrase(&new))
            .unwrap_err(),
        file.adopt(&secret(), Protection::Passphrase(&new))
            .unwrap_err(),
        file.add_lock(Some(Unlock::Passphrase(&under)), NewLock::Passphrase(&new))
            .unwrap_err(),
        file.remove_lock(Unlock::Passphrase(&under), Method::Passphrase)
            .unwrap_err(),
        file.reopen(Unlock::Passphrase(&under)).unwrap_err(),
    ];
    for refused in refusals {
        assert_eq!(refused.kind(), Kind::Link);
        assert_eq!(
            refused.to_string(),
            format!(
                "the copy's key file is a link\n  copy   {}\n  file   {}\n  \
                 The key file must be the file itself, not a link to it.",
                path_cell(&stick),
                path_cell(file.path())
            )
        );
    }
    assert_eq!(std::fs::read(home.root_key()).unwrap(), kept);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Each refusal's whole lines, for this machine's key and for a copy, at short paths whose rows are not
/// cut: the words a person reads, byte for byte. Red when any byte moves off the ruled words.
#[test]
fn each_refusal_prints_its_ruled_lines() {
    let home = Home::resolve(Some("/h".into())).unwrap();
    let machine = KeyFile::machine(&home);
    let copy = KeyFile::copy(Path::new("/stick"));
    let path = elsewhere;
    let rows: [(&KeyFile, Error, &str); 14] = [
        (
            &machine,
            Error::NotAFile { path: path() },
            "this machine's key file is not a regular file\n  file   /h/machine/key",
        ),
        (
            &machine,
            Error::Owner {
                path: path(),
                owner: 501,
            },
            "this machine's key file belongs to another user\n  file   /h/machine/key",
        ),
        (
            &copy,
            Error::Owner {
                path: path(),
                owner: 501,
            },
            "the copy's key file belongs to another user\n  copy   /stick\n  file   /stick/root.key",
        ),
        (
            &machine,
            Error::Inconsistent { path: path() },
            "this machine's key file is damaged",
        ),
        (
            &machine,
            Error::Unlock {
                path: path(),
                method: Method::TouchId,
            },
            "Touch ID did not open this machine's key",
        ),
        (
            &copy,
            Error::Unlock {
                path: path(),
                method: Method::TouchId,
            },
            "Touch ID did not open the copy\n  copy   /stick",
        ),
        (
            &machine,
            Error::Sealed { path: path() },
            "could not use this machine's key file",
        ),
        (
            &copy,
            Error::Occupied { path: path() },
            "could not use the copy's key file\n  copy   /stick",
        ),
        (
            &machine,
            Error::Unverified { path: path() },
            "could not use this machine's key file\n  The key file is as it was.",
        ),
        (
            &machine,
            Error::Changed { path: path() },
            "could not use this machine's key file\n  \
             The key file changed while this ran, and was left as it now is.",
        ),
        (
            &machine,
            Error::Unsynced {
                path: path(),
                source: io::Error::other("the disk went away"),
            },
            "this machine's key file was written but not synced to disk\n  \
             A power loss could undo the change.",
        ),
        (
            &copy,
            Error::Unsynced {
                path: path(),
                source: io::Error::other("the disk went away"),
            },
            "the copy's key file was written but not synced to disk\n  \
             copy   /stick\n  \
             A power loss could undo the change.",
        ),
        (
            &machine,
            Error::NoHardLinks {
                path: path(),
                source: io::Error::other("operation not supported"),
            },
            "this home's disk cannot store a key file safely\n  home   /h\n  \
             The disk may not support hard links, which a key file needs.",
        ),
        (
            &copy,
            Error::NoHardLinks {
                path: path(),
                source: io::Error::other("operation not supported"),
            },
            "the copy's disk cannot store a key file safely\n  copy   /stick\n  \
             The disk may not support hard links, which a key file needs.",
        ),
    ];
    for (file, error, expected) in rows {
        assert_eq!(file.refuse(error).to_string(), expected);
    }
}

/// A path wider than its row is cut to the row's room by the most columns its glyphs can fill, so a row of
/// wide glyphs never wraps onto a line of its own, and a loose file at such a path names no command, since a
/// command cut to fit would not run as printed. A path that fits prints whole, with its command. Red when a
/// row passes its room or a cut command prints.
#[test]
fn a_wide_path_is_cut_to_its_row_and_names_no_command() {
    let loose = || Error::Permissive {
        path: elsewhere(),
        mode: 0o644,
    };
    let fits = KeyFile::copy(Path::new("/Volumes/STICK"));
    assert_eq!(
        fits.refuse(loose()).to_string(),
        "the copy's key file gives other users access\n  copy   /Volumes/STICK\n  \
         file   /Volumes/STICK/root.key\n\nTo fix it:\n  chmod 600 -- /Volumes/STICK/root.key"
    );
    let dir = Path::new("/").join("鍵".repeat(40));
    let wide = KeyFile::copy(&dir);
    let line = wide.refuse(loose()).to_string();
    assert_eq!(
        line,
        format!(
            "the copy's key file gives other users access\n  copy   {}\n  file   {}\n  \
             Take that access off the file.",
            path_cell(&dir),
            path_cell(wide.path())
        )
    );
    for row in line.lines() {
        assert!(
            crate::escape::columns(row) < crate::escape::LINE_WIDTH,
            "{row}"
        );
    }
    assert!(line.contains(crate::escape::CELL_CUT), "{line}");
}

/// A refusal has no source, so `{report:#}` prints its words alone, and its `Debug` names whose file and the
/// key store's variant only. Red when a chain or the key store's text or path comes back on either.
#[test]
fn refused_has_no_source() {
    let (dir, files) = files("no-source");
    for refused in files[0].every_refusal() {
        assert!(core::error::Error::source(&refused).is_none());
        let debug = format!("{refused:?}");
        assert!(!debug.contains("elsewhere"), "{debug}");
        assert!(
            debug.starts_with("Refused { whose: Machine, error: \""),
            "{debug}"
        );
    }
    let refused = files[2].refuse(Error::Permissive {
        path: elsewhere(),
        mode: 0o644,
    });
    assert_eq!(
        format!("{refused:?}"),
        format!(
            "Refused {{ whose: Copy({:?}), error: \"Permissive\" }}",
            dir.join("stick")
        )
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A wrong passphrase and a sealed file whose body was damaged print one byte string: the cipher cannot tell
/// them apart, and a line that did would be an oracle. Red when the two lines differ, or the damage lands
/// where the parser reads it, which would not reach the unlock.
#[test]
fn wrong_or_damaged_reads_alike() {
    let dir = scratch("wrong-or-damaged");
    let home = Home::resolve(Some(dir.clone())).unwrap();
    let file = KeyFile::machine(&home);
    let right = passphrase("the right passphrase here");
    file.write(
        &Secret::take(&mut [0x33; 32]),
        Protection::Passphrase(&right),
    )
    .unwrap();
    let open = |with: &keystore::Passphrase| {
        let Some(Stored::Locked(locked)) = file.load().unwrap() else {
            panic!("sealed");
        };
        file.unlock(&locked, Unlock::Passphrase(with)).unwrap_err()
    };
    let wrong = open(&passphrase("not the passphrase at all"));
    // The last byte is the sealed seed's tag, read only by the cipher after the passphrase opens its lock.
    let mut bytes = std::fs::read(file.path()).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(file.path(), &bytes).unwrap();
    let damaged = open(&right);
    assert_eq!(wrong.kind(), Kind::Unlock(Method::Passphrase));
    assert_eq!(damaged.kind(), Kind::Unlock(Method::Passphrase));
    assert_eq!(wrong.to_string(), damaged.to_string());
    assert_eq!(
        wrong.to_string(),
        "that passphrase does not open this machine's key\n  \
         If you are sure it is right, the key file may be damaged."
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The keystore rev `Cargo.toml` pins is the one every refusal's words were read at. Red on a bump without a
/// re-read; `Cargo.lock` is not read, since a patched build rewrites it to a path.
#[test]
fn keystore_pin_is_the_read_one() {
    let manifest = include_str!("../Cargo.toml");
    let line = manifest
        .lines()
        .find(|line| line.starts_with("keystore ="))
        .expect("keystore is a dependency");
    let rev = line
        .split("rev = \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("keystore is pinned by rev");
    assert_eq!(rev, READ_AT);
}

/// The fix for a loose file is a command that runs as printed or none: a plain absolute path bare, anything
/// a shell would read specially single-quoted (a leading `~`, `=` or `-` among them), an embedded quote
/// written `'\''`, and no command for a path the escaper changes or that is not text. Red when a path that
/// needs quoting prints bare, or a command prints for one that would not run as shown.
#[test]
fn a_chmod_hint_runs_as_printed_or_is_not_printed() {
    use std::os::unix::ffi::OsStrExt as _;

    for (path, operand) in [
        (
            "/home/me/.swoosh/machine/key",
            Some("/home/me/.swoosh/machine/key"),
        ),
        ("./stick/root.key", Some("./stick/root.key")),
        ("/a b/root.key", Some("'/a b/root.key'")),
        ("~bob/root.key", Some("'~bob/root.key'")),
        // zsh's `extendedglob` reads a `~` mid-word, so one anywhere is quoted.
        ("/a~b/root.key", Some("'/a~b/root.key'")),
        ("/home/me/~/root.key", Some("'/home/me/~/root.key'")),
        ("=ls/root.key", Some("'=ls/root.key'")),
        ("-x/root.key", Some("'-x/root.key'")),
        ("stick/root.key", Some("'stick/root.key'")),
        ("/it's/root.key", Some(r"'/it'\''s/root.key'")),
        ("/$(rm)/root.key", Some("'/$(rm)/root.key'")),
        ("/a\nb/root.key", None),
        ("/a\u{1b}[2J/root.key", None),
        ("/a\u{202e}b/root.key", None),
    ] {
        assert_eq!(
            chmod_operand(Path::new(path)).as_deref(),
            operand,
            "{path:?}"
        );
    }
    let not_text = std::ffi::OsStr::from_bytes(b"/a\xff/root.key");
    assert_eq!(chmod_operand(Path::new(not_text)), None);
}

/// A loose file with a control character in its path prints the path escaped and no `To fix it:` block.
#[test]
fn a_loose_file_with_a_control_in_its_path_names_no_command() {
    let refused: Refused = KeyFile::copy(Path::new("/st\u{7}ick")).refuse(Error::Permissive {
        path: elsewhere(),
        mode: 0o644,
    });
    assert_eq!(
        refused.to_string(),
        "the copy's key file gives other users access\n  copy   /st\\u{7}ick\n  file   /st\\u{7}ick/root.key\n  \
         Take that access off the file."
    );
}
