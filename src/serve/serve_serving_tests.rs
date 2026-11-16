use std::path::Path;

use super::{Added, EditError, Mistyped, ServingError, Started};
use crate::serve::{DefinitionCause, DefinitionError, Operand};
use crate::serve_toml::ServeToml;

fn entries(list: &[&str]) -> Vec<String> {
    list.iter().map(|text| (*text).to_owned()).collect()
}

#[test]
fn default_empty_and_exclusive_selection_never_write_saved_policy() {
    for services in [None, Some(vec![]), Some(entries(&["speed"]))] {
        let file = ServeToml {
            services,
            off: ["ping".to_owned()].into(),
            ..ServeToml::default()
        };
        let before = file.clone();
        let selected = Started::of(
            &entries(&["PING", "web=tcp:localhost:3000"]),
            &file,
            Path::new("/"),
        )
        .unwrap();
        assert_eq!(selected.entries(), ["ping=ping:", "web=tcp:localhost:3000"]);
        let bare = Started::of(&[], &file, Path::new("/")).unwrap();
        assert_eq!(
            bare.entries(),
            match &file.services {
                None => entries(&["ping=ping:", "speed=speed:"]),
                Some(list) if list.is_empty() => vec![],
                Some(_) => entries(&["speed=speed:"]),
            }
        );
        assert_eq!(file, before);
    }
}

#[test]
fn duplicate_normalized_constructors_identify_the_second_operand() {
    let file = ServeToml::default();
    let error = Started::of(&entries(&["PING", "ping"]), &file, Path::new("/")).unwrap_err();
    assert!(matches!(
        error,
        ServingError::Definition(DefinitionError {
            operand: Operand::Positional,
            index: 2,
            cause: DefinitionCause::Collision,
        })
    ));
}

#[test]
fn saved_lists_receive_complete_validation_without_preparing_backends() {
    for invalid in [
        "--public=ssh",
        "-q",
        "not a service",
        "db",
        "bad=ping:80",
        "bad=file:",
        "bad=proxy:https://user:secret@example.test",
    ] {
        let file = ServeToml {
            services: Some(entries(&["ping", invalid])),
            ..ServeToml::default()
        };
        let error = Started::bare(&file).unwrap_err();
        assert!(matches!(
            error,
            ServingError::Definition(DefinitionError {
                operand: Operand::Saved,
                index: 2,
                ..
            })
        ));
        assert!(!format!("{error:?} {error}").contains(invalid));
    }
    // Syntax validity is independent of whether a path exists, stdin is a TTY, or HOME is set.
    let file = ServeToml {
        services: Some(entries(&[
            "raw=stdin:",
            "drop=recv:",
            "logs=file:/nonexistent/source",
            "pipe=fifo:/nonexistent/pipe",
        ])),
        ..ServeToml::default()
    };
    assert!(Started::bare_at(&file, Path::new("/work")).is_ok());
}

#[test]
fn invocation_paths_keep_lexical_spelling_and_receive_suffixes() {
    let selected = Started::positional(
        &entries(&[
            "inbox=recv:",
            "drop=recv:.",
            "db=unix:db.sock",
            "logs=file:app.log",
            "live=fifo:pipe+lossy",
            "abs=file:/etc/motd",
            "home=file:~/notes",
            "raw=stdin:",
            "web=tcp:127.0.0.1:8080",
            "literal=recv:dir+lossy",
        ]),
        Path::new("/work/here"),
    )
    .unwrap();
    assert_eq!(
        selected.entries(),
        [
            "inbox=recv:",
            "drop=recv:/work/here/.",
            "db=unix:/work/here/db.sock",
            "logs=file:/work/here/app.log",
            "live=fifo:/work/here/pipe+lossy",
            "abs=file:/etc/motd",
            "home=file:/work/here/~/notes",
            "raw=stdin:",
            "web=tcp:127.0.0.1:8080",
            "literal=recv:/work/here/dir+lossy",
        ]
    );
}

#[test]
fn controls_boundary_spaces_and_unrepresentable_cwd_are_finite_refusals() {
    for (entry, cwd) in [
        ("inbox=recv:.", "/work/dl\nssh=sshd:"),
        ("inbox=recv:dl\nssh=sshd:", "/work"),
        ("logs=file:app.log ", "/work"),
    ] {
        let error = Started::positional(&entries(&[entry]), Path::new(cwd)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid service definition at index 1: invalid target form"
        );
        assert!(!format!("{error:?}").contains(entry));
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let cwd = Path::new(std::ffi::OsStr::from_bytes(b"/work/\xff"));
        let error = Started::positional(&entries(&["inbox=recv:."]), cwd).unwrap_err();
        assert!(matches!(
            error,
            ServingError::Definition(DefinitionError {
                cause: DefinitionCause::Encoding,
                ..
            })
        ));
    }
}

#[test]
fn removing_saved_services_retains_off_names_and_explicit_empty_membership() {
    for (services, removed, expected) in [
        (
            Some(entries(&["ping", "speed"])),
            vec!["ping"],
            vec!["speed"],
        ),
        (Some(entries(&["ping"])), vec!["ping"], vec![]),
        (None, vec!["ping", "speed"], vec![]),
        (None, vec![], vec!["ping=ping:", "speed=speed:"]),
        (Some(vec![]), vec![], vec![]),
    ] {
        let mut file = ServeToml {
            services,
            off: ["ping".to_owned(), "unlisted".to_owned()].into(),
            ..ServeToml::default()
        };
        let off = file.off.clone();
        let names: Vec<_> = removed.iter().map(|name| name.parse().unwrap()).collect();
        file.remove(&names).unwrap();
        assert_eq!(file.services, Some(entries(&expected)));
        assert_eq!(file.off, off);
    }
}

#[test]
fn failed_whole_list_edits_are_atomic_and_readding_keeps_off_marks() {
    let cwd = Path::new("/work");
    let mut file = ServeToml {
        services: Some(entries(&["ping"])),
        off: ["ping".to_owned()].into(),
        ..ServeToml::default()
    };
    for added in [
        vec!["speed", "bad=ping:80"],
        vec!["PING", "ping"],
        vec!["speed", "ping=echo:"],
    ] {
        let before = file.clone();
        assert!(file.add(&entries(&added), cwd).is_err());
        assert_eq!(file, before);
    }
    for removed in [vec!["ping", "missing"], vec!["ping", "ping"]] {
        let before = file.clone();
        let names: Vec<_> = removed.iter().map(|name| name.parse().unwrap()).collect();
        assert!(file.remove(&names).is_err());
        assert_eq!(file, before);
    }
    assert!(matches!(
        Mistyped::check_names(["ping", "PING"]),
        Err(Mistyped(DefinitionError {
            index: 2,
            cause: DefinitionCause::Collision,
            ..
        }))
    ));
    file.remove(&["ping".parse().unwrap()]).unwrap();
    assert_eq!(file.services, Some(vec![]));
    assert_eq!(
        file.add(&entries(&["ping"]), cwd).unwrap(),
        [Added::New("ping".into())]
    );
    assert_eq!(
        file.add(&entries(&["ping"]), cwd).unwrap(),
        [Added::ListedOff("ping".into())]
    );
    assert!(file.off.contains("ping"));
}

#[test]
fn malformed_saved_membership_cannot_be_repaired_by_an_unrelated_edit() {
    for invalid in ["db", "--public=ssh", "ping", "bad=ping:80"] {
        let mut file = ServeToml {
            services: Some(entries(&["ping", invalid])),
            off: ["ping".into()].into(),
            ..ServeToml::default()
        };
        let before = file.clone();
        let error = file.remove(&["ping".parse().unwrap()]).unwrap_err();
        assert!(matches!(
            error,
            EditError::Serving(ServingError::Definition(DefinitionError {
                operand: Operand::Saved,
                index: 2,
                ..
            }))
        ));
        assert_eq!(file, before);
        assert!(file.add(&entries(&["speed"]), Path::new("/work")).is_err());
        assert_eq!(file, before);
    }
}

/// `add` writes back every entry it was not given exactly as saved: a relative path keeps the meaning it was
/// saved with rather than taking the directory this `add` ran in, and a short form stays short.
#[test]
fn add_leaves_existing_saved_entries_as_saved() {
    let saved = entries(&["files=recv:inbox", "Ping", "logs=file:./logs"]);
    let mut file = ServeToml {
        services: Some(saved.clone()),
        ..ServeToml::default()
    };
    assert_eq!(
        file.add(&entries(&["web=echo:"]), Path::new("/work"))
            .unwrap(),
        [Added::New("web".into())]
    );
    let mut expected = saved;
    expected.push("web=echo:".to_owned());
    assert_eq!(file.services, Some(expected));
    assert_eq!(
        file.add(&entries(&["files=recv:inbox"]), Path::new("/work"))
            .unwrap(),
        [Added::Listed("files".into())],
        "compared where this add ran, as the entry it was given is"
    );
}
