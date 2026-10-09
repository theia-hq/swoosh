//! What a `serve` starts with: the named list, the recorded one, or the default, and how the record is
//! read and written.

use std::path::{Path, PathBuf};

use super::{Replaced, ServingError, Started};
use crate::home::Home;
use crate::serve_toml::ServeToml;

/// What `home`'s `serve.toml` holds, as a `serve`'s watcher reads it when it claims the home.
fn kept(home: &Home) -> ServeToml {
    ServeToml::read(home).expect("read serve.toml")
}

/// A scratch home, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sw-serving-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch home");
        Self(dir)
    }

    fn home(&self) -> Home {
        Home::resolve(Some(self.0.clone())).expect("the scratch home resolves")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn named(entries: &[&str]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| super::service_entry(entry).expect("a service form"))
        .collect()
}

/// A home that never named services serves `ping` and `speed`, and records nothing.
#[test]
fn first_bare_serve_serves_the_default() {
    let scratch = Scratch::new("default");
    let home = scratch.home();
    let started =
        Started::of(&[], &kept(&home), &home, Path::new("/")).expect("a fresh home starts");
    assert_eq!(started, Started::Default);
    assert_eq!(started.entries(), ["ping=ping:", "speed=speed:"]);
    crate::serve_toml::ServeToml::update(&crate::testkit::lock(), &home, |file| {
        started.record(file, &home.serve_toml());
    })
    .expect("recording the default is a no-op");
    assert!(
        !home.serve_toml().exists(),
        "a default start writes no list for the next one"
    );
}

/// A named start is recorded, and the next bare start serves exactly that list, as a resume.
#[test]
fn a_named_list_is_what_the_next_bare_serve_resumes() {
    let scratch = Scratch::new("resume");
    let home = scratch.home();
    let started = Started::of(
        &named(&["ssh", "ping"]),
        &kept(&home),
        &home,
        Path::new("/"),
    )
    .expect("named");
    crate::serve_toml::ServeToml::update(&crate::testkit::lock(), &home, |file| {
        started.record(file, &home.serve_toml());
    })
    .expect("recorded");

    let resumed = Started::of(&[], &kept(&home), &home, Path::new("/")).expect("resumed");
    assert_eq!(
        resumed,
        Started::Resumed(vec!["ssh=sshd:".to_owned(), "ping=ping:".to_owned()]),
        "a bare start after a named one resumes it"
    );
}

/// A named start holds what the list held as a bare start reads it: a built-in written by hand as its name
/// alone (`ping`) was listed, so a start naming it keeps its `off` row. Read the raw entries and `ping`, with
/// no `=`, counts as new, and the start turns it back on (L7 fails open). A list a bare start refuses holds
/// nothing that can be read, so every `off` row stays.
#[test]
fn a_named_start_keeps_off_for_a_hand_written_built_in() {
    let path = Path::new("/home/serve.toml");
    let started = Started::Named(vec!["ping=ping:".to_owned()]);
    for (listed, why) in [
        ("ping", "a hand-written built-in is listed"),
        ("db", "a list a start refuses fails closed"),
    ] {
        let mut file = ServeToml {
            services: Some(vec![listed.to_owned()]),
            off: ["ping".to_owned()].into(),
            ..ServeToml::default()
        };
        started.record(&mut file, path);
        assert!(file.off.contains("ping"), "{why}");
        assert_eq!(file.services, Some(vec!["ping=ping:".to_owned()]), "{why}");
    }
}

/// Every entry of the record goes through the service-entry parser, never the flag parser: an entry that
/// starts with `-` is refused with the file and the entry named, and nothing is served from it.
#[test]
fn resumed_list_is_parsed_as_services_never_flags() {
    let scratch = Scratch::new("flags");
    let home = scratch.home();
    for line in ["--public=ssh", "-q", "not a service"] {
        std::fs::write(
            home.serve_toml(),
            format!("services = [\"ssh=sshd:\", \"{line}\"]\n"),
        )
        .expect("a planted list");
        let refused = Started::of(&[], &kept(&home), &home, Path::new("/"));
        let Err(error @ ServingError::NotAService { .. }) = refused else {
            panic!("a `{line}` line must refuse, not serve: {refused:?}");
        };
        assert_eq!(
            error.to_string(),
            format!(
                "{} lists {line}, which is not a service\n  Edit that file to fix or remove the entry.",
                home.serve_toml().display()
            ),
            "the refusal says what it saw and points at the file, naming no command"
        );
    }
}

/// A path target is recorded absolute, so a service manager started in another directory serves the
/// same files; a `~/…` path is relative like any other (nothing expands it), and a dirless `recv:` (it
/// saves into the inbox), raw `stdin:` and non-path targets are kept as typed.
#[test]
fn resumed_paths_are_absolute() {
    let scratch = Scratch::new("paths");
    let home = scratch.home();
    let cwd = Path::new("/work/here");
    let started = Started::of(
        &named(&[
            "inbox=recv:",
            "drop=recv:.",
            "db=unix:db.sock",
            "logs=file:app.log",
            "live=fifo:pipe+lossy",
            "abs=file:/etc/motd",
            "home=file:~/notes",
            "raw=stdin:",
            "web=tcp:127.0.0.1:8080",
        ]),
        &kept(&home),
        &home,
        cwd,
    )
    .expect("named");
    crate::serve_toml::ServeToml::update(&crate::testkit::lock(), &home, |file| {
        started.record(file, &home.serve_toml());
    })
    .expect("recorded");
    let recorded = crate::serve_toml::ServeToml::read(&home)
        .expect("the record")
        .services
        .unwrap_or_default();
    assert_eq!(
        recorded,
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
        ]
    );
}

/// A service the record cannot hold as typed is refused, and nothing is saved: a line break in the cwd or
/// the typed path, or a space at either end.
#[test]
fn a_path_with_a_newline_is_refused_not_recorded() {
    let scratch = Scratch::new("newline");
    let home = scratch.home();
    for (typed, cwd) in [
        ("inbox=recv:.", "/work/dl\nssh=sshd:"),
        ("inbox=recv:dl\nssh=sshd:", "/work"),
        ("logs=file:app.log ", "/work"),
    ] {
        let refused = Started::of(&[typed.to_owned()], &kept(&home), &home, Path::new(cwd));
        let Err(error @ ServingError::CannotSave { .. }) = refused else {
            panic!("{typed:?} under {cwd:?} must refuse, not be saved: {refused:?}");
        };
        assert!(
            error.to_string().starts_with("inbox=recv:") || error.to_string().starts_with("logs="),
            "the refusal names the service: {error}"
        );
        assert!(!home.serve_toml().exists(), "nothing is saved");
    }
}

/// A path that is not UTF-8 cannot be saved as the path it names, so it is refused.
#[test]
fn a_cwd_that_is_not_utf8_is_refused_not_recorded() {
    use std::os::unix::ffi::OsStrExt as _;

    let scratch = Scratch::new("utf8");
    let home = scratch.home();
    let cwd = Path::new(std::ffi::OsStr::from_bytes(b"/work/\xff"));
    let refused = Started::of(&["inbox=recv:.".to_owned()], &kept(&home), &home, cwd);
    assert!(
        matches!(refused, Err(ServingError::CannotSave { .. })),
        "{refused:?}"
    );
}

/// The record is owner-only: it says what this machine serves.
#[test]
fn the_record_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = Scratch::new("mode");
    let home = scratch.home();
    let started =
        Started::of(&named(&["ping"]), &kept(&home), &home, Path::new("/")).expect("named");
    crate::serve_toml::ServeToml::update(&crate::testkit::lock(), &home, |file| {
        started.record(file, &home.serve_toml());
    })
    .expect("recorded");
    let mode = std::fs::metadata(home.serve_toml())
        .expect("the record")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// What a named start replaces is read against the recorded list only: an entry it drops, a name it keeps
/// under another target, and nothing for a name kept as it was. A home that never recorded a list has
/// nothing to replace, though its default counts as listed elsewhere, and a bare start replaces nothing.
#[test]
fn a_named_start_replaces_only_what_was_recorded() {
    let scratch = Scratch::new("replaces");
    let home = scratch.home();
    let start = |entries: &[&str], kept: &ServeToml| {
        Started::of(&named(entries), kept, &home, Path::new("/")).expect("a start")
    };
    let recorded = ServeToml {
        services: Some(named(&[
            "ssh",
            "web=tcp:localhost:3000",
            "drop=recv:/srv/drop",
        ])),
        ..ServeToml::default()
    };
    assert_eq!(
        start(&["ssh", "web=tcp:localhost:4000"], &recorded)
            .replaces(&recorded, &home.serve_toml()),
        Replaced {
            dropped: vec!["drop=recv:/srv/drop".to_owned()],
            retargeted: vec![(
                "web".to_owned(),
                "tcp:localhost:4000".to_owned(),
                "tcp:localhost:3000".to_owned(),
            )],
        }
    );
    assert_eq!(
        start(&["ssh"], &ServeToml::default()).replaces(&ServeToml::default(), &home.serve_toml()),
        Replaced::default(),
        "a never-named home's default is not reported as replaced"
    );
    assert_eq!(
        start(&[], &recorded).replaces(&recorded, &home.serve_toml()),
        Replaced::default(),
        "a bare start replaces nothing"
    );
    // A built-in written by hand as its name alone is read as a bare start reads it, so dropping it is
    // reported. Read the raw entries and `ping`, with no `=`, is skipped and its drop goes unsaid.
    let by_hand = ServeToml {
        services: Some(vec!["ping".to_owned(), "ssh".to_owned()]),
        ..ServeToml::default()
    };
    assert_eq!(
        start(&["ssh"], &by_hand).replaces(&by_hand, &home.serve_toml()),
        Replaced {
            dropped: vec!["ping=ping:".to_owned()],
            retargeted: vec![],
        },
        "a hand-written built-in a named start drops is reported"
    );
}
