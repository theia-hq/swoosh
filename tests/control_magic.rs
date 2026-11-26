// A source scan panics on a tree it cannot read, which is the intent; exempt it from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Two guards on the control socket that no running test can hold, read from `src/` and `tests/`.
//!
//! The control magic is spelled once, where it is defined. A test that spells it out goes stale at a
//! version bump, and its frame is then refused as another build's, so a test meant to exercise one
//! rejection passes on that one instead. Only the definition's file, the one test that pins the tag,
//! and the fixtures that stand for another build (`SWC9`, `SWC1`) may write a tag.
//!
//! And the reach record has one codec, the control socket's: no other file names it beside its own.

use std::path::Path;

/// The file that defines the magic, and may name it in its docs as often as they need.
const DEFINED: &str = "src/serve/socket.rs";

/// The one test that pins the tag, and how many times it may spell it.
const PINNED: (&str, usize) = ("src/serve/socket_tests.rs", 1);

/// Tags that stand for another build. A frame on one of them is refused as another build's, which is
/// what those fixtures mean.
const OTHER_BUILDS: [&str; 2] = ["SWC9", "SWC1"];

#[test]
fn the_control_magic_is_spelled_once() {
    let mut pinned = 0;
    for (file, text) in sources() {
        if file == DEFINED {
            continue;
        }
        for (at, _) in text.match_indices("SWC") {
            let Some(tag) = text.get(at..at + 4) else {
                continue;
            };
            if !tag.as_bytes()[3].is_ascii_digit() || OTHER_BUILDS.contains(&tag) {
                continue;
            }
            let line = text[..at].lines().count();
            assert_eq!(
                file, PINNED.0,
                "{file}:{line}: `{tag}` spelled out; use `testkit::CONTROL_MAGIC`"
            );
            pinned += 1;
        }
    }
    // The same tag as bytes, which a text search for it misses.
    for (file, text) in sources() {
        for spelled in ["b'S', b'W', b'C'", "0x53, 0x57, 0x43"] {
            assert!(
                !text.contains(spelled) || file == "tests/control_magic.rs",
                "{file}: the magic spelled as bytes; use `testkit::control_header`"
            );
        }
    }
    assert_eq!(
        pinned, PINNED.1,
        "{} spells the tag {pinned} times",
        PINNED.0
    );
}

/// The reach record's impls, its codec among them, live only beside the type and in the control
/// socket, whose visibility keeps the codec there; and the types derive nothing that writes them
/// anywhere else.
#[test]
fn the_reach_record_has_one_codec() {
    const HOME: [&str; 2] = ["src/serve/reachable.rs", "src/serve/socket/reach.rs"];
    for (file, text) in sources() {
        if HOME.contains(&file.as_str())
            || file.ends_with("_tests.rs")
            || file.starts_with("tests/")
        {
            continue;
        }
        for name in ["Reachable", "Picks"] {
            assert!(
                !text.contains(&format!("for {name}")) && !text.contains(&format!("impl {name}")),
                "{file}: an impl on `{name}` lives beside the type or in the control socket"
            );
        }
    }
    let types = std::fs::read_to_string(Path::new("src/serve/reachable.rs")).unwrap();
    for derive in types
        .lines()
        .filter(|line| line.trim_start().starts_with("#[derive("))
    {
        let names = derive
            .trim()
            .trim_start_matches("#[derive(")
            .trim_end_matches(")]");
        for name in names.split(',').map(str::trim) {
            assert!(
                ["Debug", "Clone", "Copy", "PartialEq", "Eq"].contains(&name),
                "reachable.rs derives `{name}`, a second way to write the record"
            );
        }
    }
}

/// Every `.rs` file under `src/` and `tests/`, as (path from the crate root, text).
fn sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut dirs = vec![
        Path::new("src").to_path_buf(),
        Path::new("tests").to_path_buf(),
    ];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                out.push((path.to_string_lossy().into_owned(), text));
            }
        }
    }
    out
}
