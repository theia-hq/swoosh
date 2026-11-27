//! The lines a command's tests print that do not hold the screen law yet, each owed its law form by a later
//! change. A harness holds everything else it captures ([`hold_but_owed`]), and every entry stays alive only
//! while the line is still shipped and still breaks the law ([`every_owed_line_is_shipped_and_still_breaks`]),
//! so the list can only shrink and an entry never exempts a line it was not meant for.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use super::law;

/// One owed line: a phrase only that line holds, and the line as a run prints it.
pub(crate) struct Owed {
    /// What a captured line must contain to be held apart.
    phrase: &'static str,
    /// The line as printed, which must still break the law.
    printed: &'static str,
}

/// Every owed line, by the phrase that finds it.
pub(crate) const OWED: &[Owed] = &[
    // The bare join's lines, owed new words (SW6): the key and the command end with no sentence end.
    Owed {
        phrase: "This machine's key: ",
        printed: "This machine's key: ed01v4dkhyzjc4koj42wygojwfondfi6y3tgmkvhppqhkr7sre4dgqoq",
    },
    Owed {
        phrase: "On the machine where your root is kept:  swoosh invite",
        printed: "On the machine where your root is kept:  swoosh invite laptop \
                  ed01v4dkhyzjc4koj42wygojwfondfi6y3tgmkvhppqhkr7sre4dgqoq",
    },
    // `leave --new-key`'s path line passes 80 under a long home.
    Owed {
        phrase: "kept the old key at ",
        printed: "kept the old key at /var/folders/nx/6whq7tfd2x7_zlsnj1q8w8g00000gn/T/home/machine/key.replaced-1",
    },
];

/// Hold `captured` to the screen law, less every line an [`OWED`] phrase finds.
pub(crate) fn hold_but_owed(captured: &str) {
    let kept: Vec<_> = captured
        .lines()
        .filter(|line| !OWED.iter().any(|owed| line.contains(owed.phrase)))
        .collect();
    if let Err(breach) = law::holds(&kept.join("\n")) {
        panic!("{breach}\n{captured}");
    }
}

/// Each entry's phrase is in its printed line, the line still breaks the law, and the phrase is still in a
/// shipped source file. Red when a line's new words land and its entry stays, or its words leave the tree.
#[test]
fn every_owed_line_is_shipped_and_still_breaks() {
    let shipped = shipped();
    for owed in OWED {
        assert!(owed.printed.contains(owed.phrase), "{}", owed.phrase);
        assert!(
            law::holds(owed.printed).is_err(),
            "{:?} holds the law now: drop its entry",
            owed.printed
        );
        assert!(
            shipped.contains(owed.phrase),
            "{:?} is no longer shipped: drop its entry",
            owed.phrase
        );
    }
}

/// Every shipped source file under `src/`, test files left out, with each `\`-continued string joined
/// back into one line, as it prints.
fn shipped() -> String {
    let mut text = String::new();
    let mut dirs = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.to_string_lossy();
            if path.is_dir() {
                dirs.push(path);
            } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") {
                text.push_str(&std::fs::read_to_string(&path).unwrap());
            }
        }
    }
    let mut joined = String::with_capacity(text.len());
    for line in text.split('\n') {
        if joined.ends_with('\\') {
            joined.pop();
            joined.push_str(line.trim_start());
        } else {
            joined.push('\n');
            joined.push_str(line);
        }
    }
    joined
}
