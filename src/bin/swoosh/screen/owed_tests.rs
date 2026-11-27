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
    // The first root's lines, owed new words (SW6): each passes 80, or names its root after `root`.
    Owed {
        phrase: "This makes your root on this machine: a second key,",
        printed: "This makes your root on this machine: a second key, not a machine, that vouches for all your \
                  devices.",
    },
    Owed {
        phrase: "It is locked with a passphrase, which you type whenever",
        printed: "It is locked with a passphrase, which you type whenever you add, renew or revoke a device.",
    },
    Owed {
        phrase: "made your root root:",
        printed: "made your root root:ed01eoqexr3c…, kept on this machine, locked with a passphrase.",
    },
    // The rest of a root act's lines, owed their law form: two sentences on a line, a command after a colon,
    // or a line past 80.
    Owed {
        phrase: " can join until ",
        printed: "This machine is me/miraculouss-macbook-pro until 2027-02-25. me/tv can join until 2027-02-25.",
    },
    Owed {
        phrase: " from now, until ",
        printed: "me/tv runs 90d from now, until 2027-02-25 (the default; --expires sets 1h to 365d).",
    },
    Owed {
        phrase: "Revoke any you no longer have.",
        printed: "renewing 1 device: me/laptop (ed013omv7ysr…). Revoke any you no longer have.",
    },
    Owed {
        phrase: "Back up your root now, off this disk:",
        printed: "Back up your root now, off this disk: swoosh root backup <dir>",
    },
    Owed {
        phrase: "To keep it off this machine, back it up, then:",
        printed: "To keep it off this machine, back it up, then: swoosh root forget <dir>",
    },
    Owed {
        phrase: "not renewed, it already has ",
        printed: "me/phone: not renewed, it already has 4 renewals in force (the newest until 2026-12-17)",
    },
    Owed {
        phrase: "will be one of your own devices: it reaches everything",
        printed: "me/watch will be one of your own devices: it reaches everything your devices serve.",
    },
    Owed {
        phrase: "renewing it lets whatever machine holds that key back in.",
        printed: "warning: me/laptop (ed013omv7ysr…) ended on 2026-11-22; renewing it lets whatever machine \
                  holds that key back in. If that is not a machine you still have, do not type the \
                  passphrase: swoosh revoke me/laptop",
    },
    Owed {
        phrase: "new key is inside this invite: send it privately.",
        printed: "me/ci's new key is inside this invite: send it privately. If me/ci starts from its invite \
                  each time, give it this one the way it got the last (a runner: gh secret set \
                  SWOOSH_INVITE). The old invite works until 2027-02-25.",
    },
    Owed {
        phrase: "this copy of your root was behind your devices; brought forward:",
        printed: "this copy of your root was behind your devices; brought forward: +1 devices, +0 \
                  revocations, +0 devices marked revoked.",
    },
    Owed {
        phrase: "warning: this machine's key was revoked, so your devices no longer admit it.",
        printed: "warning: this machine's key was revoked, so your devices no longer admit it. Your root still \
                  works here.",
    },
    Owed {
        phrase: "holds a different list of your devices.",
        printed: "me/nas holds a different list of your devices. Kept every revoked key from both; your next \
                  swoosh invite or swoosh revoke settles it.",
    },
    // `revoke`'s own lines (SW4f).
    Owed {
        phrase: "Your root revoked the device it stands for already.",
        printed: "revoked the link: blocked here. Your root revoked the device it stands for already.",
    },
    Owed {
        phrase: "This did not end the root.",
        printed: "ed01eajmxegk… is also alice's root. This did not end the root. To end a root: swoosh revoke \
                  --help",
    },
    Owed {
        phrase: "sessions from devices of ",
        printed: "sessions from devices of root:ed01rbfyqv7u… end now, yours too if you reached this machine \
                  as one.",
    },
    // `leave --new-key`'s path line passes 80 under a long home.
    Owed {
        phrase: "kept the old key at ",
        printed: "kept the old key at /var/folders/nx/6whq7tfd2x7_zlsnj1q8w8g00000gn/T/home/machine/key.replaced-1",
    },
];

/// Hold `captured` to the screen law, less each line an [`OWED`] phrase finds that still breaks it. A line
/// whose length turns on a name can hold the law in one run and break it in another, so an owed line that holds
/// here is held like any other line, never set apart.
pub(crate) fn hold_but_owed(captured: &str) {
    let kept: Vec<_> = captured
        .lines()
        .filter(|line| {
            !(OWED.iter().any(|owed| line.contains(owed.phrase)) && law::holds(line).is_err())
        })
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
