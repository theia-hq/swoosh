//! Each `Reach` line as written: device names, never a number.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{Missed, Reach, What, Why};

/// 2026-12-23, midday UTC.
const UNTIL: u64 = 1_798_027_200;

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}

fn missed(name: &str, why: Why) -> Missed {
    Missed {
        name: name.to_owned(),
        why,
    }
}

/// `line` with every date (`YYYY-MM-DD`) taken out.
fn undated(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::new();
    let mut at = 0;
    while at < bytes.len() {
        let date = bytes.len() - at >= 10
            && bytes[at..at + 10].iter().enumerate().all(|(i, byte)| {
                if i == 4 || i == 7 {
                    *byte == b'-'
                } else {
                    byte.is_ascii_digit()
                }
            });
        if date {
            at += 10;
        } else {
            out.push(char::from(bytes[at]));
            at += 1;
        }
    }
    out
}

#[test]
fn reach_prints_names_and_no_number() {
    let laptop = What::Revoked("me/laptop".to_owned());
    let cases = [
        (
            Reach::Complete,
            &laptop,
            "revoked me/laptop: blocked. Only this machine admitted it.",
        ),
        (
            Reach::Published {
                took: names(&["me/desk", "me/nas"]),
                missed: vec![
                    missed("me/phone", Why::Silent),
                    missed("me/tv", Why::Refused),
                ],
                until: Some(UNTIL),
            },
            &laptop,
            "revoked me/laptop: me/desk and me/nas have it; me/phone did not answer (it gets it on its \
             next sync); me/tv refused it. A device that never syncs admits it until 2026-12-23. Anyone \
             who shared with your root admits your devices until each one's date: tell them.",
        ),
        (
            Reach::Held {
                missed: vec![missed("me/phone", Why::Silent)],
                until: Some(UNTIL),
            },
            &laptop,
            "revoked me/laptop: no device took it, and this machine does not serve. Your devices get it at \
             your next swoosh sync where one is reachable, or while this machine runs swoosh serve.",
        ),
        (
            Reach::Behind,
            &laptop,
            "revoked me/laptop is recorded here, but your devices hold a newer list than this copy of your \
             root, so nothing was published. Run swoosh sync, then run this again.",
        ),
        (
            Reach::LocalOnly { until: UNTIL },
            &laptop,
            "revoked me/laptop on this machine only. Your other devices admit it until 2026-12-23. To \
             block it everywhere, run this again where your root is kept, or here with --root <dir>.",
        ),
    ];
    for (reach, what, want) in cases {
        let line = reach.line(what);
        assert_eq!(line, want);
        assert!(
            !undated(&line).chars().any(|c| c.is_ascii_digit()),
            "no number but a date: {line}"
        );
        assert!(!line.contains("fleet:"), "no fleet: {line}");
    }
    assert_eq!(
        Reach::Behind.invite_line("me/laptop").unwrap(),
        "me/laptop's invite is recorded here, but your devices hold a newer list than this copy of your \
         root, so nothing was published. Run swoosh sync, then run this again."
    );
    for quiet in [
        Reach::Published {
            took: names(&["me/nas"]),
            missed: Vec::new(),
            until: None,
        },
        Reach::Held {
            missed: Vec::new(),
            until: None,
        },
    ] {
        assert_eq!(quiet.invite_line("me/laptop"), None);
    }
}
