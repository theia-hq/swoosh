//! The reach screens and the partial landing, read back from `revoked`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::sync::atomic::{AtomicU32, Ordering};

use bifrost::NodeId;
use nauthy::{Revocation, RevocationId, VerifyKey};
use swoosh::home::Home;
use swoosh::reach_report::{Missed, Reach, Why};
use swoosh::root::{Date, RootError};
use tightbeam::identity::AsVerifyKey as _;

use super::{Blocked, Revoked};

static SEQ: AtomicU32 = AtomicU32::new(0);

/// 2026-12-23, midday UTC.
const UNTIL: u64 = 1_798_027_200;

/// The refusal when the read-back does not hold the block, for `me/laptop`.
const UNCONFIRMED: &str = "this command could not confirm that me/laptop is blocked here\n  To see what is revoked:\n    swoosh status";

/// An empty home of its own.
fn home(tag: &str) -> Home {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("swoosh-reached-{tag}-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    Home::resolve(Some(dir)).unwrap()
}

fn key(seed: u8) -> VerifyKey {
    NodeId::from_ed25519_secret(&[seed; 32])
        .verify_key()
        .unwrap()
}

/// A home whose `revoked` holds `me/laptop`'s key, and that key's proof read back.
fn laptop_blocked(tag: &str) -> (Home, Blocked) {
    let home = home(tag);
    let written = [Revocation::Key(key(0x11))];
    swoosh::revoked::add(&swoosh::testkit::lock(), &home, written.iter().cloned()).unwrap();
    let blocked = Blocked::read(&home, Revoked::Named("me/laptop".into()), &written).unwrap();
    (home, blocked)
}

fn missed(name: &str, why: Why) -> Missed {
    Missed {
        name: name.to_owned(),
        why,
    }
}

/// The screen `blocked` prints for `reach`, held to the screen law.
fn landed(blocked: &Blocked, reach: &Reach) -> String {
    let mut err = Vec::new();
    blocked.landed(reach, &mut err).unwrap();
    let screen = String::from_utf8(err).unwrap();
    if let Err(breach) = crate::screen::law::holds(&screen) {
        panic!("{breach}\n{screen}");
    }
    screen
}

/// `this machine   blocks it now` prints only from what `revoked` holds once read back: an entry the
/// revoke asked for but the file lacks, or a file that cannot be read, refuses with no screen. Red when the
/// proof is built from the entries asked for.
#[test]
fn the_landed_set_comes_from_the_read_back_not_the_ask() {
    let (home, _) = laptop_blocked("read-back");
    let asked = [Revocation::Key(key(0x11)), Revocation::Key(key(0x22))];
    let refused = Blocked::read(&home, Revoked::Named("me/laptop".into()), &asked).unwrap_err();
    assert_eq!(format!("{refused:#}"), UNCONFIRMED);

    // Nothing written holds against any file, so it confirms nothing.
    let refused = Blocked::read(&home, Revoked::Named("me/laptop".into()), &[]).unwrap_err();
    assert_eq!(format!("{refused:#}"), UNCONFIRMED);

    // The file lost its entries after the write: its witness still counts them, so it reads as damaged.
    std::fs::remove_file(home.revoked()).unwrap();
    let held = [Revocation::Key(key(0x11))];
    let refused = Blocked::read(&home, Revoked::Named("me/laptop".into()), &held).unwrap_err();
    assert_eq!(format!("{refused:#}"), UNCONFIRMED);
}

/// Each reach prints the revoke, then a row per place it reached, in one order and only with a value, then
/// what follows a blank line below. Red on any byte.
#[test]
fn each_reach_prints_its_rows() {
    let (_home, blocked) = laptop_blocked("rows");
    let date = Date(UNTIL);
    let cases = [
        (
            Reach::Complete,
            "Revoked me/laptop.\n  this machine   blocks it now\n  your devices   none ever admitted it\n"
                .to_owned(),
        ),
        (
            Reach::Published {
                took: vec!["me/desk".into(), "me/nas".into()],
                missed: vec![missed("me/phone", Why::Silent)],
                until: Some(UNTIL),
            },
            format!(
                "Revoked me/laptop.\n  this machine    blocks it now\n  has it          me/desk, me/nas\n  \
                 did not answer  me/phone\n\nA device that did not answer gets it on its next sync.\n\
                 A device that never syncs admits it until {date}.\n\
                 Anyone who shared with your root admits your devices until each one's date.\nTell them.\n"
            ),
        ),
        (
            Reach::Held {
                missed: vec![missed("me/nas", Why::Silent)],
                until: Some(UNTIL),
            },
            "Revoked me/laptop.\n  this machine   blocks it now\n  your devices   none has it yet\n\n\
             They learn of it at your next swoosh sync, or while swoosh serve runs here.\n"
                .to_owned(),
        ),
        (
            Reach::Behind,
            "Revoked me/laptop on this machine, but nothing was published.\n\
             Your devices hold a newer list than this copy of your root.\nTo catch this copy up first:\n  \
             swoosh sync\nThen run this again.\n"
                .to_owned(),
        ),
        (
            Reach::LocalOnly { until: UNTIL },
            format!(
                "Revoked me/laptop.\n  this machine   blocks it now\n  your devices   not told; your root is \
                 not here\n\nYour other devices admit it until {date}.\n\
                 To block it everywhere, run this where your root is kept:\n  swoosh revoke me/laptop\n\
                 Or, with a copy of your root:\n  swoosh revoke me/laptop --root <dir>\n"
            ),
        ),
    ];
    for (reach, want) in cases {
        assert_eq!(landed(&blocked, &reach), want, "{reach:?}");
    }
}

/// A device that refused the cut keeps its own row, apart from one that did not answer: a refusal may leave
/// it admitting the target, the one fact here that asks the person to act. Red when the two fold together.
#[test]
fn a_refused_device_is_never_one_that_did_not_answer() {
    let (_home, blocked) = laptop_blocked("refused");
    let published = Reach::Published {
        took: vec!["me/desk".into()],
        missed: vec![missed("me/tv", Why::Refused)],
        until: None,
    };
    assert_eq!(
        landed(&blocked, &published),
        "Revoked me/laptop.\n  this machine   blocks it now\n  has it         me/desk\n  refused it     \
         me/tv\n\nA device that refused it may still admit me/laptop.\n"
    );
    let held = Reach::Held {
        missed: vec![missed("me/tv", Why::Refused), missed("me/nas", Why::Silent)],
        until: None,
    };
    let screen = landed(&blocked, &held);
    assert!(screen.contains("\n  refused it     me/tv\n"), "{screen}");
    assert!(
        screen.ends_with("A device that refused it may still admit me/laptop.\n"),
        "{screen}"
    );
    assert!(!screen.contains("did not answer"), "{screen}");
}

/// The partial landing: the success screen's two rows, the second giving one reason per cause, then the
/// step that finishes it. Every cause reads differently. Red when two causes share a reason, or the rows
/// are not the success screen's.
#[test]
fn the_partial_landing_gives_one_reason_per_cause() {
    let (_home, blocked) = laptop_blocked("partial");
    let head = "me/laptop is blocked on this machine only\n  this machine   blocks it now\n  your devices   ";
    let cases = [
        (
            RootError::NoTerminalToUnlock,
            "not told; no terminal to ask for your root's passphrase\n\n\
             To finish, run this again at a terminal:\n  swoosh revoke me/laptop\n\n\
             Over swoosh ssh, add -t after --.",
        ),
        (
            RootError::Prompt("the prompt ended".into()),
            "not told; your root was not unlocked\n\nTo finish, run this again:\n  swoosh revoke me/laptop",
        ),
        (
            RootError::NotOnThisMachine,
            "not told; your root is not on this machine\n\n\
             To finish, run this where your root is kept:\n  swoosh revoke me/laptop",
        ),
        (
            RootError::NoRootHere,
            "not told; this machine holds no root\n\n\
             To finish, run this where your root is kept:\n  swoosh revoke me/laptop",
        ),
        (
            RootError::ListChanged,
            "not told\n\n  your devices' list changed while this ran: run it again.",
        ),
    ];
    let mut reasons = Vec::new();
    for (cause, want) in cases {
        let report = blocked.partway(cause);
        let printed = format!("{report:#}");
        assert_eq!(printed, format!("{head}{want}"));
        // Held as `main` prints it.
        let screen = crate::error_lines(&report, &Vec::new());
        if let Err(breach) = crate::screen::law::holds(&screen) {
            panic!("{breach}\n{screen}");
        }
        let (reason, _) = want.split_once('\n').unwrap();
        assert!(!reasons.contains(&reason), "{reason} is two causes' reason");
        reasons.push(reason);
    }
}

/// A link is a secret, so its local-only screen names it `<link>` in the commands to run again; and
/// `invite`, kept back by a newer list, says the invite is made and how to catch up.
#[test]
fn a_link_is_never_printed_and_an_invite_behind_says_so() {
    let home = home("link");
    let written = [Revocation::Id(RevocationId::from_bytes(vec![0x42; 32]))];
    swoosh::revoked::add(&swoosh::testkit::lock(), &home, written.iter().cloned()).unwrap();
    let blocked = Blocked::read(&home, Revoked::Link, &written).unwrap();
    // The command to run again names the link by its placeholder, never the secret.
    assert_eq!(
        landed(&blocked, &Reach::LocalOnly { until: UNTIL }),
        format!(
            "Revoked the link.\n  this machine   blocks it now\n  your devices   not told; your root is not \
             here\n\nYour other devices admit it until {}.\n\
             To block it everywhere, run this where your root is kept:\n  swoosh revoke <link>\n\
             Or, with a copy of your root:\n  swoosh revoke <link> --root <dir>\n",
            Date(UNTIL)
        )
    );
    let mut err = Vec::new();
    super::invite_behind("me/laptop", &mut err).unwrap();
    assert_eq!(
        String::from_utf8(err).unwrap(),
        "The invite for me/laptop is made, but nothing was published.\n\
         Your devices hold a newer list than this copy of your root.\nTo catch this copy up first:\n  \
         swoosh sync\nThen run this again.\n"
    );
}

/// A renewal of another device by name says where it reached, a row per place, then how the device takes
/// it if it reaches none of them; a reach no renewal makes prints nothing. Red on any byte.
#[test]
fn a_renewal_prints_where_it_reached() {
    let renewed = |reach: &Reach| {
        let mut err = Vec::new();
        super::renewed("me/laptop", UNTIL, reach, &mut err).unwrap();
        let screen = String::from_utf8(err).unwrap();
        if let Err(breach) = crate::screen::law::holds(&screen) {
            panic!("{breach}\n{screen}");
        }
        screen
    };
    let published = Reach::Published {
        took: vec!["me/nas".into()],
        missed: vec![
            missed("me/phone", Why::Silent),
            missed("me/tv", Why::Refused),
        ],
        until: None,
    };
    assert_eq!(
        renewed(&published),
        format!(
            "Renewed me/laptop until {}.\n  has it          me/nas\n  did not answer  me/phone\n  refused it  \
             \x20   me/tv\n\nA device that did not answer picks it up when it next reaches your devices.\n\
             If me/laptop cannot reach your devices, paste the invite into swoosh join on it.\n",
            Date(UNTIL)
        )
    );
    let held = Reach::Held {
        missed: Vec::new(),
        until: None,
    };
    assert_eq!(
        renewed(&held),
        format!(
            "Renewed me/laptop until {}.\n\nIf me/laptop cannot reach your devices, paste the invite into \
             swoosh join on it.\n",
            Date(UNTIL)
        )
    );
    for none in [
        Reach::Behind,
        Reach::Complete,
        Reach::LocalOnly { until: UNTIL },
    ] {
        assert_eq!(renewed(&none), "", "{none:?}");
    }
}
