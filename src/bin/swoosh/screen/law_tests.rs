use super::{Rule, read};

/// The ruled screens, verbatim, each under its name. A change to one of them is a change here.
const SIGNED: &[(&str, &str)] = &[
    (
        "serve's banner",
        "swoosh is serving

  this machine   me/miraclx-mbp
  key            ed01w5exaalx3vluasmzukqiau3bzrvxovdjqj6js46cg337q5ujmlwq

reach
  internet       on
  this network   192.168.1.20:51006

serving
  ping           your devices   round-trip probe
  speed          your devices   throughput test

Press ctrl-c to stop.
",
    ),
    (
        "a bare lock under Touch ID",
        "This machine's key opens with Touch ID, on this Mac only.

locks
  touch-id     on    a touch on this Mac's sensor; opens on this Mac only
  passphrase   off   typed at each use; a copy opens on any machine

To add a passphrase beside Touch ID:
  swoosh lock passphrase
",
    ),
    (
        "join on a second machine",
        "Made this machine's key, with no lock.

To make this machine one of your devices, run this on the machine
that keeps your root, or on your first machine if you have no root yet:

  swoosh invite miraclx-air ed01omxer5i2d4ylpxtnx5h6enlm4t65wcgrs5jo36qav4yp4wnxikra

miraclx-air is this machine's hostname; swoosh rename changes it later.

Then paste the invite it prints.
Invite:
",
    ),
    (
        "the --local refusal",
        "error: could not reach me/laptop on this network
  With --local or SWOOSH_LOCAL, swoosh looks for it on this network,
  or at an address you give.
  On me/laptop, swoosh status lists its addresses under reach.
  Add one of those addresses to your command:
    --peer ed01r25iqp4gca63iwwfjmrgn54ckpnwcvkxl6ylhrtbya32mvgjrpma=<address>
",
    ),
    (
        "serve's banner, serving recv",
        "swoosh is serving

  this machine   me/miraclx-mbp
  key            ed01w5exaalx3vluasmzukqiau3bzrvxovdjqj6js46cg337q5ujmlwq

reach
  internet       on
  this network   192.168.1.20:51006

serving
  ping           your devices   round-trip probe
  speed          your devices   throughput test
  recv           your devices   files, saved to ~/Downloads

Press ctrl-c to stop.
",
    ),
];

#[test]
fn the_signed_screens_hold_the_law() {
    for (source, screen) in SIGNED {
        if let Err(breach) = read(screen) {
            panic!("{source}: {breach}");
        }
    }
}

/// The `--local` refusal as the run prints it, named and unnamed, holds the law: the code's own lines, not
/// a copy of them.
#[test]
fn the_local_refusal_holds_the_law() {
    let bound = swoosh::transport::Bound {
        local: true,
        reach: swoosh::transport::Reach::default(),
    };
    let key = bifrost::NodeId::from_ed25519_secret(&[0x1a; 32]);
    let mut contacts = swoosh::contacts::Contacts::default();
    contacts
        .save(&"me/laptop".parse().expect("a device"), key)
        .expect("the name is free");
    for saved in [contacts, swoosh::contacts::Contacts::default()] {
        let machine = swoosh::peer::Peer::Raw(key)
            .machine(&saved)
            .expect("a key is one machine");
        let refused = swoosh::reach::Outcome::Unreachable
            .into_result(&machine, &bound)
            .expect_err("a miss is an error");
        let mut screen = Vec::new();
        crate::print_error(&refused, &mut screen);
        let screen = String::from_utf8(screen).expect("the refusal is UTF-8");
        if let Err(breach) = read(&screen) {
            panic!("{breach}\n{screen}");
        }
    }
}

/// The lines said before a lock is added beside another, which the library prints as one warning each since
/// it asks inside itself, held to the law as written: the code's own constants, not a copy of them.
#[test]
fn the_lines_before_an_added_lock_hold_the_law() {
    for notice in [
        swoosh::touch::BESIDE_TOUCH_ID,
        swoosh::touch::TOUCH_ID_BESIDE,
        swoosh::touch::CHANGES_TOUCH_ID,
        swoosh::touch::EVERY_FINGERPRINT,
    ] {
        if let Err(breach) = read(notice) {
            panic!("{breach}\n{notice}");
        }
    }
}

/// A lowercase fact of fixed words, 81 columns: it breaks only the width, since no word is a token alone.
const WIDE: &str =
    "a line of fixed words that runs one column past the screen's width, so it breaks.";

#[test]
fn each_breach_is_caught_by_its_predicate() {
    assert_eq!(WIDE.chars().count(), 81);
    for (breach, rule) in [
        // `root.rs:97`: two sentences on one line.
        (swoosh::root::OWN_KEY_REVOKED, Rule::TwoSentences),
        ("error: This …", Rule::HeadCase),
        ("error: could not reach me/laptop.", Rule::HeadPeriod),
        (
            "To add a passphrase:\n  swoosh lock passphrase.",
            Rule::CommandPeriod,
        ),
        // A sentence with no end, as an earlier `root passphrase` line had it.
        (
            "Changed your root's passphrase on this machine",
            Rule::SentenceEnd,
        ),
        // A fact of 81 columns, words that could have wrapped.
        (WIDE, Rule::Width),
    ] {
        let caught = read(breach).err().map(|breach| breach.rule);
        assert_eq!(caught, Some(rule), "{breach}");
    }
    // A whole key in a flag runs to 77, inside 80; a key alone past 80 is one unbreakable token.
    let peer = "    --peer ed01r25iqp4gca63iwwfjmrgn54ckpnwcvkxl6ylhrtbya32mvgjrpma=<address>";
    assert_eq!(peer.len(), 77);
    assert!(read(peer).is_ok());
    assert!(read(&"x".repeat(81)).is_ok());
    // A sentence wrapped at 80 is one sentence, and a prompt's trailing space is not its end.
    assert!(read("To make this machine one\nthat keeps your root:\n").is_ok());
    assert!(read("Invite: ").is_ok());
    assert!(read("error: Touch ID is not available").is_ok());
}
