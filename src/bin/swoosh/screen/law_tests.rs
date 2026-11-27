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

/// The lines said before and around a lock act, which the library prints itself since it asks inside
/// itself: every before-line, every waiting line, every prompt (its trailing space trimmed) and the two
/// refusals of a lock act, held to the law as written, the code's own lines, not a copy of them; the
/// refusals by their bytes too. The law reads a lowercase line as a fact, so each line but a refusal's is
/// held to its capital here. Red when a line breaks case, period or width, or a refusal moves off its words.
#[test]
fn the_lock_lines_hold_the_law() {
    use swoosh::touch::{self, Act};

    let file = keystore::KeyFile::new(std::env::temp_dir().join("swoosh-law-lines").join("key"));
    let mut lines: Vec<String> = [
        touch::MAKES_UNDER_PASSPHRASE,
        touch::MAKES_UNDER_TOUCH_ID,
        touch::MAKES_BESIDE_ROOT,
        touch::SEALS_UNDER_PASSPHRASE,
        touch::SEALS_UNDER_TOUCH_ID,
        touch::SEALS_BESIDE_ROOT,
        touch::BESIDE_TOUCH_ID,
        touch::TOUCH_ID_BESIDE,
        touch::CHANGES_TOUCH_ID,
        touch::EVERY_FINGERPRINT,
        touch::TAKES_PASSPHRASE_OFF,
        touch::TAKES_TOUCH_ID_OFF,
        touch::TAKES_LAST_LOCK_OFF,
        touch::ROOT_BESIDE_PASSPHRASE,
        swoosh::passphrase::CHOOSE_HINT,
        swoosh::passphrase::CHOOSE_FIRST,
        swoosh::passphrase::CHOOSE_AGAIN,
    ]
    .map(str::to_owned)
    .into();
    let dir = std::path::Path::new("/tmp/stick");
    for asked in [
        swoosh::passphrase::Asked::MachineKey,
        swoosh::passphrase::Asked::Root,
        swoosh::passphrase::Asked::Copy(dir),
    ] {
        lines.push(asked.prompt());
        let said = touch::Lines::of(asked, &file, true);
        for act in [
            Act::Use,
            Act::Make,
            Act::Add,
            Act::AddPassphrase,
            Act::Remove,
        ] {
            lines.push(said.waiting(act));
        }
    }
    for line in &lines {
        let line = line.trim_end();
        if let Err(breach) = read(line) {
            panic!("{breach}\n{line}");
        }
        for sentence in line.lines() {
            assert!(
                sentence.starts_with(char::is_uppercase),
                "a capital: {sentence}"
            );
        }
    }
    // Lowercase still (its law form is SW4's), so held to width and wrap only. `SHARED_FINGER`'s ruled
    // wrap runs on at a deeper indent, which the law does not read as one sentence, so it is held to its
    // width alone.
    assert!(
        touch::SHARED_FINGER
            .lines()
            .all(|line| line.chars().count() <= 80)
    );
    for line in [swoosh::identity::TOUCH_ID_ALONE_BESIDE_ROOT] {
        if let Err(breach) = read(line) {
            panic!("{breach}\n{line}");
        }
    }
    for (refused, printed) in [
        (
            swoosh::identity::KEEPS_PASSPHRASE,
            "error: this machine's key keeps its passphrase while your root is here\n  \
             To take Touch ID off instead:\n    \
             swoosh lock touch-id --remove\n",
        ),
        (
            touch::TIMED_OUT,
            "error: Touch ID waited 60 seconds and no touch came\n",
        ),
    ] {
        let mut screen = Vec::new();
        crate::print_error(&eyre::eyre!(refused), &mut screen);
        let screen = String::from_utf8(screen).expect("the refusal is UTF-8");
        assert_eq!(screen, printed);
        if let Err(breach) = read(&screen) {
            panic!("{breach}\n{screen}");
        }
    }
}

/// A make whose touch did not land, as the run prints it, holds the law at each end and at both places a key
/// is sealed first: the code's own lines through `print_error`, not a copy of them. And the refusal over a
/// file this command did not make.
#[tokio::test]
async fn the_missed_make_refusals_hold_the_law() {
    use swoosh::touch::Touched;

    let ends = || {
        [
            Touched::Declined,
            Touched::NotHere,
            Touched::Failed(eyre::eyre!("the enclave refused")),
            Touched::TimedOut,
        ]
    };
    let mut printed = Vec::new();
    for (at, (touched, plain)) in ends()
        .into_iter()
        .map(|end| (end, None))
        .chain(ends().into_iter().map(|end| (end, Some(false))))
        .chain(ends().into_iter().map(|end| (end, Some(true))))
        .enumerate()
    {
        let dir =
            std::env::temp_dir().join(format!("swoosh-law-missed-{}-{at}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        swoosh::config::create_store_dir(&dir).expect("a home");
        let home = swoosh::home::Home::resolve(Some(dir.clone())).expect("a home");
        let answers: &[&str] = match plain {
            None => &[],
            Some(true) => {
                swoosh::identity::inspect(&home).expect("a plain key");
                std::fs::write(home.root_key(), b"a root kept here").expect("a root");
                &["a passphrase long enough"]
            }
            Some(false) => {
                std::fs::write(home.root_key(), b"a root kept here").expect("a root");
                &["a passphrase long enough"]
            }
        };
        let mut prompt = swoosh::testkit::Counting::new(answers.iter().copied())
            .at_this_mac(keystore::Health::Live)
            .touching([touched]);
        let refused = swoosh::identity::lock(&home, keystore::Method::TouchId, false, &mut prompt)
            .await
            .expect_err("a miss refuses");
        printed.push(refused);
        let _ = std::fs::remove_dir_all(&dir);
    }
    printed.push(eyre::eyre!(swoosh::identity::KEY_ALREADY_THERE));
    for refused in printed {
        let mut screen = Vec::new();
        crate::print_error(&refused, &mut screen);
        let screen = String::from_utf8(screen).expect("the refusal is UTF-8");
        if let Err(breach) = read(&screen) {
            panic!("{breach}\n{screen}");
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
