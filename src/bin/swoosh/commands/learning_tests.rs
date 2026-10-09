// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The words for a root a machine showed, over homes built on disk: the offer, the notice, the warning, and
//! what each leaves in the book.

use bifrost::NodeId;
use keystore::{KeyFile, Passphrase, Protection};
use swoosh::contacts::{ContactsStore, Source};
use swoosh::home::Home;
use swoosh::learn::{Asked, Shown};
use swoosh::passphrase::{Asked as Question, Choice, Prompt};
use swoosh::root_key::RootKey;
use swoosh::testkit::{TestNode, TestRoot};

use super::{Asking, tell};

/// Alice's root, saved here or not.
const ALICE_ROOT: u8 = 0x91;
/// A root alice's laptop shows when it is not the one saved.
const OTHER_ROOT: u8 = 0x92;
/// Alice's laptop.
const LAPTOP: u8 = 0x93;
/// This machine.
const DESK: u8 = 0x94;

/// A person at a terminal who answers every question with `typed`, or nobody at one.
struct Person {
    typed: Option<String>,
    said: Vec<String>,
    asked: Vec<String>,
}

impl Person {
    fn typing(typed: &str) -> Self {
        Self {
            typed: Some(typed.to_owned()),
            said: Vec::new(),
            asked: Vec::new(),
        }
    }
}

impl Prompt for Person {
    fn terminal(&self) -> bool {
        self.typed.is_some()
    }

    fn unlock(&mut self, _asked: Question<'_>) -> eyre::Result<Passphrase> {
        eyre::bail!("no passphrase is asked here")
    }

    fn choose(&mut self, _asked: Question<'_>) -> eyre::Result<Choice> {
        eyre::bail!("no passphrase is chosen here")
    }

    fn say(&mut self, line: &str) {
        self.said.push(line.to_owned());
    }

    fn confirm(&mut self, question: &str) -> eyre::Result<String> {
        self.asked.push(question.to_owned());
        self.typed
            .clone()
            .ok_or_else(|| eyre::eyre!("nobody is at a terminal to answer"))
    }
}

fn root(seed: u8) -> RootKey {
    RootKey::from(TestRoot::seeded(seed).node_id())
}

fn node(seed: u8) -> NodeId {
    TestNode::seeded(seed).node_id()
}

/// This machine, saving alice's laptop, and alice's root when `saved` names one.
async fn desk(tag: &str, saved: Option<RootKey>) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-learning-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    swoosh::identity::make_machine_dir(&home).unwrap();
    let mut seed = TestNode::seeded(DESK).seed();
    KeyFile::new(home.key())
        .write(&keystore::Secret::take(&mut seed), Protection::Plain)
        .unwrap();
    let mut store = ContactsStore::open(&home).await.unwrap();
    store.contacts_mut().add(
        "alice".parse().unwrap(),
        Some("laptop".parse().unwrap()),
        node(LAPTOP),
    );
    if let Some(saved) = saved {
        store
            .contacts_mut()
            .set_signet("alice".parse().unwrap(), saved.key());
    }
    store.save(&swoosh::testkit::lock()).unwrap();
    home
}

/// Alice's laptop showing `root`.
fn showing(root: RootKey) -> Shown {
    Shown {
        asked: Asked {
            person: "alice".parse().unwrap(),
            device: "laptop".parse().unwrap(),
            key: node(LAPTOP),
        },
        root,
    }
}

/// Alice's saved root and its source.
async fn alices(home: &Home) -> Option<(NodeId, Source)> {
    ContactsStore::open(home)
        .await
        .unwrap()
        .contacts()
        .signet(&"alice".parse().unwrap())
        .map(|saved| (saved.node, saved.source.clone()))
}

/// At a terminal the offer is a question; only `y` or `yes`, in any case, saves, and then says so. Enter, `n`
/// or anything else saves nothing and says nothing. The fact and the whole root come first, on the terminal.
#[tokio::test]
async fn the_learning_prompt_saves_only_on_yes() {
    let alice = root(ALICE_ROOT);
    for typed in ["", "n", "no", "x", "yess"] {
        let home = desk("declined", None).await;
        let mut person = Person::typing(typed);
        let mut err = Vec::new();
        tell(
            &home,
            &showing(alice),
            Asking::Terminal,
            &mut person,
            &mut err,
        )
        .await;
        assert_eq!(alices(&home).await, None, "{typed:?}: nothing saved");
        assert!(err.is_empty(), "{typed:?}: nothing said");
        assert_eq!(
            person.said,
            [
                "alice/laptop is vouched for by this root:".to_owned(),
                format!("  {alice}"),
            ]
        );
        assert_eq!(
            person.asked,
            ["Save it as alice's root, to share with all of alice's machines? [y/N]:"]
        );
        let _ = std::fs::remove_dir_all(home.dir());
    }
    for typed in ["y", "Y", "yes", "YES", " yes\n"] {
        let home = desk("accepted", None).await;
        let mut err = Vec::new();
        tell(
            &home,
            &showing(alice),
            Asking::Terminal,
            &mut Person::typing(typed),
            &mut err,
        )
        .await;
        assert_eq!(
            alices(&home).await,
            Some((alice.key(), Source::Learned("laptop".parse().unwrap()))),
            "{typed:?}: saved, marked learned"
        );
        assert_eq!(String::from_utf8(err).unwrap(), "Saved alice's root.\n");
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// A saved person whose machine shows another root gets the warning, never the question, and the saved root
/// stays: only a typed `contact add` replaces it. Said once per new root.
#[tokio::test]
async fn a_learned_root_never_replaces_a_saved_one() {
    let (alice, other) = (root(ALICE_ROOT), root(OTHER_ROOT));
    let home = desk("conflict", Some(alice)).await;
    let mut person = Person::typing("y");
    let mut err = Vec::new();
    tell(
        &home,
        &showing(other),
        Asking::Terminal,
        &mut person,
        &mut err,
    )
    .await;
    assert!(person.asked.is_empty(), "no question");
    assert!(person.said.is_empty(), "nothing on the terminal");
    assert_eq!(
        String::from_utf8(err).unwrap(),
        format!(
            "warning: alice/laptop is vouched for by a different root\n  alice's root here:\n    {alice}\n  \
             The root alice/laptop shows now:\n    {other}\n  If you did not expect this, do nothing.\n  The \
             links you gave all of alice's machines stay with the root saved here.\n  If alice told you the \
             root changed, save the new one:\n    swoosh contact add alice {other}\n"
        )
    );
    assert_eq!(alices(&home).await, Some((alice.key(), Source::Explicit)));

    let mut again = Vec::new();
    tell(
        &home,
        &showing(other),
        Asking::Terminal,
        &mut person,
        &mut again,
    )
    .await;
    assert!(again.is_empty(), "once per new root");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// After a saved person's machine shows another root, a link made for the person still follows the root
/// saved here, never the one shown.
#[tokio::test]
async fn a_changed_root_on_a_saved_device_is_never_followed() {
    let (alice, other) = (root(ALICE_ROOT), root(OTHER_ROOT));
    let home = desk("never-followed", Some(alice)).await;
    tell(
        &home,
        &showing(other),
        Asking::NoTerminal,
        &mut Person::typing("y"),
        &mut Vec::new(),
    )
    .await;
    let cmd =
        match <crate::Cli as clap::Parser>::try_parse_from(["swoosh", "share", "ping", "alice"])
            .unwrap()
            .command
        {
            Some(crate::Command::Share(cmd)) => cmd,
            other => panic!("share parses to share, not {other:?}"),
        };
    cmd.run(&home, &b""[..], &mut Vec::new(), &mut Vec::new())
        .await
        .expect("the share is made");
    let rows = swoosh::grants::Grants::at(home.links())
        .load()
        .await
        .unwrap();
    let holders: Vec<String> = rows.iter().map(|row| row.holder.clone()).collect();
    assert_eq!(
        holders,
        [alice.key().to_string()],
        "it follows the saved root"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Where nobody can be asked, the offer is a notice on stderr, with the command that saves the root, and
/// nothing is saved.
#[tokio::test]
async fn with_no_terminal_the_offer_is_a_notice() {
    let alice = root(ALICE_ROOT);
    let home = desk("notice", None).await;
    let mut err = Vec::new();
    tell(
        &home,
        &showing(alice),
        Asking::NoTerminal,
        &mut Person::typing("y"),
        &mut err,
    )
    .await;
    assert_eq!(
        String::from_utf8(err).unwrap(),
        format!(
            "alice/laptop is vouched for by a root not saved here.\nTo share with all of alice's machines, \
             save it as alice's root:\n  swoosh contact add alice {alice}\n"
        )
    );
    assert_eq!(alices(&home).await, None);
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Every root a learning line or a replace screen prints carries `root:`: wherever a root's key appears in
/// what is said, it is the root form.
#[tokio::test]
async fn root_keys_print_with_the_root_prefix_everywhere() {
    let (alice, other) = (root(ALICE_ROOT), root(OTHER_ROOT));
    let mut printed = String::new();

    // The offer at a terminal and as a notice, and the warning.
    let home = desk("prefix-offer", None).await;
    let mut person = Person::typing("n");
    tell(
        &home,
        &showing(alice),
        Asking::Terminal,
        &mut person,
        &mut Vec::new(),
    )
    .await;
    printed.push_str(&person.said.join("\n"));
    let home = desk("prefix-notice", None).await;
    let mut err = Vec::new();
    tell(
        &home,
        &showing(alice),
        Asking::NoTerminal,
        &mut person,
        &mut err,
    )
    .await;
    printed.push_str(&String::from_utf8(err).unwrap());
    let home = desk("prefix-warning", Some(alice)).await;
    let mut err = Vec::new();
    tell(
        &home,
        &showing(other),
        Asking::NoTerminal,
        &mut person,
        &mut err,
    )
    .await;
    printed.push_str(&String::from_utf8(err).unwrap());

    // The replace's confirmation and its result, and the refusals that name a root.
    let home = desk("prefix-replace", Some(alice)).await;
    let token: String = other.key().to_string().chars().skip(4).take(8).collect();
    let mut person = Person::typing(&token);
    let mut err = Vec::new();
    let add = match <crate::Cli as clap::Parser>::try_parse_from([
        "swoosh",
        "contact",
        "add",
        "alice",
        &other.to_string(),
    ])
    .unwrap()
    .command
    {
        Some(crate::Command::Contact(crate::commands::contact::ContactCmd::Add(cmd))) => cmd,
        found => panic!("contact add parses, not {found:?}"),
    };
    add.run(&home, &mut person, &mut err)
        .await
        .expect("replaced");
    printed.push_str(&person.said.join("\n"));
    printed.push_str(&String::from_utf8(err).unwrap());

    for key in [alice.key(), other.key()] {
        let text = key.to_string();
        let short = swoosh::credential::short(&key);
        let short = short.trim_end_matches('…');
        assert!(printed.contains(short), "the root is printed: {printed}");
        for (at, _) in printed.match_indices(short) {
            assert!(
                printed[..at].ends_with("root:"),
                "{text} printed bare at {at}: {printed}"
            );
        }
    }
}
