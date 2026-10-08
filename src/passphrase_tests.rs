//! The passphrase floor, the made passphrase, and the three tries.

use std::collections::BTreeSet;

use keystore::{KeyFile, Protection, Unlock};
use zeroize::Zeroizing;

use super::{
    Asked, Choice, MINIMUM, MISMATCH, MISMATCH_LAST, TOO_SHORT, TRIES, WORD_LIST, WORDS, choose,
    chosen, made, passphrase, unlock,
};
use crate::testkit::Counting;

fn text(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

/// The floor is 15 characters of the text as typed: 14 refused, 15 taken, and a two-byte character counts
/// once. Red when the count is bytes, the floor moves, or the text is trimmed.
#[test]
fn a_chosen_passphrase_under_15_characters_is_refused() {
    assert_eq!(MINIMUM, 15);
    assert!(matches!(chosen(text(&"a".repeat(14))), Ok(Choice::Short)));
    assert!(matches!(
        chosen(text(&"a".repeat(15))),
        Ok(Choice::Chosen(_))
    ));
    assert!(matches!(
        chosen(text(&"é".repeat(15))),
        Ok(Choice::Chosen(_))
    ));
    assert!(matches!(chosen(text(&"é".repeat(14))), Ok(Choice::Short)));
    // Nothing is trimmed: spaces are characters.
    assert!(matches!(
        chosen(text(&format!(" {} ", "a".repeat(13)))),
        Ok(Choice::Chosen(_))
    ));
}

/// The floor is a rule for choosing only: a key sealed under anything still opens. Red when the floor lands
/// in `passphrase` or on an unlock path.
#[test]
fn an_unlock_takes_any_passphrase_the_file_opens_under() {
    let dir = tempfile_dir("unlock-any");
    let file = KeyFile::device(dir.join("key"));
    let secret = keystore::Secret::generate().expect("a key");
    let short = passphrase(text("abc")).expect("a passphrase");
    file.write(&secret, Protection::Passphrase(&short))
        .expect("sealed under three characters");
    let Some(keystore::Stored::Locked(locked)) = file.load().expect("load") else {
        panic!("sealed");
    };
    let mut prompt = Counting::new(["abc"]);
    let (opened, _) = unlock(&mut prompt, Asked::MachineKey, |passphrase| {
        locked.unlock(Unlock::Passphrase(passphrase))
    })
    .expect("a short passphrase opens the key it seals");
    assert_eq!(opened.public_key(), secret.public_key());
}

/// A made passphrase is five words from the list, joined by spaces, and passes the floor. Red when the count
/// or the separator changes, or a word comes from outside the list.
#[test]
fn a_made_passphrase_is_five_listed_words() {
    let list: BTreeSet<&str> = WORD_LIST.lines().collect();
    for _ in 0..32 {
        let phrase = made();
        let words: Vec<&str> = phrase.split(' ').collect();
        assert_eq!(words.len(), WORDS);
        assert!(words.iter().all(|word| list.contains(word)), "{words:?}");
        assert!(matches!(chosen(phrase), Ok(Choice::Chosen(_))));
    }
}

/// The list is 7,776 distinct words: a made passphrase's strength is this number. Red on a truncated or
/// duplicated list.
#[test]
fn the_word_list_is_7776_distinct_words() {
    let words: Vec<&str> = WORD_LIST.lines().collect();
    assert_eq!(words.len(), 7776);
    assert_eq!(words.iter().collect::<BTreeSet<_>>().len(), 7776);
    assert!(
        words
            .iter()
            .all(|word| !word.is_empty() && !word.contains(' '))
    );
}

/// A wrong passphrase is asked again, saying so each time, three times in all; the third ends with the
/// refusal and the key file as it was. Red when the first wrong one ends the command, or a fourth is asked.
#[test]
fn a_wrong_passphrase_asks_again_up_to_three_times() {
    let dir = tempfile_dir("three-tries");
    let path = dir.join("key");
    let file = KeyFile::device(&path);
    let secret = keystore::Secret::generate().expect("a key");
    let right = passphrase(text("the right passphrase")).expect("a passphrase");
    file.write(&secret, Protection::Passphrase(&right))
        .expect("sealed");
    let before = std::fs::read(&path).expect("read");
    let Some(keystore::Stored::Locked(locked)) = file.load().expect("load") else {
        panic!("sealed");
    };

    let mut prompt = Counting::new(["one", "two", "three", "the right passphrase"]);
    let refused = unlock(&mut prompt, Asked::MachineKey, |passphrase| {
        locked.unlock(Unlock::Passphrase(passphrase))
    })
    .expect_err("three wrong passphrases refuse");
    assert_eq!(prompt.events(), TRIES);
    assert_eq!(
        prompt.said(),
        vec!["that passphrase does not open this machine's key."; 2]
    );
    assert_eq!(
        refused.to_string(),
        "that passphrase does not open this machine's key."
    );
    assert_eq!(std::fs::read(&path).expect("read"), before);

    // The right one on the last try opens it.
    let mut prompt = Counting::new(["one", "two", "the right passphrase"]);
    unlock(&mut prompt, Asked::Root, |passphrase| {
        locked.unlock(Unlock::Passphrase(passphrase))
    })
    .expect("the third try opens");
    assert_eq!(
        prompt.said(),
        vec!["that passphrase does not open your root."; 2]
    );
}

/// A round refused for a mismatch or a short passphrase asks both again, naming the reason; three rounds at
/// most. Red when a mismatch ends the command, or a fourth round is asked.
#[test]
fn a_mismatch_or_a_short_passphrase_asks_both_again() {
    // A scripted empty answer stands for a round whose two entries did not match.
    let mut prompt = Counting::new(["short", "", "a passphrase long enough"]);
    choose(&mut prompt, Asked::Root).expect("the third round takes");
    assert_eq!(prompt.events(), 3);
    // The terminal's round reads one entry for a short passphrase, two for the others.
    assert_eq!(prompt.reads(), 5);
    assert_eq!(prompt.said(), [TOO_SHORT, MISMATCH]);

    let mut prompt = Counting::new(["short", "", "", "a passphrase long enough"]);
    let refused = choose(&mut prompt, Asked::MachineKey).expect_err("three refused rounds");
    assert_eq!(prompt.events(), TRIES);
    assert_eq!(refused.to_string(), MISMATCH_LAST);
}

/// A fresh owner-only directory under the system temp dir, unique to this test and process.
fn tempfile_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-passphrase-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    crate::config::create_store_dir(&dir).expect("make the dir");
    dir
}

/// The terminal's round, scripted: each `ask` takes the next answer, or, for `again:` after a made phrase,
/// types back the phrase it was shown. Records every prompt asked and every line said.
#[derive(Default)]
struct Script {
    answers: std::collections::VecDeque<&'static str>,
    asked: Vec<String>,
    said: Vec<String>,
}

impl Script {
    fn new(answers: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            answers: answers.into_iter().collect(),
            ..Self::default()
        }
    }

    /// The phrase the round showed, if it made one.
    fn shown(&self) -> Option<String> {
        self.said
            .iter()
            .find_map(|line| line.strip_prefix("your passphrase: "))
            .map(str::to_owned)
    }
}

impl super::Lines for Script {
    fn say(&mut self, line: &str) -> eyre::Result<()> {
        self.said.push(line.to_owned());
        Ok(())
    }

    fn ask(&mut self, prompt: &str) -> eyre::Result<Zeroizing<String>> {
        self.asked.push(prompt.to_owned());
        if prompt == "again: "
            && let Some(shown) = self.shown()
        {
            return Ok(Zeroizing::new(shown));
        }
        let answer = self
            .answers
            .pop_front()
            .ok_or_else(|| eyre::eyre!("no answer left"))?;
        Ok(text(answer))
    }
}

/// A short first entry ends the round before `again:` is asked: the floor runs on the first entry, and one
/// entry is read. Red when the floor moves after `again:`.
#[test]
fn the_floor_runs_before_again() {
    let mut lines = Script::new(["fourteen chars", "fourteen chars"]);
    let choice = super::round(&mut lines, Asked::Root).expect("a round");
    assert!(matches!(choice, Choice::Short));
    assert_eq!(lines.asked, ["new root passphrase: "]);
    assert_eq!(
        lines.said,
        ["Choose a passphrase of at least 15 characters, or press Enter and swoosh makes one."]
    );
}

/// An empty Enter makes a passphrase of five listed words, shows it where the person types, and asks for it
/// once more; typed back, it is the one chosen. Red when the made phrase is skipped or `again:` is not
/// asked.
#[test]
fn an_empty_enter_makes_a_phrase_and_asks_for_it_once_more() {
    let mut lines = Script::new([""]);
    let choice = super::round(&mut lines, Asked::MachineKey).expect("a round");
    assert!(matches!(choice, Choice::Chosen(_)));
    assert_eq!(
        lines.asked,
        ["new passphrase for this machine's key: ", "again: "]
    );
    let shown = lines.shown().expect("the phrase is shown");
    let list: BTreeSet<&str> = WORD_LIST.lines().collect();
    let words: Vec<&str> = shown.split(' ').collect();
    assert_eq!(words.len(), WORDS);
    assert!(words.iter().all(|word| list.contains(word)));
    assert_eq!(
        lines.said.last().map(String::as_str),
        Some("Keep it where you keep your passwords, then type it once more.")
    );
}

/// Two entries that differ end the round as a mismatch, after two reads; a copy's round names the copy.
/// Red when the second entry is not compared.
#[test]
fn a_round_whose_entries_differ_is_a_mismatch() {
    let dir = std::path::Path::new("/tmp/stick");
    let mut lines = Script::new(["a passphrase long enough", "another passphrase entirely"]);
    let choice = super::round(&mut lines, Asked::Copy(dir)).expect("a round");
    assert!(matches!(choice, Choice::Mismatch));
    assert_eq!(
        lines.asked,
        ["new passphrase for the copy in /tmp/stick: ", "again: "]
    );
}

/// An answer to a confirmation past the cap reads as no answer, and the rest of its line is read and dropped,
/// so none of it is left on the terminal for the shell; the next line is read whole. The passphrase read keeps
/// its refusal. Red when the long line is cut at the cap and its rest left to read.
#[test]
fn a_confirmation_past_the_cap_reads_as_no_answer_and_leaves_nothing() {
    let dir = tempfile_dir("long-answer");
    let path = dir.join("typed");
    let mut typed = vec![b'x'; super::MAX_LINE + 976];
    typed.extend_from_slice(b"\nnext\n");
    std::fs::write(&path, &typed).unwrap();
    let tty = super::Tty(std::fs::File::open(&path).unwrap());
    assert!(
        tty.read_answer().unwrap().is_none(),
        "past the cap is no answer"
    );
    assert_eq!(tty.read_answer().unwrap().unwrap().as_slice(), b"next");

    let tty = super::Tty(std::fs::File::open(&path).unwrap());
    assert_eq!(
        tty.read_line().unwrap_err().to_string(),
        "the passphrase is longer than 1024 bytes"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
