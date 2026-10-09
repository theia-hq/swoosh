//! The words for a root a machine showed ([`swoosh::learn`]): the offer to save it, the notice where nobody
//! can be asked, and the warning when it is not the root saved for the person.
//!
//! The library asks and decides; this prints, after the verb's own output, and asks only at a terminal.
//! Only `y` or `yes` saves. Nothing here changes the verb's exit code.

use std::io::Write;

use swoosh::home::Home;
use swoosh::learn::{Found, Shown};
use swoosh::passphrase::Prompt;

/// Whether a person can be asked: stdin and stderr are both terminals. Read once, in the composition root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asking {
    /// A person is there: the offer is a question on the terminal.
    Terminal,
    /// Nobody can be asked: the offer is a notice on stderr, and nothing is saved.
    NoTerminal,
}

impl Asking {
    /// Read from this process's own stdin and stderr.
    pub fn here() -> Self {
        use std::io::IsTerminal as _;

        if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
            Self::Terminal
        } else {
            Self::NoTerminal
        }
    }
}

/// Tell the person about the root one machine showed, as the book reads now, then remember it as shown.
/// A failure here is logged and never fails the verb.
pub async fn tell(
    home: &Home,
    shown: &Shown,
    asking: Asking,
    prompt: &mut impl Prompt,
    err: &mut impl Write,
) {
    if let Err(error) = told(home, shown, asking, prompt, err).await {
        tracing::debug!(%error, "a root a machine showed could not be told");
    }
}

/// Tell the person once per person about the roots `sync`'s machines showed, in name order: the first new
/// root each person's machines showed. Only the machines whose root was said, or that showed the same root,
/// remember it, so a machine that showed another is said at its next dial.
pub async fn tell_each(
    home: &Home,
    shown: &[Shown],
    asking: Asking,
    prompt: &mut impl Prompt,
    err: &mut impl Write,
) {
    let mut said: Vec<&Shown> = Vec::new();
    for one in shown {
        let person = &one.asked.person;
        if said.iter().any(|told| told.asked.person == *person) {
            let same = said
                .iter()
                .any(|told| told.asked.person == *person && told.root == one.root);
            if same && let Err(error) = swoosh::learn::remember(home, one).await {
                tracing::debug!(%error, "a root a machine showed could not be remembered");
            }
            continue;
        }
        let quiet = match swoosh::contacts::ContactsStore::open(home).await {
            Ok(store) => Found::of(store.contacts(), one) == Found::Quiet,
            Err(error) => {
                tracing::debug!(%error, "the book could not be read to tell a root");
                return;
            }
        };
        if quiet {
            continue;
        }
        tell(home, one, asking, prompt, err).await;
        said.push(one);
    }
}

/// [`tell`], with its failure.
async fn told(
    home: &Home,
    shown: &Shown,
    asking: Asking,
    prompt: &mut impl Prompt,
    err: &mut impl Write,
) -> eyre::Result<()> {
    let contacts = swoosh::contacts::ContactsStore::open(home).await?;
    let Shown { asked, root } = shown;
    let person = &asked.person;
    let machine = format!("{person}/{}", asked.device);
    let seen = contacts.contacts().seen_root(person, &asked.device) == Some(root.key());
    match Found::of(contacts.contacts(), shown) {
        Found::Quiet => {}
        Found::Conflict { saved } => {
            writeln!(
                err,
                "warning: {machine} is vouched for by a different root\n  {person}'s root here:\n    \
                 {saved}\n  The root {machine} shows now:\n    {root}\n  If you did not expect this, do \
                 nothing.\n  The links you gave all of {person}'s machines stay with the root saved here.\n  \
                 If {person} told you the root changed, save the new one:\n    swoosh contact add {person} \
                 {root}"
            )?;
        }
        Found::Offer => match asking {
            Asking::Terminal => {
                prompt.say(&format!("{machine} is vouched for by this root:"));
                prompt.say(&format!("  {root}"));
                let answer = prompt.confirm(&format!(
                    "Save it as {person}'s root, to share with all of {person}'s machines? [y/N]:"
                ))?;
                let yes = ["y", "yes"]
                    .iter()
                    .any(|yes| answer.trim().eq_ignore_ascii_case(yes));
                if yes {
                    if swoosh::learn::save(home, shown).await? {
                        writeln!(err, "Saved {person}'s root.")?;
                    }
                    return Ok(());
                }
            }
            Asking::NoTerminal => {
                writeln!(
                    err,
                    "{machine} is vouched for by a root not saved here.\nTo share with all of {person}'s \
                     machines, save it as {person}'s root:\n  swoosh contact add {person} {root}"
                )?;
            }
        },
    }
    // The book is written only when the machine showed a root it had not shown before.
    if seen {
        return Ok(());
    }
    swoosh::learn::remember(home, shown).await
}

#[cfg(test)]
#[path = "learning_tests.rs"]
mod tests;
