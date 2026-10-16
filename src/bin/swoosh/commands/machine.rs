//! The words for a verb's machine argument: its help line, the usage errors a machine that is not one
//! machine exits 2 with, the line a bare person's one machine is announced by, and the refusal a dial of a
//! service prints.
//!
//! The library resolves the argument and diagnoses a refusal ([`Peer::machine`], [`reach::diagnose`]); it
//! hands back typed values, and the words live here, in the binary, beside the verbs that print them.
//!
//! [`Peer::machine`]: swoosh::peer::Peer::machine
//! [`reach::diagnose`]: swoosh::reach::diagnose

use std::ffi::OsString;

use nauthy::Service;
use swoosh::peer::{Kind, Machine, MachineError, Whose};
use swoosh::reach::Diagnosis;
use swoosh::root_key::RootKey;

use crate::commands::stop;

/// The help line of the machine argument, one line on every verb that takes one.
pub const HELP: &str = "A machine: me/<name>, <person>/<name>, a person, a key, or a link";

/// The line a verb prints on stderr, once, when a bare person had one machine saved and it dialed that
/// one: the person typed no machine, so they are told which.
pub fn picked(machine: &Machine) -> Option<String> {
    let person = machine.picked()?;
    let name = machine.name()?;
    Some(format!("{person} is {name}."))
}

/// The usage error `error` exits 2 with, or `None` for a link with no usable key, which is not a usage
/// error and which the caller reports as it always did. `argv` is the command line as typed and `typed`
/// the machine as typed, for the one refusal whose fix is that line with only the machine replaced.
pub fn usage(error: &MachineError, verb: &str, argv: &[OsString], typed: &str) -> Option<String> {
    Some(match error {
        MachineError::Several { person, machines } => {
            let listed: Vec<String> = machines
                .iter()
                .map(|label| format!("{person}/{label}"))
                .collect();
            format!("which machine?\n  {person}'s: {}.", listed.join(", "))
        }
        MachineError::NoneSaved { person } => format!(
            "none of {person}'s machines is saved here\n{}",
            save_one(person.as_str(), "<name>")
        ),
        MachineError::NotSaved { person } => {
            format!(
                "{person} is not saved here\n{}",
                save_one(person.as_str(), "<name>")
            )
        }
        // The lines `stop` prints for the same machine, so every verb refuses it alike.
        MachineError::NotYours { device, yours } => {
            format!("you have no machine {device}\n  {}", stop::listed(yours))
        }
        MachineError::NotTheirs {
            person,
            device,
            machines,
        } if machines.is_empty() => format!(
            "{person} has no machine {device}\n{}",
            save_one(person.as_str(), device.as_str())
        ),
        MachineError::NotTheirs {
            person,
            device,
            machines,
        } => {
            let listed: Vec<String> = machines
                .iter()
                .map(|label| format!("{person}/{label}"))
                .collect();
            format!(
                "{person} has no machine {device}\n  {person}'s: {}.",
                listed.join(", ")
            )
        }
        MachineError::WhichOfYours { yours } => {
            format!("which machine?\n  {}", stop::listed(yours))
        }
        MachineError::YourDevice { device } => format!(
            "name the machine:\n  {}",
            retyped(
                argv,
                verb,
                |word| word.eq_ignore_ascii_case(typed),
                &device.to_string()
            )
        ),
        MachineError::Root { whose } => root_key(whose, verb, argv),
        MachineError::Link(_) => return None,
    })
}

/// The refusal for a root's key typed where a machine goes, never echoing the key: whose root it is and
/// their machines when this book knows; else the command as typed with the root replaced by the shape a
/// machine takes.
fn root_key(whose: &Whose, verb: &str, argv: &[OsString]) -> String {
    match whose {
        Whose::Yours { devices } => format!(
            "that is your root key, not a machine's key\n  {}",
            stop::listed(devices)
        ),
        Whose::Person { person, machines } if machines.is_empty() => format!(
            "that is {person}'s root key, not a machine's key\n{}",
            save_one(person.as_str(), "<name>")
        ),
        Whose::Person { person, machines } => {
            let listed: Vec<String> = machines
                .iter()
                .map(|label| format!("{person}/{label}"))
                .collect();
            format!(
                "that is {person}'s root key, not a machine's key\n  {person}'s: {}.",
                listed.join(", ")
            )
        }
        // The argument is found by what it is, a root's key, never by its text, so no spelling of it is
        // left in the line.
        Whose::Unknown => format!(
            "that is a root key, not a machine's key; name one of its machines:\n  {}",
            retyped(
                argv,
                verb,
                |word| word.parse::<RootKey>().is_ok(),
                "<person>/<name>"
            )
        ),
    }
}

/// The detail under a refusal for a person with no machine saved: save one, with the command whose
/// placeholders only the reader can fill. `machine` is the machine's name when one was typed, else the
/// `<name>` placeholder.
fn save_one(person: &str, machine: &str) -> String {
    format!(
        "  To reach {person}, save one of {person}'s machines:\n    swoosh contact add {person}/{machine} <key>"
    )
}

/// The command line as typed, with only the machine replaced: `swoosh`, then every argument as typed,
/// global flags included (so the fix runs on the same home), each shell-quoted only when it needs it.
///
/// The machine is the argument after the verb that `is_machine` picks: the first such for every verb but
/// `send`, whose machine comes after its paths and is the last. The replacement is this binary's own
/// (`me/nas`, `<person>/<name>`), so it goes in as it is, never quoted.
fn retyped(
    argv: &[OsString],
    verb: &str,
    is_machine: impl Fn(&str) -> bool,
    replacement: &str,
) -> String {
    let words: Vec<String> = argv
        .iter()
        .skip(1)
        .map(|word| word.to_string_lossy().into_owned())
        .collect();
    let after_verb = words
        .iter()
        .position(|word| word == verb)
        .map_or(0, |at| at + 1);
    let mut matches = words
        .iter()
        .enumerate()
        .skip(after_verb)
        .filter(|(_, word)| is_machine(word))
        .map(|(at, _)| at);
    let machine = if verb == "send" {
        matches.next_back()
    } else {
        matches.next()
    };
    let mut line = String::from("swoosh");
    for (at, word) in words.iter().enumerate() {
        line.push(' ');
        if Some(at) == machine {
            line.push_str(replacement);
        } else {
            line.push_str(&quoted(word));
        }
    }
    line
}

/// `word` as one shell word: as it is when every character is one no shell reads specially, else in single
/// quotes, each `'` written as `'\''`.
fn quoted(word: &str) -> String {
    let plain = !word.is_empty()
        && word.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '-' | '.' | '/' | ':' | '=' | '@' | '%' | '+' | ',')
        });
    if plain {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

/// The refusal a dial of `service` to `machine` prints when the machine refused it `NotAdmitted`: the wire
/// says no more than that, so the words depend on the kind of machine. One of your own devices was asked
/// why ([`Diagnosis`]); a link's machine or anyone else's names both causes it cannot tell apart and no
/// command, since none the reader can run fixes it.
pub fn refused(machine: &Machine, service: &Service, diagnosis: Option<Diagnosis>) -> eyre::Report {
    eyre::Report::new(Refused(refusal(machine, service, diagnosis)))
}

/// A dial refusal, as [`refused`] words it. Its own type so a caller that escapes a peer's text in an
/// error chain knows this one carries none: every word is this home's or a fixed one, and its line breaks
/// are the refusal's own.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Refused(String);

/// The words of [`refused`].
fn refusal(machine: &Machine, service: &Service, diagnosis: Option<Diagnosis>) -> String {
    let named = match (machine.name(), machine.kind()) {
        (Some(name), _) => name.to_string(),
        (None, Kind::Link) => "the link's machine".to_owned(),
        (None, _) => "that machine".to_owned(),
    };
    let device = machine
        .name()
        .and_then(|name| name.device())
        .map_or_else(|| named.clone(), ToString::to_string);
    let head = format!("{named} refused {service}");
    match (machine.kind(), diagnosis) {
        (Kind::Yours, Some(Diagnosis::NotListed)) => format!(
            "{named} does not serve {service}\n  Only {device} can add it; on {device}, run:\n    \
                 swoosh service add {}",
            swoosh::serve::entry_for(service.as_str())
        ),
        (Kind::Yours, Some(Diagnosis::Listed)) => format!(
            "{head}\n  {service} was turned off or removed on {device}, or {device} is too busy to \
                 take it now.\n  On {device}, run this to see which:\n    swoosh status"
        ),
        (Kind::Yours, Some(Diagnosis::NotYours)) => {
            format!("{head}\n  {device} does not count this machine as one of your devices.")
        }
        (Kind::Yours, Some(Diagnosis::Unknown) | None) => head,
        (Kind::Link, _) => {
            format!("{head}\n  It does not serve {service}, or it does not accept this link.")
        }
        (Kind::Contact | Kind::Key, _) => format!(
            "{head}\n  It does not serve {service}, or its owner has not shared {service} with you."
        ),
    }
}

#[cfg(test)]
#[path = "machine_tests.rs"]
mod tests;
