//! The screen law's two mechanical predicates, case-and-period and width, applied by a line's shape so no
//! line is an exception. [`Screen::write`](super::Screen::write) holds every block a test writes to them;
//! [`read`] holds a screen given as plain text, its shapes recognised from the text.

use core::fmt;

use super::{Shape, WIDTH};

/// Names that keep their own case after `error:` or `warning:`.
const NAMES: &[&str] = &["Touch ID"];

/// A token this long is a whole key, an invite or a link: a command holding one may run past 80.
const WHOLE_KEY: usize = 56;

/// Which rule a line broke: every rule but [`Rule::Width`] is the case-and-period predicate's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Rule {
    /// Two sentences never share a line.
    TwoSentences,
    /// The clause after `error:` or `warning:` starts lowercase, unless it starts with a name.
    HeadCase,
    /// The clause after `error:` or `warning:` never ends in a period.
    HeadPeriod,
    /// A command to type never ends in a period.
    CommandPeriod,
    /// A sentence ends in `.`, `:` or `…`.
    SentenceEnd,
    /// No line past 80 scalars, unless it is an unbreakable token alone.
    Width,
}

/// A line that broke the law, and the rule it broke.
#[derive(Debug)]
pub(super) struct Breach {
    /// The rule it broke.
    pub(super) rule: Rule,
    line: String,
}

impl fmt::Display for Breach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} breached by {:?}", self.rule, self.line)
    }
}

/// Hold one block's lines, case and period first.
pub(super) fn hold<'l>(lines: impl IntoIterator<Item = (Shape, &'l str)>) -> Result<(), Breach> {
    let lines: Vec<_> = lines.into_iter().collect();
    case_and_period(&lines)?;
    width(&lines)
}

/// Hold a screen given as plain text. A line is a command when it is indented and its first word is
/// `swoosh` or a flag; any other line is prose, which the predicates read by its text.
pub(super) fn read(screen: &str) -> Result<(), Breach> {
    hold(screen.lines().map(|line| {
        let body = line.trim_start();
        let indented = body.len() < line.len();
        let first = body.split_whitespace().next().unwrap_or_default();
        let command = indented && (first == "swoosh" || first.starts_with("--"));
        (
            if command {
                Shape::Command
            } else {
                Shape::Prose
            },
            line,
        )
    }))
}

fn case_and_period(lines: &[(Shape, &str)]) -> Result<(), Breach> {
    let mut at = 0;
    while let Some(&(shape, line)) = lines.get(at) {
        at += 1;
        let body = line.trim_start();
        match shape {
            Shape::Fact | Shape::Token => continue,
            Shape::Command if line.trim_end().ends_with('.') => {
                return breach(Rule::CommandPeriod, line);
            }
            Shape::Command => continue,
            Shape::Prose => {}
        }
        two_sentences(line)?;
        if let Some(clause) = ["error: ", "warning: "]
            .iter()
            .find_map(|head| body.strip_prefix(head))
        {
            if starts_upper(clause) && !NAMES.iter().any(|name| clause.starts_with(name)) {
                return breach(Rule::HeadCase, line);
            }
            if clause.trim_end().ends_with('.') {
                return breach(Rule::HeadPeriod, line);
            }
            continue;
        }
        if !starts_upper(body) {
            continue;
        }
        // A sentence wrapped at 80 runs on while a line leaves it open and the next, at the same indent,
        // starts lowercase.
        let indent = line.len() - body.len();
        let mut last = line;
        while !ends(last) {
            let Some(&(Shape::Prose, next)) = lines.get(at) else {
                break;
            };
            let next_body = next.trim_start();
            if next.len() - next_body.len() != indent || !starts_lower(next_body) {
                break;
            }
            two_sentences(next)?;
            last = next;
            at += 1;
        }
        if !ends(last) {
            return breach(Rule::SentenceEnd, last);
        }
    }
    Ok(())
}

fn width(lines: &[(Shape, &str)]) -> Result<(), Breach> {
    for &(shape, line) in lines {
        if shape == Shape::Token || line.chars().count() <= WIDTH {
            continue;
        }
        let body = line.trim();
        let alone = !body.contains(char::is_whitespace);
        let holds_key = (body.starts_with("swoosh ") || body.starts_with("--"))
            && body
                .split_whitespace()
                .any(|word| word.chars().count() >= WHOLE_KEY);
        if !alone && !holds_key {
            return breach(Rule::Width, line);
        }
    }
    Ok(())
}

/// Two sentences never share a line: no `. ` before a capital.
fn two_sentences(line: &str) -> Result<(), Breach> {
    let shared = line
        .match_indices(". ")
        .any(|(at, _)| starts_upper(&line[at + 2..]));
    if shared {
        breach(Rule::TwoSentences, line)
    } else {
        Ok(())
    }
}

/// Whether a sentence ends here: a period, a colon before a command or a prompt, or an ellipsis on a wait.
fn ends(line: &str) -> bool {
    line.trim_end().ends_with(['.', ':', '…'])
}

fn starts_upper(text: &str) -> bool {
    text.chars().next().is_some_and(char::is_uppercase)
}

fn starts_lower(text: &str) -> bool {
    text.chars().next().is_some_and(char::is_lowercase)
}

fn breach(rule: Rule, line: &str) -> Result<(), Breach> {
    Err(Breach {
        rule,
        line: line.to_owned(),
    })
}

#[cfg(test)]
#[path = "law_tests.rs"]
mod tests;
