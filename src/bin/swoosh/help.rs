//! `swoosh --help`'s verb list, under the headings of the command table.
//!
//! clap lists subcommands as one flat section and has no headings for them, so the top-level help is a
//! template that prints each group's verbs itself. Every row is read from the `Command` clap builds from
//! the same derive, so a verb's help line still has one source, its `///` line.

use clap::Subcommand as _;
use clap::builder::Styles;

/// The verbs `swoosh --help` prints, under each heading, in the command table's order. Every visible verb
/// sits in exactly one group; a verb missing here is missing from the help, which a test holds.
pub(crate) const GROUPS: [(&str, &[&str]); 6] = [
    ("Check a machine", &["status", "ping", "speed"]),
    ("Use a machine", &["ssh", "send", "forward", "proxy"]),
    ("Serve", &["serve", "stop", "service"]),
    ("Your devices", &["invite", "join", "leave", "sync"]),
    ("People and links", &["contact", "share", "revoke"]),
    ("Keys", &["lock", "root"]),
];

/// The top-level help template: clap's own about, usage and options, with the grouped verbs between them
/// in place of clap's one `Commands:` list. A heading takes clap's header style and a verb its literal style,
/// so a terminal shows them as clap shows its own; a pipe gets them plain, as clap strips every style there.
pub(crate) fn template() -> String {
    // Built from the subcommands alone, never from `Cli`, whose own construction calls this.
    let verbs = crate::Command::augment_subcommands(clap::Command::new("swoosh"));
    let width = GROUPS
        .iter()
        .flat_map(|(_, names)| names.iter())
        .map(|name| name.len())
        .max()
        .unwrap_or_default();
    let styles = Styles::default();
    let (header, literal) = (styles.get_header(), styles.get_literal());
    let mut template = String::from("{before-help}{about-with-newline}\n{usage-heading} {usage}\n");
    for (heading, names) in GROUPS {
        template.push_str(&format!("\n{header}{heading}:{header:#}\n"));
        for name in names {
            let about = verbs
                .find_subcommand(name)
                .and_then(clap::Command::get_about)
                .map(ToString::to_string)
                .unwrap_or_default();
            // Padded outside the style, so the column holds whatever the escapes add.
            let pad = width - name.len();
            template.push_str(&format!(
                "  {literal}{name}{literal:#}{:pad$}  {about}\n",
                ""
            ));
        }
    }
    template.push_str(&format!(
        "\n{header}Options:{header:#}\n{{options}}{{after-help}}"
    ));
    template
}

#[cfg(test)]
#[path = "help_tests.rs"]
mod tests;
