//! `swoosh tree`: print the command tree by walking clap's own model.
//!
//! A local verb (binds no transport, dials nobody). It reads the same `///` one-liners clap renders for
//! `--help`, so the printed tree can never drift from the help text: that is the whole point. A Newcomer
//! or a re-review diffs "what the binary exposes" against CLI-DESIGN in one command, rather than
//! eyeballing help screens. Rendered with the same two-space indentation as `contact ls`, so there is
//! one tree idiom across the tool.

use clap::{Args, Command};

/// Print the command tree (spec vs binary).
#[derive(Debug, Args)]
pub struct TreeCmd {}

impl TreeCmd {
    /// Print the root name, then every subcommand and its one-liner, indented by depth.
    pub fn run(self, root: &Command) -> eyre::Result<()> {
        println!("{}", root.get_name());
        walk(root, 0);
        Ok(())
    }
}

/// Recurse the subcommands of `cmd`, printing each name and its trimmed `about` at two-space depth.
fn walk(cmd: &Command, depth: usize) {
    for sub in cmd.get_subcommands() {
        let about = sub
            .get_about()
            .map(|about| about.to_string())
            .unwrap_or_default();
        println!("{}{:<10}{about}", "  ".repeat(depth + 1), sub.get_name());
        walk(sub, depth + 1);
    }
}
