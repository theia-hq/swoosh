//! `swoosh identity protect <method>`: set how this identity's key file protects the key.
//!
//! The method is a property of the file, chosen here and nowhere else: no other verb takes a method, and
//! no config names one. On a home with no key yet this creates the first one under the method asked for.
//! The key, and so the node, never changes, so it is safe beside a running node.

use clap::{Args, ValueEnum};
use keystore::Method;
use swoosh::home::Home;
use swoosh::identity::{self, Protected};
use swoosh::passphrase::Terminal;

/// Set how this identity is protected.
#[derive(Debug, Args)]
pub struct ProtectCmd {
    /// how the key file protects the key
    #[arg(value_name = "method")]
    method: Protection,
}

/// The methods a key file can be protected by, as the command line names them. Only built methods are
/// values, so `--help` never offers one that does nothing.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Protection {
    /// the raw seed in one 0600 file
    Plain,
    /// sealed under a passphrase you type
    Passphrase,
}

impl From<Protection> for Method {
    fn from(protection: Protection) -> Self {
        match protection {
            Protection::Plain => Self::Plain,
            Protection::Passphrase => Self::Passphrase,
        }
    }
}

impl ProtectCmd {
    /// Rewrite (or create) the home's key file under the method, then print what now protects it.
    pub fn run(self, home: &Home) -> eyre::Result<()> {
        let method = Method::from(self.method);
        match identity::protect(home, method, &mut Terminal)? {
            // A key made here is new, so print the node it is, the way bare `identity` does.
            Protected::Created(node) => println!("{node}"),
            Protected::Rewritten | Protected::Unchanged => {}
        }
        println!("protection: {method}");
        Ok(())
    }
}
