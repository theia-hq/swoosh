//! `swoosh adopt <authkey>`: become the derived identity and trust the signet that minted it.
//!
//! The other half of `mint`: on the MACHINE (a CI runner, a new laptop), `adopt` writes the authkey's
//! child seed as SWOOSH's persisted identity, so it comes up AS the derived device, and records the signet
//! its gate trusts, so `swoosh serve` admits the owner's own devices and anyone they delegate to. A
//! local verb: no transport, no reach. The identity lands in swoosh's own store (`~/.config/swoosh/`, or
//! `--key`/`SWOOSH_KEY`) -- the SAME store `swoosh serve` binds under -- so the served node
//! id matches the contact `mint` recorded. The signet lands beside it in swoosh's own config, under the
//! same `--key` dir, where the serve gate reads it.
//!
//! The authkey is a DEVICE SECRET, so it is not forced onto argv (visible in `ps` / `/proc`): the value
//! comes off the command line where the caller chooses, via the shared secret-input convention (a literal,
//! `-` for stdin, `@<path>` for a file, or `SWOOSH_AUTHKEY`). See [`crate::secret`]. The `-`/`@` redirection
//! is an argv convention only: an authkey read from `SWOOSH_AUTHKEY` is taken VERBATIM (a leading `-` or `@`
//! there is part of the secret, not a stdin/file redirect), matching how a shell exports an env value.

use std::path::Path;

use bifrost::NodeId;
use clap::Args;
use zeroize::Zeroize as _;

use crate::authkey;
use crate::secret::SecretSource;

/// The environment variable an operator may set instead of putting the authkey on argv. A PARTIAL close
/// only: the value is owner-readable in `/proc/<pid>/environ`, but every child the process spawns inherits
/// it (and `swoosh ssh` spawns `ssh`), so it is a convenience, never a full close of the argv leak.
const AUTHKEY_ENV: &str = "SWOOSH_AUTHKEY";

/// Adopt a minted authkey: become that device identity and trust its signet.
#[derive(Debug, Args)]
pub struct AdoptCmd {
    /// the authkey to adopt (a device secret; `-` stdin, `@<path>` file, or SWOOSH_AUTHKEY)
    #[arg(
        value_name = "authkey",
        long_help = "The authkey minted for this machine, a DEVICE SECRET: adopting it becomes this \
                     identity. Give it as a literal, `-` to read stdin, or `@<path>` to read a file. \
                     argv is visible to other processes (`ps`, `/proc`), so prefer stdin or a file for \
                     the secret.\n\nOr set SWOOSH_AUTHKEY: a convenience, not a full close (spawned \
                     children inherit it). The env value is taken VERBATIM: a leading `-` or `@` has no \
                     special meaning there, so it must be the authkey itself, never a redirection."
    )]
    pub authkey: Option<SecretSource>,
}

impl AdoptCmd {
    /// Parse the authkey, write the child seed as this node's identity, and record the trusted signet.
    pub async fn run(self, key: Option<&Path>) -> eyre::Result<()> {
        // Take the authkey off argv where the caller chooses: argv leaks (`ps`, `/proc/<pid>/cmdline`), so
        // this device secret may come from stdin (`-`), a file (`@<path>`), or the environment, resolving to
        // exactly one source. Read it, then parse; the token string zeroizes when it drops.
        let token = SecretSource::resolve(
            self.authkey,
            std::env::var(AUTHKEY_ENV).ok(),
            "authkey",
            AUTHKEY_ENV,
        )?
        .read()?;
        let authkey::Authkey {
            mut seed,
            signet,
            badge,
        } = authkey::parse(&token)?;
        // Compute the adopted node id before wiping the seed, for the confirmation line.
        let node = NodeId::from_ed25519_secret(&seed);
        // Become the derived device: write the child seed as SWOOSH's persisted identity -- the SAME store
        // `swoosh serve` binds under (crate::identity::resolve), so this node comes up AS the adopted
        // device. Writing tightbeam's separate store was the bug: `swoosh serve` binds swoosh's key, so
        // the exposed node had a different id than the contact pointed at, and was never reachable. Then
        // wipe our copy.
        crate::identity::write(&seed, key).await?;
        seed.zeroize();
        // Trust the signet: the default gate admits its devices (members) and delegates (slips). The signet
        // lands beside the identity just written, under the SAME `--key` dir, in swoosh's own config, which
        // `swoosh serve` reads via `crate::config::load_signet`. One command, one dir.
        crate::config::write_signet(key, signet).await?;
        // Store the signet-signed membership badge beside the seed, so this device PRESENTS the badge the
        // signet minted for it (rooted at the signet, bound to this key) when it dials a family-gated node,
        // rather than self-signing (which roots at this child key and is refused). Absent for a legacy
        // two-field authkey; then the device falls back to self-signing (only useful for the signet holder).
        if let Some(badge) = &badge {
            crate::config::write_badge(key, badge).await?;
        }

        println!("adopted this machine as {}  [mine]", node.short());
        println!(
            "trusting signet {}: `swoosh serve` now admits its members and delegates.",
            signet.short()
        );
        if badge.is_some() {
            println!("stored your membership badge: this device now reaches your gated services.");
        }
        Ok(())
    }
}
