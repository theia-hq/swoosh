//! `swoosh adopt <invite>`: join a signet's family as this machine.
//!
//! The device half of `invite add`, one command for both invite shapes:
//!
//! - A BOUND invite (`invite:<signet>.<badge>`) was signed for a key this machine made and printed with
//!   `swoosh status --key`. Adopting trusts the signet and stores the badge, KEEPING this machine's identity.
//!   The token carries no secret, so it is safe in transit; it is NOT authenticated, so the badge is
//!   checked against this machine's key, and the full signet is printed for an out-of-band compare,
//!   before anything is written.
//! - A DERIVED invite (`invite:<seed>.<signet>.<badge>`) carries a child seed.
//!   Adopting writes that seed as this machine's identity, so it comes up AS the derived device. The seed
//!   is a device SECRET: hand this shape over a private channel only. A machine that already HAS an
//!   identity is refused here rather than re-identified, since nothing can re-issue the key it holds.
//!
//! Either way the write lands in swoosh's own store (the node home, the default `~/.config/swoosh/` or
//! `--home`/`SWOOSH_HOME`) -- the SAME store `swoosh serve` binds under -- so the served node id matches
//! the contact `invite add` recorded. The trusted signet lands beside it, where the serve gate reads it.
//!
//! An invite is a secret only for the derived shape, so it is not forced onto argv (visible in `ps` /
//! `/proc`): the value comes off the command line where the caller chooses, via the shared secret-input
//! convention (a literal, `-` for stdin, `@<path>` for a file, or `SWOOSH_INVITE`). The `-`/`@`
//! redirection is an argv convention only: an invite read from `SWOOSH_INVITE` is taken VERBATIM (a
//! leading `-` or `@` there is part of the token, not a stdin/file redirect).

use std::time::SystemTime;

use bifrost::NodeId;
use clap::Args;
use eyre::WrapErr as _;
use nauthy::Link;
use swoosh::credential::LinkExt as _;
use swoosh::home::Home;
use swoosh::invite::Invite;
use swoosh::secret::SecretSource;
use swoosh::{config, identity};
use tightbeam::identity::AsVerifyKey as _;

/// The environment variable an operator may set instead of putting the invite on argv. A PARTIAL close
/// only: the value is owner-readable in `/proc/<pid>/environ`, but every child the process spawns inherits
/// it (and `swoosh ssh` spawns `ssh`), so it is a convenience, never a full close of the argv leak.
const INVITE_ENV: &str = "SWOOSH_INVITE";

/// Adopt an invite: trust its signet and store its badge (a derived invite also becomes its identity).
#[derive(Debug, Args)]
pub struct AdoptCmd {
    /// the invite to adopt (a secret for a derived invite; `-` stdin, `@<path>` file, or SWOOSH_INVITE)
    #[arg(
        value_name = "invite",
        long_help = "The invite to adopt. A derived invite (`invite add` with no `--for`) carries a \
                     device SECRET and adopting it becomes that identity; a bound invite (`invite add \
                     --for <key>`) carries no secret and leaves this machine's identity alone. Give it as \
                     a literal, `-` to read stdin, or `@<path>` to read a file. argv is visible to other \
                     processes (`ps`, `/proc`), so prefer stdin or a file when the invite carries a \
                     secret.\n\nOr set SWOOSH_INVITE: a convenience, not a full close (spawned children \
                     inherit it). The env value is taken VERBATIM: a leading `-` or `@` has no special \
                     meaning there, so it must be the invite itself, never a redirection."
    )]
    pub invite: Option<SecretSource>,
    /// re-root this machine at a different signet, or store a badge this invite does not outlive
    #[arg(long)]
    pub force: bool,
}

impl AdoptCmd {
    /// Parse the invite and write what it carries into this home: the identity (derived shape only), the
    /// trusted signet, and the membership badge.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        // Take the invite off argv where the caller chooses: argv leaks (`ps`, `/proc/<pid>/cmdline`), so
        // a derived invite's device seed may come from stdin (`-`), a file (`@<path>`), or the environment,
        // resolving to exactly one source. Resolve QUIETLY: only the derived shape carries a secret, so the
        // leak warning waits until the shape is parsed. The token string zeroizes when it drops.
        let from_argv = matches!(self.invite, Some(SecretSource::Literal(_)));
        let token = SecretSource::resolve_quiet(
            self.invite,
            std::env::var(INVITE_ENV).ok(),
            "invite",
            INVITE_ENV,
        )?
        .read()?;
        let invite = Invite::parse(&token)?;
        if from_argv && invite.seed.is_some() {
            swoosh::secret::warn_argv_leak(&mut std::io::stderr(), "invite");
        }
        // The standing's key is the root: the invite carries it once.
        let signet = invite.standing.dial_node()?;
        let badge = invite.standing;
        match invite.seed {
            None => {
                // A bound invite admits a key this machine already holds, so there must already BE an
                // identity: minting one here would produce a key the badge is not bound to, and writing
                // the badge anyway would store a credential the far gate must refuse.
                let Some(secret) = identity::load(home).await? else {
                    eyre::bail!(
                        "this invite is bound to a device key, but this machine has no identity yet; run \
                         `swoosh status --key` to make one, then have the owner run `swoosh invite add <label> \
                         --for <that key>`"
                    );
                };
                let node = secret.node_id();
                // The token is unauthenticated transport: anyone can name any signet. Verify the badge
                // actually roots at the named signet AND binds THIS machine, unexpired, before any write.
                let badge = verify_badge(badge, node, signet)?;
                admit_signet(home, signet, self.force).await?;
                // The credential half of the same rule: a token is not authenticated, so a badge that
                // does not OUTLIVE the stored one (an old or revoked replay) must not overwrite it.
                admit_badge(home, &badge, node, self.force).await?;
                admit_live_signet(home, signet).await?;
                // Trust the signet: the default gate admits its members and delegates. The signet lands
                // beside the identity, in the SAME home, which `swoosh serve` reads via `load_signet`.
                config::write_signet(home, signet).await?;
                // Store the signet-signed membership badge beside the seed, so this device PRESENTS the
                // badge the signet minted for it when it dials a family-gated node.
                config::write_badge(home, &badge).await?;
                println!("this machine is already {node}; trusting signet {signet}");
                println!("{}", COMPARE_SIGNET);
                println!(
                    "stored your membership badge: this device now reaches your gated services."
                );
            }
            Some(seed) => {
                // Compute the adopted node id before the seed drops (the zeroizing wrapper wipes it).
                let node = NodeId::from_ed25519_secret(&seed);
                // Same device-side check as the bound arm, on the node the seed derives: the badge must
                // root at the named signet and bind this device before the seed or badge is persisted.
                let badge = verify_badge(badge, node, signet)?;
                admit_signet(home, signet, self.force).await?;
                // Same badge guard as the bound arm, before the seed write: a stored badge cannot be
                // displaced by a token that does not outlive it without `--force`. `node` is the seed's
                // device, so a derived invite re-identifying this machine never reads as a renewal of
                // the outgoing device's badge.
                admit_badge(home, &badge, node, self.force).await?;
                admit_live_signet(home, signet).await?;
                // Become the derived device: write the child seed as SWOOSH's persisted identity -- the
                // SAME store `swoosh serve` binds under -- so this node comes up AS the adopted device.
                // This is the transaction's THIRD admission, and the only one that does not live beside
                // its siblings above: the rule belongs to the key file, not to this verb, so it is
                // enforced in `identity::write` for every caller (a machine already holding a different
                // key is refused there, and `--force` does not reach it, because that key is the one
                // thing here nobody can re-issue). Like the two above it, it fires before any write.
                identity::write(&seed, home).await?;
                // Trust the signet, exactly as the bound shape does.
                config::write_signet(home, signet).await?;
                // Store the badge the derived invite carries, so this device presents the signet-signed
                // credential when it dials a family-gated node.
                config::write_badge(home, &badge).await?;
                println!("adopted this machine as {node}  [mine]");
                println!(
                    "trusting signet {signet}: `swoosh serve` now admits its members and delegates."
                );
                println!("{}", COMPARE_SIGNET);
                println!(
                    "stored your membership badge: this device now reaches your gated services."
                );
            }
        }
        Ok(())
    }
}

/// The out-of-band check every adopt prints. The badge inside is signed by the signet it names, but the
/// token itself is not signed at all, so anyone who can swap the message can name their own key as the
/// signet. Comparing the full signet with the owner is the one check that catches that substitution.
const COMPARE_SIGNET: &str = "compare that signet with the owner out of band before serving: the token is \
                              not signed by the signet it names, so it alone does not prove who sent it.";

/// Verify a carried badge is a usable credential for THIS machine: a membership cap rooted at `signet`,
/// bound to `node`, and unexpired now. The invite token is unauthenticated transport, so this is the check
/// that keeps a forged, mismatched, or stale badge off disk.
///
/// It CONSUMES the badge and hands it back, so the only way to reach a write is through the check: a
/// caller cannot hold a verified badge it never verified, and skipping the call is a missing binding the
/// compiler names rather than a check a reader has to spot the absence of.
fn verify_badge(badge: Link, node: NodeId, signet: NodeId) -> eyre::Result<Link> {
    badge
        .cap()
        .verify_member_at_root_without_revocation(
            SystemTime::now(),
            node.verify_key()?,
            signet.verify_key()?,
        )
        .wrap_err_with(|| {
            format!(
                "the invite's badge does not bind this machine ({node}) at signet {signet}: it is bound \
                 to another key, rooted elsewhere, or expired. Ask the owner to sign a fresh invite for \
                 this machine's key: `swoosh invite add <label> --for {node}`"
            )
        })?;
    Ok(badge)
}

/// Refuse to trust a signet this node has disabled. A disable is terminal and `--force` does not reach
/// it: the gate would refuse every badge that key signs, so adopting it would store a credential that
/// admits nowhere here and a signet this node has already said it no longer trusts. Asked last, right
/// before the first write, so a disable that lands while the invite is being checked is still seen.
async fn admit_live_signet(home: &Home, signet: NodeId) -> eyre::Result<()> {
    if config::is_disabled(home, signet).await? {
        eyre::bail!(
            "signet {signet} is disabled at this node, so it will not adopt an invite that key signed"
        );
    }
    Ok(())
}

/// Refuse to silently re-root this machine: when the home already trusts a DIFFERENT signet than the
/// invite names, adopting would switch the gate's root, so it takes an explicit `--force`. An absent
/// signet file is first provisioning, not a switch.
async fn admit_signet(home: &Home, signet: NodeId, force: bool) -> eyre::Result<()> {
    if force {
        return Ok(());
    }
    if let Some(trusted) = config::load_signet(home).await?
        && trusted != signet
    {
        eyre::bail!(
            "this machine already trusts signet {trusted}; adopting this invite would re-root it at \
                 {signet}. Re-run with --force if that is intended"
        );
    }
    Ok(())
}

/// Refuse to silently DOWNGRADE this machine's stored badge, while letting a routine renewal through.
///
/// A bound invite's token is not authenticated, and the carried badge passes verification without a
/// revocation check, so a replayed old or revoked token under the SAME signet must not overwrite the
/// live credential (the signet compare cannot catch it). But what makes a replay a replay is that it is
/// OLDER, not that it DIFFERS. Refusing every differing badge made the quarterly renewal (the routine,
/// strictly-safer act, since renewal IS re-enrolment and there is no renew verb) demand the very
/// `--force` that also disables [`admit_signet`]'s re-root guard, so the safe act required the
/// dangerous flag. The predicate is therefore "is this a downgrade", and `--force` keeps its real
/// meaning: re-root, or accept a badge that is not an improvement.
///
/// Accepted with no flag: an absent stored badge (first provisioning), the exact bytes already on disk
/// (a no-op re-adopt), and a RENEWAL as [`renews`] defines it. Everything else still takes `--force`.
async fn admit_badge(home: &Home, badge: &Link, node: NodeId, force: bool) -> eyre::Result<()> {
    if force {
        return Ok(());
    }
    let Some(stored) = config::load_badge(home).await? else {
        return Ok(());
    };
    if stored.as_str() == badge.as_str() || renews(&stored, badge, node)? {
        return Ok(());
    }
    eyre::bail!(
        "this machine already stores a membership badge that this invite does not outlive; adopting it \
         would replace the stored badge with one that is older, bound to another device, rooted at \
         another signet, or carries no readable expiry. To narrow a device's window, cut the old \
         badge first with `swoosh invite rm <label>`, then mint the shorter one: re-issuing short \
         over a live longer badge does not narrow anything, because the longer one stays signed and \
         admitted. Re-run with --force if replacing it is what you meant"
    )
}

/// Whether `incoming` RENEWS the `stored` badge for the device `node`: the same signet, the same device,
/// and a strictly LATER expiry. The one predicate [`admit_badge`] turns on, so "is this safe to store"
/// has exactly one answer.
///
/// A replay is not later than the badge it replaced, so the guard the byte-inequality check existed
/// for is kept whole while the routine act passes. ONE case escapes that and it is recorded rather
/// than closed: if the owner re-issues a SHORTER badge over a live longer one, the longer token is
/// still signed, unexpired and admitted everywhere, so replaying it afterwards reads as a renewal.
/// Expiry is the only ordering fact a badge carries, so no comparison here can tell "newer" from
/// "longer". It costs nothing, because re-issuing short never narrowed the window in the first
/// place: the correct act is `invite rm <label>` and then the shorter mint, which the refusal text
/// below now teaches. Ruled an accepted cost. The two expiries come from nauthy's advisory `expires_at` fact,
/// which is an UPPER BOUND (a narrowing an attenuation block added is invisible to the origin-0 read),
/// and that cuts the safe way twice here: a badge carrying no fact reads `None` and falls back to the
/// byte-inequality refusal rather than to acceptance, and an attenuated badge that reads longer than it
/// truly is can only cost a stored credential that dies sooner than believed, which the dial-time
/// refusal then names.
fn renews(stored: &Link, incoming: &Link, node: NodeId) -> eyre::Result<bool> {
    // Same signet, read off the badge itself rather than off the signet file: the file says what this
    // machine trusts NOW, and the question here is whether the two credentials share a root.
    if stored.root() != incoming.root() {
        return Ok(false);
    }
    let Some(was) = superseded(stored.cap().expiry()?, incoming.cap().expiry()?) else {
        return Ok(false);
    };
    // The stored badge must bind the SAME device, or a DERIVED invite (which adopts a whole new
    // identity) would read as a renewal of the outgoing device's credential and quietly re-identify the
    // machine. Asked at the last instant the stored badge was alive, so its own expiry check answers the
    // binding question instead of masking it: a badge dead since yesterday still binds exactly the
    // device it always bound.
    Ok(stored
        .cap()
        .verify_member_at_root_without_revocation(was, node.verify_key()?, stored.root())
        .is_ok())
}

/// The stored expiry that `incoming` supersedes, when it does: `Some(was)` only when BOTH badges carry a
/// readable expiry and the incoming one falls strictly later. Pure and total over the unreadable case,
/// so every arm of the decision is testable without minting a badge nauthy alone can make.
///
/// Returning the instant rather than a bool hands [`renews`] the one moment at which the stored badge is
/// known to have been alive, which is where its device binding must be asked.
fn superseded(stored: Option<SystemTime>, incoming: Option<SystemTime>) -> Option<SystemTime> {
    match (stored, incoming) {
        // Strictly later, never equal: a token replayed verbatim under a re-mint that happened to land
        // on the same second buys the holder nothing and must not pass as an improvement.
        (Some(was), Some(now)) if now > was => Some(was),
        _ => None,
    }
}

#[cfg(test)]
#[path = "adopt_tests.rs"]
mod adopt_tests;
