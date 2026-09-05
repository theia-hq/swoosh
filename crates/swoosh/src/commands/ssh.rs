//! `swoosh ssh <peer>`: reach a peer's sshd over the overlay, then hand the terminal to the system ssh.
//!
//! A LAUNCHER, a third verb category beside the local and reach families. Like a local verb it reads the
//! contact store (to resolve the peer to a raw key) and binds no bifrost `Node` in this process; unlike a
//! local verb it ends up reaching a peer. It does so by `exec`ing the system `ssh` with a `ProxyCommand`
//! that re-invokes THIS binary (`<self> tunnel-connect <key> --service <name> --to -`, via
//! `current_exe()`, see [`self_invocation`]) and that hidden re-invocation binds the `Node` under
//! swoosh's OWN identity and pipes the overlay stream over ssh's stdin/stdout, so ssh talks to the far
//! sshd as if it were local. One binary, no `tightbeam` on PATH and no `$PATH` lookup at all, and the dial
//! carries swoosh's key, so a membership badge presented there binds to the identity the family gate
//! proves. `swoosh ssh alice` is a drop-in for `ssh <host>`.
//!
//! The peer resolves in-process, BEFORE ssh runs, through the same [`Peer`]/contact-store lookup
//! `ping`/`speed` use, so `alice/desk` is fine here (ssh never sees the `/`; it sees only the resolved
//! key in the `ProxyCommand` and a stable placeholder host). A `sheer:` link is a peer too now: it
//! self-addresses to its cap root and forwards as the presented slip. Everything after `--` is forwarded
//! to ssh verbatim (a remote command, `-p`, `-i`), so swoosh interprets nothing the user means for ssh.
//!
//! `ssh` is spec'd as a group that will also own `ssh config` (emit `~/.ssh/config` blocks) once contacts
//! carry advertised-service metadata; that leaf is HELD and deliberately not built. This one shipping op
//! takes the peer positionally, the shape CLI-DESIGN reserves for it.
//!
//! ## Host-key pinning
//!
//! The far sshd derives its host key from its node secret (a KDF distinct from the node key, so no
//! cross-protocol reuse), so a client holding only the peer's public node id CANNOT compute that host key
//! in advance: there is nothing to pre-seed. The host-key check here is therefore not the primary auth:
//! the OVERLAY already authenticated the peer end to end (raw-public-key TLS to the exact node id, an
//! in-process pipe with no seam a MITM could enter), so ssh's own check is self-consistency bookkeeping
//! on top of that. This launcher binds only the authenticated default transport (it exposes no
//! `--transport`), so "first use" always rides the authenticated tunnel.
//!
//! So rather than pollute the user's global `~/.ssh/known_hosts` and prompt an interactive TOFU keyed on a
//! mutable petname, `swoosh ssh` keeps its OWN known_hosts (`~/.config/swoosh/known_hosts`), keyed on the
//! immutable node id via `HostKeyAlias`, with `StrictHostKeyChecking=accept-new`: pin on first sight (safe,
//! because first sight is over the authenticated overlay), reject a later key change. `accept-new` not
//! `yes`, precisely because the derived key is not client-computable; node id not petname, so a rename
//! never orphans a pin. The private file is `0600` in a `0700` dir, and a loose one is refused rather than
//! trusted.

use std::path::{Path, PathBuf};

use clap::Args;

use crate::contacts::Contacts;
use crate::credential::SheerLink;
use crate::peer::Peer;
use crate::transport;

/// The exposed service name reached when the user names none: a host's sshd under the default label.
const DEFAULT_SERVICE: &str = "ssh";

/// The system binary a launch shells out to: the far sshd is reached by the system `SSH`, whose overlay
/// transport is THIS binary re-invoked as its `ProxyCommand` (see [`self_invocation`]): no separate
/// `tightbeam` binary. Named as a constant so a "not found on PATH" error can point at the exact binary.
const SSH: &str = "ssh";

/// Reach a peer's sshd over the overlay; runs the system ssh.
#[derive(Debug, Args)]
pub struct SshCmd {
    /// the peer to reach: a petname (`alice`, `alice/desk`), a raw node id, or a `sheer:` link
    #[arg(value_name = "peer")]
    pub peer: Peer,
    /// The exposed service name to reach on the host.
    #[arg(long, value_name = "service", default_value = DEFAULT_SERVICE)]
    pub service: String,
    /// present a `sheer:` cap link to a cap-gated host (a delegate's slip)
    #[arg(long, value_name = "link")]
    pub present: Option<SheerLink>,
    /// direct address hint for the peer, `<key>=<addr>` (repeatable)
    #[arg(id = "peer-hint", long = "peer", value_name = "key=addr")]
    pub peer_hint: Vec<transport::PeerHint>,
    /// Args forwarded verbatim to the system ssh, after `--`.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "ssh args"
    )]
    pub args: Vec<String>,
}

impl SshCmd {
    /// Resolve the peer to a raw key, then replace this process with the system `ssh` reaching it over the
    /// overlay. On success swoosh's PID *becomes* ssh (unix); a resolve or PATH failure returns before any
    /// exec, so a caller prints its clean message and exits non-zero. Prints nothing on the success path.
    pub fn run(self, contacts: &Contacts, identity_key: Option<&Path>) -> eyre::Result<()> {
        // A `sheer:` link peer already presents its own credential, so a second explicit `--present` is a
        // loud conflict, not a silent pick.
        self.peer.reject_redundant_present(self.present.as_ref())?;
        // The fold: a `sheer:` link-as-peer supplies its own slip (self-addressing), else the explicit
        // `--present`. `ssh` computes no slots; it forwards this slip as `--present <link>` into the
        // ProxyCommand, where the re-invoked `tunnel-connect` runs the ONE resolver (so a signet-bound
        // link-as-peer gets its slot-2 badge there, for free, through the existing `--present` path).
        let present = self.peer.self_present().or_else(|| self.present.clone());

        // Resolve in-process, before ssh sees anything: take the first device for a bare petname (as
        // `speed` does), the exact one for `alice/desk`, a raw key straight through, and a `sheer:` link's
        // cap root (its one self-addressed candidate). The peer as typed is kept for the placeholder host,
        // so known_hosts stays stable per peer.
        let candidates = self.peer.candidates(contacts)?;
        let Some(first) = candidates.into_iter().next() else {
            // `candidates` never yields an empty success (an unknown name is a clean error), but a match
            // keeps this total rather than resting on that invariant with an unwrap.
            eyre::bail!("could not resolve {}: no known device", self.peer);
        };
        let host = self.peer.to_string();
        let key = first.node.to_string();

        // swoosh keeps its own host-key book (see module docs): prepare the private file, and on the first
        // sight of this node id print the id being pinned, so a human can eyeball it against an out-of-band
        // value. First sight is over the already-authenticated overlay, so this is a record, not blind TOFU.
        let known_hosts = known_hosts_path()?;
        prepare_known_hosts(&known_hosts)?;
        if !already_pinned(&known_hosts, &key) {
            eprintln!("swoosh: pinning {key} on first connection (over the authenticated overlay)");
        }

        let proxy = self_invocation()?;
        // Thread the effective --key into the ProxyCommand so the re-invoked tunnel-connect dials under the
        // SAME identity `swoosh ssh` was given, not swoosh's default. Absolute, since the re-invocation may
        // not share this CWD. Without this, `swoosh ssh --key X` silently dialed as the DEFAULT identity: the
        // "one flag, a second surface that ignores it" bug that faked an auth bypass.
        let identity_key = identity_key.map(std::path::absolute).transpose()?;
        let argv = ssh_argv(
            &proxy,
            &key,
            &self.service,
            present.as_ref().map(SheerLink::link),
            &host,
            &known_hosts,
            identity_key.as_deref(),
            &self.peer_hint,
            &self.args,
        );
        exec_ssh(argv)
    }
}

/// The `ssh` argv for a resolved peer: the `ProxyCommand` bridge, the private host-key pinning options, a
/// stable placeholder `host`, then the passthrough `args` verbatim.
///
/// Pure so it is unit-testable (the `exec` itself is not): given the shell-quoted `proxy` (this binary's
/// own path, see [`self_invocation`]), the resolved `key`, the `service`, an optional `present` capability
/// link, the placeholder `host`, the private `known_hosts` path, the direct-address `hints`, and the user's
/// trailing ssh `args`, it assembles the exact argv [`exec_ssh`] hands to `ssh`. The `ProxyCommand` value is
/// `<self> tunnel-connect <key> --service <name> --to - [--present <link>] [--peer <key>=<addr>]...`: ssh
/// runs it to bridge the overlay stream in-process, under swoosh's own identity, with no `tightbeam` binary
/// and no `$PATH` lookup. ssh splits `ProxyCommand` on whitespace, so `proxy` is pre-quoted and the other
/// tokens are whitespace-free (a `NodeId` is base32, the service is a single name, a `sheer:` link is one
/// token like a key, a `<key>=<addr>` hint is one token too).
///
/// The four host-key options (see the module docs) come BEFORE the passthrough args: ssh honors the first
/// occurrence of an option, so swoosh's intent wins over a user's trailing `-o`. `HostKeyAlias` keys the
/// pin on the node id, not the mutable placeholder host; the `UserKnownHostsFile` path is double-quoted so
/// an install dir with a space stays one filename to ssh.
// ssh's argv has this many genuinely distinct, independent inputs (the proxy bridge, the resolved identity,
// the service, an optional cap link, the host placeholder, the known_hosts path, the address hints, and the
// passthrough args); bundling them into a struct would only rename the same fields without making any
// illegal state unrepresentable, so keep the flat signature of a pure argv-assembler.
#[allow(clippy::too_many_arguments)]
fn ssh_argv(
    proxy: &str,
    key: &str,
    service: &str,
    present: Option<&str>,
    host: &str,
    known_hosts: &Path,
    identity_key: Option<&Path>,
    hints: &[transport::PeerHint],
    args: &[String],
) -> Vec<String> {
    // `--to -` streams the overlay service over stdin/stdout (the ProxyCommand shape). `-` is one
    // whitespace-free token, safe in ssh's whitespace-split ProxyCommand, like the key and the service.
    let mut proxy_command = format!("{proxy} tunnel-connect {key} --service {service} --to -");
    // Carry the caller's identity dir into the re-invocation, so `swoosh ssh --key X` dials as X (its
    // membership badge roots at X). `--key` is a global, valid after the subcommand; double-quoted so a
    // dir with a space stays one token. Absent, the bridge uses swoosh's default identity, as before.
    if let Some(path) = identity_key {
        proxy_command.push_str(&format!(" --key \"{}\"", path.display()));
    }
    // A `sheer:` link is whitespace-free (a single token, like the key), so it is safe unquoted in the
    // whitespace-split ProxyCommand. Appended only when present; without it the bridge self-signs a badge.
    if let Some(link) = present {
        proxy_command.push_str(&format!(" --present {link}"));
    }
    // Forward each `--peer <key>=<addr>` hint verbatim into the bridge's own reach flags, where the dial
    // actually happens (so DNS resolves at the dial site, not this launcher). A `<key>=<host:port>` hint is
    // whitespace-free (base32 key, `=`, host:port), so it rides unquoted in the whitespace-split
    // ProxyCommand like the key and the link. The bridge's flattened `ReachArgs` receives them as any other
    // reach verb would.
    for hint in hints {
        proxy_command.push_str(&format!(" --peer {}", hint.as_arg()));
    }
    let mut argv = vec![
        "-o".to_owned(),
        format!("ProxyCommand={proxy_command}"),
        "-o".to_owned(),
        format!("UserKnownHostsFile=\"{}\"", known_hosts.display()),
        "-o".to_owned(),
        "GlobalKnownHostsFile=/dev/null".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=accept-new".to_owned(),
        "-o".to_owned(),
        format!("HostKeyAlias={key}"),
        host.to_owned(),
    ];
    argv.extend(args.iter().cloned());
    argv
}

/// swoosh's private known_hosts, `~/.config/swoosh/known_hosts`, beside the identity and address book.
/// Isolated from the user's global `~/.ssh/known_hosts` so pins never pollute or collide with it.
fn known_hosts_path() -> eyre::Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| eyre::eyre!("HOME is not set"))?;
    Ok(Path::new(&home)
        .join(".config")
        .join("swoosh")
        .join("known_hosts"))
}

/// Ensure the private known_hosts directory exists (`0700`) and refuse a file writable by group or other.
///
/// The file is a trust root: anyone who can write it can pre-seed a host-key pin (a silent MITM) or wedge a
/// peer with a bogus "host key changed". So a loose file fails closed rather than being trusted. ssh itself
/// creates the file `0600` on the first `accept-new` write; swoosh only guarantees the directory and vets
/// an existing file.
#[cfg(unix)]
fn prepare_known_hosts(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.permissions().mode() & 0o022 != 0 {
            eyre::bail!(
                "{} is writable by group or other; refusing to trust it (chmod 600 it)",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_known_hosts(path: &Path) -> eyre::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// Whether `node_id` is already pinned in the private known_hosts (a line whose host field is the alias).
/// Best-effort and only drives the one-time first-pin notice: an unreadable or absent file reads as "not
/// pinned", so the notice prints once on the first successful connection.
fn already_pinned(path: &Path, node_id: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    text.lines().any(|line| {
        line.split_whitespace()
            .next()
            .is_some_and(|field| field.split(',').any(|host| host == node_id))
    })
}

/// This binary's own path, shell-quoted for use as the ssh `ProxyCommand` executable.
///
/// Using `current_exe()` (not the bare name `swoosh`, and not a separate `tightbeam`) means ssh spawns
/// exactly THIS binary by absolute path (no `$PATH` entry needed) and the overlay bridge runs in-process
/// under swoosh's own identity. ssh runs a `ProxyCommand` through `/bin/sh -c` and splits it on
/// whitespace, so the path is shell-quoted to survive an install directory with a space.
fn self_invocation() -> eyre::Result<String> {
    use eyre::WrapErr as _;

    let exe = std::env::current_exe()
        .wrap_err("could not locate this executable to build the ssh ProxyCommand")?;
    let path = exe
        .to_str()
        .ok_or_else(|| eyre::eyre!("this executable's path is not valid UTF-8"))?;
    Ok(shell_quote(path))
}

/// Single-quote `s` for `/bin/sh`, so a path with spaces stays one shell word. A literal single quote is
/// emitted as the standard `'\''` break-out-and-back-in; the common no-quote path is a plain wrap.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Replace this process with `ssh <argv>` on unix; spawn-and-wait elsewhere.
///
/// unix `exec` is what lets ssh own the tty (an interactive session, password/passphrase prompts, a
/// remote pty) as if invoked directly: swoosh's PID becomes ssh, so there is no wrapper process in the
/// signal or job-control path. A non-unix fallback spawns and mirrors ssh's exit code, since `exec` is a
/// unix primitive. Either way a missing `ssh` on PATH surfaces as a clean error before ssh takes over.
#[cfg(unix)]
fn exec_ssh(argv: Vec<String>) -> eyre::Result<()> {
    use std::os::unix::process::CommandExt as _;

    // `exec` only returns on failure (otherwise the image is replaced); the most common failure is `ssh`
    // not being on PATH, so name that binary in the error, matching the launcher's other PATH errors.
    let error = std::process::Command::new(SSH).args(&argv).exec();
    Err(eyre::Report::new(error).wrap_err(format!("could not run `{SSH}` (is it on PATH?)")))
}

#[cfg(not(unix))]
fn exec_ssh(argv: Vec<String>) -> eyre::Result<()> {
    use eyre::WrapErr as _;

    // No `exec` off unix: spawn ssh, wait, and mirror its exit status so a caller still sees ssh's result.
    let status = std::process::Command::new(SSH)
        .args(&argv)
        .status()
        .wrap_err_with(|| format!("could not run `{SSH}` (is it on PATH?)"))?;
    match status.code() {
        Some(0) | None => Ok(()),
        Some(code) => Err(eyre::eyre!("ssh exited with status {code}")),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    /// A real base32 `NodeId` string, so the assembled `ProxyCommand` carries the exact key form a
    /// resolved peer would (parsed through the boundary, not hand-built).
    const KEY: &str = "bf01aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq";

    /// A stand-in for this binary's own quoted path ([`self_invocation`]'s output), fixed so the argv is
    /// deterministic in tests (the real path is `current_exe()` at runtime).
    const PROXY: &str = "'/opt/bin/swoosh'";

    /// A fixed private known_hosts path, so the assembled argv is deterministic in tests.
    fn known_hosts() -> PathBuf {
        PathBuf::from("/home/me/.config/swoosh/known_hosts")
    }

    /// A thin clap wrapper so a test parses a real `SshCmd` from an argv the same way the binary does (its
    /// fields flatten in, so the peer positional leads and `--peer`/`--present` are options after it).
    #[derive(clap::Parser)]
    struct WrapSsh {
        #[command(flatten)]
        ssh: SshCmd,
    }

    /// Parse an `SshCmd` from an argv (`["prog", <peer>, ...]`), as the CLI boundary would.
    fn parse_ssh(argv: &[&str]) -> SshCmd {
        WrapSsh::try_parse_from(argv).expect("ssh args parse").ssh
    }

    /// A real `sheer:` link (work issues a signet-bound slip for a foreign fleet), so a link-as-peer test
    /// exercises the true parse/self-address path rather than a fake token.
    fn signet_link() -> String {
        let work = nauthy::Identity::from_secret(&[1u8; 32]).expect("valid work secret");
        let fleet = nauthy::Identity::from_secret(&[2u8; 32])
            .expect("valid fleet secret")
            .verifying_key();
        tightbeam::tunnel::mint_signet_link(
            &work,
            &"ssh".parse().expect("valid service"),
            fleet,
            core::time::Duration::from_secs(3600),
        )
        .expect("mint a signet-bound slip")
    }

    /// A direct-address hint parsed through the real boundary, keyed on `KEY` and an IP:port (no DNS).
    fn hint(addr: &str) -> transport::PeerHint {
        format!("{KEY}={addr}").parse().expect("a hint parses")
    }

    #[test]
    fn argv_wires_the_proxy_then_pinning_options_then_host() {
        let argv = ssh_argv(
            PROXY,
            KEY,
            "ssh",
            None,
            "alice/desk",
            &known_hosts(),
            None,
            &[],
            &[],
        );
        assert_eq!(
            argv,
            vec![
                "-o".to_owned(),
                format!("ProxyCommand={PROXY} tunnel-connect {KEY} --service ssh --to -"),
                "-o".to_owned(),
                "UserKnownHostsFile=\"/home/me/.config/swoosh/known_hosts\"".to_owned(),
                "-o".to_owned(),
                "GlobalKnownHostsFile=/dev/null".to_owned(),
                "-o".to_owned(),
                "StrictHostKeyChecking=accept-new".to_owned(),
                "-o".to_owned(),
                format!("HostKeyAlias={KEY}"),
                "alice/desk".to_owned(),
            ]
        );
    }

    #[test]
    fn argv_threads_the_identity_key_into_the_proxy_command() {
        // `swoosh ssh --key <dir>` must DIAL under that identity: the re-invoked tunnel-connect gets the
        // same --key, so its membership badge roots at that key. Without this, --key was silently dropped
        // and the dial used swoosh's default identity -- the bug that faked an auth bypass.
        let with_key = ssh_argv(
            PROXY,
            KEY,
            "ssh",
            None,
            "alice",
            &known_hosts(),
            Some(Path::new("/tmp/yah")),
            &[],
            &[],
        );
        assert!(
            with_key.iter().any(|a| a
                == &format!("ProxyCommand={PROXY} tunnel-connect {KEY} --service ssh --to - --key \"/tmp/yah\"")),
            "the ProxyCommand must carry --key so the dial uses the given identity: {with_key:?}"
        );
        // Absent, no --key rides the ProxyCommand: the bridge uses swoosh's default identity, as before.
        let without = ssh_argv(
            PROXY,
            KEY,
            "ssh",
            None,
            "alice",
            &known_hosts(),
            None,
            &[],
            &[],
        );
        assert!(without.iter().all(|a| !a.contains("--key")));
    }

    #[test]
    fn argv_pins_on_the_node_id_not_the_placeholder_host() {
        // The known_hosts pin is keyed on the node id via HostKeyAlias, so a petname rename never orphans
        // it. The placeholder host is the mutable petname; the alias is the immutable key.
        let argv = ssh_argv(
            PROXY,
            KEY,
            "ssh",
            None,
            "alice/desk",
            &known_hosts(),
            None,
            &[],
            &[],
        );
        assert!(argv.contains(&format!("HostKeyAlias={KEY}")));
        assert!(argv.contains(&"StrictHostKeyChecking=accept-new".to_owned()));
        assert!(argv.contains(&"GlobalKnownHostsFile=/dev/null".to_owned()));
    }

    #[test]
    fn argv_forwards_passthrough_args_after_the_host() {
        let args = vec!["-p".to_owned(), "2222".to_owned(), "ls".to_owned()];
        let argv = ssh_argv(
            PROXY,
            KEY,
            "ssh",
            None,
            "bob",
            &known_hosts(),
            None,
            &[],
            &args,
        );
        // The passthrough args land last, after the host and after swoosh's own options, so swoosh's
        // host-key options (ssh honors the first occurrence) win over any the user trails.
        let host_at = argv.iter().position(|a| a == "bob").expect("host present");
        assert_eq!(&argv[host_at + 1..], &["-p", "2222", "ls"]);
        assert!(argv[..host_at].contains(&"StrictHostKeyChecking=accept-new".to_owned()));
    }

    #[test]
    fn argv_honors_a_non_default_service() {
        let argv = ssh_argv(
            PROXY,
            KEY,
            "admin-ssh",
            None,
            "alice",
            &known_hosts(),
            None,
            &[],
            &[],
        );
        assert_eq!(
            argv[1],
            format!("ProxyCommand={PROXY} tunnel-connect {KEY} --service admin-ssh --to -")
        );
    }

    #[test]
    fn argv_appends_a_present_link_to_the_proxy_command() {
        // A `sheer:` link (whitespace-free, like the key) rides unquoted in the whitespace-split
        // ProxyCommand, after `--to -`, so the bridge presents the given slip instead of self-signing.
        let link = "sheer:abcdef0123456789";
        let argv = ssh_argv(
            PROXY,
            KEY,
            "ssh",
            Some(link),
            "alice",
            &known_hosts(),
            None,
            &[],
            &[],
        );
        assert_eq!(
            argv[1],
            format!(
                "ProxyCommand={PROXY} tunnel-connect {KEY} --service ssh --to - --present {link}"
            )
        );
    }

    #[test]
    fn argv_forwards_peer_hints_into_the_proxy_command() {
        // Each `--peer <key>=<addr>` hint rides verbatim in the ProxyCommand, appended after `--to -` (and
        // after any `--present`), one whitespace-free token per hint, so the whitespace-split ProxyCommand
        // hands them to the bridge intact for the bridge to resolve at the dial site.
        let hints = [hint("127.0.0.1:9000"), hint("198.51.100.4:22")];
        let argv = ssh_argv(
            PROXY,
            KEY,
            "ssh",
            None,
            "alice",
            &known_hosts(),
            None,
            &hints,
            &[],
        );
        assert_eq!(
            argv[1],
            format!(
                "ProxyCommand={PROXY} tunnel-connect {KEY} --service ssh --to - \
                 --peer {KEY}=127.0.0.1:9000 --peer {KEY}=198.51.100.4:22"
            )
        );
    }

    #[test]
    fn a_link_peer_forwards_present_and_dials_the_root() {
        // `swoosh ssh sheer:<link>`: the link is a self-addressing peer, so it self-presents its own slip
        // and self-addresses to the cap root. The forwarded ProxyCommand dials that root key and appends
        // `--present <link>` (the fold), so the bridge presents the slip the user named as the peer.
        let link = signet_link();
        let cmd = parse_ssh(&["swoosh", &link]);
        assert!(
            matches!(cmd.peer, Peer::Capability(_)),
            "a sheer: link parses as a Capability peer"
        );
        let present = cmd
            .peer
            .self_present()
            .expect("a link peer self-presents its own slip");
        assert_eq!(
            present.link(),
            link,
            "the forwarded present is the link itself"
        );
        let root = cmd
            .peer
            .candidates(&Contacts::default())
            .expect("a link self-addresses with no store")
            .into_iter()
            .next()
            .expect("one candidate")
            .node
            .to_string();
        let argv = ssh_argv(
            PROXY,
            &root,
            "ssh",
            Some(present.link()),
            &cmd.peer.to_string(),
            &known_hosts(),
            None,
            &[],
            &[],
        );
        assert_eq!(
            argv[1],
            format!(
                "ProxyCommand={PROXY} tunnel-connect {root} --service ssh --to - --present {link}"
            )
        );

        // A `Named`/`Raw` peer does NOT self-present, so the fold forwards the EXPLICIT `--present` instead.
        let cmd = parse_ssh(&["swoosh", "alice", "--present", &link]);
        assert!(
            cmd.peer.self_present().is_none(),
            "a petname peer supplies no self-credential"
        );
        let present = cmd
            .peer
            .self_present()
            .or_else(|| cmd.present.clone())
            .expect("the explicit --present is the forwarded slip");
        assert_eq!(present.link(), link);
    }

    #[test]
    fn ssh_hosts_both_a_positional_peer_and_a_peer_hint() {
        // The `--peer` HINT (clap id `peer-hint`) and the positional `peer` coexist with no clap id
        // collision: this used to panic at parse because both derived the id `peer`.
        let cmd = parse_ssh(&[
            "swoosh",
            "alice",
            "--peer",
            &format!("{KEY}=127.0.0.1:9000"),
        ]);
        assert!(
            matches!(cmd.peer, Peer::Named(_)),
            "the positional is the peer to reach"
        );
        assert_eq!(
            cmd.peer_hint.len(),
            1,
            "the --peer address hint parses under its own id alongside the positional peer"
        );
    }

    #[test]
    fn shell_quote_wraps_and_escapes() {
        assert_eq!(shell_quote("/opt/bin/swoosh"), "'/opt/bin/swoosh'");
        // A path with a space stays one shell word so ssh's whitespace split does not break it.
        assert_eq!(shell_quote("/My Apps/swoosh"), "'/My Apps/swoosh'");
        // A literal single quote breaks out and back in, keeping the whole path one word.
        assert_eq!(shell_quote("/a'b/swoosh"), r"'/a'\''b/swoosh'");
    }
}
