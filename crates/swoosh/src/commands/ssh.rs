//! `swoosh ssh <peer>`: reach a peer's sshd over the overlay, then hand the terminal to the system ssh.
//!
//! A LAUNCHER, a third verb category beside the local and reach families. Like a local verb it reads the
//! contact store (to resolve the peer to a raw key) and binds no bifrost `Node` in this process; unlike a
//! local verb it ends up reaching a peer. It does so by `exec`ing the system `ssh` with a `ProxyCommand`
//! that re-invokes THIS binary (`<self> tunnel-connect <key> --service <name> --stdio`, via
//! `current_exe()`, see [`self_invocation`]) and that hidden re-invocation binds the `Node` under
//! swoosh's OWN identity and pipes the overlay stream over ssh's stdin/stdout, so ssh talks to the far
//! sshd as if it were local. One binary, no `tightbeam` on PATH and no `$PATH` lookup at all, and the dial
//! carries swoosh's key, so a membership badge presented there binds to the identity the family gate
//! proves. `swoosh ssh alice` is a drop-in for `ssh <host>`.
//!
//! The peer resolves in-process, BEFORE ssh runs, through the same `Target`/contact-store lookup
//! `ping`/`speed` use, so `alice/desk` is fine here (ssh never sees the `/`; it sees only the resolved
//! key in the `ProxyCommand` and a stable placeholder host). Everything after `--` is forwarded to ssh
//! verbatim (a remote command, `-p`, `-i`), so swoosh interprets nothing the user means for ssh.
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

use crate::contacts::{Contacts, Target};

/// The exposed service name reached when the user names none: a host's sshd under the default label.
const DEFAULT_SERVICE: &str = "ssh";

/// The system binary a launch shells out to: the far sshd is reached by the system `SSH`, whose overlay
/// transport is THIS binary re-invoked as its `ProxyCommand` (see [`self_invocation`]): no separate
/// `tightbeam` binary. Named as a constant so a "not found on PATH" error can point at the exact binary.
const SSH: &str = "ssh";

/// Reach a peer's sshd over the overlay; runs the system ssh.
#[derive(Debug, Args)]
pub struct SshCmd {
    /// The peer to reach: a saved petname (`alice`, `alice/desk`) or a raw bifrost node id.
    #[arg(value_name = "peer")]
    pub peer: Target,
    /// The exposed service name to reach on the host.
    #[arg(long, value_name = "service", default_value = DEFAULT_SERVICE)]
    pub service: String,
    /// Present a `sheer:` capability link to a cap-gated host (e.g. an ssh slip minted with `swoosh grant
    /// issue`). Without it, the tunnel-connect bridge self-signs a membership badge from swoosh's key.
    #[arg(long, value_name = "link")]
    pub present: Option<String>,
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
    pub fn run(self, contacts: &Contacts) -> eyre::Result<()> {
        // Resolve in-process, before ssh sees anything: take the first device for a bare petname (as
        // `speed` does), the exact one for `alice/desk`, and pass a raw key straight through. The peer as
        // typed is kept for the placeholder host, so known_hosts stays stable per peer.
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
        let argv = ssh_argv(
            &proxy,
            &key,
            &self.service,
            self.present.as_deref(),
            &host,
            &known_hosts,
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
/// link, the placeholder `host`, the private `known_hosts` path, and the user's trailing ssh `args`, it
/// assembles the exact argv [`exec_ssh`] hands to `ssh`. The `ProxyCommand` value is `<self>
/// tunnel-connect <key> --service <name> --stdio [--present <link>]`: ssh runs it to bridge the overlay
/// stream in-process, under swoosh's own identity, with no `tightbeam` binary and no `$PATH` lookup. ssh
/// splits `ProxyCommand` on whitespace, so `proxy` is pre-quoted and the other tokens are whitespace-free
/// (a `NodeId` is base32, the service is a single name, a `sheer:` link is one token like a key).
///
/// The four host-key options (see the module docs) come BEFORE the passthrough args: ssh honors the first
/// occurrence of an option, so swoosh's intent wins over a user's trailing `-o`. `HostKeyAlias` keys the
/// pin on the node id, not the mutable placeholder host; the `UserKnownHostsFile` path is double-quoted so
/// an install dir with a space stays one filename to ssh.
fn ssh_argv(
    proxy: &str,
    key: &str,
    service: &str,
    present: Option<&str>,
    host: &str,
    known_hosts: &Path,
    args: &[String],
) -> Vec<String> {
    let mut proxy_command = format!("{proxy} tunnel-connect {key} --service {service} --stdio");
    // A `sheer:` link is whitespace-free (a single token, like the key), so it is safe unquoted in the
    // whitespace-split ProxyCommand. Appended only when present; without it the bridge self-signs a badge.
    if let Some(link) = present {
        proxy_command.push_str(&format!(" --present {link}"));
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

    #[test]
    fn argv_wires_the_proxy_then_pinning_options_then_host() {
        let argv = ssh_argv(PROXY, KEY, "ssh", None, "alice/desk", &known_hosts(), &[]);
        assert_eq!(
            argv,
            vec![
                "-o".to_owned(),
                format!("ProxyCommand={PROXY} tunnel-connect {KEY} --service ssh --stdio"),
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
    fn argv_pins_on_the_node_id_not_the_placeholder_host() {
        // The known_hosts pin is keyed on the node id via HostKeyAlias, so a petname rename never orphans
        // it. The placeholder host is the mutable petname; the alias is the immutable key.
        let argv = ssh_argv(PROXY, KEY, "ssh", None, "alice/desk", &known_hosts(), &[]);
        assert!(argv.contains(&format!("HostKeyAlias={KEY}")));
        assert!(argv.contains(&"StrictHostKeyChecking=accept-new".to_owned()));
        assert!(argv.contains(&"GlobalKnownHostsFile=/dev/null".to_owned()));
    }

    #[test]
    fn argv_forwards_passthrough_args_after_the_host() {
        let args = vec!["-p".to_owned(), "2222".to_owned(), "ls".to_owned()];
        let argv = ssh_argv(PROXY, KEY, "ssh", None, "bob", &known_hosts(), &args);
        // The passthrough args land last, after the host and after swoosh's own options, so swoosh's
        // host-key options (ssh honors the first occurrence) win over any the user trails.
        let host_at = argv.iter().position(|a| a == "bob").expect("host present");
        assert_eq!(&argv[host_at + 1..], &["-p", "2222", "ls"]);
        assert!(argv[..host_at].contains(&"StrictHostKeyChecking=accept-new".to_owned()));
    }

    #[test]
    fn argv_honors_a_non_default_service() {
        let argv = ssh_argv(PROXY, KEY, "admin-ssh", None, "alice", &known_hosts(), &[]);
        assert_eq!(
            argv[1],
            format!("ProxyCommand={PROXY} tunnel-connect {KEY} --service admin-ssh --stdio")
        );
    }

    #[test]
    fn argv_appends_a_present_link_to_the_proxy_command() {
        // A `sheer:` link (whitespace-free, like the key) rides unquoted in the whitespace-split
        // ProxyCommand, after `--stdio`, so the bridge presents the given slip instead of self-signing.
        let link = "sheer:abcdef0123456789";
        let argv = ssh_argv(PROXY, KEY, "ssh", Some(link), "alice", &known_hosts(), &[]);
        assert_eq!(
            argv[1],
            format!(
                "ProxyCommand={PROXY} tunnel-connect {KEY} --service ssh --stdio --present {link}"
            )
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
