//! Unit tests for `serve`'s stop classification and banner: a GRACEFUL stop is a typed [`Stopped`] the run
//! reports and exits 0 on, and an ERRORED teardown never becomes one (it stays an `Err` the run propagates,
//! so the process exits non-zero). The end-to-end proof that a member's `control.serve` stop makes the exposer
//! return `Ok` (which the run turns into [`Stopped::Requested`], exit 0) lives in `tests/gated_stop.rs`.
//!
//! What only the real composition root can prove is driven by spawning the compiled `swoosh` binary: one
//! `serve` per home, the resumed list, the runtime directory, and that a `serve` stays the foreground
//! process.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use bifrost_mdns::{At, Dialable, Missing};
use clap::CommandFactory as _;
use swoosh::home::{Home, HomeWrite, ServeLock};
use swoosh::reach;
use swoosh::serve::control_codec::{ControlError, Request, Response};
use swoosh::serve::{
    CONTROL_SERVE_SERVICE, DEFAULT_SERVICES, Internet, Lan, Picks, ProxyScope, ProxyService,
    Reachable, SYNC_SERVICE, Stopped, bind_entry, control, extract_recv_services,
};
use swoosh::transport::{MdnsState, Reach, RelayHome, Resolver};
use swoosh::unbound::Unbound;
use tightbeam::duration::Lifetime;
use tightbeam::tunnel::{
    CancellationToken, ManifestEntry, Metering, Posture, RawSource, Router, TargetKind,
};

use super::{
    Keeper, ReachRows, Scope, Serving, banner, expire, keeper_line, log_bind, off_lines,
    supervised, waiting_warnings,
};

#[path = "serve_relative_tests.rs"]
mod relative_tests;

/// A service name for a test-built router overlay.
fn svc(name: &str) -> nauthy::Service {
    name.parse().expect("a valid service name")
}

/// A gated handler/forward entry for a banner test (the common case: everything behind the family gate). A
/// handler or a forward carries no raw source to warn about.
fn entry_gated(name: &str, kind: TargetKind, metering: Option<Metering>) -> ManifestEntry {
    ManifestEntry {
        name: name.to_owned(),
        posture: Posture::Gated,
        kind,
        metering,
        raw_source: None,
    }
}

/// An opened (public) handler/forward entry for a banner test.
fn entry_open(name: &str, kind: TargetKind, metering: Option<Metering>) -> ManifestEntry {
    ManifestEntry {
        name: name.to_owned(),
        posture: Posture::Open,
        kind,
        metering,
        raw_source: None,
    }
}

/// The default `swoosh serve` manifest (gated ping + speed + the node's own `control.*` routes), name-sorted as the
/// exposer returns it, so a banner test exercises the same shape the product path builds. The default
/// diagnostic routes are family-gated, so they bind the OWNER engines and report unmetered.
fn default_manifest() -> Vec<ManifestEntry> {
    vec![
        entry_gated(
            "control.serve",
            TargetKind::Handler,
            Some(Metering::Unmetered),
        ),
        entry_gated(
            "control.sync",
            TargetKind::Handler,
            Some(Metering::Unmetered),
        ),
        entry_gated("ping", TargetKind::Handler, Some(Metering::Unmetered)),
        entry_gated("speed", TargetKind::Handler, Some(Metering::Unmetered)),
    ]
}

/// `control.serve`, bound through the same `bind_serve` every serve calls, after the routes `router` holds.
fn serve_route(router: Router) -> Router {
    let root = swoosh::testkit::TestRoot::seeded(7).node_id();
    let own = swoosh::testkit::TestNode::seeded(8).node_id();
    // The callers are plain tests, so the cut is built on a runtime of its own.
    let (_gate, cut, home) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(swoosh::testkit::admitting(root, own));
    let (router, _catalog, _first_round) = control::bind_serve(
        router,
        CancellationToken::new(),
        std::sync::Arc::default(),
        &cut,
    )
    .expect("control.serve binds");
    let _ = std::fs::remove_dir_all(home.dir());
    router
}

/// The update route every serve binds, over a home with no update: what a machine with none yet
/// answers from.
fn update_route(router: Router) -> Router {
    let home = swoosh::home::Home::resolve(Some(
        std::env::temp_dir().join(format!("swoosh-no-update-{}", std::process::id())),
    ))
    .expect("a home");
    router
        .member_service(
            SYNC_SERVICE.parse().expect("a name"),
            control::Sync::new(home),
        )
        .expect("the update route binds")
}

/// The `serving` block as a pipe reads it.
fn serving_block(
    started: &swoosh::serve::Started,
    saved: Option<&swoosh::serve::Started>,
    manifest: &[ManifestEntry],
) -> eyre::Result<String> {
    let mut out = Vec::new();
    crate::screen::Screen::default()
        .block(Serving::of(started, saved, manifest).block())
        .write(&mut out)?;
    Ok(String::from_utf8(out)?)
}

/// The banner for key `ed01exampleid` on a host with [`LAN`] and [`LOOPBACK`], stopped by ctrl-c, as a
/// pipe reads it.
fn render_banner(serving: &Serving<'_>, keeper: Option<&str>) -> String {
    let reach = ReachRows::of(
        &reachable(Internet::On, Lan::Announced, host(&[LAN, LOOPBACK])),
        Scope::Banner,
    );
    let mut out = Vec::new();
    banner(
        "swoosh is serving",
        "ed01exampleid",
        &reach,
        serving,
        keeper,
        "ctrl-c to stop",
    )
    .write(&mut out)
    .unwrap();
    String::from_utf8(out).unwrap()
}

/// An address on this network, the reach fixtures' port throughout.
const LAN: &str = "192.168.1.20:51006";
/// The loopback address a wildcard bind answers on.
const LOOPBACK: &str = "127.0.0.1:51006";
/// A globally routable address, in the documentation range.
const PUBLIC: &str = "[2001:db8:85a3::8a2e:370:7334]:51006";
/// An address on a point-to-point link.
const TUNNEL: &str = "100.101.102.103:51006";
/// The widest address a row can hold: a v6 with no group to compress and a five-digit port, 47 columns.
const WIDEST_LAN: &str = "[2605:59c1:18c2:df08:1cc1:8f16:193c:5912]:65535";

/// One entry of a host's expansion, its class read off the address: loopback, a CGNAT tunnel, a
/// private network address, else the internet.
fn entry(socket: &str) -> At {
    let socket: core::net::SocketAddr = socket.parse().expect("a fixture socket");
    let scope = match socket.ip() {
        ip if ip.is_loopback() => bifrost_mdns::Scope::ThisMachine,
        core::net::IpAddr::V4(v4) if v4.octets()[0] == 100 => bifrost_mdns::Scope::Tunnel {
            link: "utun4".to_owned(),
        },
        core::net::IpAddr::V4(v4) if v4.is_private() => bifrost_mdns::Scope::Network,
        core::net::IpAddr::V6(v6) if v6.segments()[0] == 0x2605 => bifrost_mdns::Scope::Network,
        _ => bifrost_mdns::Scope::Internet,
    };
    At { socket, scope }
}

/// A host whose interfaces read, answering at `sockets`.
fn host(sockets: &[&str]) -> Dialable {
    sockets.iter().copied().map(entry).collect()
}

/// A host whose interfaces could not be read, answering at only `sockets`.
fn unread(sockets: &[&str]) -> Dialable {
    Dialable::short(
        sockets.iter().copied().map(entry),
        Missing::Interfaces(io::Error::other("getifaddrs: denied")),
    )
}

/// What a running serve answers about a bind on `host`.
fn reachable(internet: Internet, lan: Lan, host: Dialable) -> Reachable {
    Reachable {
        internet,
        lan,
        at: Picks::of(&host),
    }
}

/// The `reach` block for `reach` under `scope`, written through the screen as a pipe reads it, so the
/// screen law holds every line of it.
fn reach_block(reach: &Reachable, scope: Scope) -> String {
    let mut out = Vec::new();
    crate::screen::Screen::default()
        .block(ReachRows::of(reach, scope).block("reach"))
        .write(&mut out)
        .expect("a Vec takes the block");
    String::from_utf8(out).expect("the block is UTF-8")
}

/// Every reach state the banner can show, named: how the internet and this network read, and the host.
fn reach_fixtures() -> Vec<(&'static str, Reachable)> {
    let every = || host(&[LOOPBACK, TUNNEL, PUBLIC, LAN]);
    vec![
        (
            "default, announced",
            reachable(Internet::On, Lan::Announced, every()),
        ),
        (
            "default, by address only",
            reachable(Internet::On, Lan::ByAddressOnly, every()),
        ),
        (
            "default, offline",
            reachable(Internet::On, Lan::Announced, host(&[LOOPBACK])),
        ),
        (
            "default, unread",
            reachable(Internet::On, Lan::Announced, unread(&[LOOPBACK])),
        ),
        (
            "default, public and tunnel with no network",
            reachable(
                Internet::On,
                Lan::Announced,
                host(&[LOOPBACK, TUNNEL, PUBLIC]),
            ),
        ),
        (
            "--local, every class",
            reachable(Internet::Off, Lan::Announced, every()),
        ),
        (
            "--local, loopback only",
            reachable(Internet::Off, Lan::ByAddressOnly, host(&[LOOPBACK])),
        ),
        (
            "--local, unread beside a public address",
            reachable(
                Internet::Off,
                Lan::ByAddressOnly,
                unread(&[PUBLIC, LOOPBACK]),
            ),
        ),
        (
            "--local, a named bind with no loopback",
            reachable(Internet::Off, Lan::Announced, host(&[PUBLIC])),
        ),
        (
            "--local, the widest address, by address only",
            reachable(
                Internet::Off,
                Lan::ByAddressOnly,
                host(&[WIDEST_LAN, LOOPBACK]),
            ),
        ),
    ]
}

/// The `reach` block reads as ruled: `internet`, then by default only the address on this network, or
/// the loopback address when there is none. A public or tunnel address never shows by default, since a
/// banner is pasted into logs and issues; under `--local` every class shows, one row each. A host that
/// could not read its addresses reads `unknown`, never offline, never by address only, and with no
/// loopback row beside it.
#[test]
fn the_reach_block_reads_as_ruled() {
    let want = [
        "reach\n  internet       on\n  this network   192.168.1.20:51006\n",
        "reach\n  internet       on\n  this network   192.168.1.20:51006, by address only\n",
        "reach\n  internet       on\n  this computer  127.0.0.1:51006\n",
        "reach\n  internet       on\n  this network   unknown\n",
        "reach\n  internet       on\n  this computer  127.0.0.1:51006\n",
        "reach\n  internet       off (--local)\n  public         [2001:db8:85a3::8a2e:370:7334]:51006\n  this network   192.168.1.20:51006\n  tunnel         100.101.102.103:51006\n  this computer  127.0.0.1:51006\n",
        "reach\n  internet       off (--local)\n  this computer  127.0.0.1:51006\n",
        "reach\n  internet       off (--local)\n  public         [2001:db8:85a3::8a2e:370:7334]:51006\n  this network   unknown\n",
        "reach\n  internet       off (--local)\n  public         [2001:db8:85a3::8a2e:370:7334]:51006\n",
        // One column past 80 on one line, so the row stacks: the address and its gloss stay whole.
        "reach\n  internet       off (--local)\n  this network\n    [2605:59c1:18c2:df08:1cc1:8f16:193c:5912]:65535, by address only\n  this computer  127.0.0.1:51006\n",
    ];
    let fixtures = reach_fixtures();
    assert_eq!(fixtures.len(), want.len());
    for ((name, reach), want) in fixtures.iter().zip(want) {
        assert_eq!(reach_block(reach, Scope::Banner), want, "{name}");
    }
}

/// The banner's rows are every class's rows less the hidden ones, through one function: under `--local`
/// the banner already shows every class, so the two are the same bytes; by default, every class adds
/// only the public, tunnel and loopback rows, and the rows both show read the same.
#[test]
fn the_banner_rows_are_the_all_rows_less_the_hidden_ones() {
    for (name, reach) in reach_fixtures() {
        let banner = reach_block(&reach, Scope::Banner);
        let all = reach_block(&reach, Scope::All);
        if reach.internet == Internet::Off {
            assert_eq!(banner, all, "{name}");
            continue;
        }
        let shown: Vec<&str> = banner.lines().collect();
        let mut extra = all.lines().filter(|line| !shown.contains(line));
        assert!(
            extra.all(|line| ["  public ", "  tunnel ", "  this computer "]
                .iter()
                .any(|label| line.starts_with(label))),
            "{name}: {all}"
        );
        let both: Vec<&str> = all.lines().filter(|line| shown.contains(line)).collect();
        assert_eq!(both, shown, "{name}: the shared rows, in the same order");
    }
}

/// Every reach line holds the screen law with no exemption: each fixture, in both scopes, is written
/// through the screen, whose `write` holds every line to case, period and width under test and panics
/// on a breach; this row adds that no reach line is one the law excuses.
#[test]
fn the_reach_block_holds_the_law() {
    for (name, reach) in reach_fixtures() {
        for scope in [Scope::Banner, Scope::All] {
            let block = reach_block(&reach, scope);
            for line in block.lines() {
                assert!(
                    !crate::screen::law::OWED.contains(&line),
                    "{name}: {line:?} is excused"
                );
            }
        }
    }
}

/// A log line, captured.
struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl io::Write for LogCapture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("the capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What `log_bind` writes, at every level, for one bind.
fn bind_log(dialable: &Dialable, mdns: &MdnsState, reach: &Reach, local: bool) -> String {
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = std::sync::Arc::clone(&log);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || LogCapture(std::sync::Arc::clone(&writer)))
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        log_bind(dialable, mdns, reach, local);
    });
    String::from_utf8(log.lock().expect("the capture lock").clone()).expect("utf-8")
}

/// The bind's log carries causes and class names, never an address: no host address, no announced
/// address, and no URL of a relay or resolver the person runs. Each degraded cause still reaches it.
#[test]
fn the_bind_log_names_causes_and_no_address() {
    let own = Reach {
        relay: RelayHome::Custom("https://relay.example.net".parse().expect("a relay url")),
        resolver: Resolver::Custom("https://pkarr.example.net".parse().expect("a resolver url")),
    };
    // A public and a tunnel address, with the network class gone to expiry.
    let expiring = Dialable::short(
        [entry(PUBLIC), entry(TUNNEL), entry(LOOPBACK)],
        Missing::Expiring(
            bifrost_mdns::Expiring::of([bifrost_mdns::Scope::Network]).expect("a drop"),
        ),
    );
    let unchecked = Dialable::short([entry(PUBLIC), entry(LOOPBACK)], Missing::Flags);
    let logs = [
        bind_log(&expiring, &MdnsState::LoopbackOnly, &own, false),
        bind_log(
            &unchecked,
            &MdnsState::BrowseOnly(bifrost_mdns::MdnsError::NoAddrs),
            &own,
            false,
        ),
        bind_log(
            &host(&[PUBLIC, LAN, LOOPBACK]),
            &MdnsState::OnLan(vec![LAN.parse().expect("an address")]),
            &own,
            false,
        ),
    ];
    let all = logs.concat();
    for word in all.split(|c: char| c.is_whitespace() || c == '"' || c == ',' || c == '=') {
        let word = word.trim_matches(|c: char| c == '.' || c == ';');
        assert!(
            word.parse::<core::net::IpAddr>().is_err()
                && word.parse::<core::net::SocketAddr>().is_err(),
            "an address in the log: {word:?}\n{all}"
        );
    }
    assert!(!all.contains("example.net"), "a URL in the log:\n{all}");
    for cause in [
        "only expiring addresses reach this class",
        "class=Network",
        "mDNS on this host only",
        "could not check for expiry",
        "finding peers, not announcing you",
        "resolver=\"custom\"",
        "relay=\"custom\"",
    ] {
        assert!(all.contains(cause), "{cause:?} is logged:\n{all}");
    }
    assert!(
        !logs[2].contains("WARN"),
        "a clean bind warns nothing:\n{}",
        logs[2]
    );
}

#[test]
fn the_banner_frames_selection_actual_targets_and_how_to_stop() {
    let manifest = default_manifest();
    let serving = Serving::of(
        &swoosh::serve::Started::Default,
        Some(&swoosh::serve::Started::Default),
        &manifest,
    );
    // `reach` sits under the key, with its values in the key's column; the stop line is a block of its
    // own, a blank line under `serving`.
    assert_eq!(
        render_banner(&serving, None),
        "swoosh is serving\n\n  key            ed01exampleid\n\nreach\n  internet       on\n  this network   192.168.1.20:51006\n\nserving\n  selection  default services\n  ping       your devices  ping:\n  speed      your devices  speed:\n\nctrl-c to stop\n"
    );
}

#[test]
fn explicit_origin_is_not_inferred_from_saved_target_equality() {
    use swoosh::serve::Started;
    let entries = vec!["ping=ping:".to_owned()];
    for (started, origin) in [
        (Started::Named(entries.clone()), "this run only (not saved)"),
        // Kept saved entries are saved: a relative start is never called unsaved.
        (
            Started::Adjusted(entries.clone()),
            "saved services, adjusted for this run",
        ),
        (Started::Resumed(entries.clone()), "saved services"),
        (Started::Default, "default services"),
    ] {
        let out = serving_block(
            &started,
            Some(&Started::Resumed(started.entries())),
            &default_manifest(),
        )
        .unwrap();
        assert!(out.contains(&format!("  selection  {origin}\n")));
        assert!(!out.contains("saved for bare start"));
        assert!(!out.contains("apply to the next bare or --with/--without serve"));
    }
}

/// A home that never saved a list holds no saved services: the defaults a bare start would serve are not
/// shown as saved beside an explicit selection.
#[test]
fn an_explicit_start_on_a_fresh_home_shows_no_defaults_as_saved() {
    use swoosh::serve::Started;
    let started = Started::Named(vec!["ssh=sshd:".to_owned()]);
    let out = serving_block(&started, Some(&Started::Default), &default_manifest()).unwrap();
    assert!(!out.contains("saved for bare start"), "{out}");
    assert!(
        !out.contains("apply to the next bare or --with/--without serve"),
        "{out}"
    );
    assert!(
        out.contains("  selection  this run only (not saved)\n"),
        "{out}"
    );
}

#[test]
fn serving_rows_keep_bound_only_and_adjacent_saved_alternatives() {
    use swoosh::serve::Started;
    let started = Started::Named(vec![
        "web=tcp:bound:1".to_owned(),
        "logs=file:/bound logs".to_owned(),
    ]);
    let saved = Started::Resumed(vec!["web=tcp:saved:2".to_owned(), "ping=ping:".to_owned()]);
    let manifest = vec![entry_open("logs", TargetKind::RawStream, None)];
    let out = serving_block(&started, Some(&saved), &manifest).unwrap();
    assert_eq!(
        out,
        "serving\n  selection       this run only (not saved)\n  web             your devices          tcp:bound:1\n  web             saved for bare start  tcp:saved:2\n  logs            anyone                file:/bound logs\n  ping            saved for bare start  ping:\n  saved services  apply to the next bare or --with/--without serve\n"
    );
    let values = [
        "this run only",
        "your devices",
        "saved for bare start",
        "anyone",
        "apply to the next bare or --with/--without serve",
    ];
    let columns: Vec<_> = out
        .lines()
        .filter_map(|line| values.iter().find_map(|value| line.find(value)))
        .collect();
    assert_eq!(columns.len(), 6);
    assert!(columns.iter().all(|column| *column == 18), "{out}");
    // At a terminal `anyone` is styled as a risk, and nothing else in the block but its title.
    let mut terminal = anstream::AutoStream::always(Vec::new());
    crate::screen::Screen::default()
        .block(Serving::of(&started, Some(&saved), &manifest).block())
        .write(&mut terminal)
        .unwrap();
    let styled = String::from_utf8(terminal.into_inner()).unwrap();
    let risk = clap::builder::styling::Style::new()
        .bold()
        .fg_color(Some(clap::builder::styling::AnsiColor::Yellow.into()));
    let title = clap::builder::styling::Style::new().bold();
    assert!(
        styled.contains(&format!("{risk}anyone{risk:#}")),
        "{styled}"
    );
    let unstyled = styled
        .replacen(&format!("{title}serving{title:#}"), "serving", 1)
        .replacen(&format!("{risk}anyone{risk:#}"), "anyone", 1);
    assert_eq!(unstyled, out, "{styled}");
    let unavailable = serving_block(&started, None, &manifest).unwrap();
    assert!(!unavailable.contains("saved for bare start"));
    assert!(!unavailable.contains("saved services  apply"));
    assert!(unavailable.contains("file:/bound logs"));
}

#[test]
fn serving_rows_escape_complete_targets_and_stack_without_splitting() {
    use swoosh::serve::Started;
    for target in [
        "unix:/秘密 with spaces".to_owned(),
        format!("unix:/{} with spaces", "x".repeat(4096)),
        "unix:/a\n\r\t\u{1b}\u{202e}".to_owned(),
    ] {
        let started = Started::Named(vec![format!("a={target}"), "z=ping:".to_owned()]);
        let out = serving_block(&started, None, &default_manifest()).unwrap();
        assert!(out.contains(&format!("{}", swoosh::escape::EscapedComplete(&target))));
        assert!(!out.contains("..."));
        assert!(out.lines().all(|line| !line.ends_with(' ')));
        assert!(out.lines().filter(|line| line.len() > 80).all(
            |line| line.trim_start() == format!("{}", swoosh::escape::EscapedComplete(&target))
        ));
    }
    let empty = serving_block(
        &Started::Resumed(vec![]),
        Some(&Started::Resumed(vec![])),
        &[],
    )
    .unwrap();
    assert!(empty.contains(
        "Serving nothing.\nTo save a service for a bare start:\n  swoosh service add <service>\n"
    ));
}

/// A service saved but off says so and names the command that turns it on, each on its own line.
#[test]
fn an_off_service_names_the_command_that_turns_it_on() {
    let mut out = Vec::new();
    off_lines("web").write(&mut out).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "web is off.\nTo turn it on:\n  swoosh service on web\n"
    );
}

/// A banner that cannot be written, as to a pipe its reader closed, is an error for `serve` to exit 1 on,
/// never a panic.
#[test]
fn a_banner_on_a_closed_pipe_is_an_error() {
    use crate::commands::through_serve::tests::Unwritable;

    let manifest = default_manifest();
    let serving = Serving::of(&swoosh::serve::Started::Default, None, &manifest);
    let reach = ReachRows::of(
        &reachable(Internet::On, Lan::Announced, host(&[LOOPBACK])),
        Scope::Banner,
    );
    let written = banner(
        "swoosh is serving",
        "ed01exampleid",
        &reach,
        &serving,
        None,
        "ctrl-c to stop",
    )
    .write(&mut Unwritable);
    assert_eq!(
        written.map_err(|error| error.kind()).unwrap_err(),
        io::ErrorKind::BrokenPipe
    );
}

/// The line that says how to keep this machine serving prints only where no service manager runs it and
/// a person started it at a terminal; under systemd or launchd it would be noise in the journal.
#[test]
fn banner_names_the_service_manager_line_when_not_supervised() {
    let env = |set: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            set.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        }
    };
    let systemd =
        "to keep this machine serving after a reboot: systemctl --user enable --now swoosh";
    // Unsupervised, at a terminal: the line.
    assert_eq!(
        keeper_line(supervised(env(&[])), true, || Keeper::Systemd),
        Some(systemd)
    );
    // A Terminal session on macOS sets `XPC_SERVICE_NAME=0`: still unsupervised.
    assert_eq!(
        keeper_line(supervised(env(&[("XPC_SERVICE_NAME", "0")])), true, || {
            Keeper::Brew
        }),
        Some("to keep this machine serving after a reboot: brew services start swoosh")
    );
    // Under a service manager, or with no terminal, nothing, and the keeper is never asked.
    for set in [
        &[("INVOCATION_ID", "5f1c")][..],
        &[("JOURNAL_STREAM", "8:1234")][..],
        &[("XPC_SERVICE_NAME", "homebrew.mxcl.swoosh")][..],
    ] {
        assert_eq!(
            keeper_line(supervised(env(set)), true, || panic!("never asked")),
            None,
            "supervised by {set:?}: no line"
        );
    }
    assert_eq!(
        keeper_line(supervised(env(&[])), false, || panic!("never asked")),
        None,
        "no terminal: no line"
    );
    // The line rides the banner before how to stop.
    let manifest = default_manifest();
    let serving = Serving::of(&swoosh::serve::Started::Default, None, &manifest);
    let banner = render_banner(&serving, Some(systemd));
    assert!(
        banner.ends_with(&format!("{systemd}\nctrl-c to stop\n")),
        "{banner}"
    );
    assert_eq!(
        Keeper::Elsewhere.line(),
        "to keep this machine serving after a reboot: see docs/use-cases/run-at-login.md"
    );
}

// Binding preserves finite refusal categories instead of retaining target text.
#[test]
fn invalid_targets_have_finite_safe_errors() {
    use swoosh::serve::{DefinitionCause, DefinitionError, Operand};

    for (entry, cause, words) in [
        (
            "x=png:",
            DefinitionCause::Scheme,
            "unsupported target scheme",
        ),
        ("x=nonsense", DefinitionCause::Arity, "invalid target form"),
        ("x=tcp:nope", DefinitionCause::Endpoint, "invalid endpoint"),
    ] {
        let Err(error) = bind_entry(Router::new(gated()), entry, [0u8; 32], &[]) else {
            panic!("{entry} must refuse");
        };
        assert_eq!(
            error.downcast_ref::<DefinitionError>(),
            Some(&DefinitionError {
                operand: Operand::Positional,
                index: 1,
                cause,
            })
        );
        assert_eq!(
            format!("{error:#}"),
            format!("invalid service definition at index 1: {words}")
        );
        for source in error.chain() {
            assert!(!format!("{source} {source:?}").contains(entry));
        }
    }
}

/// [`ServedTarget::never_public`] is each engine's own ceiling, read off the engine a gated `serve` binds: the answer is
/// `true` exactly where the engine declares `Exposure = Never`, so the public proof refuses to open it, and
/// `false` where it assembles open. A raw stream opens only through `--public-unsafe`, so it answers
/// `false` and is never put to this proof. Every scheme has a case, so a new one cannot skip it.
#[test]
fn never_public_is_each_engines_own_ceiling() {
    use swoosh::serve::{Scheme, ServedTarget, bind_recv};

    let never_public = |target: &str| {
        target
            .parse::<ServedTarget>()
            .unwrap_or_else(|error| panic!("{target}: {error}"))
            .never_public()
    };

    let name: nauthy::Service = "x".parse().expect("a name");
    let opened = |router: Router| router.public([name.clone()]).expose().is_ok();
    let by_entry = |target: &str| {
        bind_entry(Router::new(gated()), &format!("x={target}"), [0u8; 32], &[])
            .unwrap_or_else(|error| panic!("x={target} binds: {error:#}"))
    };
    let mut cases: Vec<(&str, Option<Router>)> = vec![
        ("ping:", Some(by_entry("ping:"))),
        ("speed:", Some(by_entry("speed:"))),
        ("tcp:localhost:1", Some(by_entry("tcp:localhost:1"))),
        (
            "unix:/tmp/swoosh-x.sock",
            Some(by_entry("unix:/tmp/swoosh-x.sock")),
        ),
        ("echo:", Some(by_entry("echo:"))),
        (
            "recv:/tmp",
            Some(bind_recv(Router::new(gated()), name.clone(), "/tmp".into(), None).expect("recv")),
        ),
        (
            "proxy:",
            Some(
                Router::new(gated())
                    .service(name.clone(), ::fetch::Fetch)
                    .expect("proxy"),
            ),
        ),
        (
            "proxy:https://news.example",
            Some(
                Router::new(gated())
                    .service(
                        name.clone(),
                        ::fetch::ScopedFetch::new(
                            ::fetch::OriginAllowlist::parse(["https://news.example"])
                                .expect("an origin"),
                        )
                        .expect("a scoped proxy"),
                    )
                    .expect("scoped proxy"),
            ),
        ),
        ("file:/tmp/x", None),
        ("fifo:/tmp/x", None),
        ("stdin:", None),
    ];
    #[cfg(feature = "ssh")]
    cases.push(("sshd:", Some(by_entry("sshd:"))));
    #[cfg(not(feature = "ssh"))]
    cases.push(("sshd:", None));
    let covered: BTreeSet<&str> = cases
        .iter()
        .filter_map(|(target, _)| Scheme::parse(target).map(|(scheme, _)| scheme.as_str()))
        .collect();
    let every: BTreeSet<&str> = Scheme::ALL.iter().map(|scheme| scheme.as_str()).collect();
    assert_eq!(covered, every, "every scheme has a case");
    for (target, bound) in cases {
        match bound {
            Some(router) => assert_eq!(
                never_public(target),
                !opened(router),
                "{target}: never_public is the engine's own ceiling"
            ),
            None if target == "sshd:" => assert!(never_public(target), "a shell is never open"),
            None => assert!(!never_public(target), "{target}: a raw stream"),
        }
    }
}

/// THE defect the scheme-on-every-target grammar exists to kill. While a bare `host:port` was a legal
/// target, `ping=ping:80` was syntactically indistinguishable from a forward to a host named `ping`, so a
/// probe entry that missed the exact string `ping:` silently became a TCP forward instead. Every engine
/// swoosh serves takes no argument, so a tail is refused here, by name, with the rule stated.
#[test]
fn ping_with_an_argument_is_refused_rather_than_read_as_a_forward() {
    for (entry, scheme) in [("ping=ping:80", "ping"), ("speed=speed:80", "speed")] {
        let Err(error) = bind_entry(Router::new(gated()), entry, [0u8; 32], &[]) else {
            panic!("`{entry}` gives an argument to an engine that takes none and must be refused");
        };
        let message = format!("{error:#}");
        let _ = scheme;
        assert_eq!(
            message,
            "invalid service definition at index 1: invalid target form"
        );
        assert!(!message.contains(entry));
    }
    // The zero-argument spelling still binds, so the refusal is about the tail and nothing else.
    assert!(
        bind_entry(Router::new(gated()), "ping=ping:", [0u8; 32], &[]).is_ok(),
        "`ping=ping:` is the spelling that binds the probe"
    );
}

/// The exposure coupling on the product path: a diagnostic route binds the METERED engine when the operator
/// opens it (the safety caps by construction), and the OWNER engine when it stays family-gated (owner
/// limits, unbounded). The manifest is tightbeam's own read of the bound handler, so this asserts the same
/// fact the banner renders.
#[test]
fn an_open_diagnostic_binds_the_metered_engine_and_a_gated_one_the_owner_engine() {
    let speed: nauthy::Service = "speed".parse().expect("a valid service name");

    let open = bind_entry(
        Router::new(gated()),
        "speed=speed:",
        [0u8; 32],
        core::slice::from_ref(&speed),
    )
    .expect("speed binds")
    .public([speed])
    .expose()
    .expect("an open speed route assembles");
    let entry = open
        .manifest()
        .into_iter()
        .find(|entry| entry.name == "speed")
        .expect("speed is served");
    assert_eq!(
        entry.metering,
        Some(Metering::Metered),
        "an open diagnostic route binds the metered engine"
    );
    assert_eq!(entry.posture, Posture::Open);

    let gated = bind_entry(Router::new(gated()), "speed=speed:", [0u8; 32], &[])
        .expect("speed binds")
        .expose()
        .expect("a member-only speed route assembles");
    let entry = gated
        .manifest()
        .into_iter()
        .find(|entry| entry.name == "speed")
        .expect("speed is served");
    assert_eq!(
        entry.metering,
        Some(Metering::Unmetered),
        "a family diagnostic route binds the owner engine (owner limits, unbounded)"
    );
    assert_eq!(entry.posture, Posture::Gated);
}

/// The M3 wall, pinned: a public route cannot be armed with an uncapped engine. The owner engine declares
/// `Never`, so the public proof refuses it even when the name is exactly right, while the metered engine
/// (capped by construction) assembles the same route.
#[test]
fn a_public_route_cannot_arm_an_uncapped_diagnostic() {
    let ping: nauthy::Service = "ping".parse().expect("a valid service name");

    let Err(error) = Router::new(gated())
        .service(
            ping.clone(),
            tightbeam::tunnel::Serve(measure::server::Ping::new(&measure::server::Limits::owner())),
        )
        .expect("the owner engine binds")
        .public([ping.clone()])
        .expose()
    else {
        panic!("an uncapped engine must not be openable, whatever profile an assembly hands it");
    };
    assert!(
        error.to_string().contains("no legitimate public use"),
        "the public proof refuses the owner engine: {error}"
    );

    Router::new(gated())
        .service(ping.clone(), measure::server::MeteredPing::new())
        .expect("the metered engine binds")
        .public([ping])
        .expose()
        .expect("the capped engine is openable");
}

/// Every graceful-stop reason reports a distinct, non-empty line, so a CI action log (a CI teardown)
/// reads a deliberate stop as a clean end rather than a bare exit. The line names WHY the node stopped.
#[test]
fn each_graceful_stop_reason_has_a_distinct_legible_message() {
    let requested = Stopped::Requested.message();
    let interrupted = Stopped::Interrupted.message();
    let local = Stopped::Local.message();

    assert!(
        requested.contains("gracefully"),
        "an owner-requested stop reads as a graceful success: {requested:?}"
    );
    assert!(
        interrupted.contains("interrupted"),
        "a Ctrl-C reads as an interrupt: {interrupted:?}"
    );
    assert!(
        local.contains("local"),
        "a socket stop reads as a local stop: {local:?}"
    );
    assert_ne!(
        requested, interrupted,
        "the two graceful reasons print distinct lines, so a log tells them apart"
    );
    assert_ne!(requested, local, "the socket stop prints its own line");
    assert_ne!(
        interrupted, local,
        "the interrupt and the socket stop are the pair a log reader most often must tell apart"
    );
}

/// `Stopped` exists ONLY on the success path: it has an arm for each way an owner GRACEFULLY stops the
/// node (a requested `control.serve` stop or `--expires`, a socket stop, or a Ctrl-C), and NO arm for a
/// failure. A real teardown error stays an `Err` the run propagates, so a graceful stop and an
/// errored teardown are unconflatable by construction: this is why a deliberate `swoosh stop`
/// exits 0 while a crash exits non-zero.
#[test]
fn stopped_has_an_arm_only_for_graceful_reasons() {
    // A total destructuring of `Stopped`: every variant is a graceful (exit-0) reason, so adding a
    // non-graceful variant would fail to compile here, forcing the author to keep failures OFF this
    // type and on the `Err` path. The compile-time exhaustiveness is the whole check; there is
    // deliberately no runtime assertion to make.
    for reason in [Stopped::Requested, Stopped::Interrupted, Stopped::Local] {
        let (Stopped::Requested | Stopped::Interrupted | Stopped::Local) = reason;
    }
}

/// M3: a resident stop is classified from the recorded source, never from which select arm the
/// reactor completed. A socket stop renders the local line even if the exposer arm wins the poll;
/// a wire `control.serve` stop or a `--expires` (both record nothing) renders the requested line.
#[test]
fn resident_stop_classifies_from_its_source() {
    use swoosh::serve::{StopKind, classify_stop};

    assert_eq!(
        classify_stop(Some(StopKind::Socket)),
        Stopped::Local,
        "the socket stop renders as the local stop"
    );
    let wire = StopKind::Wire(swoosh::testkit::TestNode::seeded(0x0b).verify_key());
    for source in [None, Some(wire), Some(StopKind::Expires)] {
        assert_eq!(
            classify_stop(source),
            Stopped::Requested,
            "a wire or expires stop renders as requested: {source:?}"
        );
    }
    assert_eq!(
        classify_stop(Some(StopKind::Interrupted)),
        Stopped::Interrupted,
        "a recorded interrupt renders as interrupted"
    );
}

/// The route table a BARE `swoosh serve` builds, assembled from the product's own default set through
/// the product's own bind edge, plus the two node-control routes every run adds by value. Not a list
/// of names retyped here: a test that retyped them would keep passing the day the product set widened,
/// which is the one thing the caller below exists to catch.
fn bare_serve() -> BTreeSet<String> {
    let mut router = Router::new(gated());
    for entry in DEFAULT_SERVICES {
        router = bind_entry(router, entry, [0u8; 32], &[]).expect("a default entry binds");
    }
    let exposer = serve_route(update_route(router))
        .expose()
        .expect("the bare service set assembles under the family gate");
    exposer
        .manifest()
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

/// What a bare `swoosh serve` binds is EXACTLY `ping`, `speed`, `control.serve` and the member-gated
/// update route.
///
/// The narrow posture had nothing holding it, so widening it was a silent edit. The rule it holds: a
/// default service may cost a peer BANDWIDTH, and may never cost it code execution, a byte of its
/// disk, or a packet from its IP. `ping` and `speed` pass that, and the update route is read only by
/// this root's own devices; a shell, a receive sink and an egress relay each fail it, which is why a
/// client that wants one of them says so itself instead of every node paying for it by default.
///
/// An EXACT set, not a membership check: membership is exactly what a widening walks through.
#[test]
fn a_bare_serve_binds_exactly_ping_speed_the_control_routes_and_the_update_route() {
    let bound = bare_serve();

    // NEGATIVE FIRST, and the order is the point: a widening fails the equality below as well, so an
    // inversion run that stopped at the equality would report this loop as covered without ever
    // having reached it. This is the assertion that NAMES what was let in, so it runs first.
    for unbound in Unbound::all() {
        assert!(
            !bound.contains(unbound.name()),
            "a bare serve must not bind `{}`: a peer that wants to offer it types `swoosh serve {}`, \
             and typing it IS the consent",
            unbound.name(),
            swoosh::serve::entry_for(unbound.name()),
        );
    }

    // Then the whole set, so a fifth route of any name (not just the four refused above) has to be
    // defended here before it can ship.
    let expected: BTreeSet<String> = [
        reach::PING_SERVICE,
        reach::SPEED_SERVICE,
        CONTROL_SERVE_SERVICE,
        SYNC_SERVICE,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(
        bound, expected,
        "the bare set is the two diagnostics the reach verbs dial plus the node's own control surface \
         and its update route"
    );
}

/// Every defaulted service name either names something a bare `serve` binds, or is a name the client
/// itself teaches the `serve` entry for. Walked over the REAL parser, so a verb added later that
/// defaults to a third kind of name (one nobody serves and nobody explains) fails HERE rather than
/// against a stranger's zero-config node with a refusal that names nothing.
#[test]
fn every_defaulted_service_name_is_bound_by_a_bare_serve_or_teaches_its_serve_entry() {
    let mut defaults = BTreeSet::new();
    collect_service_defaults(&crate::Cli::command(), &mut defaults);

    // The walk must be able to SEE the defaults it vets: a walk that matched nothing would pass this
    // test for free, which is the shape of a test that reports a guard as covered without running it.
    for named in ["ssh", "recv", "proxy"] {
        assert!(
            defaults.contains(named),
            "the walk found no `--service` default `{named}`: either it is not looking where the \
             verbs are, or that verb's default changed and this list has to be defended and updated \
             with it. Found: {defaults:?}"
        );
    }

    let bound = bare_serve();
    for name in &defaults {
        assert!(
            bound.contains(name) || Unbound::dialed(name).is_some(),
            "`{name}` is defaulted by a verb, is not bound by a bare serve, and has no serve entry to \
             teach: the dial would fail against a fresh peer with a refusal that names nothing"
        );
    }
}

/// Collect every `--service` default the command tree carries, recursing into subcommands, so the walk
/// reads the parser the binary actually runs rather than a list of verbs kept by hand. A slot with NO
/// default (the required `reach <service>` positional, the `tunnel-connect` ABI flag) contributes
/// nothing: the rule is about what a verb dials when the user named nothing.
///
/// Takes clap's own `Command`, qualified because this file also drives `std::process::Command` to
/// spawn the real binary.
fn collect_service_defaults(cmd: &clap::Command, into: &mut BTreeSet<String>) {
    for arg in cmd.get_arguments() {
        if arg.get_id() != "service" {
            continue;
        }
        into.extend(
            arg.get_default_values()
                .iter()
                .map(|value| value.to_string_lossy().into_owned()),
        );
    }
    for sub in cmd.get_subcommands() {
        collect_service_defaults(sub, into);
    }
}

/// The control socket adds no service: it is served AFTER the route table and the manifest are cut, so
/// the exposer's manifest is the default set exactly; and the control `Request` enum can express two reads
/// and a stop, never a toggle or a revoke, so the socket can never mutate the gate. Both halves are
/// asserted: the manifest equality against the default, and the legal request set (the mutate-free
/// guarantee is compile-enforced by the closed enum).
#[test]
fn the_control_socket_adds_no_service() {
    // The route table a bare serve builds: the base ping/speed plus the member-only control.*
    // handlers, one handler value per route (the Router's bind-by-value shape). `bind_entry` binds only the
    // named routes, so `sshd` is absent here exactly as it is from the plain default set.
    let router =
        bind_entry(Router::new(gated()), "ping=ping:", [0u8; 32], &[]).expect("ping binds");
    let router = bind_entry(router, "speed=speed:", [0u8; 32], &[]).expect("speed binds");
    let router = serve_route(update_route(router));
    let exposer = router
        .expose()
        .expect("the default service set assembles under the family gate");

    assert_eq!(
        exposer.manifest(),
        default_manifest(),
        "the manifest is exactly the default set; the control socket adds no service"
    );

    // The total match forces every new socket request to be checked against the no-toggle rule.
    for request in [
        Request::Services,
        Request::Status,
        Request::Whoami,
        Request::Stop,
        Request::LocalServiceDetail,
    ] {
        match request {
            // An Open reaches a peer's service and a Path reads its connection's path; neither turns
            // one here on or off.
            Request::Services
            | Request::Status
            | Request::Whoami
            | Request::Stop
            | Request::LocalServiceDetail
            | Request::Open(_)
            | Request::Path(_) => {}
        }
    }
}

/// A `serve` for `scratch` running in the background: the child, what it printed, and its control socket.
struct Running {
    child: KillOnDrop,
    stdout: std::sync::Arc<std::sync::Mutex<String>>,
    socket: PathBuf,
}

impl Running {
    /// Start `swoosh serve <args>` under `scratch` and wait until its control socket answers.
    fn start(scratch: &ProcessScratch, args: &[&str]) -> Self {
        use std::io::Read as _;

        let home =
            Home::resolve(Some(scratch.home_dir.clone())).expect("the scratch home resolves");
        let socket = runtime_leaf(&home, &scratch.xdg).join("control.sock");
        let mut command = Command::new(swoosh_binary());
        command
            .arg("--home")
            .arg(&scratch.home_dir)
            .arg("serve")
            .args(args)
            .env("XDG_RUNTIME_DIR", &scratch.xdg)
            .env_remove("SWOOSH_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = KillOnDrop(command.spawn().expect("serve spawns"));
        let stdout = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let mut pipe = child.0.stdout.take().expect("piped stdout");
        let sink = std::sync::Arc::clone(&stdout);
        std::thread::spawn(move || {
            let mut byte = [0u8; 256];
            while let Ok(read @ 1..) = pipe.read(&mut byte) {
                sink.lock()
                    .expect("the capture lock")
                    .push_str(&String::from_utf8_lossy(&byte[..read]));
            }
        });
        let mut running = Self {
            child,
            stdout,
            socket,
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        while running.catalog().is_none() {
            if let Some(status) = running.child.0.try_wait().ok().flatten() {
                panic!("serve {args:?} exited before its socket answered: {status}");
            }
            assert!(Instant::now() < deadline, "serve {args:?} never answered");
            std::thread::sleep(Duration::from_millis(50));
        }
        running
    }

    /// The served catalog, read over the control socket: `(name, posture)` for every route but the
    /// node's own. `None` while the socket does not answer yet.
    fn catalog(&self) -> Option<Vec<(String, Posture)>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let reply = runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                control_round_trip(&self.socket, Request::Services),
            )
            .await
        });
        let Ok(Ok(Response::Catalog(menu))) = reply else {
            return None;
        };
        Some(
            menu.catalog
                .entries()
                // The node's own routes (`control.*`, `lookup.*`) are dotted; a person's services never are.
                .filter(|entry| !entry.name.contains('.'))
                .map(|entry| (entry.name.clone(), entry.posture))
                .collect(),
        )
    }

    /// The services it has off, read over the control socket; `None` when it does not answer or cannot
    /// read its own list.
    fn off(&self) -> Option<Vec<String>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let reply = runtime.block_on(control_round_trip(&self.socket, Request::Services));
        let Ok(Response::Catalog(menu)) = reply else {
            return None;
        };
        match menu.disabled {
            swoosh::serve::control_codec::DisabledList::Known(names) => Some(names),
            swoosh::serve::control_codec::DisabledList::Unknown(_) => None,
        }
    }

    /// Stop it over its socket and wait for a clean exit; what it printed.
    fn stop(mut self) -> String {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let _ = runtime.block_on(control_round_trip(&self.socket, Request::Stop));
        let status = self.child.0.wait().expect("reap serve");
        assert!(status.success(), "a stopped serve exits 0: {status}");
        std::thread::sleep(Duration::from_millis(100));
        self.stdout.lock().expect("the capture lock").clone()
    }
}

/// Run `swoosh serve <args>` under `scratch` to its end, with a deadline.
fn serve_once(scratch: &ProcessScratch, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(swoosh_binary());
    command
        .arg("--home")
        .arg(&scratch.home_dir)
        .arg("serve")
        .args(args)
        .env("XDG_RUNTIME_DIR", &scratch.xdg)
        .env_remove("SWOOSH_HOME");
    run_binary_with_deadline(&mut command, Duration::from_secs(60))
}

/// A `--with` definition that cannot be one service is refused for itself, before the running one is found:
/// the refusal reads the same whether or not a `serve` runs here.
#[test]
fn a_bad_with_definition_is_refused_before_the_running_check() {
    let scratch = ProcessScratch::new("bad-with");
    let _running = Running::start(&scratch, &["--local", "--quiet", "ping"]);
    let second = serve_once(&scratch, &["--with", "bad=ping:80"]);
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(!second.status.success(), "{stderr}");
    assert!(
        stderr.contains("invalid service definition at index 1"),
        "{stderr}"
    );
    assert!(!stderr.contains("already running"), "{stderr}");
}

/// One `serve` per home: a second one refuses, exit 1, with the running one's pid and what it serves,
/// then the one fix that fits what it asked for, in order: a flag that changes how it runs needs a stop,
/// and a service the running one does not serve is added with `service add`. A typed service it serves
/// and has on, or nothing typed, needs no fix.
#[test]
fn a_second_serve_for_one_home_refuses_and_names_the_fix() {
    let scratch = ProcessScratch::new("second");
    let running = Running::start(&scratch, &["--local", "--quiet", "ping", "speed"]);
    let pid = running.child.0.id();
    let head = format!(
        "error: swoosh serve is already running here (pid {pid})\n  It serves ping, speed.\n"
    );
    let stop = "  To change how it runs, stop it first:\n    swoosh stop\n";
    for (args, fix) in [
        (&["ping"][..], ""),
        (&["ping", "--expires", "1h"][..], stop),
        (&["--expires", "1h"][..], stop),
        (&["--local"][..], stop),
        (&["probe=echo:", "--public", "ping"][..], stop),
        (&[][..], ""),
        (
            &["probe=echo:"][..],
            "  To save services for a bare start:\n    swoosh service add probe=echo:\n",
        ),
        (
            &["probe=echo:", "web=tcp:localhost:3000", "ping"][..],
            "  To save services for a bare start:\n    swoosh service add probe=echo: web=tcp:localhost:3000\n",
        ),
    ] {
        let second = serve_once(&scratch, args);
        let stderr = String::from_utf8_lossy(&second.stderr);
        assert_eq!(
            second.status.code(),
            Some(1),
            "a second serve {args:?} refuses: {stderr}"
        );
        assert!(
            stderr.ends_with(&format!("{head}{fix}")),
            "serve {args:?} names the running one and then `{fix}`: {stderr}"
        );
    }
    assert_eq!(
        running.catalog().map(|catalog| catalog.len()),
        Some(2),
        "the running serve is untouched"
    );
    running.stop();
}

/// The refusal for `serve <args>` against a running node that serves `serves` and has `off` off.
fn refusal_against(args: &[&str], serves: &[&str], off: &[&str]) -> String {
    use clap::Parser as _;

    let mut argv = vec!["swoosh", "serve"];
    argv.extend_from_slice(args);
    let Some(crate::Command::Serve(mut cmd)) = crate::Cli::try_parse_from(argv)
        .expect("serve parses")
        .command
    else {
        panic!("serve parses to the serve verb");
    };
    let running = crate::commands::service::Running {
        serves: serves.iter().map(|&name| name.to_owned()).collect(),
        off: Some(off.iter().map(|&name| name.to_owned()).collect()),
    };
    cmd.normalize_services(std::path::Path::new("/work"))
        .expect("pure claim normalization");
    cmd.running_refusal(4121, Some(&running))
}

/// A running node that cannot say which services are off says why, and names no `service on`.
#[test]
fn serve_on_a_running_node_that_cannot_read_its_file_says_so() {
    use clap::Parser as _;

    let Some(crate::Command::Serve(cmd)) = crate::Cli::try_parse_from(["swoosh", "serve", "ssh"])
        .expect("serve parses")
        .command
    else {
        panic!("serve parses to the serve verb");
    };
    let running = crate::commands::service::Running {
        serves: vec!["ssh".to_owned()],
        off: None,
    };
    assert_eq!(
        cmd.running_refusal(4121, Some(&running)),
        "swoosh serve is already running here (pid 4121)\n  It serves ssh.\n  It cannot read its \
         serve.toml, so it refuses new connections to its services until it can."
    );
}

/// A `serve` naming a service the running node does not serve names the `service add` that lists it,
/// every new entry in one command, as typed; never "A second one needs its own".
#[test]
fn serve_on_a_running_node_names_service_add() {
    let head = "swoosh serve is already running here (pid 4121)\n  It serves ssh, ping, speed.";
    assert_eq!(
        refusal_against(&["web=tcp:localhost:3000"], &["ssh", "ping", "speed"], &[]),
        format!(
            "{head}\n  To save services for a bare start:\n    swoosh service add web=tcp:localhost:3000"
        )
    );
    assert_eq!(
        refusal_against(
            &[
                "web=tcp:localhost:3000",
                "proxy:https://news.example",
                "ssh=tcp:localhost:22"
            ],
            &["ssh", "ping", "speed"],
            &[]
        ),
        format!(
            "{head}\n  To save services for a bare start:\n    swoosh service add web=tcp:localhost:3000 proxy:https://news.example"
        )
    );
    // Nothing bound: no `It serves` line.
    assert_eq!(
        refusal_against(&["web=tcp:localhost:3000"], &[], &[]),
        "swoosh serve is already running here (pid 4121)\n  To save services for a bare start:\n    swoosh service add \
         web=tcp:localhost:3000"
    );
    assert!(
        !refusal_against(&["web=tcp:localhost:3000"], &["ssh"], &[]).contains("its own"),
        "the second-home fix is gone"
    );
}

/// A `serve` naming a service the running node serves and has off names `service on`; one it has on gets
/// no fix line.
#[test]
fn serve_svc_on_a_running_node_names_service_on() {
    let head = "swoosh serve is already running here (pid 4121)\n  It serves ssh, ping, speed.";
    assert_eq!(
        refusal_against(
            &["ssh=tcp:localhost:22"],
            &["ssh", "ping", "speed"],
            &["ssh"]
        ),
        format!("{head}\n  To turn ssh on:\n    swoosh service on ssh")
    );
    assert_eq!(
        refusal_against(&["ssh=tcp:localhost:22"], &["ssh", "ping", "speed"], &[]),
        head,
        "a name it serves and has on needs no fix"
    );
}

/// A flag that changes how the node runs comes before an off name: `service on` would leave the flag
/// unmet and the retry refused again, so the one fix is the stop.
#[test]
fn serve_with_a_flag_and_an_off_name_says_stop_first() {
    let head = "swoosh serve is already running here (pid 4121)\n  It serves ssh, web.";
    assert_eq!(
        refusal_against(
            &[
                "ssh=tcp:localhost:22",
                "web=tcp:localhost:3000",
                "--public",
                "web"
            ],
            &["ssh", "web"],
            &["ssh"]
        ),
        format!("{head}\n  To change how it runs, stop it first:\n    swoosh stop")
    );
}

/// Run `swoosh <args>` under `scratch` to its end, with a deadline: a `service` leaf beside a running
/// `serve`.
fn swoosh_once(scratch: &ProcessScratch, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(swoosh_binary());
    command
        .arg("--home")
        .arg(&scratch.home_dir)
        .args(args)
        .env("XDG_RUNTIME_DIR", &scratch.xdg)
        .env_remove("SWOOSH_HOME");
    run_binary_with_deadline(&mut command, Duration::from_secs(60))
}

/// Poll `running` until its `off` list is `want`, or panic after a bound: the gate reads `serve.toml` live,
/// so the change lands with no restart.
fn wait_for_off(running: &Running, want: &[&str]) {
    let want: Vec<String> = want.iter().map(|&name| name.to_owned()).collect();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let off = running.off();
        if off.as_ref() == Some(&want) {
            return;
        }
        assert!(Instant::now() < deadline, "off is {off:?}, never {want:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `service off` turns a started service off live: the running `serve` refuses it with no restart.
#[test]
fn service_off_turns_a_started_service_off_live() {
    let scratch = ProcessScratch::new("off-live");
    std::fs::write(
        scratch.home_dir.join("serve.toml"),
        "services = [\"web=echo:\"]\n",
    )
    .unwrap();
    let running = Running::start(&scratch, &["--local", "--quiet", "web=echo:"]);
    let off = swoosh_once(&scratch, &["service", "off", "web"]);
    assert_eq!(off.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&off.stderr),
        "Turned web off here.\n"
    );
    wait_for_off(&running, &["web"]);
    running.stop();
}

/// `service on` turns it back on live.
#[test]
fn service_on_turns_it_back_on_live() {
    let scratch = ProcessScratch::new("on-live");
    std::fs::write(
        scratch.home_dir.join("serve.toml"),
        "off = [\"web\"]\nservices = [\"web=echo:\"]\n",
    )
    .expect("web listed and off");
    let running = Running::start(&scratch, &["--local", "--quiet"]);
    wait_for_off(&running, &["web"]);
    let on = swoosh_once(&scratch, &["service", "on", "web"]);
    assert_eq!(on.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&on.stderr), "Turned web on here.\n");
    wait_for_off(&running, &[]);
    running.stop();
}

/// `on` and `off` never ask the running node: a service added after start, which the running one did not
/// bind, is turned off and on by writing the file, each exit 0 with its one line.
#[test]
fn service_on_and_off_ask_no_running_node() {
    let scratch = ProcessScratch::new("no-ask");
    let running = Running::start(&scratch, &["--local", "--quiet", "web=echo:"]);
    let added = swoosh_once(&scratch, &["service", "add", "db=tcp:localhost:1"]);
    assert_eq!(added.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&added.stderr),
        "Added db to the saved list.\n"
    );
    for (verb, line) in [
        ("off", "Turned db off here.\n"),
        ("on", "Turned db on here.\n"),
    ] {
        let out = swoosh_once(&scratch, &["service", verb, "db"]);
        assert_eq!(out.status.code(), Some(0), "{verb}");
        assert_eq!(String::from_utf8_lossy(&out.stderr), line);
    }
    running.stop();
}

/// A typed machine, a second service to `off`, and an entry with no name or no target, are usage errors:
/// exit 2, with clap's usage.
#[test]
fn service_and_serve_usage_errors_exit_2() {
    let scratch = ProcessScratch::new("usage");
    for (args, head) in [
        (
            &["service", "off", "ssh", "me/nas"][..],
            "error: swoosh service off acts only on this machine\n  To run it on nas:\n    swoosh ssh me/nas \
             -- swoosh service off ssh\n",
        ),
        (
            &["service", "off", "me/nas"][..],
            "error: swoosh service off acts only on this machine\n  To run it on nas:\n    swoosh ssh me/nas \
             -- swoosh service off <service>\n",
        ),
        (
            &["service", "off", "ssh", "web"][..],
            "error: swoosh service off takes one service\n",
        ),
        (
            &["service", "add", "db"][..],
            "error: invalid service definition at index 1: invalid target form\n",
        ),
        (
            &[
                "service",
                "add",
                "web=tcp:localhost:1",
                "web=tcp:localhost:2",
            ][..],
            "error: invalid service definition at index 2: service name already used\n",
        ),
        (
            &["serve", "--local", "tcp:localhost:3000"][..],
            "error: invalid service definition at index 1: invalid target form\n",
        ),
        (
            &["serve", "--local", "db"][..],
            "error: invalid service definition at index 1: invalid target form\n",
        ),
    ] {
        let out = swoosh_once(&scratch, args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.starts_with(head), "{args:?}: {stderr}");
        assert!(stderr.contains("Usage: swoosh "), "{args:?}: {stderr}");
    }
    assert!(
        !scratch.home_dir.join("serve.toml").exists(),
        "a usage error writes nothing"
    );
}

/// A port alone is never a service's name: `serve 3000` and `service add 3000` refuse naming the name and
/// the TCP form the port stands for, and `app=3000` the target it needs, exit 2 at every entry site and
/// before anything is bound.
#[test]
fn serve_a_bare_port_refuses_and_names_a_service_name() {
    let scratch = ProcessScratch::new("bare-port");
    for (args, head) in [
        (
            &["serve", "--local", "3000"][..],
            "error: invalid service definition at index 1: invalid target form\n",
        ),
        (
            &["service", "add", "3000"][..],
            "error: invalid service definition at index 1: invalid target form\n",
        ),
        (
            &["serve", "--local", "app=3000"][..],
            "error: invalid service definition at index 1: invalid target form\n",
        ),
        (
            &["service", "add", "app=3000"][..],
            "error: invalid service definition at index 1: invalid target form\n",
        ),
    ] {
        let out = swoosh_once(&scratch, args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.starts_with(head), "{args:?}: {stderr}");
        assert!(out.stdout.is_empty(), "{args:?}: nothing served");
    }
    assert!(
        !scratch.home_dir.join("serve.toml").exists(),
        "a usage error writes nothing"
    );
}

/// `recv:<dir>` names itself `recv`, as `proxy:<url>` names itself `proxy`, so the form a refused dial
/// teaches runs as typed; `recv:` alone does too, and saves into the inbox.
#[test]
fn recv_with_a_dir_names_itself_recv() {
    let scratch = ProcessScratch::new("recv-name");
    let out = swoosh_once(&scratch, &["service", "add", "recv:/tmp/x"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listed = std::fs::read_to_string(scratch.home_dir.join("serve.toml")).expect("the list");
    assert!(listed.contains("\"recv=recv:/tmp/x\""), "{listed}");
    assert_eq!(
        definition("recv:").expect("recv: alone parses"),
        "recv=recv:"
    );
    assert_eq!(swoosh::serve::as_typed("recv=recv:/tmp/x"), "recv:/tmp/x");
}

/// `--quiet`, set by `SWOOSH_QUIET` as the hidden flag is, withholds stdout: no banner and no key on it.
/// The same run without it prints the key there, so the empty stdout is the gate's doing.
#[test]
fn quiet_serve_prints_no_banner_and_no_activity() {
    let scratch = ProcessScratch::new("quiet");
    let run = |quiet: bool| {
        let mut command = Command::new(swoosh_binary());
        command
            .arg("--home")
            .arg(&scratch.home_dir)
            .args(["serve", "--local", "--expires", "1s", "ping"])
            .env("XDG_RUNTIME_DIR", &scratch.xdg)
            .env_remove("SWOOSH_HOME")
            .env_remove("SWOOSH_QUIET");
        if quiet {
            command.env("SWOOSH_QUIET", "1");
        }
        run_binary_with_deadline(&mut command, Duration::from_secs(60))
    };
    let loud = run(false);
    assert!(
        loud.status.success(),
        "{}",
        String::from_utf8_lossy(&loud.stderr)
    );
    let key = String::from_utf8_lossy(&loud.stdout).into_owned();
    assert!(key.contains("ed01"), "a plain serve prints its key: {key}");
    let quiet = run(true);
    assert!(
        quiet.status.success(),
        "{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
    assert!(
        quiet.stdout.is_empty(),
        "a quiet serve prints nothing on stdout: {}",
        String::from_utf8_lossy(&quiet.stdout)
    );
}

/// A list edited by hand to hold an entry that is not a service stops a bare `serve` with exit 1, as a saved
/// definition by its index and without the entry's text: nothing was typed, so it is never a usage error,
/// which a service manager would restart on forever with a usage line about a command line no one wrote.
#[test]
fn a_hand_edited_list_with_a_non_service_exits_1_as_a_saved_definition() {
    let scratch = ProcessScratch::new("not-a-service");
    for entry in ["db", "tcp:localhost:3000"] {
        std::fs::write(
            scratch.home_dir.join("serve.toml"),
            format!("services = [{entry:?}]\n"),
        )
        .expect("a hand-edited list");
        let out = serve_once(&scratch, &["--local", "--expires", "1s"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{entry}: {stderr}");
        assert!(
            stderr.contains("invalid saved service definition at index 1: invalid target form")
                && !stderr.contains(entry),
            "{entry}: {stderr}"
        );
        assert!(!stderr.contains("Usage:"), "{entry}: {stderr}");
    }
}

/// Naming any service at start makes the typed list the whole list: `ping` and `speed` are not served.
#[test]
fn naming_a_service_drops_ping_and_speed() {
    let scratch = ProcessScratch::new("named-only");
    let running = Running::start(&scratch, &["--local", "--quiet", "web=echo:"]);
    let names: Vec<String> = running
        .catalog()
        .expect("it answers")
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(names, ["web"]);
    running.stop();
}

/// A list emptied by `service rm` starts a bare `serve` that binds no service, answers its own routes (its
/// socket answers, so `stop` and `status` reach it), and says how to add one; the starter never returns.
#[test]
fn an_emptied_list_does_not_bring_the_starter_back() {
    let scratch = ProcessScratch::new("emptied");
    std::fs::write(scratch.home_dir.join("serve.toml"), "services = []\n").expect("an empty list");
    let running = Running::start(&scratch, &["--local"]);
    assert_eq!(
        running.catalog(),
        Some(Vec::new()),
        "no service, ping and speed included"
    );
    let printed = running.stop();
    assert!(
        printed.contains("Serving nothing.\nTo save a service for a bare start:\n  swoosh service add <service>\n"),
        "{printed}"
    );
}

#[test]
fn bare_serve_uses_saved_or_default_services_not_the_previous_invocation() {
    for saved in [None, Some("services = ['speed=speed:']\n")] {
        let scratch = ProcessScratch::new("invocation-then-bare");
        let file = scratch.home_dir.join("serve.toml");
        if let Some(saved) = saved {
            std::fs::write(&file, saved).unwrap();
        }
        let named = serve_once(&scratch, &["--local", "--expires", "1s", "ping"]);
        assert!(
            named.status.success(),
            "{}",
            String::from_utf8_lossy(&named.stderr)
        );
        let stdout = String::from_utf8_lossy(&named.stdout);
        let stderr = String::from_utf8_lossy(&named.stderr);
        assert!(stdout.contains("this run only (not saved)"));
        assert!(!stderr.contains("No longer serving"));
        assert!(!stderr.contains("now serves"));
        assert_eq!(std::fs::read_to_string(&file).ok().as_deref(), saved);
        let bare = Running::start(&scratch, &["--local"]);
        let expected = if saved.is_some() {
            vec![("speed".to_owned(), Posture::Gated)]
        } else {
            vec![
                ("ping".to_owned(), Posture::Gated),
                ("speed".to_owned(), Posture::Gated),
            ]
        };
        assert_eq!(bare.catalog(), Some(expected));
        let out = bare.stop();
        assert!(out.contains(if saved.is_some() {
            "selection  saved services"
        } else {
            "selection  default services"
        }));
    }
}

/// `--public`, `--public-unsafe`, `--admit` and `--expires` also apply only to this run.
#[test]
fn bare_serve_never_resumes_public() {
    let scratch = ProcessScratch::new("public");
    let first = Running::start(&scratch, &["--local", "ping", "speed", "--public", "ping"]);
    assert!(
        first
            .catalog()
            .is_some_and(|catalog| catalog.contains(&("ping".to_owned(), Posture::Open))),
        "the first run opens ping"
    );
    first.stop();

    let resumed = Running::start(&scratch, &["--local"]);
    assert_eq!(
        resumed.catalog(),
        Some(vec![
            ("ping".to_owned(), Posture::Gated),
            ("speed".to_owned(), Posture::Gated)
        ]),
        "a restart serves the same services, none of them open"
    );
    resumed.stop();
}

/// A start that fails leaves what the next bare `serve` resumes as it was.
#[test]
fn successful_and_failed_launches_leave_service_policy_unchanged() {
    let scratch = ProcessScratch::new("afterbind");
    let serving = scratch.home_dir.join("serve.toml");
    let before = "off = [\"ping\", \"unlisted\"]\nservices = [\"speed=speed:\"]\n";
    std::fs::write(&serving, before).unwrap();
    Running::start(&scratch, &["--local", "--quiet", "ping"]).stop();
    assert_eq!(std::fs::read_to_string(&serving).unwrap(), before);

    // A keyless shell cannot be opened to anyone, and a scheme nobody serves cannot bind: both refuse
    // after the list is known and before anything serves.
    for (args, code) in [
        #[cfg(feature = "ssh")]
        (&["--local", "ssh", "--public", "ssh"][..], 1),
        #[cfg(not(feature = "ssh"))]
        (&["--local", "ssh", "--public", "ssh"][..], 2),
        (&["--local", "speed", "x=png:"][..], 2),
    ] {
        let failed = serve_once(&scratch, args);
        assert_eq!(
            failed.status.code(),
            Some(code),
            "serve {args:?} refuses: {}",
            String::from_utf8_lossy(&failed.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&serving).expect("the record"),
            before,
            "a failed serve {args:?} leaves the record as it was"
        );
    }
}

/// `swoosh status` under `scratch`: every home with a key reports a serving row, including what the next
/// bare start serves when no resident answers.
fn status_serving(scratch: &ProcessScratch) -> Option<String> {
    let mut command = Command::new(swoosh_binary());
    command
        .arg("--home")
        .arg(&scratch.home_dir)
        .arg("status")
        .env("XDG_RUNTIME_DIR", &scratch.xdg)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null());
    let output = run_binary_with_deadline(&mut command, Duration::from_secs(30));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "status exits 0: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
        .lines()
        .find(|line| line.starts_with("serving:"))
        .map(str::to_owned)
}

/// A `serve` that refuses after it claimed the home leaves no control socket behind, so `status` says
/// nothing is running rather than that it could not read it.
#[test]
fn a_refused_serve_leaves_status_showing_the_next_start() {
    let scratch = ProcessScratch::new("refused");
    let home = Home::resolve(Some(scratch.home_dir.clone())).expect("the scratch home resolves");
    let socket = runtime_leaf(&home, &scratch.xdg).join("control.sock");
    for (args, code) in [
        #[cfg(feature = "ssh")]
        (&["--local", "ssh", "--public", "ssh"][..], 1),
        #[cfg(not(feature = "ssh"))]
        (&["--local", "ssh", "--public", "ssh"][..], 2),
        (&["--local", "speed", "x=png:"][..], 2),
    ] {
        let failed = serve_once(&scratch, args);
        assert_eq!(failed.status.code(), Some(code), "serve {args:?} refuses");
        assert!(!socket.exists(), "serve {args:?} leaves no socket");
        assert_eq!(
            status_serving(&scratch),
            Some("serving: ping, speed, when swoosh serve runs".to_owned()),
            "after serve {args:?}, the never-named list still starts the default"
        );
    }
}

/// A service manager stops `serve` with SIGTERM: it stops the way a ctrl-c does, and takes its socket with it.
#[test]
fn a_terminated_serve_removes_its_socket() {
    let scratch = ProcessScratch::new("sigterm");
    let mut running = Running::start(&scratch, &["--local", "--quiet", "ping"]);
    let pid = libc::pid_t::try_from(running.child.0.id()).expect("a pid");
    // SAFETY: `kill` only sends a signal to the child this test spawned and still holds.
    assert_eq!(
        unsafe { libc::kill(pid, libc::SIGTERM) },
        0,
        "SIGTERM is sent"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = running.child.0.try_wait().expect("poll serve") {
            break status;
        }
        assert!(Instant::now() < deadline, "serve exits on SIGTERM");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        status.code().is_some(),
        "serve exits on SIGTERM, not killed by it: {status}"
    );
    assert!(
        !running.socket.exists(),
        "a terminated serve removes its socket"
    );
    assert_eq!(
        status_serving(&scratch),
        Some("serving: ping, speed, when swoosh serve runs".to_owned()),
        "an explicit start leaves the next bare start at defaults"
    );
}

/// A `serve` killed outright leaves its socket file with nothing listening on it: `status` reads that as
/// nothing running.
#[test]
fn a_killed_serve_leaves_status_showing_the_next_start() {
    let scratch = ProcessScratch::new("sigkill");
    let mut running = Running::start(&scratch, &["--local", "--quiet", "ping"]);
    running.child.0.kill().expect("SIGKILL is sent");
    running.child.0.wait().expect("reap serve");
    assert!(
        running.socket.exists(),
        "a killed serve cannot remove its socket"
    );
    assert_eq!(
        status_serving(&scratch),
        Some("serving: ping, speed, when swoosh serve runs".to_owned()),
        "an explicit start leaves the next bare start at defaults"
    );
}

/// Explicit service constructors select only this invocation; they do not change saved services or
/// clear `off` names.
#[test]
fn naming_an_off_only_service_at_start_retains_every_off_name() {
    let scratch = ProcessScratch::new("new-off");
    let file = scratch.home_dir.join("serve.toml");
    std::fs::write(&file, "off = [\"web\", \"speed\"]\n").expect("two services turned off");

    let running = Running::start(&scratch, &["--local", "--quiet", "web=echo:"]);
    // The bound name leads the reported list, the other marks after it.
    assert_eq!(
        running.off().as_deref(),
        Some(&["web".to_owned(), "speed".to_owned()][..]),
        "web remains refused"
    );
    running.stop();
    assert_eq!(
        std::fs::read_to_string(&file).expect("the setting"),
        "off = [\"web\", \"speed\"]\n",
        "the complete off policy remains unchanged"
    );

    std::fs::write(&file, "off = [\"ping\"]\n").expect("ping turned off again");
    let bare = serve_once(&scratch, &["--local", "--quiet", "--expires", "1s"]);
    assert!(
        bare.status.success(),
        "{}",
        String::from_utf8_lossy(&bare.stderr)
    );
    assert!(
        String::from_utf8_lossy(&bare.stderr)
            .contains("ping is off.\nTo turn it on:\n  swoosh service on ping\n"),
        "{}",
        String::from_utf8_lossy(&bare.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&file).expect("the setting"),
        "off = [\"ping\"]\n",
        "a bare serve leaves the setting as it is"
    );
}

/// A start never widens exposure: naming a service the list already holds, turned off, leaves it off, so
/// a restart by a service manager (after any of your devices stopped it) never undoes an off typed here.
/// The default counts as listed on a home that never named a list.
#[test]
fn a_start_never_clears_off_for_a_listed_name() {
    let scratch = ProcessScratch::new("listed-off");
    let file = scratch.home_dir.join("serve.toml");
    std::fs::write(&file, "off = [\"web\"]\nservices = [\"web=echo:\"]\n")
        .expect("web listed, off");
    let running = Running::start(&scratch, &["--local", "--quiet", "web=echo:"]);
    assert_eq!(
        running.off().as_deref(),
        Some(&["web".to_owned()][..]),
        "web stays off"
    );
    running.stop();
    assert_eq!(
        std::fs::read_to_string(&file).expect("the setting"),
        "off = [\"web\"]\nservices = [\"web=echo:\"]\n",
        "the off row is kept"
    );

    // A home that never named a list holds the default: `ping` off stays off when a start names it.
    let fresh = ProcessScratch::new("default-off");
    let file = fresh.home_dir.join("serve.toml");
    std::fs::write(&file, "off = [\"ping\"]\n").expect("ping off");
    Running::start(&fresh, &["--local", "--quiet", "ping", "web=echo:"]).stop();
    assert_eq!(
        std::fs::read_to_string(&file).expect("the setting"),
        "off = [\"ping\"]\n",
        "ping stays off"
    );
}

/// A named start that keeps a listed service off says so, one block per name, before the banner that lists
/// it: the service refuses every stream, and no other line on screen says why.
#[test]
fn a_named_serve_of_an_off_name_says_it_is_off() {
    let scratch = ProcessScratch::new("named-off");
    std::fs::write(
        scratch.home_dir.join("serve.toml"),
        "off = [\"ping\", \"web\"]\nservices = [\"ping=ping:\", \"web=echo:\"]\n",
    )
    .expect("ping and web listed, both off");
    let named = serve_once(
        &scratch,
        &["--local", "--expires", "1s", "web=echo:", "ping"],
    );
    let stderr = String::from_utf8_lossy(&named.stderr);
    assert!(named.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "web is off.\nTo turn it on:\n  swoosh service on web\nping is off.\nTo turn it on:\n  \
             swoosh service on ping\n"
        ),
        "{stderr}"
    );
}

/// A built-in written by hand as its name alone (`ping`) is listed, so a named `serve ping` keeps its `off`
/// row and says it is off. Read the raw entries and `ping`, with no `=`, counts as new: the start drops the
/// row and serves it on.
#[test]
fn a_named_serve_keeps_off_for_a_hand_written_built_in() {
    let scratch = ProcessScratch::new("named-off-hand");
    std::fs::write(
        scratch.home_dir.join("serve.toml"),
        "off = [\"ping\"]\nservices = [\"ping\"]\n",
    )
    .expect("ping listed by hand, off");
    let named = serve_once(&scratch, &["--local", "--expires", "1s", "ping"]);
    let stderr = String::from_utf8_lossy(&named.stderr);
    assert!(named.status.success(), "{stderr}");
    assert!(
        stderr.contains("ping is off.\nTo turn it on:\n  swoosh service on ping\n"),
        "{stderr}"
    );
    let file = std::fs::read_to_string(scratch.home_dir.join("serve.toml")).expect("the file");
    assert!(file.contains("off = [\"ping\"]"), "{file}");
}

/// Where no private runtime directory resolves, `serve` refuses with the fix before anything is written
/// or bound: a fresh home gets no key.
#[cfg(target_os = "linux")]
#[test]
fn serve_without_a_runtime_dir_refuses_before_binding() {
    for xdg in [None, Some("run/user/1000")] {
        let scratch = ProcessScratch::new("noxdg");
        let mut command = Command::new(swoosh_binary());
        command
            .arg("--home")
            .arg(&scratch.home_dir)
            .args(["serve", "--local"])
            .env_remove("SWOOSH_HOME");
        match xdg {
            Some(value) => command.env("XDG_RUNTIME_DIR", value),
            None => command.env_remove("XDG_RUNTIME_DIR"),
        };
        let output = run_binary_with_deadline(&mut command, Duration::from_secs(30));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{xdg:?}: {stderr}");
        assert!(
            stderr.contains(
                "swoosh serve needs a private runtime directory. Set XDG_RUNTIME_DIR to a directory \
                 only you can use (for example /run/user/$(id -u)), or run it as a systemd --user \
                 service."
            ),
            "{xdg:?}: {stderr}"
        );
        assert!(
            !scratch.home_dir.join("machine").join("key").exists(),
            "{xdg:?}: nothing was made or bound"
        );
    }
}

/// `serve` never presents the root. With a root kept here, sealed, and no terminal for a passphrase prompt
/// to open, it starts and stops on its expiry: a prompt would have failed, and so would the run.
#[test]
fn serve_never_opens_root_key() {
    use std::os::unix::process::CommandExt as _;

    let scratch = ProcessScratch::new("sealed-root");
    let home = Home::resolve(Some(scratch.home_dir.clone())).expect("the scratch home resolves");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let minted = runtime.block_on(swoosh::root::Root::mint(
        &home,
        &mut swoosh::testkit::Counting::new(["a passphrase for the root"]),
    ));
    assert!(
        matches!(minted, Ok(swoosh::root::Minted::Made(_))),
        "the home keeps a sealed root: {minted:?}"
    );
    drop(minted);

    let mut command = Command::new(swoosh_binary());
    command
        .arg("--home")
        .arg(&scratch.home_dir)
        .args(["serve", "--quiet", "--expires", "1s"])
        .env("XDG_RUNTIME_DIR", &scratch.xdg)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null());
    // SAFETY: `setsid` is async-signal-safe and touches only the child's own session. The child leaves
    // the test's terminal, so `/dev/tty` opens for nothing in it.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let output = run_binary_with_deadline(&mut command, Duration::from_secs(30));
    assert!(
        output.status.success(),
        "serve runs beside a sealed root without asking for it: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `serve --local` must keep the node's address: the bind takes the PERSISTED key, so two runs report
/// the same key `status --key` prints, never a fresh key per run. Its `reach` block, with no flag, prints
/// only addresses a peer could dial, never the unspecified socket, and the loopback one under `this
/// computer`. Its network row reports the advertisement that actually happened, read off the same run's
/// stderr.
#[test]
fn serve_local_keeps_the_persisted_key_across_two_runs() {
    let scratch = ProcessScratch::new("local-key");

    // Observe the persisted key once, through the verb a user would compare against.
    let mut identity = Command::new(swoosh_binary());
    identity
        .arg("--home")
        .arg(&scratch.home_dir)
        .args(["leave", "--new-key"])
        .env("XDG_RUNTIME_DIR", &scratch.xdg)
        .env_remove("SWOOSH_HOME");
    let output = run_binary_with_deadline(&mut identity, Duration::from_secs(30));
    assert!(
        output.status.success(),
        "leave --new-key exits 0: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let key = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .expect("status --key prints the key")
        .to_owned();

    for run in 0..2 {
        let mut command = Command::new(swoosh_binary());
        command
            .arg("--home")
            .arg(&scratch.home_dir)
            .args(["serve", "--local", "--expires", "1s"])
            .env("XDG_RUNTIME_DIR", &scratch.xdg)
            // Surface the composition seam's own warning, so the test can hold the banner to the
            // discovery state the SAME run reported instead of assuming which way the box went.
            .env("RUST_LOG", "warn")
            .env_remove("SWOOSH_HOME");
        let output = run_binary_with_deadline(&mut command, Duration::from_secs(30));
        assert!(
            output.status.success(),
            "serve --local run {run} exits 0 on its expiry: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // The key fact remains the full persisted identity.
        let reported = stdout
            .lines()
            .find_map(|line| line.strip_prefix("  key            "))
            .unwrap_or_else(|| {
                panic!("serve --local run {run} prints the banner key line: {stdout}")
            });
        assert_eq!(
            reported, key,
            "serve --local run {run} reports the persisted key, not a fresh one: {stdout}"
        );
        assert!(
            !stdout.contains("[::]"),
            "the banner never hands out an unspecified wildcard hint: {stdout}"
        );
        // With no internet channel the row says so, and every class this host has shows: a wildcard
        // bind always answers on loopback, so that row is always there.
        assert!(
            stdout.contains("\nreach\n  internet       off (--local)\n"),
            "serve --local run {run} reads its internet channel off: {stdout}"
        );
        assert!(
            stdout.contains("\n  this computer  127.0.0.1:"),
            "serve --local run {run} names the address a peer on this machine dials: {stdout}"
        );
        // The network row reads what the same run's advertisement managed: a run that warned mDNS
        // could not start is reached on this network by address only.
        if stderr.contains("mDNS discovery unavailable")
            && let Some(row) = stdout
                .lines()
                .find(|line| line.starts_with("  this network   "))
                .filter(|row| !row.ends_with(" unknown"))
        {
            assert!(
                row.ends_with(", by address only"),
                "serve --local run {run} warned mDNS was unavailable: {stdout}"
            );
        }
    }
}

/// No self-daemonizing: `serve` stays the process the caller spawned. Spawn the real
/// binary, wait for its control socket, assert the status reply names the spawned pid (no
/// double-fork or re-exec), assert the spawned child is still alive, stop it through the control
/// socket, and reap a normal exit with the socket unlinked.
#[test]
fn no_self_daemonize() {
    let scratch = ProcessScratch::new("foreground");
    let home = Home::resolve(Some(scratch.home_dir.clone())).expect("the scratch home resolves");
    let socket = runtime_leaf(&home, &scratch.xdg).join("control.sock");

    let mut command = Command::new(swoosh_binary());
    command
        .arg("--home")
        .arg(&scratch.home_dir)
        .args(["serve", "--local", "--quiet"])
        .env("XDG_RUNTIME_DIR", &scratch.xdg)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = KillOnDrop(command.spawn().expect("the resident serve spawns"));
    let pid = child.0.id();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a control-client runtime");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut stream = runtime
        .block_on(catalog_stream(&socket, deadline, || {
            if let Some(status) = child.0.try_wait()? {
                return Err(io::Error::other(format!(
                    "the resident exited before accepting its socket: {status}"
                )));
            }
            Ok(())
        }))
        .expect("the resident control listener becomes reachable");
    let reply = runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(10), async {
                Request::Status
                    .write(&mut stream)
                    .await
                    .map_err(ControlError::Io)?;
                Response::read(&mut stream).await
            })
            .await
        })
        .expect("the status round-trip is bounded")
        .expect("the status round-trip answers");
    let Response::Status(status) = reply else {
        panic!("a Status request answers a Status reply");
    };
    assert_eq!(
        status.pid, pid,
        "the spawned pid IS the serving pid: no double-fork or re-exec"
    );
    assert_eq!(
        status.reach.internet,
        swoosh::serve::Internet::Off,
        "a `--local` bind says so in its reach"
    );
    assert!(
        status
            .reach
            .at
            .computer()
            .is_some_and(|socket| socket.ip().is_loopback()),
        "a wildcard bind answers on loopback, and the reply names it: {:?}",
        status.reach
    );
    assert!(
        child.0.try_wait().expect("poll the resident").is_none(),
        "the resident stays the foreground child the caller spawned"
    );

    let ack = runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                control_round_trip(&socket, Request::Stop),
            )
            .await
        })
        .expect("the stop round-trip is bounded")
        .expect("the stop round-trip answers");
    assert!(matches!(ack, Response::Ack), "the socket stop is acked");
    let status = child.0.wait().expect("reap the resident");
    assert!(status.success(), "a socket stop exits 0: {status}");
    assert!(!socket.exists(), "the released socket is unlinked");
}

/// The update route is bound on every `serve`, whatever the standing and with no entry naming it: the
/// real binary serves a home as `Unpinned`, as a `Device`, and as a damaged home, and each run's catalog,
/// read over the control socket, carries it.
#[test]
fn a_bare_serve_serves_the_update_route() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let device = swoosh::testkit::TestNode::seeded(0x5d);
    let root = swoosh::testkit::TestRoot::seeded(0x5e);
    for standing in ["unpinned", "device", "damaged"] {
        let scratch = ProcessScratch::new(standing);
        let home =
            Home::resolve(Some(scratch.home_dir.clone())).expect("the scratch home resolves");
        runtime.block_on(async {
            swoosh::identity::write(&device.seed(), &home)
                .await
                .expect("this machine's key");
            match standing {
                "device" => {
                    swoosh::config::write_signet(&swoosh::testkit::lock(), &home, root.node_id())
                        .expect("the pin");
                    let badge = root
                        .device_badge(
                            device.node_id(),
                            nauthy::Request::expires_in(Duration::from_secs(3600)),
                        )
                        .expect("a badge");
                    swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &badge)
                        .expect("the badge");
                }
                // A pin naming this machine's own key, as a home from before roots had their own keys.
                "damaged" => {
                    swoosh::config::write_signet(&swoosh::testkit::lock(), &home, device.node_id())
                        .expect("the pin")
                }
                _ => {}
            }
        });
        let socket = runtime_leaf(&home, &scratch.xdg).join("control.sock");
        let mut command = Command::new(swoosh_binary());
        command
            .arg("--home")
            .arg(&scratch.home_dir)
            .args(["serve", "--local", "--quiet"])
            .env("XDG_RUNTIME_DIR", &scratch.xdg)
            .env_remove("SWOOSH_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = KillOnDrop(command.spawn().expect("the resident serve spawns"));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let stream = runtime
            .block_on(catalog_stream(&socket, deadline, || {
                if let Some(status) = child.0.try_wait()? {
                    return Err(io::Error::other(format!(
                        "the {standing} serve exited before accepting its socket: {status}"
                    )));
                }
                Ok(())
            }))
            .expect("the resident control listener becomes reachable");
        let reply = runtime
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(10), catalog_reply(stream)).await
            })
            .expect("the catalog round-trip is bounded")
            .expect("the catalog round-trip answers");
        let Response::Catalog(menu) = reply else {
            panic!("a Services request answers a catalog");
        };
        assert!(
            menu.catalog
                .entries()
                .any(|entry| entry.name == SYNC_SERVICE && entry.posture == Posture::Gated),
            "a {standing} serve binds the update route, gated"
        );
        let _ = runtime.block_on(control_round_trip(&socket, Request::Stop));
        let _ = child.0.wait();
    }
}

/// A scratch dir for the spawned-binary tests: a home, a 0700 `XDG_RUNTIME_DIR` stand-in, and one
/// owned base. Drop removes exactly the base it created.
struct ProcessScratch {
    base: PathBuf,
    home_dir: PathBuf,
    xdg: PathBuf,
}

/// Serializes scratch base names within this test process, like the other serve test fixtures.
static PROCESS_SEQ: AtomicU32 = AtomicU32::new(0);

impl ProcessScratch {
    fn new(tag: &str) -> Self {
        let short: String = tag.chars().take(8).collect();
        let seq = PROCESS_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("swp-{short}-{}-{seq}", std::process::id()));
        let home_dir = base.join("home");
        let xdg = base.join("xdg");
        std::fs::create_dir_all(&home_dir).expect("scratch home");
        std::fs::create_dir_all(&xdg).expect("scratch xdg");
        use std::os::unix::fs::PermissionsExt as _;
        // 0700 on the runtime-root stand-in: the resident chain verifier refuses a looser base.
        std::fs::set_permissions(&xdg, std::fs::Permissions::from_mode(0o700))
            .expect("the scratch xdg is 0700");
        Self {
            base,
            home_dir,
            xdg,
        }
    }
}

impl Drop for ProcessScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// The compiled `swoosh` binary beside the test targets: `target/<profile>/swoosh` is two levels up
/// from `target/<profile>/deps/<test-bin>` (the umbrella redirects the target dir; the relative shape
/// is the same). `cargo test -p swoosh` builds the bin, so the real path is present.
fn swoosh_binary() -> PathBuf {
    let test_bin = std::env::current_exe().expect("the test binary path");
    let bin = test_bin
        .parent()
        .and_then(Path::parent)
        .expect("the target profile dir")
        .join("swoosh");
    assert!(
        bin.is_file(),
        "the product binary sits beside the test targets: {}",
        bin.display()
    );
    bin
}

/// The per-home runtime leaf a spawned serve resolves for this scratch: on Linux `<xdg>/swoosh/<key>`
/// mirrors `runtime_root()`; on macOS the root ignores `XDG_RUNTIME_DIR` and comes from confstr, so
/// read it from the same `runtime_root()` helper the binary uses.
fn runtime_leaf(home: &Home, xdg: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let _ = xdg;
        home.runtime_dir()
            .expect("the per-user runtime root resolves")
    }
    #[cfg(not(target_os = "macos"))]
    {
        home.runtime_leaf(&xdg.join("swoosh"))
    }
}

/// A spawned child killed and reaped on drop, so a panicking test never orphans it. Skips the kill
/// once the child is already reaped: a recycled pid must never be signaled.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Run a prepared command to completion under a deadline, killing only the exact spawned pid on
/// timeout so a hung serve can never leak. Captures stdout/stderr after exit.
fn run_binary_with_deadline(command: &mut Command, deadline: Duration) -> std::process::Output {
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the product binary");
    let mut child = KillOnDrop(child);
    let started = Instant::now();
    loop {
        if let Some(status) = child.0.try_wait().expect("poll the product binary") {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            if let Some(mut out) = child.0.stdout.take() {
                std::io::copy(&mut out, &mut stdout).expect("read the child stdout");
            }
            if let Some(mut err) = child.0.stderr.take() {
                std::io::copy(&mut err, &mut stderr).expect("read the child stderr");
            }
            return std::process::Output {
                status,
                stdout,
                stderr,
            };
        }
        assert!(
            started.elapsed() < deadline,
            "the product binary did not exit within {deadline:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Startup acquisition ends at one successful connect; protocol exchange is never retried.
async fn catalog_stream(
    socket: &Path,
    deadline: tokio::time::Instant,
    mut alive: impl FnMut() -> io::Result<()>,
) -> io::Result<tokio::net::UnixStream> {
    // The deadline bounds pending connects and the retry cadence, not just completed refusals.
    tokio::time::timeout_at(deadline, async {
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            alive()?;
            match tokio::net::UnixStream::connect(socket).await {
                Ok(stream) => return Ok(stream),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) => {}
                Err(error) => return Err(error),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// The acquired stream is consumed once, so an exchange cannot reacquire or reuse a failed stream.
async fn catalog_reply(mut stream: tokio::net::UnixStream) -> Result<Response, ControlError> {
    Request::Services
        .write(&mut stream)
        .await
        .map_err(ControlError::Io)?;
    Response::read(&mut stream).await
}

/// Own a filesystem socket before listen, exposing the kernel transition without a timing guess.
struct BoundCatalogSocket(std::os::fd::OwnedFd);

impl BoundCatalogSocket {
    fn bind(path: &Path) -> Self {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::ffi::OsStrExt as _;

        // SAFETY: sockaddr_un is plain C integer/byte data; zero initializes its padding and the
        // pathname terminator. The family and pathname are filled before the kernel reads it.
        let mut address: libc::sockaddr_un = unsafe { core::mem::zeroed() };
        let bytes = path.as_os_str().as_bytes();
        assert!(bytes.len() < address.sun_path.len());
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as libc::c_char;
        }
        // Only the pathname and its terminator belong in the address length. Including trailing
        // padding makes peer_addr report a different path, invalidating reconnect observations.
        let length = (core::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1)
            as libc::socklen_t;
        #[cfg(target_os = "macos")]
        {
            address.sun_len = length as u8;
        }
        // Linux sets close-on-exec during creation. Other platforms use checked immediate fcntl
        // after ownership acquisition; that creation-to-fcntl window is not atomic with exec.
        #[cfg(target_os = "linux")]
        let kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let kind = libc::SOCK_STREAM;
        // SAFETY: socket takes no pointers and returns a fresh descriptor or -1.
        let raw = unsafe { libc::socket(libc::AF_UNIX, kind, 0) };
        assert!(raw >= 0, "create the owned AF_UNIX socket");
        // SAFETY: raw is a fresh descriptor with no other owner; OwnedFd closes it on every exit.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        #[cfg(not(target_os = "linux"))]
        {
            // SAFETY: fd is owned and live; F_GETFD reads flags without any pointer argument.
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0, "read new fixture descriptor flags");
            // SAFETY: F_SETFD updates this owned descriptor's flags, preserving every existing bit.
            let set =
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) };
            assert_eq!(set, 0, "set close-on-exec on the owned fixture descriptor");
        }
        // SAFETY: fd is owned and address is fully initialized; length covers exactly that object.
        let bound =
            unsafe { libc::bind(fd.as_raw_fd(), core::ptr::addr_of!(address).cast(), length) };
        assert_eq!(
            bound,
            0,
            "bind without listening: {}",
            io::Error::last_os_error()
        );
        Self(fd)
    }

    fn listen(self) -> tokio::net::UnixListener {
        use std::os::fd::AsRawFd as _;

        // SAFETY: this same owned descriptor is already bound as AF_UNIX/SOCK_STREAM, not listening.
        assert_eq!(unsafe { libc::listen(self.0.as_raw_fd(), 1) }, 0);
        let listener = std::os::unix::net::UnixListener::from(self.0);
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        tokio::net::UnixListener::from_std(listener).expect("register the owned listener")
    }
}

#[test]
fn catalog_raw_socket_is_close_on_exec() {
    use std::os::fd::AsRawFd as _;

    let scratch = ProcessScratch::new("cat-flag");
    let bound = BoundCatalogSocket::bind(&scratch.base.join("control.sock"));
    // SAFETY: the descriptor is owned and live; F_GETFD reads flags and takes no pointer argument.
    let flags = unsafe { libc::fcntl(bound.0.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0, "read the owned fixture descriptor flags");
    assert_ne!(
        flags & libc::FD_CLOEXEC,
        0,
        "the raw fixture socket is close-on-exec"
    );
}

#[test]
fn catalog_raw_socket_does_not_survive_exec() {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    let scratch = ProcessScratch::new("cat-exec");
    let path = scratch.base.join("control.sock");
    let bound = BoundCatalogSocket::bind(&path);
    let metadata = std::fs::File::from(bound.0.try_clone().unwrap())
        .metadata()
        .unwrap();
    assert!(metadata.file_type().is_socket());
    // macOS dev_t is signed 32-bit; compare its bit pattern across Rust/Python representations.
    #[cfg(target_os = "macos")]
    let device_mask = u64::from(u32::MAX);
    #[cfg(not(target_os = "macos"))]
    let device_mask = u64::MAX;
    const PROBE: &str = r#"
import errno
import os
import socket
import stat
import sys
fd, device, inode, mask = map(int, sys.argv[1:5])
try:
    metadata = os.fstat(fd)
except OSError as error:
    if error.errno == errno.EBADF:
        sys.exit(0)
    raise
# An exec can reuse the number. Only the held socket's identity, type and pathname mean inheritance.
identity = stat.S_ISSOCK(metadata.st_mode) and (metadata.st_dev & mask) == device and metadata.st_ino == inode
inherited = identity and socket.socket(fileno=fd).getsockname() == sys.argv[5]
sys.exit(1 if inherited else 0)
"#;
    let status = Command::new("python3")
        .args(["-I", "-c", PROBE])
        .arg(bound.0.as_raw_fd().to_string())
        .arg((metadata.dev() & device_mask).to_string())
        .arg(metadata.ino().to_string())
        .arg(device_mask.to_string())
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn and reap only the owned exec probe");
    assert_eq!(
        status.code(),
        Some(0),
        "exec must not inherit the owned raw socket identity"
    );
    drop(bound);
}

#[tokio::test]
async fn catalog_acquisition_waits_for_listen_not_a_socket_path() {
    use futures::FutureExt as _;

    let scratch = ProcessScratch::new("cat-wait");
    let socket = scratch.base.join("control.sock");
    let bound = BoundCatalogSocket::bind(&socket);
    assert!(socket.exists(), "the raw bind made the pathname visible");
    let refused = tokio::net::UnixStream::connect(&socket).await.unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
    let acquisition = catalog_stream(
        &socket,
        tokio::time::Instant::now() + Duration::from_secs(30),
        || Ok(()),
    );
    tokio::pin!(acquisition);
    assert!(
        acquisition.as_mut().now_or_never().is_none(),
        "path existence must not complete readiness before listen"
    );
    // This is the barrier: no descriptor listens until refusal and incomplete readiness are proven.
    let listener = bound.listen();
    let stream = acquisition
        .await
        .expect("the same bound descriptor now listens");
    assert_eq!(
        stream.peer_addr().unwrap().as_pathname(),
        Some(socket.as_path()),
        "the acquired peer pathname has no padding"
    );
    let server = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.expect("accept acquired stream");
        assert!(matches!(
            Request::read(&mut peer).await.unwrap(),
            Request::Services
        ));
        Response::Ack.write(&mut peer).await.unwrap();
    });
    assert!(matches!(catalog_reply(stream).await, Ok(Response::Ack)));
    server.await.unwrap();
}

#[tokio::test]
async fn catalog_acquisition_retries_only_missing_startup_paths() {
    use futures::FutureExt as _;

    let scratch = ProcessScratch::new("cat-miss");
    let socket = scratch.base.join("control.sock");
    assert!(!socket.exists());
    let acquisition = catalog_stream(
        &socket,
        tokio::time::Instant::now() + Duration::from_secs(30),
        || Ok(()),
    );
    tokio::pin!(acquisition);
    assert!(acquisition.as_mut().now_or_never().is_none());
    let listener = BoundCatalogSocket::bind(&socket).listen();
    let stream = acquisition
        .await
        .expect("a missing path can become listening");
    let (_peer, _) = listener.accept().await.unwrap();
    drop(stream);
}

#[tokio::test(start_paused = true)]
async fn catalog_acquisition_never_listening_reaches_its_deadline() {
    let scratch = ProcessScratch::new("cat-time");
    let socket = scratch.base.join("control.sock");
    let _bound = BoundCatalogSocket::bind(&socket);
    let start = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        catalog_stream(&socket, start + Duration::from_millis(30), || Ok(())),
    )
    .await;
    assert!(
        result.is_ok(),
        "the acquisition deadline bounds permanent refusal"
    );
    assert_eq!(result.unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(
        tokio::time::Instant::now() - start,
        Duration::from_millis(30)
    );
    let listening = scratch.base.join("expired.sock");
    let _listener = BoundCatalogSocket::bind(&listening).listen();
    let checks = core::cell::Cell::new(0);
    let result = catalog_stream(&listening, tokio::time::Instant::now(), || {
        checks.set(checks.get() + 1);
        Ok(())
    })
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(
        checks.get(),
        0,
        "expired startup does no liveness or connect work"
    );
}

#[tokio::test(start_paused = true)]
async fn catalog_acquisition_keeps_child_exit_and_unexpected_errors() {
    use core::cell::Cell;

    let scratch = ProcessScratch::new("cat-exit");
    let socket = scratch.base.join("control.sock");
    let _listener = BoundCatalogSocket::bind(&socket).listen();
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn an owned exiting child");
    child.wait().expect("reap exactly the owned child");
    let start = tokio::time::Instant::now();
    let result = catalog_stream(&socket, start + Duration::from_secs(30), || {
        if child.try_wait()?.is_some() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    })
    .await;
    assert_eq!(
        result.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe,
        "an exited child fails even if its pathname is listening"
    );
    let unready = scratch.base.join("unready.sock");
    let _bound = BoundCatalogSocket::bind(&unready);
    let checks = Cell::new(0);
    let result = catalog_stream(&unready, start + Duration::from_secs(30), || {
        checks.set(checks.get() + 1);
        if checks.get() == 2 {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    })
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(checks.get(), 2, "liveness is checked again after refusal");

    let start = tokio::time::Instant::now();
    let checks = Cell::new(0);
    let too_long = scratch.base.join("x".repeat(256));
    let result = catalog_stream(&too_long, start + Duration::from_secs(30), || {
        checks.set(checks.get() + 1);
        Ok(())
    })
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    assert_eq!(
        checks.get(),
        1,
        "unexpected acquisition errors are not retried"
    );
    assert_eq!(tokio::time::Instant::now(), start);
}

#[tokio::test]
async fn catalog_connected_exchange_never_reconnects_or_repeats_requests() {
    use tokio::io::AsyncWriteExt as _;

    enum Reply {
        Eof,
        Malformed,
        Unexpected,
    }
    for reply in [Reply::Eof, Reply::Malformed, Reply::Unexpected] {
        let scratch = ProcessScratch::new("cat-once");
        let socket = scratch.base.join("control.sock");
        let listener = BoundCatalogSocket::bind(&socket).listen();
        let stream = catalog_stream(
            &socket,
            tokio::time::Instant::now() + Duration::from_secs(30),
            || Ok(()),
        )
        .await
        .unwrap();
        let unexpected = matches!(reply, Reply::Unexpected);
        let (done, completed) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            assert!(matches!(
                Request::read(&mut peer).await.unwrap(),
                Request::Services
            ));
            match reply {
                Reply::Eof => {}
                // Deliberately invalid magic, not a second implementation of the control codec.
                Reply::Malformed => peer.write_all(&[0; 4]).await.unwrap(),
                Reply::Unexpected => Response::Ack.write(&mut peer).await.unwrap(),
            }
            peer.shutdown().await.unwrap();
            // Keep the listener alive until the exchange ends, and observe reconnects while a
            // broken retry could be waiting for a second response. Completion is an explicit barrier.
            let reconnected = tokio::select! {
                accepted = listener.accept() => {
                    let _second = accepted.expect("the live fixture listener accepts");
                    true
                }
                ended = completed => {
                    ended.expect("the client completed its single exchange");
                    false
                }
            };
            assert!(!reconnected, "no second connection is acquired");
            assert!(
                Request::read(&mut peer).await.is_err(),
                "one connected stream carries one request only"
            );
            // Probe the kernel queue directly after completion, not cached reactor readiness.
            let listener = listener.into_std().unwrap();
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
            );
        });
        let exchange = tokio::time::timeout(Duration::from_secs(1), async {
            let result = catalog_reply(stream).await;
            done.send(())
                .expect("release the server completion barrier");
            if unexpected {
                assert!(matches!(result, Ok(Response::Ack)));
            } else {
                assert!(result.is_err(), "connected failures stay failures");
            }
            server.await.unwrap();
        })
        .await;
        assert!(
            exchange.is_ok(),
            "a failed exchange must not hang awaiting a retried request"
        );
    }
}

/// One control request/response over the resident control socket, bounded by the caller's timeout.
async fn control_round_trip(socket: &Path, request: Request) -> Result<Response, ControlError> {
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(ControlError::Io)?;
    request.write(&mut stream).await.map_err(ControlError::Io)?;
    Response::read(&mut stream).await
}

/// Both forms use the callable-name rule before a home is read or a process binds anything.
#[test]
fn serve_refuses_reserved_bare_names_before_home_writes() {
    assert_reserved_serve_entries(&[
        "control", "lookup", "CONTROL", "LookUp", "me", "Root", "anyone",
    ]);
}

#[test]
fn serve_refuses_reserved_explicit_names_before_home_writes() {
    assert_reserved_serve_entries(&[
        "control=ping:",
        "lookup=ping:",
        "CONTROL=ping:",
        "LookUp=ping:",
        "me=ping:",
        "Root=ping:",
        "anyone=ping:",
    ]);
}

#[tokio::test]
async fn cli_definition_failures_never_echo_credentials_or_prepare_a_valid_prefix() {
    let scratch = ProcessScratch::new("safe-definition-errors");
    let home = Home::resolve(Some(scratch.home_dir.clone())).unwrap();
    let policy = home.serve_toml();
    let accepted = b"services = ['speed=speed:']\noff = ['raw']\n";
    std::fs::write(&policy, accepted).unwrap();
    for entry in [
        "bad=proxy:https://user:secret@host.test/?token=private",
        "secret/name=echo:",
        "bad=ping:secret",
    ] {
        let parsed = <crate::Cli as clap::Parser>::try_parse_from([
            "swoosh",
            "serve",
            "raw=stdin:",
            "drop=recv:",
            entry,
        ])
        .unwrap();
        let Some(crate::Command::Serve(cmd)) = parsed.command else {
            panic!("serve parses")
        };
        let error = cmd
            .claim(&home)
            .await
            .expect_err("complete validation precedes preparation");
        assert!(error.downcast_ref::<swoosh::serve::Mistyped>().is_some());
        for cause in error.chain() {
            let text = format!("{cause:?} {cause}");
            for forbidden in [entry, "secret", "private", "user:", "host.test"] {
                assert!(!text.contains(forbidden), "{text}");
            }
        }
        assert!(format!("{error:#}").contains("index 3"));
        assert_eq!(std::fs::read(&policy).unwrap(), accepted);
        assert_eq!(std::fs::read_dir(&scratch.home_dir).unwrap().count(), 1);
    }
}

fn assert_reserved_serve_entries(entries: &[&str]) {
    let scratch = ProcessScratch::new("reserved");
    let path = scratch.home_dir.join("serve.toml");
    let original = b"services = ['ssh=sshd:']\n";
    std::fs::write(&path, original).unwrap();
    let before = std::fs::metadata(&path).unwrap().modified().unwrap();
    for entry in entries {
        <crate::Cli as clap::Parser>::try_parse_from([
            "swoosh",
            "--home",
            scratch.home_dir.to_str().unwrap(),
            "serve",
            entry,
        ])
        .expect("definition validation occurs after clap without raw operand echo");
        let word = entry
            .split_once('=')
            .map_or(*entry, |(name, _)| name)
            .to_ascii_lowercase();
        assert!(matches!(
            definition(entry),
            Err(swoosh::serve::DefinitionError {
                operand: swoosh::serve::Operand::Positional,
                index: 1,
                cause: swoosh::serve::DefinitionCause::Reserved(reserved),
            }) if reserved.as_str() == word
        ));
        let output = swoosh_once(&scratch, &["serve", entry]);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .starts_with(&format!(
                    "error: {word} is reserved; no service can have that name\n"
                ))
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before
        );
        assert_eq!(std::fs::read_dir(&scratch.home_dir).unwrap().count(), 1);
    }
}

#[test]
fn serve_preserves_callable_names_short_forms_and_unnamed_target_teaching() {
    use swoosh::serve::Mistyped;

    for (entry, expected) in [
        ("Ping", "ping=ping:"),
        ("Speed", "speed=speed:"),
        ("recv:", "recv=recv:"),
        (
            "proxy:https://pkgs.example.com",
            "proxy=proxy:https://pkgs.example.com",
        ),
        ("Web=tcp:localhost:3000", "web=tcp:localhost:3000"),
    ] {
        assert_eq!(definition(entry).unwrap(), expected);
        assert!(<crate::Cli as clap::Parser>::try_parse_from(["swoosh", "serve", entry]).is_ok());
    }
    #[cfg(feature = "ssh")]
    {
        assert_eq!(definition("SSH").unwrap(), "ssh=sshd:");
        assert_eq!(
            refusal_against(&["SSH"], &["ssh"], &["ssh"]),
            "swoosh serve is already running here (pid 4121)\n  It serves ssh.\n  To turn ssh on:\n    swoosh service on ssh"
        );
    }
    #[cfg(not(feature = "ssh"))]
    for entry in ["SSH", "ssh=sshd:"] {
        let Some(crate::Command::Serve(mut cmd)) =
            <crate::Cli as clap::Parser>::try_parse_from(["swoosh", "serve", entry])
                .unwrap()
                .command
        else {
            panic!("serve parses");
        };
        assert!(matches!(
            cmd.normalize_services(std::path::Path::new("/work")),
            Err(swoosh::serve::ServingError::Definition(
                swoosh::serve::DefinitionError {
                    operand: swoosh::serve::Operand::Positional,
                    index: 1,
                    cause: swoosh::serve::DefinitionCause::Scheme,
                }
            ))
        ));
    }
    for name in ["ssh", "ping", "speed"] {
        assert!(swoosh::names::service(name).is_ok());
    }
    for entry in ["ssh=sshd:22", "ssh=sshd:+lossy"] {
        assert!(definition(entry).is_err());
        assert!(Mistyped::check(&[entry.to_owned()]).is_err());
    }
    for entry in ["tcp:localhost:3000", "3000", "me", "root", "anyone"] {
        assert!(definition(entry).is_err());
        assert!(Mistyped::check(&[entry.to_owned()]).is_err());
    }
}

/// `entry` as `serve` normalizes it when typed alone, or the refusal it gets there.
fn definition(entry: &str) -> Result<String, swoosh::serve::DefinitionError> {
    match swoosh::serve::Started::positional(&[entry.to_owned()], std::path::Path::new("/work")) {
        Ok(started) => Ok(started.entries().remove(0)),
        Err(swoosh::serve::ServingError::Definition(error)) => Err(error),
        Err(error) => panic!("one definition is never a mistyped list: {error}"),
    }
}

/// `serve proxy:<url>` names itself `proxy`, the way `sshd:` names itself `ssh`; a named instance keeps the
/// name it was given.
#[test]
fn a_bare_proxy_url_names_itself_proxy() {
    let Some(crate::Command::Serve(cmd)) = <crate::Cli as clap::Parser>::try_parse_from([
        "swoosh",
        "serve",
        "proxy:https://pkgs.example.com",
        "pkgs=proxy:https://pkgs.example.com",
    ])
    .expect("both proxy forms parse")
    .command
    else {
        panic!("serve parses to the serve verb");
    };
    assert_eq!(
        cmd.services,
        [
            "proxy:https://pkgs.example.com",
            "pkgs=proxy:https://pkgs.example.com"
        ]
    );
}

/// A proxy is always served with what it reaches, named or not: `serve proxy`, `serve proxy:` and
/// `serve files=proxy:` name no origin, and an empty origin is an open egress relay under this machine's
/// address. Each is a usage error (exit 2) that names the form to type, with the name typed, refused at
/// parse, before anything binds.
///
/// Bind it with an empty origin instead (`proxy` read as `proxy=proxy:`, or a named one let through) and
/// the parse succeeds: the node would serve an unconstrained relay nobody asked for.
#[test]
fn serve_proxy_without_a_target_is_a_usage_error() {
    for (entry, form) in [
        ("proxy", "proxy:<url>"),
        ("Proxy", "proxy:<url>"),
        ("proxy:", "proxy:<url>"),
        ("proxy=proxy:", "proxy:<url>"),
        ("files=proxy:", "files=proxy:<url>"),
        ("Files=proxy:", "files=proxy:<url>"),
    ] {
        let _ = form;
        <crate::Cli as clap::Parser>::try_parse_from(["swoosh", "serve", entry]).unwrap();
        let error = swoosh::serve::Mistyped::check(&[entry.to_owned()]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid service definition at index 1: invalid proxy origin"
        );
    }
}

/// A proxy's URL is an origin only. The engine admits every path and query on the origin it is given, so
/// a path would promise one file and serve the whole site, and a query (a signed link) would be stored and
/// printed for nothing. A usage error (exit 2) that names the origin to type instead, with the name typed.
///
/// Read the whole URL as the scope instead and each parses, to a service wider than its line says.
#[test]
fn a_proxy_url_with_a_path_or_query_is_a_usage_error() {
    for (entry, form) in [
        (
            "proxy:https://cdn.example/releases/v1.iso",
            "proxy:https://cdn.example",
        ),
        (
            "dl=proxy:https://cdn.example/v1.iso?X-Amz-Signature=abc",
            "dl=proxy:https://cdn.example",
        ),
        (
            "dl=proxy:https://cdn.example/?a=b",
            "dl=proxy:https://cdn.example",
        ),
        (
            "dl=proxy:https://cdn.example/#top",
            "dl=proxy:https://cdn.example",
        ),
        (
            "dl=proxy:http://cdn.example:8080/x",
            "dl=proxy:http://cdn.example:8080",
        ),
        // Bare, with an `=` in its query: the `=` is the URL's, never a `name=` split.
        (
            "proxy:https://cdn.example/a?b=c",
            "proxy:https://cdn.example",
        ),
    ] {
        let _ = form;
        <crate::Cli as clap::Parser>::try_parse_from(["swoosh", "serve", entry]).unwrap();
        let error = swoosh::serve::Mistyped::check(&[entry.to_owned()]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid service definition at index 1: invalid proxy origin"
        );
    }

    // The origin, with or without its trailing slash, is the form that serves.
    for entry in ["proxy:https://cdn.example", "dl=proxy:https://cdn.example/"] {
        assert!(
            <crate::Cli as clap::Parser>::try_parse_from(["swoosh", "serve", entry]).is_ok(),
            "`serve {entry}` names an origin"
        );
    }
}

/// The engine fetches only http and https, so a proxy URL with any other scheme is a usage error (exit 2),
/// refused before its path and query are stored. Its line names neither: `foo://h:1` has an opaque origin
/// the path check cannot read, and the engine's origin parse would take it (a host and a port).
///
/// Drop the scheme check and `foo:` reaches the path check, which names its opaque origin; `file:` and
/// `data:` pass the entry and are refused only at expose.
#[test]
fn a_proxy_url_that_is_not_http_or_https_is_a_usage_error() {
    for (entry, form) in [
        ("proxy:foo://h:1/p?sig=x", "proxy:https://<host>"),
        ("dl=proxy:file:///etc/passwd", "dl=proxy:https://<host>"),
        ("dl=proxy:data:text/plain,x", "dl=proxy:https://<host>"),
    ] {
        let _ = form;
        <crate::Cli as clap::Parser>::try_parse_from(["swoosh", "serve", entry]).unwrap();
        let error = swoosh::serve::Mistyped::check(&[entry.to_owned()]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid service definition at index 1: invalid proxy origin"
        );
    }
}

/// A proxy URL with a user or password is refused in swoosh's words: the engine's own line names the
/// engine, a word no person types.
#[test]
fn a_proxy_origin_with_userinfo_never_names_the_engine() {
    let mut requested = vec!["name=proxy:https://u:p@host.example".to_owned()];
    let Err(error) = ProxyScope::extract(&mut requested) else {
        panic!("a proxy URL with a user and password is refused");
    };
    let line = format!("{error:#}");
    assert_eq!(
        line,
        "invalid service definition at index 1: invalid proxy origin"
    );
    assert!(!line.contains("fetch"), "{line}");
}

/// Two `name=proxy:<origin>` services de-merge into TWO separate `ProxyService`s, each with its own served
/// name, its OWN unspellable synthetic scheme, and ONLY its own origin scope. `extract` removes them from the
/// requested set (leaving the non-proxy entries for the router's grammar).
#[test]
fn named_proxy_origins_de_merge_into_per_service_instances() {
    let mut requested = vec![
        "news=proxy:https://news.example".to_owned(),
        "apple=proxy:https://apple.example".to_owned(),
    ];
    let proxy = ProxyScope::extract(&mut requested).expect("origins parse");

    assert!(
        requested.is_empty(),
        "proxy entries are removed from the set the router then binds"
    );
    let services = proxy.services();
    assert_eq!(
        services.len(),
        2,
        "two proxy services de-merge into two instances"
    );
    let names: Vec<&str> = services.iter().map(ProxyService::name).collect();
    assert!(
        names.contains(&"news") && names.contains(&"apple"),
        "each keeps its served name"
    );
    assert!(
        services.iter().all(|s| !s.allow().is_unconstrained()),
        "each declared its own origin, so each allowlist is scoped"
    );
}

/// An entry with no `=` that reaches the de-merge names no service and is refused with the line that
/// fills in a name, the one `serve` and `service add` print. A typed bare `proxy:<url>` never gets here unnamed ([`a_bare_proxy_url_names_itself_proxy`]);
/// this is the de-merge's own guard, for an entry from anywhere else.
#[test]
fn bare_proxy_is_refused_with_the_name_addr_teaching_error() {
    let mut requested = vec!["proxy:".to_owned()];
    let Err(error) = ProxyScope::extract(&mut requested) else {
        panic!("a bare `proxy:` should be refused, not served");
    };
    assert_eq!(
        error.to_string(),
        "invalid service definition at index 1: invalid proxy origin"
    );
}

/// Non-proxy services pass through in order, and only proxy is de-merged out, so extraction is scoped to proxy
/// and does not disturb the rest of the requested set.
#[test]
fn non_proxy_services_pass_through_and_only_proxy_is_removed() {
    let mut requested = vec![
        "ping=ping:".to_owned(),
        "web=tcp:127.0.0.1:8080".to_owned(),
        "gh=proxy:https://api.github.com".to_owned(),
    ];
    let proxy = ProxyScope::extract(&mut requested).expect("origin parses");

    assert_eq!(
        requested,
        vec!["ping=ping:".to_owned(), "web=tcp:127.0.0.1:8080".to_owned()],
        "the proxy entry is removed; ping and the raw forward are left exactly as given, in order"
    );
    assert_eq!(
        proxy.services().len(),
        1,
        "only the one proxy service is de-merged out"
    );
}

/// A malformed origin fails at expose time with a teaching error, not at dial time as an opaque refusal.
#[test]
fn a_malformed_proxy_origin_is_refused_at_expose_time() {
    let mut requested = vec!["bad=proxy:not a url".to_owned()];
    assert!(
        ProxyScope::extract(&mut requested).is_err(),
        "an unparseable origin is refused when the service is declared"
    );
}

/// An entry that reaches the de-merge with no origin is refused there too, whatever path it came by: an
/// empty scope is an open egress relay, so no proxy service is ever built unconstrained and the binder has
/// only the scoped engine to bind.
///
/// Read an empty origin as an empty allowlist instead and each extracts, to a proxy that fetches any site.
#[test]
fn a_proxy_entry_with_no_origin_is_refused_at_the_de_merge() {
    for entry in ["api=proxy:", "proxy=proxy:"] {
        let mut requested = vec![entry.to_owned()];
        let Err(error) = ProxyScope::extract(&mut requested) else {
            panic!("`{entry}` names no origin and is refused");
        };
        assert!(
            error
                .to_string()
                .starts_with("invalid service definition at index 1: invalid proxy origin"),
            "`{entry}`: {error}"
        );
    }
}

/// BLOCKER-3: a PUBLIC proxy instance holds ONLY its own origin scope, so it cannot reach a GATED proxy
/// instance's origins. The public `pub` and the gated `internal` are separate instances, each scoped to its
/// OWN origin; there is no shared allowlist to over-permit.
#[test]
fn a_public_proxy_instance_cannot_reach_a_gated_proxy_s_origins() {
    let mut requested = vec![
        "pub=proxy:https://public.example".to_owned(),
        "internal=proxy:http://10.0.0.5".to_owned(),
    ];
    let proxy = ProxyScope::extract(&mut requested).expect("parse");
    let public = proxy
        .services()
        .iter()
        .find(|s| s.name() == "pub")
        .expect("pub");
    let internal = proxy
        .services()
        .iter()
        .find(|s| s.name() == "internal")
        .expect("internal");

    // The public instance is scoped to its OWN origin (not unconstrained), and it is a SEPARATE allowlist
    // from the gated instance's: there is no shared list holding the internal origin for it to reach. (That
    // an allowlist admits ONLY its listed origin, exact-match, is proven in `fetch`'s own origin tests.)
    assert!(
        !public.allow().is_unconstrained(),
        "the public proxy is scoped to its own origin only"
    );
    assert!(
        !internal.allow().is_unconstrained(),
        "the gated proxy holds its own internal origin only"
    );
}

/// The inbox when `HOME` is unset: there is none.
fn no_inbox() -> Option<PathBuf> {
    None
}

/// Two `name=recv:<dir>` services de-merge into TWO separate `RecvService`s, each with its own served name
/// and ONLY its own output dir. `extract` removes them from the requested set (leaving the non-recv entries
/// for the router's grammar), so `a=recv:/x b=recv:/y` writes each peer's pushes into its OWN directory
/// rather than the first-named one (the single-sink bug this fix removes).
#[test]
fn named_recv_dirs_de_merge_into_per_service_instances() {
    let mut requested = vec!["a=recv:/tmp/x".to_owned(), "b=recv:/tmp/y".to_owned()];
    let recv = extract_recv_services(&mut requested, no_inbox).expect("entries parse");

    assert!(
        requested.is_empty(),
        "recv entries are removed from the set the router then binds"
    );
    assert_eq!(
        recv.len(),
        2,
        "two receive services de-merge into two instances"
    );
    let a = recv.iter().find(|s| s.name() == "a").expect("service a");
    let b = recv.iter().find(|s| s.name() == "b").expect("service b");
    assert_eq!(
        a.out(),
        std::path::Path::new("/tmp/x"),
        "service a keeps its OWN output dir"
    );
    assert_eq!(
        b.out(),
        std::path::Path::new("/tmp/y"),
        "service b's dir is NOT masked by the first-named one"
    );
}

/// An unnamed `recv:` that reaches the extraction without the service-entry parser (which names it `recv`)
/// is refused with the line that fills in a name, never served under no name.
#[test]
fn bare_recv_is_refused_with_the_name_addr_teaching_error() {
    let mut requested = vec!["recv:".to_owned()];
    let Err(error) = extract_recv_services(&mut requested, no_inbox) else {
        panic!("a bare `recv:` should be refused, not served");
    };
    assert_eq!(
        error.to_string(),
        "HOME is not set, so recv: has no inbox to save into; name a directory: swoosh serve recv=recv:<dir>"
    );
}

/// Non-recv services pass through in order, and only recv is de-merged out, so extraction is scoped to recv
/// and does not disturb the rest of the requested set.
#[test]
fn non_recv_services_pass_through_and_only_recv_is_removed() {
    let mut requested = vec![
        "ping=ping:".to_owned(),
        "in=recv:/tmp/x".to_owned(),
        "web=tcp:127.0.0.1:8080".to_owned(),
    ];
    let recv = extract_recv_services(&mut requested, no_inbox).expect("entries parse");

    assert_eq!(
        requested,
        vec!["ping=ping:".to_owned(), "web=tcp:127.0.0.1:8080".to_owned()],
        "the recv entry is removed; ping and the raw forward are left exactly as given, in order"
    );
    assert_eq!(
        recv.len(),
        1,
        "only the one receive service is de-merged out"
    );
}

/// With no `HOME` there is no inbox, so a dirless `recv:` is refused with the fix that names a directory,
/// spelled with the service's own name.
#[test]
fn a_dirless_recv_with_no_home_teaches_its_own_name() {
    let mut requested = vec!["drop=recv:".to_owned()];
    let Err(error) = extract_recv_services(&mut requested, no_inbox) else {
        panic!("a dirless `recv:` with no inbox should be refused");
    };
    assert_eq!(
        error.to_string(),
        "HOME is not set, so recv: has no inbox to save into; name a directory: \
         swoosh serve drop=recv:<dir>"
    );
}

/// A minimal family gate for a construction test: an empty, non-persisting family gate, so the public
/// proof's per-service check runs without standing up a signet.
fn gated() -> nauthy::Gate {
    nauthy::Gate::rooted(
        swoosh::testkit::TestRoot::seeded(7).verify_key(),
        nauthy::Denylist::load(std::env::temp_dir().join("swoosh-serve-tests-no-revocations"))
            .expect("an absent denylist loads empty"),
    )
}

/// The base diagnostic route table the product `serve` path assembles, on a fresh family gate, with the
/// same open set the caller names: an open name binds the metered engine, a gated one the owner engine,
/// through the same edges the product binds them.
fn diagnostics(public: &[nauthy::Service]) -> Router {
    swoosh::serve::diagnostics(Router::new(gated()), public).expect("the base diagnostics bind")
}

/// The shared helper the integration proofs assemble their nodes from binds EXACTLY the diagnostics a
/// bare `serve` binds, and nothing else.
///
/// Those proofs are what "a default node answers this" MEANS in this repo, so a route bound here that
/// the product's bare set does not carry re-points every one of them at a node nobody runs. A shell is
/// the sharpest case and the reason this is pinned: the bare set binds none, and no client requests
/// the engine's own spelling `sshd` anyway (a `sshd:` target auto-names to `ssh`). A proof that wants
/// a shell binds one itself, by name.
#[test]
fn the_shared_diagnostics_helper_binds_exactly_what_a_bare_serve_binds() {
    let bound: BTreeSet<String> = diagnostics(&[])
        .expose()
        .expect("the base diagnostics assemble")
        .manifest()
        .into_iter()
        .map(|entry| entry.name)
        .collect();

    // NEGATIVE FIRST: an inversion that binds one of these fails the equality below too, and a run
    // that stopped there would report these as covered without ever reaching them.
    assert!(
        !bound.contains("sshd"),
        "the helper must not bind a shell: no client dials `sshd`, and no bare serve binds one"
    );
    for unbound in Unbound::all() {
        assert!(
            !bound.contains(unbound.name()),
            "the helper must not bind `{}`: a bare serve does not, so a proof built on it would be \
             a proof about a node nobody runs",
            unbound.name()
        );
    }

    let expected: BTreeSet<String> = [reach::PING_SERVICE, reach::SPEED_SERVICE]
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        bound, expected,
        "the helper binds the two diagnostics and leaves every other route to the caller that wants it"
    );
}

/// `serve speed --public speed` BUILDS (the metered speed engine is OptIn, openable), and `--public
/// <unknown>` is refused with a message that names the served set. Proves the CLI's per-service overlay
/// wires onto the real swoosh handlers through the Router's public proof.
#[test]
fn public_speed_builds_and_public_unknown_is_refused() {
    // `--public speed` builds: the open set binds the metered (OptIn, capped) engine and opens it, so the
    // overlay and the bound engine are one input.
    let built = diagnostics(&[svc("speed")]).expose();
    assert!(
        built.is_ok(),
        "`--public speed` must build (speed is openable)"
    );

    // `--public <unknown>` is refused, naming what the node DOES serve.
    let Err(error) = diagnostics(&[]).public([svc("nope")]).expose() else {
        panic!("an unknown public name must be refused");
    };
    assert!(
        error.to_string().contains("no service named"),
        "an unknown public name is refused with the served list: {error}"
    );
}

/// `serve logs=file:<path> --public-unsafe logs` opens the raw stream to anyone, and the banner says so:
/// the stream the operator KNOWINGLY named reaches `Posture::Open` with its resolved absolute source, so
/// its row reads `(anyone)`. Built through the real router `expose` + `manifest` path, not a hand-built
/// manifest.
#[test]
fn public_unsafe_reads_anyone_in_the_banner() {
    // A fixed short path keeps the row within 80 columns on every host; a long temp dir stacks it.
    let path = std::path::Path::new("/tmp/swoosh-public-unsafe-banner");
    let entry = format!("logs=file:{}", path.display());
    // A family BASE gate (not `Gate::Open`), so the whole-node raw-stream door never fires; the unsafe
    // OVERLAY alone opens `logs` (swoosh's per-service model).
    let exposer = Router::new(gated())
        .parse(&[entry])
        .expect("the raw-stream route binds")
        .public_unsafe([svc("logs")])
        .expose()
        .expect("a raw stream named in the unsafe overlay builds under a family gate");
    let manifest = exposer.manifest();
    let logs = manifest
        .iter()
        .find(|entry| entry.name == "logs")
        .expect("`logs` is in the manifest");
    assert_eq!(
        logs.posture,
        Posture::Open,
        "the unsafe-open raw stream reads Open"
    );
    assert!(
        matches!(&logs.raw_source, Some(RawSource::Path(_))),
        "a file: source resolves to an absolute path: {logs:?}"
    );
    assert_eq!(
        serving_block(
            &swoosh::serve::Started::Named(vec![format!("logs=file:{}", path.display())]),
            None,
            &manifest
        )
        .unwrap(),
        format!(
            "serving\n  selection  this run only (not saved)\n  logs       anyone  file:{}\n",
            path.display()
        )
    );
}

/// `serve logs=file:<path> --public logs` (the SAFE overlay, not the unsafe one) is REFUSED at build with the
/// unified redirect (STRING A): a raw byte source has no auth of its own, so `--public` will not serve it, and
/// the message points the operator at the distinct louder opt-in. This is the accident-vs-intent wall: a raw
/// stream never slips open through the everyday flag.
#[test]
fn plain_public_refuses_a_raw_stream_and_points_at_public_unsafe() {
    let path = std::env::temp_dir().join("swoosh-plain-public-raw");
    let entry = format!("logs=file:{}", path.display());
    let Err(error) = Router::new(gated())
        .parse(&[entry])
        .expect("the raw-stream route binds")
        .public([svc("logs")])
        .expose()
    else {
        panic!("`--public` naming a raw stream must be refused, not silently opened");
    };
    let message = error.to_string();
    assert!(
        message.contains("raw byte source") && message.contains("unsafe raw-stream set"),
        "the refusal redirects a raw stream to the distinct louder opt-in: {message:?}"
    );
}

/// `--public-unsafe ping` (a HANDLER, not a raw stream) is REFUSED with the reverse redirect (STRING B): the
/// unsafe overlay is ONLY for raw byte sources, and a handler is opened through the everyday public overlay
/// instead. The disjoint-token partition holds in both directions, so neither flag silently opens the other's
/// class.
#[test]
fn public_unsafe_naming_a_non_raw_service_is_refused() {
    // `ping` must be a bound handler so the unsafe proof reaches the raw-target check, where naming a handler
    // in the unsafe overlay is the redirect under test.
    let Err(error) = diagnostics(&[]).public_unsafe([svc("ping")]).expose() else {
        panic!("a handler named in the unsafe overlay must be redirected, not opened");
    };
    assert!(
        error.to_string().contains("not a raw byte source"),
        "the unsafe overlay redirects a handler to the public overlay: {error}"
    );
}

/// `--public sshd` (naming the keyless shell) is refused with a TEACHING error that names the service and the
/// fix and never leaks the marker names, posture winning over the operator's request.
#[cfg(feature = "ssh")]
#[test]
fn public_sshd_is_refused_with_a_teaching_error() {
    // The `ssh` feature binds the shell handler; without it a `ssh=sshd:` entry is a teaching parse error
    // before the public proof ever runs, which is why this test is feature-gated.
    let router = Router::new(gated())
        .service(svc("ssh"), sshh::Sshd::new([0u8; 32]))
        .expect("the shell route binds");
    let Err(error) = router.public([svc("ssh")]).expose() else {
        panic!("`--public ssh` (a keyless shell) must be refused");
    };
    let message = error.to_string();
    assert!(
        message.contains("ssh") && message.contains("gated"),
        "the teaching error names the service and leads with the fix: {message:?}"
    );
    for marker in ["Never", "OptIn"] {
        assert!(
            !message.contains(marker),
            "the refusal must not leak the marker {marker:?}: {message:?}"
        );
    }
}

/// The `--public` CLI surface: bare `--public` (the node-wide open that caused the bug) is an ERROR by
/// construction, the value is a comma-list, and omitting it opens nothing.
#[test]
fn public_flag_requires_a_value_and_splits_on_commas() {
    use clap::Parser as _;

    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        serve: super::ServeCmd,
    }

    // Bare `--public` (no value) is a parse error: node-wide-open is untypeable.
    assert!(
        Wrap::try_parse_from(["x", "--public"]).is_err(),
        "bare --public must be an error (no whole-node open)"
    );
    // The value is a comma-list of service names.
    let wrap = Wrap::try_parse_from(["x", "speed=speed:", "--public", "speed,fetch"])
        .expect("a comma-list parses");
    assert_eq!(
        wrap.serve.public,
        vec![svc("speed"), svc("fetch")],
        "--public splits on commas into the per-service set"
    );
    // Omitting `--public` opens nothing.
    let wrap = Wrap::try_parse_from(["x"]).expect("no --public parses");
    assert!(
        wrap.serve.public.is_empty(),
        "no --public means nothing is opened"
    );
}

/// The duration timer moved off `--for` onto `--expires` (`--for` once named who a link
/// was for, which is `share`'s second positional now). `--expires 30m` parses into the local timer; `--for 30m` no longer parses (the flag is
/// gone), so the overloaded word can never mean two things.
#[test]
fn serve_duration_is_expires_not_for() {
    use clap::Parser as _;

    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        serve: super::ServeCmd,
    }

    // `--expires 30m` arms the bounded-time timer.
    let wrap = Wrap::try_parse_from(["x", "--expires", "30m"]).expect("--expires parses");
    let expires = wrap.serve.expires.expect("the timer is armed");
    assert_eq!(
        expires.duration(),
        core::time::Duration::from_secs(30 * 60),
        "--expires 30m arms a 30-minute local timer"
    );

    // `--for 30m` no longer parses as a duration: the flag is gone from `serve`.
    assert!(
        Wrap::try_parse_from(["x", "--for", "30m"]).is_err(),
        "serve --for is gone; the duration is --expires now"
    );

    // Omitting it leaves the node running until Ctrl-C (no timer).
    let wrap = Wrap::try_parse_from(["x"]).expect("no timer parses");
    assert!(
        wrap.serve.expires.is_none(),
        "no --expires means run until stopped"
    );
}

/// `--quiet` withholds the whole activity class at its one gate: a quiet serve builds no renderer, so no
/// engine is handed a sink and nothing can render, whatever `RUST_LOG` says. A plain serve builds one,
/// and a fact through it reaches the writer.
#[test]
fn quiet_builds_no_activity_renderer_and_a_plain_serve_does() {
    use std::sync::{Arc, Mutex};

    use clap::Parser as _;
    use transfer::{Received, ReceivedSink as _};

    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        serve: super::ServeCmd,
    }

    /// A writer the test reads back after the renderer has drained.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Shared {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("the capture lock")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let quiet = Wrap::try_parse_from(["x", "--quiet"]).expect("--quiet parses");
    assert!(
        quiet
            .serve
            .activity(Shared::default())
            .expect("a quiet serve starts")
            .is_none(),
        "a quiet serve builds no renderer, so no engine gets a sink"
    );

    let plain = Wrap::try_parse_from(["x"]).expect("plain serve parses");
    let out = Shared::default();
    let activity = plain
        .serve
        .activity(out.clone())
        .expect("a plain serve starts")
        .expect("a plain serve renders activity");
    let sender = swoosh::testkit::TestNode::seeded(7).verify_key();
    activity.recv(svc("recv")).received(Received {
        path: "notes.txt".into(),
        bytes: 5,
        from: sender,
    });
    drop(activity);
    // `writeln!` writes the line and its newline in separate writes, so wait for the newline, not for the
    // first byte. The bytes are copied out before the assert, so a failing assert holds no guard and
    // poisons no lock under the renderer.
    let deadline = Instant::now() + Duration::from_secs(5);
    let written = loop {
        let written =
            String::from_utf8_lossy(&out.0.lock().expect("the capture lock")).into_owned();
        if written.ends_with('\n') || Instant::now() >= deadline {
            break written;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(
        written,
        format!("recv: received notes.txt (5 bytes) from {sender}\n"),
        "a plain serve's renderer carries the line"
    );
}

/// A capital folds on both sides of `serve`: `Web=…` binds `web` and `--public Web` opens `web`, so the
/// overlay finds the route it names and the node serves it open.
#[test]
fn a_capital_service_name_binds_and_opens_one_spelling() {
    use clap::Parser as _;

    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        serve: super::ServeCmd,
    }

    let wrap = Wrap::try_parse_from(["x", "Web=tcp:127.0.0.1:1", "--public", "Web"])
        .expect("capital names parse");
    let mut router = Router::new(gated());
    for entry in &wrap.serve.services {
        router = bind_entry(router, entry, [0u8; 32], &wrap.serve.public).expect("the entry binds");
    }
    let manifest = router
        .public(wrap.serve.public.clone())
        .expose()
        .expect("`--public Web` opens the route `Web=` bound")
        .manifest();
    let web = manifest
        .iter()
        .find(|entry| entry.name == "web")
        .expect("`web` is in the manifest");
    assert_eq!(web.posture, Posture::Open, "the one spelling is opened");
}

/// The update route's one name, on both sides: the route every serve binds is catalogued as
/// `control.sync`, and the dial every exchange makes requests that same name.
#[test]
fn the_update_route_is_control_sync() {
    let exposer = update_route(Router::new(gated()))
        .expose()
        .expect("the update route exposes");
    assert!(
        exposer
            .manifest()
            .iter()
            .any(|entry| entry.name == "control.sync" && entry.posture == Posture::Gated),
        "serve binds the update route as control.sync, gated"
    );
    let dial = swoosh::sync::connector(bifrost::NodeId::from_ed25519_secret(&[9; 32]), None)
        .expect("the dial builds");
    assert_eq!(
        dial.service().to_string(),
        "control.sync",
        "an exchange dials control.sync"
    );
}

/// `serve --admit` takes a root key, and refuses before it serves: this machine's own key, a root revoked
/// here, a person's root, and on a machine that trusts a root already. What it admits, it holds for the
/// run, so `join` refuses meanwhile.
#[tokio::test]
async fn serve_admit_refuses_what_it_must_not_admit() {
    use swoosh::testkit::{TestNode, TestRoot};
    use tightbeam::identity::AsVerifyKey as _;

    let scratch = |tag: &str| {
        let dir =
            std::env::temp_dir().join(format!("swoosh-serve-admit-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        swoosh::config::create_store_dir(&dir).unwrap();
        Home::resolve(Some(dir)).unwrap()
    };
    let own = TestNode::seeded(0x11).node_id();
    let root = TestRoot::seeded(0x21).node_id();
    let refusal = |result: eyre::Result<()>| match result {
        Ok(()) => panic!("refused"),
        Err(error) => format!("{error:#}"),
    };
    // `serve.lock` as a claimed `serve` holds it, recording this process.
    let serving = |home: Home| async move {
        let home_lock = HomeWrite::take(&home).await.unwrap();
        let serve_lock = ServeLock::take(&home_lock, &home).unwrap();
        serve_lock.record(&home_lock, None).unwrap();
        serve_lock
    };

    let home = scratch("own");
    let held = serving(home.clone()).await;
    assert_eq!(
        refusal(super::admitting(&held, &home, own, own).await),
        "that is this machine's key, not a root."
    );

    let home = scratch("revoked");
    let held = serving(home.clone()).await;
    swoosh::revoked::add(
        &swoosh::testkit::lock(),
        &home,
        [nauthy::Revocation::Key(root.verify_key().unwrap())],
    )
    .unwrap();
    assert!(
        refusal(super::admitting(&held, &home, own, root).await)
            .contains("was revoked on this machine")
    );

    let home = scratch("contact");
    let held = serving(home.clone()).await;
    let mut store = swoosh::contacts::ContactsStore::open(&home).await.unwrap();
    store
        .contacts_mut()
        .set_signet("alice".parse().unwrap(), root);
    store.save(&swoosh::testkit::lock()).unwrap();
    assert!(
        refusal(super::admitting(&held, &home, own, root).await)
            .contains("is alice's root: admitting it would admit every one of alice's devices"),
    );

    let home = scratch("pinned");
    let held = serving(home.clone()).await;
    swoosh::config::write_signet(
        &swoosh::testkit::lock(),
        &home,
        TestRoot::seeded(0x31).node_id(),
    )
    .unwrap();
    swoosh::config::write_badge(
        &swoosh::testkit::lock(),
        &home,
        &TestRoot::seeded(0x31)
            .device_badge(own, nauthy::Request::expires_in(Duration::from_secs(3600)))
            .unwrap(),
    )
    .unwrap();
    let mut seed = TestNode::seeded(0x11).seed();
    swoosh::identity::make_machine_dir(&home).unwrap();
    keystore::KeyFile::new(home.key())
        .write(
            &keystore::Secret::take(&mut seed),
            keystore::Protection::Plain,
        )
        .unwrap();
    assert!(
        refusal(super::admitting(&held, &home, own, root).await)
            .contains("--admit is for a machine that trusts no root")
    );

    let home = scratch("admits");
    let held = serving(home.clone()).await;
    super::admitting(&held, &home, own, root)
        .await
        .expect("admits");
    assert_eq!(ServeLock::recorded(&home).admit, Some(root));
    assert!(!home.root_pub().exists(), "no pin is written");
    drop(held);
    assert_eq!(ServeLock::recorded(&home).admit, None);
}

/// `--admit` takes one key, typed `root:ed01…`, and is not repeated.
#[test]
fn serve_admit_takes_one_root_key() {
    use clap::Parser as _;
    use swoosh::testkit::TestRoot;

    let root = TestRoot::seeded(0x21).node_id();
    let typed = format!("root:{root}");
    let cli = super::super::super::Cli::try_parse_from(["swoosh", "serve", "--admit", &typed])
        .expect("a root key");
    let Some(super::super::super::Command::Serve(serve)) = cli.command else {
        panic!("serve");
    };
    assert_eq!(serve.admit, Some(root));
    assert!(
        super::super::super::Cli::try_parse_from([
            "swoosh", "serve", "--admit", &typed, "--admit", &typed
        ])
        .is_err(),
        "one key, not repeated"
    );
}

/// `--admit` with a bare key, a machine's, refuses at parse, exit 2, and never prints the key back: admitting
/// one machine's devices means nothing.
#[test]
fn admit_refuses_a_machine_key() {
    let key = swoosh::testkit::TestNode::seeded(0x21)
        .node_id()
        .to_string();
    let error = crate::parse_from(["swoosh", "serve", "--admit", &key])
        .expect_err("a machine's key refuses");
    assert_eq!(error.exit_code(), 2);
    let printed = error.to_string();
    assert!(
        printed.starts_with("error: --admit takes a root key, not a machine's key\n"),
        "{printed}"
    );
    assert!(
        !printed.contains(&key),
        "the key is never echoed: {printed}"
    );
}

/// The first round with your devices runs as `serve` starts: the round has dialed nas before any time
/// passed. A first round that waited would leave a restarted machine open to a stop before it learns a
/// revocation.
#[tokio::test(start_paused = true)]
async fn the_first_sync_round_runs_at_start() {
    let nas = bifrost_mem::MemTransport::bind();
    let home = home_with_a_sibling("start", bifrost::Transport::node_id(&nas)).await;
    let node = bifrost::Node::new(bifrost_mem::MemTransport::bind(), bifrost::NoDiscovery);
    let peers = swoosh::peers::Peers::new(&node);
    let own = swoosh::streams::OwnBind::new(&peers, &home, node.node_id(), &FAMILY);
    let (dial, fetch) = (
        swoosh::sync::SourceDial::new(&own, &home),
        swoosh::renewal::SourceFetch::new(&own),
    );
    let (first_round, _held) = control::FirstRound::new();
    let started = tokio::time::Instant::now();
    tokio::select! {
        () = super::sync_rounds(&home, &dial, &fetch, first_round) => unreachable!("the rounds never end"),
        dialed = bifrost::Transport::accept(&nas) => {
            dialed.expect("the round dials nas");
        }
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the first round dials at start, not after a wait: {:?}",
        started.elapsed()
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `serve`'s rounds ride its own sessions, through the one source every exchange uses, and each round
/// presents the standing as it reads then: a renewal between two rounds is the one the second presents.
#[tokio::test(start_paused = true)]
async fn serves_rounds_ride_its_own_peers() {
    use swoosh::testkit::{STANDING_UNTIL, Script, ScriptedPeer, TestNode, TestRoot};

    let nas = TestNode::seeded(0x73).node_id();
    let home = home_with_a_sibling("own-peers", nas).await;
    let desk = TestNode::seeded(0x71).node_id();
    let wire = ScriptedPeer::new(nas, (0..4).map(|_| Script::Lists(Vec::new())));
    let node = bifrost::Node::new(wire.clone(), bifrost::NoDiscovery);
    let peers = swoosh::peers::Peers::new(&node);
    let own = swoosh::streams::OwnBind::new(&peers, &home, desk, &FAMILY);
    let (dial, fetch) = (
        swoosh::sync::SourceDial::new(&own, &home),
        swoosh::renewal::SourceFetch::new(&own),
    );
    let (first_round, _held) = control::FirstRound::new();
    let renewed = TestRoot::seeded(FIRST_ROUND_ROOT)
        .device_badge(
            desk,
            std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL - 60),
        )
        .expect("a badge");
    let asked = async |count: usize| {
        while wire.requests().len() < count {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let rounds = super::sync_rounds(&home, &dial, &fetch, first_round);
    tokio::pin!(rounds);
    tokio::select! {
        () = &mut rounds => unreachable!("the rounds never end"),
        () = asked(1) => {}
    }
    swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &renewed).expect("the renewal");
    tokio::select! {
        () = &mut rounds => unreachable!("the rounds never end"),
        () = asked(2) => {}
    }
    let stored = swoosh::config::load_badge(&home).await.expect("the badge");
    let requests = wire.requests();
    assert!(
        requests
            .iter()
            .all(|request| request.service == swoosh::serve::SYNC_SERVICE),
        "every stream is an exchange"
    );
    assert_ne!(
        requests[0].capability, requests[1].capability,
        "the second round read the standing afresh"
    );
    assert_eq!(
        requests[1].capability.as_deref(),
        stored.as_ref().map(nauthy::Link::as_str)
    );
    assert_eq!(
        wire.dials(),
        2,
        "one session per standing, on the run's own endpoint"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A remote stop is held while the first round waits on a sibling that never answers, and let in once the
/// round gives up on it at its bound. Open the stop only on a newer list and a machine whose
/// devices are all out of reach could never be stopped from another one.
#[tokio::test(start_paused = true)]
async fn a_round_that_finds_no_sibling_still_opens_stop() {
    // Bound, so the dial lands, and never accepting, so nothing answers it.
    let nas = bifrost_mem::MemTransport::bind();
    let home = home_with_a_sibling("silent", bifrost::Transport::node_id(&nas)).await;
    let node = bifrost::Node::new(bifrost_mem::MemTransport::bind(), bifrost::NoDiscovery);
    let peers = swoosh::peers::Peers::new(&node);
    let own = swoosh::streams::OwnBind::new(&peers, &home, node.node_id(), &FAMILY);
    let (dial, fetch) = (
        swoosh::sync::SourceDial::new(&own, &home),
        swoosh::renewal::SourceFetch::new(&own),
    );
    let (first_round, hold) = control::FirstRound::new();
    let started = tokio::time::Instant::now();
    let rounds = super::sync_rounds(&home, &dial, &fetch, first_round);
    tokio::pin!(rounds);

    tokio::select! {
        () = &mut rounds => unreachable!("the rounds never end"),
        () = tokio::time::sleep(swoosh::sync::EACH / 2) => {}
    }
    assert!(
        hold.is_held(),
        "a stop is held while the round waits on nas"
    );

    tokio::select! {
        () = &mut rounds => unreachable!("the rounds never end"),
        () = hold.opened() => {}
        () = tokio::time::sleep(swoosh::sync::EACH * 4 + Duration::from_secs(1)) => {
            panic!("a round no sibling answered left a stop held")
        }
    }
    // A Main open's own four-second deadline ends the ask on a silent nas, inside the exchange bound.
    assert!(
        started.elapsed() >= Duration::from_secs(4),
        "the round waited out nas's bound: {:?}",
        started.elapsed()
    );
    assert!(!hold.is_held(), "and then lets a stop in");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A machine that is not one of your devices (a `serve --admit` host trusts no root) has no one to ask:
/// its first round ends at once, and a remote stop is let in from then on. Wait for a newer list and
/// such a host could never be stopped from a device of the root it admits.
#[tokio::test(start_paused = true)]
async fn a_host_that_is_not_your_device_opens_stop_after_its_round() {
    let dir = std::env::temp_dir().join(format!("swoosh-first-round-host-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).expect("the store dir");
    let home = Home::resolve(Some(dir)).expect("the scratch home resolves");
    let node = bifrost::Node::new(bifrost_mem::MemTransport::bind(), bifrost::NoDiscovery);
    let peers = swoosh::peers::Peers::new(&node);
    let own = swoosh::streams::OwnBind::new(&peers, &home, node.node_id(), &FAMILY);
    let (dial, fetch) = (
        swoosh::sync::SourceDial::new(&own, &home),
        swoosh::renewal::SourceFetch::new(&own),
    );
    let (first_round, hold) = control::FirstRound::new();
    let started = tokio::time::Instant::now();
    tokio::select! {
        () = super::sync_rounds(&home, &dial, &fetch, first_round) => unreachable!("the rounds never end"),
        () = hold.opened() => {}
        () = tokio::time::sleep(swoosh::sync::EACH) => {
            panic!("a host with no devices to ask left a stop held")
        }
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "a round with no one to ask ends at once: {:?}",
        started.elapsed()
    );
    assert!(!hold.is_held(), "and lets a stop in");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A revoked device asked first in the first round cannot stop this machine over `control.serve`: the round
/// asks every device, so the one holding the list that revokes it is asked too. The thief opens its streams
/// during the first round, while the gate still admits it and just before the revoking list lands, and sends a `Stop` on one the moment the round ends
/// and every 10 ms for three debounces after. Each is refused, unanswered and reset, and your other
/// device's stop is answered `Done` after. The stream was admitted before the fold, so the handler's own
/// look at `revoked` is all that refuses it, and that look is fresh only because the round waits out a
/// stat debounce before it ends: open the stop the moment the round ends and the store, last read when
/// the thief's streams opened just before the fold, answers from that read and lets the thief stop this
/// machine.
#[tokio::test]
async fn a_device_revoked_on_a_sibling_cannot_stop_this_machine_through_control_serve() {
    use core::cell::RefCell;

    use bifrost::Session as _;
    use tightbeam::identity::AsVerifyKey as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    tokio::task::LocalSet::new()
        .run_until(async {
            let host = bifrost::Node::new(bifrost_mem::MemTransport::bind(), bifrost::NoDiscovery);
            let host_id = host.node_id();
            let thief = bifrost::Node::new(bifrost_mem::MemTransport::bind(), bifrost::NoDiscovery);
            let sibling =
                bifrost::Node::new(bifrost_mem::MemTransport::bind(), bifrost::NoDiscovery);
            let thief_key = thief.node_id().verify_key().expect("a usable key");
            let sibling_key = sibling.node_id().verify_key().expect("a usable key");
            let others = [(thief_key, "laptop"), (sibling_key, "phone")];
            let home = home_listing("revoked-first-serve", &others).await;

            let (gate, cut) =
                swoosh::gate::anchored(&home, host_id, swoosh::serve::BoundTargets::default())
                    .await
                    .expect("the gate");
            let cancel = CancellationToken::new();
            let source = std::sync::Arc::new(swoosh::serve::StopSource::new());
            // The store the gate reads, as `serve` passes it. No live cut: the thief's session outlives
            // the fold, so the handler's own look is the only thing between its stream and a stop.
            let (router, _catalog, first_round) = control::bind_serve(
                swoosh::serve::diagnostics(Router::new(gate), &[]).expect("the diagnostics bind"),
                cancel.clone(),
                std::sync::Arc::clone(&source),
                &cut,
            )
            .expect("control.serve binds");
            let hold = first_round.hold();
            let exposer = router.expose().expect("the exposer builds");
            let run = tokio::task::spawn_local({
                let cancel = cancel.clone();
                async move { exposer.run(&host, cancel).await }
            });
            let serve: nauthy::Service = swoosh::serve::CONTROL_SERVE_SERVICE
                .parse()
                .expect("a service");

            let thief_session = member_connector(host_id, &serve, thief.node_id())
                .open_service(&thief)
                .await
                .expect("the thief's connect lands; the gate decides per stream");
            let opened = RefCell::new(Vec::new());
            let dial = InOrder {
                home: home.clone(),
                // The thief's list, from before its revocation, then the one that revokes it.
                lists: [
                    first_round_list(2, &others, &[]),
                    first_round_list(3, &others[1..], &[thief_key]),
                ],
                // The thief's streams, then one more a debounce after them, so that admission reads
                // `revoked` afresh just before the fold: the store's last read is from before it.
                before_revoking: async || {
                    let mut streams = Vec::new();
                    for _ in 0..40 {
                        streams.push(
                            thief_session
                                .open_bi()
                                .await
                                .expect("the gate admits the thief before the fold"),
                        );
                    }
                    tokio::time::sleep(nauthy::STAT_DEBOUNCE * 2).await;
                    streams.push(
                        thief_session
                            .open_bi()
                            .await
                            .expect("the gate admits the thief before the fold"),
                    );
                    opened.borrow_mut().extend(streams);
                },
                asked: AtomicU32::new(0),
            };
            let asking = async {
                tokio::time::timeout(Duration::from_secs(30), hold.opened())
                    .await
                    .expect("the round opens the stop");
                // A stop open before the revoking list landed is open to the thief whatever the handler
                // asks: the row would prove nothing.
                assert_eq!(
                    dial.asked.load(Ordering::SeqCst),
                    2,
                    "the stop opened before the revoking list landed"
                );
                // At once and for a few debounces after the hold opens: the window a store still holding
                // its read from before the fold would answer the thief's stop in.
                let mut streams = opened.take().into_iter();
                let started = tokio::time::Instant::now();
                while started.elapsed() < nauthy::STAT_DEBOUNCE * 3 {
                    let (mut writer, mut reader) =
                        streams.next().expect("a stream opened before the fold");
                    writer
                        .write_all(&[control::Request::Stop.encode()])
                        .await
                        .expect("the request is sent");
                    let mut answer = Vec::new();
                    let read = reader.read_to_end(&mut answer).await;
                    assert!(
                        read.is_err() && answer.is_empty(),
                        "the thief's stop is never answered: {read:?} {answer:?}"
                    );
                    assert!(!cancel.is_cancelled(), "and the node runs on");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            tokio::select! {
                () = super::sync_rounds(&home, &dial, &NoRenewal, first_round) => {
                    unreachable!("the rounds never end")
                }
                () = asking => {}
            }
            assert_eq!(source.first(), None, "nothing noted a stop");

            let (mut writer, mut reader) = member_connector(host_id, &serve, sibling.node_id())
                .open_service(&sibling)
                .await
                .expect("your other device reaches control.serve")
                .open_bi()
                .await
                .expect("your other device is admitted");
            writer
                .write_all(&[control::Request::Stop.encode()])
                .await
                .expect("the request is sent");
            let mut answer = [0_u8; 1];
            reader
                .read_exact(&mut answer)
                .await
                .expect("the node answers the stop");
            assert_eq!(answer, [control::Answer::Done.encode()]);
            writer.shutdown().await.expect("the device closes its side");
            tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("the stop ends the run")
                .expect("the run task joins");
            assert_eq!(
                source.first(),
                Some(swoosh::serve::StopKind::Wire(sibling_key))
            );
            let _ = std::fs::remove_dir_all(home.dir());
        })
        .await;
}

/// A connector from `node` to `service` on `host`, presenting a device badge the first-round root signed.
fn member_connector(
    host: bifrost::NodeId,
    service: &nauthy::Service,
    node: bifrost::NodeId,
) -> tightbeam::tunnel::Connector {
    let until =
        std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(swoosh::testkit::STANDING_UNTIL);
    let badge = swoosh::testkit::TestRoot::seeded(FIRST_ROUND_ROOT)
        .device_badge(node, until)
        .expect("a badge");
    tightbeam::tunnel::Connector::to_node(host, service.clone(), Some(badge))
}

/// Devices that answer in the order asked, whoever is asked: the first hands over `lists[0]`, the second
/// `lists[1]` once `before_revoking` has run, each folded here as an exchange that took it folds it, and
/// every later ask finds the same list. The order the round shuffles your devices into cannot change who
/// answers first.
struct InOrder<F> {
    home: Home,
    lists: [Vec<u8>; 2],
    before_revoking: F,
    asked: AtomicU32,
}

impl<F: AsyncFn()> swoosh::sync::Dial for InOrder<F> {
    async fn exchange(
        &self,
        _peer: bifrost::NodeId,
    ) -> Result<swoosh::sync::Answer, swoosh::sync::ExchangeError> {
        let asked = self.asked.load(Ordering::SeqCst);
        let Some(list) = self.lists.get(asked as usize) else {
            return Ok(swoosh::sync::Answer::Same);
        };
        if asked == 1 {
            (self.before_revoking)().await;
        }
        fold_into(&self.home, list).await;
        self.asked.fetch_add(1, Ordering::SeqCst);
        Ok(swoosh::sync::Answer::Took)
    }

    async fn offer(
        &self,
        _peer: bifrost::NodeId,
        _number: swoosh::roster::Epoch,
        _bytes: &[u8],
    ) -> Result<swoosh::sync::Answer, swoosh::sync::ExchangeError> {
        Ok(swoosh::sync::Answer::Same)
    }
}

/// A pick-up that finds no renewal: the rounds here are never refused.
struct NoRenewal;

impl swoosh::renewal::Fetch for NoRenewal {
    async fn fetch(
        &self,
        _peer: bifrost::NodeId,
    ) -> Result<Option<nauthy::Link>, swoosh::renewal::FetchError> {
        Ok(None)
    }
}

/// A home for `me/desk`, one of a root's devices, whose list names one other device, `me/nas` at `nas`.
async fn home_with_a_sibling(tag: &str, nas: bifrost::NodeId) -> Home {
    use tightbeam::identity::AsVerifyKey as _;

    home_listing(tag, &[(nas.verify_key().expect("a usable key"), "nas")]).await
}

/// The root every first-round home belongs to.
const FIRST_ROUND_ROOT: u8 = 0x72;

/// What `serve`'s rounds present: this home's standing, never a slip.
const FAMILY: swoosh::credential::Credential =
    swoosh::credential::Credential::Family { present: None };

/// The list `others` and `me/desk` make, at `number`, revoking `revoked`, signed by the first-round root.
fn first_round_list(
    number: u64,
    others: &[(nauthy::VerifyKey, &str)],
    revoked: &[nauthy::VerifyKey],
) -> Vec<u8> {
    use swoosh::roster::{Epoch, RosterDoc};
    use swoosh::testkit::{TestNode, TestRoot};

    let root = TestRoot::seeded(FIRST_ROUND_ROOT);
    let members = core::iter::once((TestNode::seeded(0x71).verify_key(), "desk"))
        .chain(others.iter().copied())
        .map(|(key, label)| {
            root.member(key, label.parse().expect("a name"))
                .expect("a member")
        })
        .collect();
    let revoked = revoked
        .iter()
        .copied()
        .map(swoosh::testkit::revoked)
        .collect();
    root.sign_update(
        &RosterDoc::with_revocations(Epoch(number), members, Vec::new(), revoked).expect("a list"),
    )
}

/// A home for `me/desk`, one of a root's devices, holding the list at number 1 that names `others` too.
async fn home_listing(tag: &str, others: &[(nauthy::VerifyKey, &str)]) -> Home {
    use swoosh::testkit::{STANDING_UNTIL, TestNode, TestRoot};

    let dir = std::env::temp_dir().join(format!("swoosh-first-round-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).expect("the store dir");
    let home = Home::resolve(Some(dir)).expect("the scratch home resolves");
    let desk = TestNode::seeded(0x71);
    let root = TestRoot::seeded(FIRST_ROUND_ROOT);
    let mut seed = desk.seed();
    swoosh::identity::make_machine_dir(&home).expect("the machine dir");
    keystore::KeyFile::new(home.key())
        .write(
            &keystore::Secret::take(&mut seed),
            keystore::Protection::Plain,
        )
        .expect("this machine's key");
    swoosh::config::write_signet(&swoosh::testkit::lock(), &home, root.node_id()).expect("the pin");
    let until = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL);
    let badge = root.device_badge(desk.node_id(), until).expect("a badge");
    swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &badge).expect("the badge");
    fold_into(&home, &first_round_list(1, others, &[])).await;
    home
}

/// Fold `update` into `home`, as an exchange that took it does.
async fn fold_into(home: &Home, update: &[u8]) {
    swoosh::roster::fold(
        &HomeWrite::take(home).await.expect("home.lock"),
        home,
        update,
    )
    .await
    .expect("the list folds");
}

#[test]
fn waiting_warnings_include_the_prefix_in_the_width_and_never_split_names() {
    use swoosh::serve_toml::Waiting;

    assert!(waiting_warnings(&Waiting::default()).is_empty());
    let prefix = "warning: saved service ";
    let suffix = " applies to the next bare or --with/--without serve";
    let boundary = 80 - prefix.len() - suffix.len();
    for size in [
        boundary - 1,
        boundary,
        boundary + 1,
        swoosh::names::Name::MAX_LEN - 1,
        swoosh::names::Name::MAX_LEN,
    ] {
        let name = "a".repeat(size);
        swoosh::names::service(&name).unwrap();
        for waiting in [
            Waiting {
                added: vec![name.clone()],
                ..Waiting::default()
            },
            Waiting {
                changed: vec![name.clone()],
                ..Waiting::default()
            },
        ] {
            let out = waiting_warnings(&waiting);
            assert_eq!(
                out.split_whitespace().collect::<Vec<_>>().join(" "),
                format!("{prefix}{name}{suffix}")
            );
            assert!(out.lines().any(|line| line.contains(&name)), "{out}");
            assert!(out.lines().all(|line| line.len() <= 80), "{out}");
            if size <= boundary {
                assert_eq!(out, format!("{prefix}{name}{suffix}\n"));
            } else {
                assert!(out.lines().count() > 1, "{out}");
            }
        }
    }
    let waiting = Waiting {
        relay: true,
        resolver: true,
        added: vec!["one".to_owned()],
        changed: vec!["two".to_owned()],
    };
    assert_eq!(
        waiting_warnings(&waiting),
        concat!(
            "warning: the changed relay in serve.toml takes effect at the next start\n",
            "warning: the changed resolver in serve.toml takes effect at the next start\n",
            "warning: saved service one applies to the next bare or --with/--without serve\n",
            "warning: saved service two applies to the next bare or --with/--without serve\n",
        )
    );
}

#[test]
fn wide_serving_labels_keep_fixed_words_bounded_and_targets_complete() {
    use swoosh::serve::Started;

    let name = "a".repeat(63);
    let started = Started::Named(vec![format!("{name}=ping:")]);
    let manifest = vec![entry_open(&name, TargetKind::RawStream, None)];
    let out = serving_block(&started, None, &manifest).unwrap();
    assert!(
        out.contains("  selection\n    this run only (not saved)\n"),
        "{out}"
    );
    assert!(out.contains(&format!("  {name}  anyone  ping:\n")), "{out}");
    assert!(out.lines().all(|line| line.len() <= 80), "{out}");
}

/// `--expires` fires the run's one teardown token once its lifetime passes, and with no lifetime never
/// does, while the timer itself never ends (so it can never win the run's select).
#[tokio::test(start_paused = true)]
async fn expires_cancels_the_run_at_its_deadline_and_never_without_one() {
    let lifetime: Lifetime = "1h".parse().unwrap();
    let cancel = CancellationToken::new();
    let ended = tokio::time::timeout(
        lifetime.duration() + Duration::from_secs(1),
        expire(Some(lifetime), cancel.clone()),
    )
    .await;
    assert!(ended.is_err(), "the timer never returns");
    assert!(cancel.is_cancelled(), "the deadline cancels the run");

    let cancel = CancellationToken::new();
    let ended = tokio::time::timeout(
        Duration::from_secs(400 * 24 * 3600),
        expire(None, cancel.clone()),
    )
    .await;
    assert!(ended.is_err());
    assert!(!cancel.is_cancelled(), "no lifetime, no cancel");
}

/// A run that stops before its `--expires` deadline leaves no timer behind: the timer is owned by the run,
/// so once the run drops it, passing the deadline cancels nothing.
#[tokio::test(start_paused = true)]
async fn a_run_stopped_before_its_deadline_leaves_no_timer_behind() {
    let lifetime: Lifetime = "1h".parse().unwrap();
    let cancel = CancellationToken::new();
    let mut expiry = Box::pin(expire(Some(lifetime), cancel.clone()));
    assert!(futures::poll!(&mut expiry).is_pending());
    drop(expiry);
    // Let anything the timer may have started run up to its own sleep before the clock moves.
    tokio::task::yield_now().await;
    tokio::time::advance(lifetime.duration() + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(
        !cancel.is_cancelled(),
        "a dropped run's timer fired after the run had stopped"
    );
}
