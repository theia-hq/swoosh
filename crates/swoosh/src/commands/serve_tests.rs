//! Unit tests for `serve`'s stop classification and banner: a GRACEFUL stop is a typed [`Stopped`] the run
//! reports and exits 0 on, and an ERRORED teardown never becomes one (it stays an `Err` the run propagates,
//! so the process exits non-zero). The end-to-end proof that a member `control.stop` makes the exposer
//! return `Ok` (which the run turns into [`Stopped::Requested`], exit 0) lives in `tests/gated_stop.rs`.
//!
//! Two properties only the real composition root can prove are driven by spawning the compiled `swoosh`
//! binary: plain serve creates no runtime state, and `--resident` stays the foreground process.

use core::net::SocketAddr;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use tightbeam::tunnel::{
    CancellationToken, ManifestEntry, Metering, Posture, RawSource, Router, ServiceCatalog,
    TargetKind,
};

use super::control::{ControlError, Request, Response};
use super::{
    CONTROL_SERVICES_SERVICE, CONTROL_STOP_SERVICE, FetchScope, Group, MdnsState, ReachKind,
    ServiceList, Stop, Stopped, describe, display_targets, reach_section, render_ready_banner,
    serving_section,
};
use crate::home::Home;

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

/// The default `swoosh serve` manifest (gated ping + speed + the two control.* reads), name-sorted as the
/// exposer returns it, so a banner test exercises the same shape the product path builds.
fn default_manifest() -> Vec<ManifestEntry> {
    vec![
        entry_gated(
            "control.services",
            TargetKind::Handler,
            Some(Metering::Unmetered),
        ),
        entry_gated(
            "control.stop",
            TargetKind::Handler,
            Some(Metering::Unmetered),
        ),
        entry_gated("ping", TargetKind::Handler, Some(Metering::Unmetered)),
        entry_gated("speed", TargetKind::Handler, Some(Metering::Unmetered)),
    ]
}

/// The display map the default serve builds (control.* + ping + speed point at their own schemes).
fn default_targets() -> HashMap<String, String> {
    display_targets(&[
        "ping=ping:".to_owned(),
        "speed=speed:".to_owned(),
        "control.stop=control.stop:".to_owned(),
        "control.services=control.services:".to_owned(),
    ])
    .expect("explicit entries display")
}

/// The default iroh + mDNS-on banner: a copy-clean full id, an `internet` channel that says "automatic" and
/// never names the backend, an mDNS LAN line, one family-gated group with the `control.*` fold, no public
/// group, and the plain stop line.
#[test]
fn the_default_banner_tells_reach_and_posture_without_backend_jargon() {
    let banner = render_ready_banner(
        "bf01exampleid",
        ReachKind::Internet,
        MdnsState::Available,
        &[],
        &default_manifest(),
        &default_targets(),
        &HashSet::new(),
        "ctrl-c to stop",
        None,
    );

    assert!(
        banner.starts_with("swoosh ready\n\n    bf01exampleid\n\n"),
        "{banner}"
    );
    assert!(banner.contains("how peers reach you"), "{banner}");
    assert!(
        banner.contains("internet"),
        "an iroh node shows the internet channel: {banner}"
    );
    assert!(
        !banner.contains("iroh"),
        "the backend is never named: {banner}"
    );
    // "automatic" leads BOTH auto channels (the Newcomer fix), not just LAN.
    assert_eq!(banner.matches("automatic").count(), 2, "{banner}");
    assert!(
        banner.contains("(mDNS)"),
        "the LAN line is an mDNS tell: {banner}"
    );
    assert!(banner.contains("family-gated"), "{banner}");
    assert!(
        banner.contains("control.*")
            && !banner.contains("control.stop")
            && !banner.contains("control.services"),
        "the two control reads fold to one control.* line: {banner}"
    );
    assert!(
        !banner.contains("anyone"),
        "no group is opened to anyone when nothing is public: {banner}"
    );
    assert!(banner.trim_end().ends_with("ctrl-c to stop"), "{banner}");
}

/// The mix banner: an open unmetered service carries a QUIET inline caveat (no loud glyph), the public-UNSAFE group
/// sits last carrying the loudest marker, `name -> target` renders only when they differ, and the danger
/// vocabulary is monotonic (the `public` marker is strictly shorter/quieter than `public-UNSAFE`).
#[test]
fn the_mix_banner_keeps_one_monotonic_danger_vocabulary() {
    let manifest = vec![
        entry_open("logs", TargetKind::RawStream, None),
        entry_gated("ping", TargetKind::Handler, Some(Metering::Unmetered)),
        entry_open("speed", TargetKind::Handler, Some(Metering::Unmetered)),
        entry_gated("ssh", TargetKind::Handler, None),
    ];
    let targets = display_targets(&[
        "ping=ping:".to_owned(),
        "speed=speed:".to_owned(),
        "ssh=sshd:".to_owned(),
        "logs=file:/var/log/app.log".to_owned(),
    ])
    .expect("explicit entries display");
    let section = serving_section(&manifest, &targets, &HashSet::new());

    // `name -> target` only when they differ: `ssh -> sshd`, but `speed` alone (name == scheme).
    assert!(section.contains("ssh -> sshd"), "{section}");
    assert!(
        section.contains("logs -> file:/var/log/app.log"),
        "{section}"
    );
    assert!(
        section.contains("\n    speed ") || section.contains("\n    speed\n"),
        "a name that equals its scheme renders without an arrow: {section}"
    );
    // The open-unmetered caveat is quiet prose, NOT a competing loud glyph.
    assert!(
        section.contains("unmetered: a stranger can drain your uplink"),
        "{section}"
    );
    assert!(
        !section.contains("[!]"),
        "the unmetered caveat is not a loud glyph: {section}"
    );

    // Groups are safest-first and the danger marker is monotonic down the list.
    let family = section.find("family-gated").expect("family group present");
    let public = section.find("public !").expect("public group present");
    let unsafe_grp = section
        .find("public-UNSAFE !!")
        .expect("public-UNSAFE group present");
    assert!(
        family < public && public < unsafe_grp,
        "safest-first ordering: {section}"
    );
}

/// The reach section flips the LAN line to a next-step down-state when mDNS is blocked, and a quirk node with
/// a routable hint prints a `direct` channel with the address on its own copy-clean line.
#[test]
fn the_reach_section_handles_blocked_mdns_and_direct_hints() {
    let blocked = reach_section(ReachKind::Internet, MdnsState::Blocked, &[]);
    assert!(blocked.contains("off; multicast blocked here"), "{blocked}");
    assert!(
        blocked.contains("over the internet"),
        "the down-state says what to do instead: {blocked}"
    );

    let routable: SocketAddr = "192.168.1.20:58131".parse().expect("valid addr");
    let quirk = reach_section(ReachKind::DirectOnly, MdnsState::Available, &[routable]);
    assert!(
        !quirk.contains("internet"),
        "a direct-only node shows no internet channel: {quirk}"
    );
    assert!(quirk.contains("direct"), "{quirk}");
    assert!(quirk.contains("hand a peer this address:"), "{quirk}");
    assert!(quirk.contains("192.168.1.20:58131"), "{quirk}");

    // A loopback-only bind reads "on this machine only", never "hand a peer" an un-handable address.
    let loop_addr: SocketAddr = "127.0.0.1:58131".parse().expect("valid addr");
    let local = reach_section(ReachKind::DirectOnly, MdnsState::Available, &[loop_addr]);
    assert!(local.contains("reachable on this machine only:"), "{local}");
    assert!(!local.contains("hand a peer"), "{local}");
}

/// A de-merged fetch service glosses by name (its synthetic scheme is unspellable, so it never leaks into the
/// `name -> target` arrow), while a plain forward shows its address.
#[test]
fn a_fetch_service_glosses_by_name_and_never_leaks_its_scope() {
    let entry = entry_gated("news", TargetKind::Handler, None);
    let mut fetch_names = HashSet::new();
    fetch_names.insert("news".to_owned());
    let (label, gloss) = describe(&entry, &HashMap::new(), &fetch_names);
    assert_eq!(label, "news", "no synthetic scheme in the label");
    assert!(gloss.contains("fetches"), "{gloss}");
    assert!(
        !label.contains("fetch_"),
        "the synthetic scheme never appears: {label}"
    );
}

/// Every graceful-stop reason reports a distinct, non-empty line, so a CI action log (the qat teardown)
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
/// node (a requested `control.stop`/`--expires`, a socket stop, or a Ctrl-C), and NO arm for a
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
/// a wire `control.stop` or a `--expires` (both record nothing) renders the requested line.
#[test]
fn resident_stop_classifies_from_its_source() {
    use super::{StopKind, classify_stop};

    assert_eq!(
        classify_stop(Some(StopKind::Socket)),
        Stopped::Local,
        "the socket stop renders as the local stop"
    );
    for source in [None, Some(StopKind::Wire), Some(StopKind::Expires)] {
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

/// BLOCKER-2: the resident control socket adds no service. `--resident` adds only the local socket
/// arm AFTER the route table and the manifest are cut, so the exposer's manifest is the plain-serve set
/// exactly (`control.*` folds as always); and the control `Request` enum can express two reads and a
/// stop, never a toggle/revoke, so the socket can never mutate the gate. Both halves are asserted:
/// the manifest equality against the plain default, and the legal request set constructed and
/// round-tripped (the mutate-free guarantee is compile-enforced by the closed enum).
#[test]
fn resident_manifest_equals_plain_manifest() {
    let cancel = CancellationToken::new();
    // The route table the resident path builds: the base ping/speed plus the two member-only control.*
    // handlers, one handler value per route (the Router's bind-by-value shape). `bind_entry` binds only the
    // named routes, so `sshd` is absent here exactly as it is from the plain default set.
    let empty_roster = std::sync::Arc::new(Vec::new());
    let router = super::bind_entry(Router::new(gated()), "ping=ping:", [0u8; 32], &empty_roster)
        .expect("ping binds");
    let router =
        super::bind_entry(router, "speed=speed:", [0u8; 32], &empty_roster).expect("speed binds");
    let router = router
        .member_service(
            CONTROL_STOP_SERVICE.parse().expect("a name"),
            Stop::new(cancel),
        )
        .expect("control.stop binds")
        .member_service(
            CONTROL_SERVICES_SERVICE.parse().expect("a name"),
            ServiceList::new(ServiceCatalog::decode(&0u32.to_be_bytes()).expect("empty catalog")),
        )
        .expect("control.services binds");
    let exposer = router
        .expose()
        .expect("the resident service set assembles under the family gate");

    assert_eq!(
        exposer.manifest(),
        default_manifest(),
        "the resident manifest is exactly the plain-serve set; the control socket adds no service"
    );

    // The mutate-free guarantee BY TYPE: the socket carries two reads and a stop, and no toggle. A
    // total match with no wildcard is the guard: adding a control request variant (a toggle) makes
    // this fail to compile, at the seat that would break the invariant.
    for request in [Request::Services, Request::Status, Request::Stop] {
        match request {
            Request::Services | Request::Status | Request::Stop => {}
        }
    }
}

/// Plain serve creates no runtime state: drive the REAL binary with a temp home, a temp
/// `XDG_RUNTIME_DIR`, `--quiet`, and a one-second expiry, then assert no `control.sock`, no
/// `control.lock`, and no runtime root or per-home leaf exists. The production composition root runs
/// for real; nothing here parses a flag or renders a banner in-process.
#[test]
fn plain_serve_creates_no_runtime_state() {
    let scratch = ProcessScratch::new("plain");
    let home = Home::resolve(Some(scratch.home_dir.clone())).expect("the scratch home resolves");
    let leaf = runtime_leaf(&home, &scratch.xdg);
    // The macOS per-user runtime root is a shared confstr path other processes may own, so record
    // whether it pre-existed: the post-run assertion holds THIS run to not creating it.
    #[cfg(target_os = "macos")]
    let (mac_root, mac_root_existed) = {
        let root = crate::home::runtime_root().expect("the per-user runtime root path resolves");
        let existed = root.exists();
        (root, existed)
    };

    let mut command = Command::new(swoosh_binary());
    command
        .arg("--home")
        .arg(&scratch.home_dir)
        .args(["serve", "--quiet", "--expires", "1s"])
        .env("XDG_RUNTIME_DIR", &scratch.xdg)
        .env_remove("SWOOSH_HOME")
        .env_remove("SWOOSH_KEY");
    let output = run_binary_with_deadline(&mut command, Duration::from_secs(30));
    assert!(
        output.status.success(),
        "plain serve exits 0 on its expiry: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !leaf.join("control.sock").exists(),
        "plain serve binds no control socket"
    );
    assert!(
        !leaf.join("control.lock").exists(),
        "plain serve takes no control lock"
    );
    assert!(
        !leaf.exists(),
        "plain serve creates no per-home runtime leaf: {}",
        leaf.display()
    );
    // On Linux the root itself is ours (under the temp XDG); on macOS the shared confstr root is
    // asserted only against creation by this run.
    #[cfg(not(target_os = "macos"))]
    assert!(
        !scratch.xdg.join("swoosh").exists(),
        "plain serve creates no runtime root"
    );
    #[cfg(target_os = "macos")]
    assert!(
        mac_root_existed || !mac_root.exists(),
        "plain serve creates no runtime root"
    );
}

/// The resident banner differs from the plain one ONLY by the control line, and it is the production
/// `control_line` that renders: the path appears exactly once and a non-resident call returns `None`.
#[test]
fn resident_banner_differs_only_by_the_control_line() {
    use clap::Parser as _;

    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        serve: super::ServeCmd,
    }

    let socket = Path::new("/run/swoosh/x/control.sock");
    let plain_cmd = Wrap::try_parse_from(["x"]).expect("plain serve parses");
    assert_eq!(
        plain_cmd.serve.control_line(Some(socket)),
        None,
        "a plain serve prints no control line"
    );
    let resident_cmd = Wrap::try_parse_from(["x", "--resident"]).expect("--resident parses");
    let control = resident_cmd
        .serve
        .control_line(Some(socket))
        .expect("a resident serve prints the control line");
    assert_eq!(
        control, "control /run/swoosh/x/control.sock (local, this user)",
        "the control line names the real path and its local-only scope"
    );
    assert_eq!(
        control
            .matches(socket.to_str().expect("a utf-8 socket path"))
            .count(),
        1,
        "the socket path appears exactly once in the line: {control}"
    );

    let plain = render_ready_banner(
        "bf01exampleid",
        ReachKind::Internet,
        MdnsState::Available,
        &[],
        &default_manifest(),
        &default_targets(),
        &HashSet::new(),
        "ctrl-c to stop",
        None,
    );
    let resident = render_ready_banner(
        "bf01exampleid",
        ReachKind::Internet,
        MdnsState::Available,
        &[],
        &default_manifest(),
        &default_targets(),
        &HashSet::new(),
        "ctrl-c to stop",
        Some(control.as_str()),
    );
    assert_eq!(
        resident.matches(&control).count(),
        1,
        "the control line appears exactly once in the banner: {resident}"
    );
    assert_eq!(
        resident
            .matches(socket.to_str().expect("a utf-8 socket path"))
            .count(),
        1,
        "the real socket path appears exactly once in the banner: {resident}"
    );
    let stripped = resident.replacen(&format!("{control}\n"), "", 1);
    assert_eq!(
        stripped, plain,
        "the resident banner is the plain banner plus exactly one control line"
    );
    assert!(
        resident.contains("(local, this user)"),
        "the control line names its local-only scope: {resident}"
    );
}

/// No self-daemonizing: `serve --resident` stays the process the caller spawned. Spawn the real
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
        .args(["serve", "--resident", "--quiet"])
        .env("XDG_RUNTIME_DIR", &scratch.xdg)
        .env_remove("SWOOSH_HOME")
        .env_remove("SWOOSH_KEY")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = KillOnDrop(command.spawn().expect("the resident serve spawns"));
    let pid = child.0.id();

    let deadline = Instant::now() + Duration::from_secs(30);
    while !socket.exists() {
        if let Some(status) = child.0.try_wait().expect("poll the resident") {
            panic!("the resident exited before binding its socket: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "the resident never bound {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a control-client runtime");
    let reply = runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                control_round_trip(&socket, Request::Status),
            )
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

/// One SWC1 request/response over the resident control socket, bounded by the caller's timeout.
async fn control_round_trip(socket: &Path, request: Request) -> Result<Response, ControlError> {
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(ControlError::Io)?;
    request.write(&mut stream).await.map_err(ControlError::Io)?;
    Response::read(&mut stream).await
}

/// Two `name=fetch:<origin>` services de-merge into TWO separate `FetchService`s, each with its own served
/// name, its OWN unspellable synthetic scheme, and ONLY its own origin scope. `extract` removes them from the
/// requested set (leaving the non-fetch entries for the router's grammar).
#[test]
fn named_fetch_origins_de_merge_into_per_service_instances() {
    let mut requested = vec![
        "news=fetch:https://news.example".to_owned(),
        "apple=fetch:https://apple.example".to_owned(),
    ];
    let fetch = FetchScope::extract(&mut requested).expect("origins parse");

    assert!(
        requested.is_empty(),
        "fetch entries are removed from the set the router then binds"
    );
    let services = fetch.services();
    assert_eq!(
        services.len(),
        2,
        "two fetch services de-merge into two instances"
    );
    let names: Vec<&str> = services.iter().map(super::FetchService::name).collect();
    assert!(
        names.contains(&"news") && names.contains(&"apple"),
        "each keeps its served name"
    );
    assert!(
        services.iter().all(|s| !s.allow().is_unconstrained()),
        "each declared its own origin, so each allowlist is scoped"
    );
}

/// A bare `fetch:` (no `=`, no name) names no service and is refused with the `name=addr` teaching
/// error: only `name=fetch:<origin>` is spelled.
#[test]
fn bare_fetch_is_refused_with_the_name_addr_teaching_error() {
    let mut requested = vec!["fetch:".to_owned()];
    let Err(error) = FetchScope::extract(&mut requested) else {
        panic!("a bare `fetch:` should be refused, not served");
    };
    assert!(
        error.to_string().contains("name=addr"),
        "the refusal teaches the grammar: {error}"
    );
}

/// Non-fetch services pass through in order, and only fetch is de-merged out, so extraction is scoped to fetch
/// and does not disturb the rest of the requested set.
#[test]
fn non_fetch_services_pass_through_and_only_fetch_is_removed() {
    let mut requested = vec![
        "ping=ping:".to_owned(),
        "web=127.0.0.1:8080".to_owned(),
        "gh=fetch:https://api.github.com".to_owned(),
    ];
    let fetch = FetchScope::extract(&mut requested).expect("origin parses");

    assert_eq!(
        requested,
        vec!["ping=ping:".to_owned(), "web=127.0.0.1:8080".to_owned()],
        "the fetch entry is removed; ping and the raw forward are left exactly as given, in order"
    );
    assert_eq!(
        fetch.services().len(),
        1,
        "only the one fetch service is de-merged out"
    );
}

/// A malformed origin fails at expose time with a teaching error, not at dial time as an opaque refusal.
#[test]
fn a_malformed_fetch_origin_is_refused_at_expose_time() {
    let mut requested = vec!["bad=fetch:not a url".to_owned()];
    assert!(
        FetchScope::extract(&mut requested).is_err(),
        "an unparseable origin is refused when the service is declared"
    );
}

/// BLOCKER-3: a PUBLIC fetch instance holds ONLY its own origin scope, so it cannot reach a GATED fetch
/// instance's origins. The public `pub` and the gated `internal` are separate instances, each scoped to its
/// OWN origin; there is no shared allowlist to over-permit.
#[test]
fn a_public_fetch_instance_cannot_reach_a_gated_fetch_s_origins() {
    let mut requested = vec![
        "pub=fetch:https://public.example".to_owned(),
        "internal=fetch:http://10.0.0.5".to_owned(),
    ];
    let fetch = FetchScope::extract(&mut requested).expect("parse");
    let public = fetch
        .services()
        .iter()
        .find(|s| s.name() == "pub")
        .expect("pub");
    let internal = fetch
        .services()
        .iter()
        .find(|s| s.name() == "internal")
        .expect("internal");

    // The public instance is scoped to its OWN origin (not unconstrained), and it is a SEPARATE allowlist
    // from the gated instance's: there is no shared list holding the internal origin for it to reach. (That
    // an allowlist admits ONLY its listed origin, exact-match, is proven in `fetch`'s own origin tests.)
    assert!(
        !public.allow().is_unconstrained(),
        "the public fetch is scoped to its own origin only"
    );
    assert!(
        !internal.allow().is_unconstrained(),
        "the gated fetch holds its own internal origin only"
    );
}

/// BLOCKER-3 masking sub-attack: an origin-scoped GATED fetch beside an unconstrained PUBLIC fetch must NOT
/// mask the open relay. Per-service, `refuse_open_relay` reasons about the PUBLIC fetch's own scope, so an
/// unconstrained public fetch is refused even when a second, scoped, gated fetch is present.
#[test]
fn a_scoped_gated_fetch_does_not_mask_a_bare_public_open_relay() {
    let mut requested = vec![
        "internal=fetch:http://10.0.0.5".to_owned(), // scoped, gated
        "pub=fetch:".to_owned(),                     // unconstrained, public
    ];
    let fetch = FetchScope::extract(&mut requested).expect("parse");
    let public = vec!["pub".to_owned()];
    assert!(
        fetch.refuse_open_relay(&public).is_err(),
        "an unconstrained public fetch is an open relay even beside a scoped gated fetch (no masking)"
    );
}

/// MAJOR-1: an unconstrained fetch NAMED in `--public` is refused at build time with a teaching error
/// that names the problem and the fix, mirroring the sshd-cannot-be-public refusal.
#[test]
fn an_unconstrained_public_fetch_is_refused_as_an_open_relay() {
    let mut requested = vec!["api=fetch:".to_owned()];
    let fetch = FetchScope::extract(&mut requested).expect("unconstrained fetch parses");
    let public = vec!["api".to_owned()];
    let error = fetch
        .refuse_open_relay(&public)
        .expect_err("a public unconstrained fetch is an open relay and must be refused");
    let message = format!("{error}");
    assert!(
        message.contains("origin-scoped") && message.contains("open relay"),
        "the refusal teaches the fix (origin-scope it) and names the problem (an open relay): {message:?}"
    );
}

/// A `serve api=fetch:https://origin --public api` (a SCOPED public fetch) is the safe, intended shape: its
/// own allowlist is armed, so it is allowed.
#[test]
fn a_scoped_public_fetch_is_allowed() {
    let mut requested = vec!["api=fetch:https://origin.example".to_owned()];
    let fetch = FetchScope::extract(&mut requested).expect("origin parses");
    let public = vec!["api".to_owned()];
    assert!(
        fetch.refuse_open_relay(&public).is_ok(),
        "a public fetch scoped to an origin is armed, not an open relay"
    );
}

/// A `name=fetch:` that is NOT named in `--public` stays legal: it is gated (the family gate terminates it),
/// so an unconstrained allowlist is not an open relay. Only a PUBLIC unconstrained fetch is refused.
#[test]
fn a_gated_bare_fetch_is_allowed() {
    let mut requested = vec!["api=fetch:".to_owned()];
    let fetch = FetchScope::extract(&mut requested).expect("unconstrained fetch parses");
    // `api` is served but NOT public.
    assert!(
        fetch.refuse_open_relay(&[]).is_ok(),
        "a gated (member-only) fetch is unchanged; the family gate terminates it"
    );
}

/// Two `name=recv:<dir>` services de-merge into TWO separate `RecvService`s, each with its own served name
/// and ONLY its own sink dir. `extract` removes them from the requested set (leaving the non-recv entries
/// for the router's grammar), so `a=recv:/x b=recv:/y` writes each peer's pushes into its OWN directory
/// rather than the first-named one (the single-sink bug this fix removes).
#[test]
fn named_recv_dirs_de_merge_into_per_service_instances() {
    let mut requested = vec!["a=recv:/tmp/x".to_owned(), "b=recv:/tmp/y".to_owned()];
    let recv = super::extract_recv_services(&mut requested).expect("entries parse");

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
        "service a keeps its OWN sink dir"
    );
    assert_eq!(
        b.out(),
        std::path::Path::new("/tmp/y"),
        "service b's dir is NOT masked by the first-named one"
    );
}

/// A bare `recv:` (no `=`, no name) names no service and is refused with the `name=addr` teaching
/// error: only `name=recv:<dir>` is spelled.
#[test]
fn bare_recv_is_refused_with_the_name_addr_teaching_error() {
    let mut requested = vec!["recv:".to_owned()];
    let Err(error) = super::extract_recv_services(&mut requested) else {
        panic!("a bare `recv:` should be refused, not served");
    };
    assert!(
        error.to_string().contains("name=addr"),
        "the refusal teaches the grammar: {error}"
    );
}

/// Non-recv services pass through in order, and only recv is de-merged out, so extraction is scoped to recv
/// and does not disturb the rest of the requested set.
#[test]
fn non_recv_services_pass_through_and_only_recv_is_removed() {
    let mut requested = vec![
        "ping=ping:".to_owned(),
        "in=recv:/tmp/x".to_owned(),
        "web=127.0.0.1:8080".to_owned(),
    ];
    let recv = super::extract_recv_services(&mut requested).expect("entries parse");

    assert_eq!(
        requested,
        vec!["ping=ping:".to_owned(), "web=127.0.0.1:8080".to_owned()],
        "the recv entry is removed; ping and the raw forward are left exactly as given, in order"
    );
    assert_eq!(
        recv.len(),
        1,
        "only the one receive service is de-merged out"
    );
}

/// A minimal family gate for a construction test: an empty, non-persisting family gate, so the public
/// proof's per-service check runs without standing up a signet.
fn gated() -> nauthy::Gate {
    nauthy::Gate::rooted(
        nauthy::VerifyKey::new([1u8; 32]),
        nauthy::FileDenylist::empty(std::path::PathBuf::new()),
    )
}

/// The base diagnostic route table the product `serve` path assembles, on a fresh family gate.
fn diagnostics() -> Router {
    super::diagnostics(Router::new(gated()), [0u8; 32]).expect("the base diagnostics bind")
}

/// `serve speed --public speed` BUILDS (speed is OptIn, openable), and `--public <unknown>` is refused with a
/// message that names the served set. Proves the CLI's per-service overlay wires onto the real swoosh
/// handlers through the Router's public proof.
#[test]
fn public_speed_builds_and_public_unknown_is_refused() {
    // `--public speed` builds: `speed` is an OptIn handler, so the overlay proves it open-safe.
    let built = diagnostics().public([svc("speed")]).expose();
    assert!(
        built.is_ok(),
        "`--public speed` must build (speed is openable)"
    );

    // `--public <unknown>` is refused, naming what the node DOES serve.
    let Err(error) = diagnostics().public([svc("nope")]).expose() else {
        panic!("an unknown public name must be refused");
    };
    assert!(
        error.to_string().contains("no service named"),
        "an unknown public name is refused with the served list: {error}"
    );
}

/// `serve logs=file:<path> --public-unsafe logs` lights the `public-UNSAFE` banner tier end-to-end: the raw
/// stream the operator KNOWINGLY named reaches `Posture::Open`, so `Group::of` sorts it into `PublicUnsafe`,
/// and the banner carries BOTH the loud `public-UNSAFE !!` marker and the RESOLVED ABSOLUTE path of the
/// source (the delib-11 exfil tell: the operator sees the exact bytes a stranger can read). Built through the
/// real router `expose` + `manifest` path so the posture-union and `raw_source` resolution are exercised, not
/// a hand-built manifest.
#[test]
fn public_unsafe_reaches_the_public_unsafe_banner_tier() {
    let path = std::env::temp_dir().join("swoosh-public-unsafe-banner");
    let entry = format!("logs=file:{}", path.display());
    // A family BASE gate (not `Gate::Open`), so the whole-node raw-stream door never fires; the unsafe
    // OVERLAY alone opens `logs` (swoosh's per-service model). No handlers are bound: a `file:` source is a
    // raw stream, not a handler, so it needs nothing registered.
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
        "the unsafe-open raw stream reads Open, so its posture lights the loud tier"
    );
    assert_eq!(
        super::Group::of(logs),
        Group::PublicUnsafe,
        "an open raw stream sorts into the loudest group"
    );
    let RawSource::Path(absolute) = logs
        .raw_source
        .as_ref()
        .expect("an open raw stream declares its resolved source")
    else {
        panic!("a file: source resolves to an absolute Path, not Stdin: {logs:?}");
    };

    let banner = render_ready_banner(
        "bf01exampleid",
        ReachKind::Internet,
        MdnsState::Available,
        &[],
        &manifest,
        &display_targets(&[format!("logs=file:{}", path.display())])
            .expect("explicit entries display"),
        &HashSet::new(),
        "ctrl-c to stop",
        None,
    );
    assert!(
        banner.contains("public-UNSAFE !!"),
        "the open raw stream fires the loud banner tier: {banner}"
    );
    assert!(
        banner.contains(absolute.as_str()),
        "the banner names the RESOLVED ABSOLUTE path of the bytes at risk ({absolute}): {banner}"
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
    let Err(error) = diagnostics().public_unsafe([svc("ping")]).expose() else {
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
        .service(
            svc("ssh"),
            super::Sshd {
                host_seed: [0u8; 32],
            },
        )
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
        vec!["speed".to_owned(), "fetch".to_owned()],
        "--public splits on commas into the per-service set"
    );
    // Omitting `--public` opens nothing.
    let wrap = Wrap::try_parse_from(["x"]).expect("no --public parses");
    assert!(
        wrap.serve.public.is_empty(),
        "no --public means nothing is opened"
    );
}

/// The duration timer moved off `--for` onto `--expires` (`--for` is now the WHO family, reserved for
/// `grant issue`). `--expires 30m` parses into the local timer; `--for 30m` no longer parses (the flag is
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
