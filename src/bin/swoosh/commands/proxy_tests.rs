//! `swoosh proxy`'s local half: the URL it composes, the requests its loopback listener answers, the
//! response heads it passes on, and the bounds it keeps on local connections.

use core::cell::{OnceCell, RefCell};
use core::net::SocketAddr;
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::sync::Arc;

use bifrost::Session;
use clap::Parser as _;
use swoosh::contacts::Contacts;
use swoosh::credential::Credential;
use swoosh::peer::Machine;
use swoosh::peers::{Hints, Lane, Peers, Presents};
use swoosh::reaching::{BindRole, Reaching as _};
use swoosh::serve::control_codec::{OpenRefusal, PeerRefusal};
use swoosh::streams::{Ask, Opened, OwnBind, Resident, StreamSource, Tracked, Unopened};
use swoosh::testkit::TestWrite;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use super::{
    BadHead, Client, HEAD_TIMEOUT, Head, Local, Parsed, ProxyCmd, Refused, accept_each, origin_url,
};
use crate::commands::connect::{Listener, Over, PipeFailures};
use crate::commands::route::Route;
use crate::commands::through_serve::tests::{
    Answer, END, Heard, ROW_BOUND, Reply, Rig, Served, book, machine, on_a_big_stack, resident_key,
    routed, scripted,
};
use crate::commands::through_serve::{Dial, ServeStopped, StandingEnded, ThisMachine};

/// A fixed token, so a test can write the request a downloader sends to the printed URL.
const TOKEN: &str = "00112233445566778899aabbccddeeff";

/// The base URL the tests' proxy was given.
const BASE: &str = "https://example.com/big.iso";

/// `text` parsed, as clap parses a typed URL.
fn url(text: &str) -> url::Url {
    url::Url::parse(text).unwrap()
}

#[test]
fn root_request_uses_the_base_verbatim() {
    assert_eq!(
        origin_url(&url("https://example.com/big.iso"), "/").unwrap(),
        "https://example.com/big.iso"
    );
}

#[test]
fn a_path_and_query_resolve_against_the_base() {
    assert_eq!(
        origin_url(&url("https://api.example.com"), "/users?id=5").unwrap(),
        "https://api.example.com/users?id=5"
    );
}

/// A base with a trailing slash and a target with a leading one compose to ONE slash, not two: the join
/// merges the paths per the URL grammar, so `https://api.example.com/` + `/users` is
/// `https://api.example.com/users`, never the `https://api.example.com//users` a raw `format!` yields.
#[test]
fn a_trailing_slash_base_and_leading_slash_target_do_not_double_the_slash() {
    assert_eq!(
        origin_url(&url("https://api.example.com/"), "/users").unwrap(),
        "https://api.example.com/users"
    );
}

/// A URL that does not parse is a usage error (exit 2), refused before anything is dialed or printed.
///
/// Take the URL as text instead and it parses, to a run that prints a local URL and serves 502 on every
/// request.
#[test]
fn a_proxy_url_that_does_not_parse_is_a_usage_error() {
    let error =
        <crate::Cli as clap::Parser>::try_parse_from(["swoosh", "proxy", "nas", "not a url"])
            .expect_err("a URL that does not parse refuses");
    assert_eq!(error.exit_code(), 2, "{error}");
}

/// The listener the tests' requests are written to: loopback, port 8080, the fixed [`TOKEN`].
fn local() -> Local {
    local_at(SocketAddr::from(([127, 0, 0, 1], 8080)))
}

fn local_at(addr: SocketAddr) -> Local {
    Local {
        addr,
        token: TOKEN.to_owned(),
    }
}

/// A `GET` of `target` naming `hosts`, each as its own `Host` line.
fn request(target: &str, hosts: &[&str]) -> Parsed {
    Parsed {
        method: "GET".to_owned(),
        target: target.to_owned(),
        headers: hosts
            .iter()
            .map(|host| ("Host".to_owned(), (*host).to_owned()))
            .collect(),
    }
}

/// What the listener makes of `target`, sent to its own address.
fn admitted(target: &str) -> Result<String, Refused> {
    local().admit(&request(target, &["127.0.0.1:8080"]), &url(BASE))
}

/// A request sent to the printed URL is admitted, root and path alike: the token's segment is the
/// URL's and never the origin's.
#[test]
fn the_printed_url_is_admitted_and_its_path_resolves_past_the_token() {
    assert_eq!(admitted(&format!("/{TOKEN}/")), Ok(BASE.to_owned()));
    assert_eq!(admitted(&format!("/{TOKEN}")), Ok(BASE.to_owned()));
    assert_eq!(
        admitted(&format!("/{TOKEN}/other.iso?part=2")),
        Ok("https://example.com/other.iso?part=2".to_owned())
    );
}

/// The `Host` must name this listener. A page that rebinds its own name to 127.0.0.1 makes the browser
/// send that name, so it is refused; so is a request with no `Host`, or two.
#[test]
fn a_request_naming_another_host_is_refused() {
    let target = format!("/{TOKEN}/");
    for hosts in [
        ["rebound.example:8080"].as_slice(),
        ["127.0.0.1:9090"].as_slice(),
        [].as_slice(),
        ["127.0.0.1:8080", "rebound.example"].as_slice(),
    ] {
        assert_eq!(
            local().admit(&request(&target, hosts), &url(BASE)).err(),
            Some(Refused::Host),
            "Host {hosts:?}"
        );
    }
}

/// On port 80 a client writes the `Host` with no port, as http's default, so the bare address names the
/// listener too; on any other port the port is part of the name.
///
/// Compare the `Host` to the address alone and a listener pinned to 80 refuses every request.
#[test]
fn on_port_80_the_host_may_omit_the_port() {
    let target = format!("/{TOKEN}/");
    let on_80 = local_at(SocketAddr::from(([127, 0, 0, 1], 80)));
    for host in ["127.0.0.1", "127.0.0.1:80"] {
        assert_eq!(
            on_80.admit(&request(&target, &[host]), &url(BASE)),
            Ok(BASE.to_owned()),
            "Host {host}"
        );
    }
    assert_eq!(
        local()
            .admit(&request(&target, &["127.0.0.1"]), &url(BASE))
            .err(),
        Some(Refused::Host),
        "on 8080 the port is required"
    );
}

/// The path must start with the token, as its whole first segment. Another account on this machine can
/// find the port; without the token it gets nothing through.
#[test]
fn a_request_without_the_token_is_refused() {
    for target in [
        "/".to_owned(),
        "/big.iso".to_owned(),
        "/ffeeddccbbaa99887766554433221100/".to_owned(),
        format!("/{TOKEN}x/"),
        format!("/{}", &TOKEN[..TOKEN.len() - 1]),
    ] {
        assert_eq!(
            local().rest(&target),
            Err(Refused::Token),
            "target {target}"
        );
    }
}

/// An absolute-form target names its own host, and a join would go there: refused as a target, before
/// the token is even read.
#[test]
fn an_absolute_form_target_is_refused() {
    for target in [
        format!("http://evil.example/{TOKEN}/"),
        "https://evil.example/".to_owned(),
        "*".to_owned(),
    ] {
        assert_eq!(
            local().rest(&target),
            Err(Refused::Target),
            "target {target}"
        );
    }
}

/// After the token, `//` starts a new host in the URL grammar: `//evil.example/x` joined onto the base
/// is `https://evil.example/x`. Refused as a target.
#[test]
fn a_target_that_starts_a_new_host_is_refused() {
    assert_eq!(
        local().rest(&format!("/{TOKEN}//evil.example/x")),
        Err(Refused::Target)
    );
}

/// Whatever passes the form check, the composed URL must stay on the base's origin. A `\` is a `/` to
/// the URL grammar for an `https` base, so `/\evil.example/x` passes the form check and still names a new
/// host; the origin check is what refuses it.
#[test]
fn a_target_that_leaves_the_origin_is_refused() {
    let target = format!("/{TOKEN}/\\evil.example/x");
    assert_eq!(
        local().rest(&target),
        Ok("/\\evil.example/x"),
        "the form check alone lets this through"
    );
    assert_eq!(admitted(&target), Err(Refused::Target));
}

/// A target that does not join onto the base is the client's bad request, refused as a target (400)
/// before anything is dialed: `/\evil.example:99999/x` passes the form check, and the URL grammar reads
/// it as a host with a port out of range.
///
/// Treat a failed join as the proxy's own failure instead and the client reads a 502.
#[test]
fn a_target_that_does_not_join_is_refused() {
    let target = format!("/{TOKEN}/\\evil.example:99999/x");
    assert!(
        local().rest(&target).is_ok(),
        "the form check alone lets this through"
    );
    assert_eq!(admitted(&target), Err(Refused::Target));
}

/// The printed URL carries a fresh token each run, so a URL seen once (a shell history, a log) is no use
/// to the next run.
#[test]
fn the_printed_url_carries_a_fresh_token_each_run() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let (first, second) = (Local::new(addr), Local::new(addr));
    assert_ne!(first.token, second.token, "two runs mint two tokens");
    assert_eq!(first.token.len(), 32, "128 bits, in hex");
    assert_eq!(
        first.to_string(),
        format!("http://127.0.0.1:8080/{}/", first.token)
    );
}

/// A head from the machine is written to a local client only once checked: a CR or LF in a value would
/// split the local response and add lines the machine chose, and a name that is not a token is no header.
#[test]
fn a_header_the_machine_sent_malformed_is_refused() {
    for (name, value) in [
        ("X-Note", "fine\r\nSet-Cookie: session=stolen"),
        ("X-Note", "fine\nTransfer-Encoding: chunked"),
        ("X-Note", "nul\0byte"),
        ("X Note", "a space in the name"),
        ("X-Note\r\nSet-Cookie", "x"),
        ("", "no name"),
    ] {
        let headers = vec![(name.to_owned(), value.to_owned())];
        assert!(
            matches!(Head::checked(200, headers), Err(BadHead::Header)),
            "{name:?}: {value:?}"
        );
    }
    let fine = Head::checked(
        206,
        vec![("Content-Range".to_owned(), "bytes 0-1/2".to_owned())],
    )
    .expect("a well-formed head passes");
    assert_eq!(fine.headers.len(), 1);
}

/// Only a final status passes: an informational one has no place on a closed response, and a number
/// outside the HTTP range is no status at all.
#[test]
fn a_status_outside_200_to_599_is_refused() {
    for status in [0, 100, 199, 600, 999, u16::MAX] {
        assert!(
            matches!(Head::checked(status, Vec::new()), Err(BadHead::Status(found)) if found == status),
            "status {status}"
        );
    }
    for status in [200, 404, 599] {
        assert!(Head::checked(status, Vec::new()).is_ok(), "status {status}");
    }
}

/// A thin clap wrapper so a test can parse a `ProxyCmd` from a real argv the same way the binary does.
#[derive(clap::Parser)]
struct Wrap {
    #[command(flatten)]
    proxy: ProxyCmd,
}

/// `swoosh proxy <peer> <url>` is FAMILY-gated by default: it dials carrying the `Family` credential,
/// so the owner reaching their OWN exit node presents the member badge (the fix for the
/// owner-reaching-own-node 403). Before this redesign the verb was slip-only and an owner with no slip
/// was refused. The identity derived from `Family` is `PersistedIfPresent`, so the self-badge roots
/// correctly.
#[test]
fn proxy_is_family_gated_by_default_so_it_presents_a_badge() {
    let key = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]).to_string();
    let cmd = Wrap::try_parse_from(["swoosh", &key, "http://example.com/x"])
        .expect("proxy parses")
        .proxy;
    assert!(
        matches!(
            cmd.bind_role(),
            BindRole::Dialing(Credential::Family { present: None })
        ),
        "proxy to a key dials presenting the member badge"
    );
    assert_eq!(
        cmd.identity(),
        swoosh::identity::Identity::PersistedIfPresent,
        "a Family credential fuses the identity to PersistedIfPresent so the self-badge roots"
    );
}

/// What the far half of a [`Scripted`] session does with the stream it is handed.
#[derive(Clone, Copy)]
enum Script {
    /// Nothing: the far half is dropped, so the stream is never answered.
    Silent,
    /// Admit the request, read the origin request, and answer with this head and a one-line body.
    Answer(u16, &'static str, &'static str),
    /// Fail every stream as it opens, the transport's cause carrying this text.
    Fails(&'static str),
}

/// A machine whose sessions' streams are in-memory pipes, with the far half driven by a [`Script`].
/// A dial hands back a clone sharing its counts.
#[derive(Clone)]
struct Scripted {
    script: Script,
    opened: Arc<AtomicUsize>,
    dials: Arc<AtomicUsize>,
}

impl Scripted {
    fn new(script: Script) -> Self {
        Self {
            script,
            opened: Arc::new(AtomicUsize::new(0)),
            dials: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl bifrost::Transport for Scripted {
    type Session = Self;

    fn node_id(&self) -> bifrost::NodeId {
        Session::peer(self)
    }

    fn local_addr(&self) -> bifrost::Addr {
        bifrost::Addr::from_node(Session::peer(self))
    }

    fn bound_sockets(&self) -> Vec<SocketAddr> {
        Vec::new()
    }

    async fn connect(&self, _addr: bifrost::Addr) -> Result<Self, bifrost::Error> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        Ok(self.clone())
    }

    async fn accept(&self) -> Result<Self, bifrost::Error> {
        Err(bifrost::Error::Closed)
    }

    async fn close(&self) {}
}

impl Session for Scripted {
    type Write = TestWrite<tokio::io::WriteHalf<tokio::io::DuplexStream>>;
    type Read = tokio::io::ReadHalf<tokio::io::DuplexStream>;

    fn peer(&self) -> bifrost::NodeId {
        bifrost::NodeId::from_ed25519_secret(&[0u8; 32])
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        if let Script::Fails(cause) = self.script {
            return Err(bifrost::Error::Stream(cause.into()));
        }
        let (near, mut far) = tokio::io::duplex(64 * 1024);
        if let Script::Answer(status, name, value) = self.script {
            tokio::spawn(async move {
                tightbeam::protocol::Request::read(&mut far)
                    .await
                    .expect("the proxy asks for its service");
                tightbeam::protocol::Response::Ok
                    .write(&mut far)
                    .await
                    .expect("admit");
                ::fetch::http::FetchRequest::read(&mut far)
                    .await
                    .expect("the proxy sends its origin request");
                ::fetch::http::FetchResponse::Ok {
                    status,
                    headers: vec![(name.to_owned(), value.to_owned())],
                }
                .write(&mut far)
                .await
                .expect("answer");
                far.write_all(b"body\n").await.expect("body");
                far.shutdown().await.expect("end");
            });
        }
        let (read, write) = tokio::io::split(near);
        Ok((write.into(), read))
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        Err(bifrost::Error::Closed)
    }

    /// Open until dropped: a held session already closed is redialed before its next stream.
    async fn wait_closed(&self) {
        core::future::pending::<()>().await;
    }

    /// A double that carries nothing has nothing to end.
    fn close(&self) {}

    /// No transport under it, so no path, once.
    fn path_changes(&self) -> bifrost::PathChanges {
        bifrost::PathChanges::fixed(bifrost::Path::Unknown)
    }
}

/// The proxy command the tests serve with, with `extra` appended to its argv.
fn proxy(extra: &[&str]) -> ProxyCmd {
    let key = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]).to_string();
    let mut argv = vec!["swoosh", &key, "http://example.com/x"];
    argv.extend_from_slice(extra);
    Wrap::try_parse_from(argv).expect("proxy parses").proxy
}

/// A fresh home whose standing is a device badge for the machine `this`, as every own-bind request
/// presents it.
fn standing(this: bifrost::NodeId) -> swoosh::home::Home {
    static HOMES: AtomicUsize = AtomicUsize::new(0);
    let at = HOMES.fetch_add(1, Ordering::SeqCst);
    crate::probe_route_tests::device_home(&format!("proxy-{at}"), this).0
}

/// `run` over `cmd`'s listener to `machine`, with streams from `source` worded by `route`.
async fn listening<S: StreamSource, R>(
    cmd: &ProxyCmd,
    source: S,
    route: &Route<'_>,
    machine: &Machine,
    run: impl AsyncFnOnce(&Listener<'_, S>) -> R,
) -> R {
    let ask = cmd.ask(machine);
    let listener = Listener {
        source: &source,
        ask: &ask,
        route,
        machine,
    };
    run(&listener).await
}

/// `run` over `cmd`'s listener to `machine` by own bind on `node` and its run's `peers`, presenting the
/// standing a fresh home holds.
async fn own<'n, T: bifrost::Transport, R>(
    node: &'n bifrost::Node<T, bifrost::NoDiscovery>,
    peers: &Peers<'n, T, bifrost::NoDiscovery>,
    cmd: &ProxyCmd,
    machine: &Machine,
    run: impl AsyncFnOnce(&Listener<'_, OwnBind<'_, 'n, T, bifrost::NoDiscovery>>) -> R,
) -> R {
    let home = standing(node.node_id());
    let bound = crate::probe_route_tests::bound();
    let route = Route::Own {
        bound: &bound,
        this: node.node_id(),
    };
    let credential = Credential::dialing(&cmd.peer, cmd.service.as_str());
    let source = OwnBind::new(peers, &home, node.node_id(), &credential);
    listening(cmd, source, &route, machine, run).await
}

/// `run` over `cmd`'s listener to `me/nas` through the `serve` at `served`, as the dialing route runs
/// it: the run's one tracked source over the resident.
async fn through<R>(
    served: &Served,
    cmd: &ProxyCmd,
    run: impl AsyncFnOnce(&Listener<'_, &Tracked<Resident>>) -> R,
) -> R {
    let contacts = book();
    let machine = machine(&contacts, "me/nas");
    let socket = Rc::new(swoosh::node_client::UidSocket::resolve(&served.home).unwrap());
    let source = Tracked::new(Resident::new(Rc::clone(&socket)), HashMap::new());
    let dial = Dial {
        machine: &machine,
        service: &cmd.service,
        contacts: &contacts,
    };
    let route = Route::Serve {
        dial: &dial,
        socket: &socket,
    };
    listening(cmd, &source, &route, &machine, run).await
}

/// Write `head` to a fresh local listener, serve that one connection by own bind to a machine whose
/// sessions are `session`, and return what `serve` returned and the whole HTTP response the local client
/// read.
async fn exchange(
    head: impl FnOnce(&Local) -> String,
    cmd: &ProxyCmd,
    session: &Scripted,
) -> (eyre::Result<ControlFlow<Over>>, String) {
    let node = bifrost::Node::new(session.clone(), bifrost::NoDiscovery);
    let peers = Peers::new(&node);
    let machine = scripted_machine();
    own(&node, &peers, cmd, &machine, async |listener| {
        exchange_on(head, cmd, listener).await
    })
    .await
}

/// [`exchange`] through `listener`, whose source the caller holds.
async fn exchange_on<S: StreamSource>(
    head: impl FnOnce(&Local) -> String,
    cmd: &ProxyCmd,
    listener: &Listener<'_, S>,
) -> (eyre::Result<ControlFlow<Over>>, String) {
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let local = local_at(tcp.local_addr().unwrap());
    let mut client = TcpStream::connect(local.addr).await.unwrap();
    let (server, _) = tcp.accept().await.unwrap();
    client.write_all(head(&local).as_bytes()).await.unwrap();

    let failures = PipeFailures::new(&scripted_machine(), Vec::new());
    let served = cmd
        .serve(
            Client::new(server, &OnceCell::new()),
            &local,
            listener,
            &failures,
        )
        .await;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    (served, String::from_utf8_lossy(&response).into_owned())
}

/// A run's warnings, kept unread: for a row that pins something else.
fn quiet() -> PipeFailures<Vec<u8>> {
    PipeFailures::new(&machine(&book(), "me/nas"), Vec::new())
}

/// The scripted machines' key, as the one machine a run dials.
fn scripted_machine() -> Machine {
    machine(
        &book(),
        &bifrost::NodeId::from_ed25519_secret(&[0u8; 32]).to_string(),
    )
}

/// The request a downloader sends to the printed URL.
fn printed(local: &Local) -> String {
    format!(
        "GET /{}/ HTTP/1.1\r\nHost: {}\r\n\r\n",
        local.token, local.addr
    )
}

/// The line the DOWNLOADER reads when a request fails without a refusal (here one that never reached
/// the exit node at all) names no service and no command: a failure that was not a refusal says nothing
/// about what the machine serves, whatever service was asked for.
#[tokio::test]
async fn a_failed_request_teaches_no_service() {
    let session = Scripted::new(Script::Silent);
    for args in [&[][..], &["--service", "news"][..]] {
        let (served, body) = exchange(printed, &proxy(args), &session).await;
        assert!(served.is_err(), "the silent session fails the request");
        assert!(!body.contains("swoosh serve"), "{args:?}: {body}");
        assert!(!body.contains("service add"), "{args:?}: {body}");
    }
}

/// A request the listener refuses is answered locally: no stream opens, so the credential never leaves,
/// and the body teaches nothing about the machine or the run.
#[tokio::test]
async fn a_refused_local_request_never_opens_a_stream() {
    for (head, status) in [
        (
            Box::new(|local: &Local| {
                format!(
                    "GET /{}/ HTTP/1.1\r\nHost: rebound.example:{}\r\n\r\n",
                    local.token,
                    local.addr.port()
                )
            }) as Box<dyn FnOnce(&Local) -> String>,
            "HTTP/1.1 400 Bad Request",
        ),
        (
            Box::new(|local: &Local| format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", local.addr)),
            "HTTP/1.1 404 Not Found",
        ),
    ] {
        let session = Scripted::new(Script::Silent);
        let (served, text) = exchange(head, &proxy(&[]), &session).await;
        assert!(served.is_ok(), "a refused request is answered, not failed");
        assert!(text.starts_with(status), "{text}");
        assert!(text.ends_with("use the URL swoosh proxy printed"), "{text}");
        assert_eq!(session.opened.load(Ordering::SeqCst), 0, "no stream opened");
    }
}

/// A head the machine sent malformed never reaches the local client: it gets a `502`, and none of the
/// lines the machine tried to add.
#[tokio::test]
async fn a_malformed_head_from_the_machine_serves_a_502_and_none_of_its_lines() {
    for script in [
        Script::Answer(200, "X-Note", "fine\r\nSet-Cookie: session=stolen"),
        Script::Answer(101, "Upgrade", "websocket"),
    ] {
        let session = Scripted::new(script);
        let (served, text) = exchange(printed, &proxy(&[]), &session).await;
        assert!(served.is_err(), "the head is refused");
        assert!(text.starts_with("HTTP/1.1 502 Bad Gateway"), "{text}");
        assert!(!text.contains("Set-Cookie"), "{text}");
        assert!(!text.contains("websocket"), "{text}");
        assert!(
            text.contains("the machine answered with an invalid"),
            "{text}"
        );
    }

    // The same exchange with a clean head passes it through.
    let session = Scripted::new(Script::Answer(200, "X-Note", "fine"));
    let (served, text) = exchange(printed, &proxy(&[]), &session).await;
    assert!(served.is_ok(), "{:?}", served.err());
    assert!(
        text.starts_with("HTTP/1.1 200 OK\r\nX-Note: fine\r\n"),
        "{text}"
    );
}

/// A local client that connects and sends nothing is let go after [`HEAD_TIMEOUT`], and gets a `502`
/// saying why. Without the bound it would hold its descriptor, and its slot under the cap, for good.
#[tokio::test(start_paused = true)]
async fn a_client_that_sends_no_head_is_let_go() {
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let local = local_at(tcp.local_addr().unwrap());
    let mut client = TcpStream::connect(local.addr).await.unwrap();
    let (server, _) = tcp.accept().await.unwrap();
    let session = Scripted::new(Script::Silent);
    let node = bifrost::Node::new(session.clone(), bifrost::NoDiscovery);
    let peers = Peers::new(&node);
    let cmd = proxy(&[]);
    let machine = scripted_machine();
    let failures = PipeFailures::new(&machine, Vec::new());

    let served = own(&node, &peers, &cmd, &machine, async |listener| {
        tokio::time::timeout(
            HEAD_TIMEOUT * 6,
            cmd.serve(
                Client::new(server, &OnceCell::new()),
                &local,
                listener,
                &failures,
            ),
        )
        .await
    })
    .await
    .expect("the head timeout lets the connection go before the test's own bound");
    assert!(served.is_err(), "a silent client is an error, logged");
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 502 Bad Gateway"), "{text}");
    assert!(text.contains("no request within 10s"), "{text}");
}

/// The listener holds at most its cap of connections at once; the rest wait in the kernel's backlog
/// until one ends.
#[tokio::test]
async fn the_listener_holds_at_most_its_cap_of_connections() {
    const CAP: usize = 2;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let held = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&held);
    let accepting = tokio::spawn(accept_each(listener, CAP, move |_tcp| {
        counted.fetch_add(1, Ordering::SeqCst);
        // Never ends, so every accepted connection stays held.
        core::future::pending::<ControlFlow<eyre::Report>>()
    }));

    let mut clients = Vec::new();
    for _ in 0..CAP + 3 {
        clients.push(TcpStream::connect(addr).await.unwrap());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while held.load(Ordering::SeqCst) < CAP && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Room for any accept past the cap to happen, were the cap gone.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(held.load(Ordering::SeqCst), CAP, "accepts stop at the cap");
    accepting.abort();
}

/// The `proxy` the tests run to `me/nas` and its key, for a run that ends before any request.
fn to_nas() -> (ProxyCmd, Contacts, Machine) {
    let contacts = book();
    let cmd = Wrap::try_parse_from(["swoosh", "me/nas", "http://example.com/x"])
        .expect("proxy parses")
        .proxy;
    let machine = cmd.peer.machine(&contacts).expect("one machine");
    (cmd, contacts, machine)
}

/// A proxy one of your devices refuses ends with the one dial refusal before any URL is printed or a
/// listener bound, on both paths: admission is proven on one stream first, and the device is asked why
/// through the same source, one `control.serve` stream on Main asking for its list. A proxy that skipped the check
/// would serve until stopped, so the run is bounded.
#[test]
fn a_refused_proxy_names_the_cause_on_both_paths() {
    use swoosh::serve::control_codec::OpenLane;

    on_a_big_stack(async || {
        let line = "me/nas does not serve proxy\n  Only nas can add it; on nas, run:\n    swoosh service add proxy:<url>";
        let (cmd, contacts, machine) = to_nas();
        let peer = swoosh::testkit::ScriptedPeer::new(
            machine.key(),
            [
                swoosh::testkit::Script::Refuse(bifrost::Refusal::NotAdmitted),
                swoosh::testkit::Script::Lists(vec!["ping"]),
            ],
        );
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = Peers::new(&node);
        let home = standing(node.node_id());
        let bound = crate::probe_route_tests::bound();
        let route = Route::Own {
            bound: &bound,
            this: node.node_id(),
        };
        let credential = Credential::dialing(&cmd.peer, cmd.service.as_str());
        let source = OwnBind::new(&peers, &home, node.node_id(), &credential);
        let mut out = Vec::new();
        let error = tokio::time::timeout(
            ROW_BOUND,
            cmd.proxy(source, &route, &machine, &contacts, &mut out),
        )
        .await
        .expect("a refused proxy ends, never serving")
        .expect_err("a refused proxy exits non-zero");
        assert_eq!(format!("{error:#}"), line);
        assert_eq!(out, b"", "no URL");
        let asked: Vec<String> = peer
            .requests()
            .into_iter()
            .map(|request| request.service)
            .collect();
        assert_eq!(asked, ["proxy", "control.serve"]);

        let mut served = Served::new("proxy-refused").await;
        let rig = Rig::default();
        let resident = scripted(
            &mut served,
            vec![
                Answer::Refuse(OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
                Answer::AfterEnd(crate::dial_route_tests::list_answer(&["ping"])),
            ],
            &rig,
        );
        let mut out = Vec::new();
        let error = tokio::time::timeout(ROW_BOUND, async {
            let socket = Rc::new(swoosh::node_client::UidSocket::resolve(&served.home).unwrap());
            let source = Tracked::new(Resident::new(Rc::clone(&socket)), HashMap::new());
            let dial = Dial {
                machine: &machine,
                service: &cmd.service,
                contacts: &contacts,
            };
            let route = Route::Serve {
                dial: &dial,
                socket: &socket,
            };
            cmd.proxy(&source, &route, &machine, &contacts, &mut out)
                .await
        })
        .await
        .expect("a refused proxy ends, never serving")
        .expect_err("a refused proxy exits non-zero");
        rig.stop.cancel();
        let heard = resident.await.unwrap();
        assert_eq!(format!("{error:#}"), line);
        assert_eq!(out, b"", "no URL");
        let asked: Vec<(&str, OpenLane)> = heard
            .iter()
            .map(|open| (open.service.as_str(), open.lane))
            .collect();
        assert_eq!(
            asked,
            [("proxy", OpenLane::Bulk), ("control.serve", OpenLane::Main)]
        );
    });
}

/// A bare `proxy` admitted prints its URL and nothing else on `out`, stdout in a run: the line a
/// refused request's body sends a downloader back to, and the one a script reads.
#[test]
fn an_admitted_proxy_prints_its_url_alone() {
    on_a_big_stack(async || {
        let (cmd, contacts, machine) = to_nas();
        let peer =
            swoosh::testkit::ScriptedPeer::new(machine.key(), [swoosh::testkit::Script::Holds]);
        let node = bifrost::Node::new(peer, bifrost::NoDiscovery);
        let peers = Peers::new(&node);
        let home = standing(node.node_id());
        let bound = crate::probe_route_tests::bound();
        let route = Route::Own {
            bound: &bound,
            this: node.node_id(),
        };
        let credential = Credential::dialing(&cmd.peer, cmd.service.as_str());
        let source = OwnBind::new(&peers, &home, node.node_id(), &credential);
        let out = Shared::default();
        let mut writer = out.clone();
        // The run serves until stopped, so it is dropped once its first line is out, and a while
        // after, so a line written later would be seen too.
        let printed = async {
            while !out.0.borrow().ends_with(b"\n") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        tokio::time::timeout(ROW_BOUND, async {
            tokio::select! {
                ended = cmd.proxy(source, &route, &machine, &contacts, &mut writer) => {
                    panic!("an admitted proxy serves until stopped: {ended:?}")
                }
                () = printed => {}
            }
        })
        .await
        .expect("an admitted proxy prints its URL");
        let out = String::from_utf8(out.0.take()).unwrap();
        let url = out.strip_suffix('\n').unwrap();
        assert!(!url.contains('\n'), "the URL alone: {out:?}");
        let url = url::Url::parse(url).unwrap();
        assert_eq!(url.host_str(), Some("127.0.0.1"), "{url}");
        assert_eq!(url.path().len(), 2 + 32, "one token segment: {url}");
    });
}

/// A writer the test reads while the run still holds it.
#[derive(Clone, Default)]
struct Shared(Rc<RefCell<Vec<u8>>>);

impl std::io::Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Every request rides the Bulk lane: with the machine's Main lane full, a request still passes, on a
/// held session of its own.
#[tokio::test]
async fn proxy_requests_ride_the_bulk_lane() {
    let session = Scripted::new(Script::Answer(200, "X-Note", "fine"));
    let node = bifrost::Node::new(session.clone(), bifrost::NoDiscovery);
    let peers = Peers::new(&node);
    let key = Session::peer(&session);
    let mut main = Vec::new();
    for _ in 0..64 {
        main.push(
            peers
                .open(
                    key,
                    Hints::NONE,
                    "proxy".parse().unwrap(),
                    Lane::Main,
                    Presents::Standing(None),
                )
                .await
                .expect("below the Main cap"),
        );
    }
    assert!(matches!(
        peers
            .open(
                key,
                Hints::NONE,
                "proxy".parse().unwrap(),
                Lane::Main,
                Presents::Standing(None)
            )
            .await,
        Err(swoosh::peers::OpenError::Busy)
    ));
    let cmd = proxy(&[]);
    let machine = scripted_machine();
    let (served, text) = own(&node, &peers, &cmd, &machine, async |listener| {
        exchange_on(printed, &cmd, listener).await
    })
    .await;
    assert!(served.is_ok(), "{:?}", served.err());
    assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
    assert_eq!(
        session.dials.load(Ordering::SeqCst),
        2,
        "one session per lane"
    );
}

/// The status line and body of a whole HTTP response.
fn status_and_body(response: &str) -> (&str, &str) {
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((response, ""));
    (head.lines().next().unwrap_or_default(), body)
}

/// `requests` local clients, one at a time, each sending the GET `local` printed and reading its whole
/// response: the responses, in order.
fn requesting(local: &Local, requests: usize) -> tokio::task::JoinHandle<Vec<String>> {
    let head = printed(local);
    let addr = local.addr;
    tokio::spawn(async move {
        let mut responses = Vec::new();
        for _ in 0..requests {
            responses.push(got(addr, &head).await);
        }
        responses
    })
}

/// One local client at `addr` that sends `head` and reads its whole response.
async fn got(addr: SocketAddr, head: &str) -> String {
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(head.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response).await;
    String::from_utf8_lossy(&response).into_owned()
}

/// `proxy`'s listener for `me/nas` through a resident answering `answers`, while `requests` clients
/// send the printed GET one at a time. Returns the line the run ended with, each response and the Opens
/// the resident heard.
async fn proxied(
    tag: &str,
    answers: Vec<Answer>,
    requests: usize,
) -> (eyre::Report, Vec<String>, Vec<Heard>) {
    let (ended, responses, heard, _) = proxied_warning(tag, answers, requests).await;
    (ended, responses, heard)
}

/// [`proxied`], with what the run wrote to stderr as it ran.
async fn proxied_warning(
    tag: &str,
    answers: Vec<Answer>,
    requests: usize,
) -> (eyre::Report, Vec<String>, Vec<Heard>, String) {
    let mut served = Served::new(tag).await;
    let rig = Rig::default();
    let resident = scripted(&mut served, answers, &rig);
    let cmd = proxy(&[]);
    let (ended, responses, err) = through(&served, &cmd, async |listener| {
        listened(&cmd, listener, requests).await
    })
    .await;
    rig.stop.cancel();
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .expect("the resident ended")
        .unwrap();
    (ended, responses, heard, err)
}

/// `cmd`'s listener answering through `listener`, which leaves for `me/nas`, while `requests` clients
/// send the printed GET one at a time, until the run ends: the line it ended with, each response, and
/// what it wrote to stderr.
async fn listened<S: StreamSource>(
    cmd: &ProxyCmd,
    listener: &Listener<'_, S>,
    requests: usize,
) -> (eyre::Report, Vec<String>, String) {
    let mut err = Vec::new();
    let failures = PipeFailures::new(&machine(&book(), "me/nas"), &mut err);
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let local = local_at(tcp.local_addr().unwrap());
    let clients = requesting(&local, requests);
    let (ended, responses) = tokio::time::timeout(ROW_BOUND, async {
        tokio::join!(cmd.answer_each(tcp, &local, listener, &failures), clients)
    })
    .await
    .expect("the run ended");
    (ended, responses.unwrap(), String::from_utf8(err).unwrap())
}

/// The `502` a request gets when `serve` is gone: one line, the serve-stopped line's head.
const STOPPED_BODY: &str =
    "proxy failed: swoosh serve stopped here and ended the connection to me/nas";

/// `proxy` through `serve` proves admission on one Open on Bulk, unobserved, and ends that stream with
/// End rather than dropping it, so the machine reads a clean empty upload, never a reset.
#[tokio::test]
async fn proxy_through_serve_admits_on_an_open_it_ends_with_end() {
    use swoosh::serve::control_codec::{Observation, OpenLane};

    let mut served = Served::new("proxy-admit").await;
    let resident = scripted(&mut served, vec![Answer::Attach], &Rig::default());
    let cmd = proxy(&[]);
    let contacts = book();
    // The run listens on once admitted; the resident resolves once the admission stream has closed.
    let heard = through(&served, &cmd, async |listener| {
        let mut out = Vec::new();
        tokio::time::timeout(ROW_BOUND, async {
            tokio::select! {
                ended = cmd.proxy(listener.source, listener.route, listener.machine, &contacts, &mut out) => {
                    panic!("the run ended before a request: {:?}", ended.map(|_| ()))
                }
                heard = resident => heard.unwrap(),
            }
        })
        .await
        .expect("the admission Open was made and closed")
    })
    .await;
    let [admission] = heard.as_slice() else {
        panic!("{} Opens, not the one admission", heard.len());
    };
    assert_eq!(admission.lane, OpenLane::Bulk);
    assert_eq!(admission.observation, Observation::Unobserved);
    assert_eq!(
        admission.upload, END,
        "the admission stream ends with End alone"
    );
}

/// A request's own failure (`serve`'s `Busy`, the machine unavailable, a cut while `serve` still
/// answers) keeps the listener up: its client gets a `502` whose body is one line, the head of the
/// terminal's line with none of its detail, and the next request's Open is made.
#[tokio::test]
async fn a_requests_own_failure_keeps_the_proxy_up_and_its_502_is_one_line() {
    let (ended, responses, heard) = proxied(
        "proxy-own",
        vec![
            Answer::Refuse(OpenRefusal::Busy),
            Answer::Refuse(OpenRefusal::Peer(PeerRefusal::Unavailable(
                bifrost::RefusalDetail::bounded("down"),
            ))),
            Answer::Cut,
            Answer::Refuse(OpenRefusal::Busy),
        ],
        5,
    )
    .await;
    assert!(ended.is::<ServeStopped>(), "{ended:#}");
    assert_eq!(heard.len(), 4);
    let answered: Vec<_> = responses.iter().map(|r| status_and_body(r)).collect();
    let busy = "proxy failed: too many connections open through swoosh serve on this machine";
    assert!(
        answered
            .iter()
            .all(|(status, body)| *status == "HTTP/1.1 502 Bad Gateway" && !body.contains('\n')),
        "{answered:?}"
    );
    assert_eq!(answered[0].1, busy);
    assert_eq!(answered[3].1, busy);
    assert_eq!(answered[4].1, STOPPED_BODY);
}

/// A refusal every later request would meet ends the run with its line once the client has its answer:
/// `NotAdmitted` a `403` as by own bind, an ended standing and the machine being this one a `502`.
/// `NotAdmitted` then asks the machine why, one `control.serve` Open on Main, which its resident holds
/// an answer for. The others' residents stop after their one answer, gone as the line is worded, so
/// their lines carry no remedy the resident would name.
#[tokio::test]
async fn a_refusal_every_later_request_would_meet_ends_the_proxy_after_its_answer() {
    use swoosh::serve::control_codec::OpenLane;

    let why = [("proxy", OpenLane::Bulk), ("control.serve", OpenLane::Main)];
    for (tag, refusal, status, body, asked, catalog) in [
        (
            "proxy-admitted",
            OpenRefusal::Peer(PeerRefusal::NotAdmitted),
            "HTTP/1.1 403 Forbidden",
            format!("proxy service refused: {}", bifrost::Refusal::NotAdmitted),
            &why[..],
            Some(crate::dial_route_tests::list_answer(&["ping"])),
        ),
        (
            "proxy-standing",
            OpenRefusal::StandingEnded,
            "HTTP/1.1 502 Bad Gateway",
            "proxy failed: this device's standing has ended, so a machine that admits only your \
             devices will refuse this dial"
                .to_owned(),
            &why[..1],
            None,
        ),
        (
            "proxy-here",
            OpenRefusal::NotHere,
            "HTTP/1.1 502 Bad Gateway",
            "proxy failed: me/nas is this machine".to_owned(),
            &why[..1],
            None,
        ),
    ] {
        let expected = refusal.clone();
        let answers = core::iter::once(Answer::Refuse(refusal))
            .chain(catalog.map(Answer::AfterEnd))
            .collect();
        let (ended, responses, heard) = proxied(tag, answers, 1).await;
        let heard: Vec<(&str, OpenLane)> = heard
            .iter()
            .map(|open| (open.service.as_str(), open.lane))
            .collect();
        assert_eq!(heard, asked, "{tag}");
        assert_eq!(
            responses
                .iter()
                .map(|r| status_and_body(r))
                .collect::<Vec<_>>(),
            [(status, body.as_str())]
        );
        match expected {
            OpenRefusal::Peer(_) => {
                assert!(ended.is::<crate::commands::machine::Refused>(), "{ended:#}")
            }
            OpenRefusal::StandingEnded => assert!(ended.is::<StandingEnded>(), "{ended:#}"),
            _ => assert!(ended.is::<ThisMachine>(), "{ended:#}"),
        }
    }
}

/// `serve` stopping under a request's stream ends the run at once: the broken request asks the socket,
/// its client gets the serve-stopped `502`, and no next request is needed.
#[tokio::test]
async fn serve_stopping_under_a_request_ends_the_proxy_with_its_502() {
    let (ended, responses, heard) = proxied("proxy-stop", vec![Answer::Stop], 1).await;
    assert!(ended.is::<ServeStopped>(), "{ended:#}");
    assert_eq!(heard.len(), 1);
    assert_eq!(
        responses
            .iter()
            .map(|r| status_and_body(r))
            .collect::<Vec<_>>(),
        [("HTTP/1.1 502 Bad Gateway", STOPPED_BODY)]
    );
}

/// A request through `serve` that attaches gets the machine's answer: a `200` and its body.
#[tokio::test]
async fn a_request_through_serve_gets_the_machines_200() {
    let (ended, responses, heard) =
        proxied("proxy-200", vec![Answer::Exchange(answered_200().await)], 2).await;
    assert!(ended.is::<ServeStopped>(), "{ended:#}");
    assert_eq!(heard.len(), 1);
    assert_eq!(
        status_and_body(&responses[0]),
        ("HTTP/1.1 200 OK", "body\n")
    );
}

/// An ended standing refused while `serve` still answers its status: the `502` body is one line, the
/// terminal line's head, then its remedy keyed to the key `serve` runs as, with the command to type; the
/// run ends. Red when the body loses the remedy or takes a second line.
#[tokio::test]
async fn an_ended_standing_with_serve_up_ends_the_proxy_after_a_502_with_its_remedy() {
    let (ended, responses, heard) = proxied(
        "proxy-remedy",
        vec![Answer::Refuse(OpenRefusal::StandingEnded), Answer::Attach],
        1,
    )
    .await;
    assert!(ended.is::<StandingEnded>(), "{ended:#}");
    assert!(
        format!("{ended:#}").ends_with(&swoosh::badge::remedy(resident_key())),
        "{ended:#}"
    );
    assert_eq!(heard.len(), 1);
    let body = format!(
        "proxy failed: this device's standing has ended, so a machine that admits only your devices will \
         refuse this dial; renew it where your root is kept: swoosh invite <name> {}",
        resident_key()
    );
    assert_eq!(
        responses
            .iter()
            .map(|r| status_and_body(r))
            .collect::<Vec<_>>(),
        [("HTTP/1.1 502 Bad Gateway", body.as_str())]
    );
}

/// A machine's answer to an origin request: a `200` and a one-line body.
async fn answered_200() -> Vec<u8> {
    let mut answer = Vec::new();
    ::fetch::http::FetchResponse::Ok {
        status: 200,
        headers: vec![("Content-Type".to_owned(), "text/plain".to_owned())],
    }
    .write(&mut answer)
    .await
    .unwrap();
    answer.extend_from_slice(b"body\n");
    answer
}

/// Through `serve`, the first request to fail after the start warns, the failures after it do not, and
/// once a request's stream attaches the next failure warns again.
#[tokio::test]
async fn proxy_through_serve_warns_once_per_run_of_failed_requests() {
    let (ended, responses, heard, err) = proxied_warning(
        "proxy-warn",
        vec![
            Answer::Refuse(OpenRefusal::Busy),
            Answer::Refuse(OpenRefusal::Peer(PeerRefusal::Unavailable(
                bifrost::RefusalDetail::bounded("down"),
            ))),
            Answer::Exchange(answered_200().await),
            Answer::Refuse(OpenRefusal::Busy),
        ],
        5,
    )
    .await;
    assert!(ended.is::<ServeStopped>(), "{ended:#}");
    assert_eq!(heard.len(), 4);
    assert_eq!(
        status_and_body(&responses[2]),
        ("HTTP/1.1 200 OK", "body\n")
    );
    let busy = crate::commands::through_serve::tests::warning("too many connections here");
    assert_eq!(err, format!("{busy}{busy}"));
}

/// `me/nas` by own bind, its gate answering `script`, as every request's exit.
fn own_nas(
    script: Vec<swoosh::testkit::Script>,
) -> (
    swoosh::testkit::ScriptedPeer,
    bifrost::Node<swoosh::testkit::ScriptedPeer, bifrost::NoDiscovery>,
) {
    let key = machine(&book(), "me/nas").key();
    let peer = swoosh::testkit::ScriptedPeer::new(key, script);
    let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
    (peer, node)
}

/// By own bind a later request's `NotAdmitted` ends the run with the dial refusal, one of your devices
/// asked why, once its client has its `403`; it prints no warning first.
#[tokio::test]
async fn a_later_not_admitted_ends_the_proxy_by_own_bind_after_its_403() {
    use swoosh::testkit::Script;

    let (_peer, node) = own_nas(vec![
        Script::Refuse(bifrost::Refusal::NotAdmitted),
        Script::Lists(vec!["ping"]),
    ]);
    let peers = Peers::new(&node);
    let nas = machine(&book(), "me/nas");
    let cmd = proxy(&[]);
    let (ended, responses, err) = own(&node, &peers, &cmd, &nas, async |listener| {
        listened(&cmd, listener, 1).await
    })
    .await;
    assert_eq!(
        format!("{ended:#}"),
        "me/nas does not serve proxy\n  Only nas can add it; on nas, run:\n    swoosh service add proxy:<url>"
    );
    let not_admitted = format!("proxy service refused: {}", bifrost::Refusal::NotAdmitted);
    assert_eq!(
        responses
            .iter()
            .map(|r| status_and_body(r))
            .collect::<Vec<_>>(),
        [("HTTP/1.1 403 Forbidden", not_admitted.as_str())]
    );
    assert_eq!(err, "");
}

/// By own bind the first request to fail after the start warns, by its kind, the failures after it do
/// not, and a request whose stream opened is carried whatever ends it: one broken before its answer
/// warns nothing, and the next request refused warns again.
#[tokio::test]
async fn proxy_by_own_bind_warns_once_per_run_of_failed_requests() {
    use swoosh::testkit::Script;

    let down = || {
        Script::Refuse(bifrost::Refusal::Unavailable {
            detail: bifrost::RefusalDetail::bounded("down"),
        })
    };
    let (_peer, node) = own_nas(vec![
        down(),
        down(),
        Script::Ends,
        down(),
        Script::Refuse(bifrost::Refusal::NotAdmitted),
        Script::Lists(vec!["proxy"]),
    ]);
    let peers = Peers::new(&node);
    let nas = machine(&book(), "me/nas");
    let cmd = proxy(&[]);
    let (ended, _, err) = own(&node, &peers, &cmd, &nas, async |listener| {
        listened(&cmd, listener, 5).await
    })
    .await;
    assert!(ended.is::<crate::commands::machine::Refused>(), "{ended:#}");
    let down =
        crate::commands::through_serve::tests::warning("reached, but refused (unavailable: d…)");
    assert_eq!(err, format!("{down}{down}"));
}

/// The bodies a local client reads carry the machine's text escaped, as every line of it is: a refusal's
/// detail, an origin's error and a stream's failure, none of them able to write a control byte or a line
/// of their own into a terminal that prints the body.
#[tokio::test]
async fn a_machines_text_in_a_proxy_body_is_escaped() {
    const HOSTILE: &str = "\u{1b}[2Kforged\r\nline";
    const SHOWN: &str = r"\u{1b}[2Kforged\r\nline";
    let mut origin = Vec::new();
    ::fetch::http::FetchResponse::Error(HOSTILE.to_owned())
        .write(&mut origin)
        .await
        .unwrap();
    let (_peer, node) = own_nas(vec![
        swoosh::testkit::Script::Refuse(bifrost::Refusal::Unavailable {
            detail: bifrost::RefusalDetail::bounded(HOSTILE),
        }),
        swoosh::testkit::Script::Says(origin),
    ]);
    let peers = Peers::new(&node);
    let nas = machine(&book(), "me/nas");
    let cmd = proxy(&[]);
    let mut bodies = own(&node, &peers, &cmd, &nas, async |listener| {
        let mut bodies = Vec::new();
        for _ in 0..2 {
            let (_, response) = exchange_on(printed, &cmd, listener).await;
            bodies.push(status_and_body(&response).1.to_owned());
        }
        bodies
    })
    .await;
    let (_, response) = exchange(printed, &cmd, &Scripted::new(Script::Fails(HOSTILE))).await;
    bodies.push(status_and_body(&response).1.to_owned());
    assert_eq!(
        bodies,
        [
            format!("proxy service refused: unavailable: {SHOWN}"),
            format!("origin error: {SHOWN}"),
            format!("proxy failed: stream: {SHOWN}"),
        ]
    );
}

/// What a [`Staged`] source does at each open, in order.
enum Stage {
    /// Never answer: the request waits for its answer.
    Hold,
    /// Attach, and send these bytes down without an end: the request is mid-body.
    Says(Vec<u8>),
    /// As [`Says`](Self::Says), then fail the download once the source's `cut` fires, as a transport's
    /// stream fails when the host cuts its connection.
    SaysThenCut(Vec<u8>),
    /// Give no stream, so.
    Meets(Unopened),
}

/// A source whose opens do what `stages` says, in order, keeping each attached stream's far halves
/// open.
#[derive(Default)]
struct Staged {
    stages: RefCell<VecDeque<Stage>>,
    opened: RefCell<usize>,
    far: RefCell<Vec<tokio::io::DuplexStream>>,
    /// Fails every [`Stage::SaysThenCut`] download, once fired.
    cut: tightbeam::tunnel::CancellationToken,
}

impl Staged {
    fn new(stages: impl IntoIterator<Item = Stage>) -> Self {
        Self {
            stages: RefCell::new(stages.into_iter().collect()),
            ..Self::default()
        }
    }
}

/// A download that yields what its far half sent, then fails once `cut` resolves.
struct Severed {
    read: tokio::io::DuplexStream,
    cut: core::pin::Pin<Box<dyn Future<Output = ()>>>,
}

impl tokio::io::AsyncRead for Severed {
    fn poll_read(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        // What was sent before the cut is read first, as a transport delivers what it already holds.
        if let core::task::Poll::Ready(read) =
            core::pin::Pin::new(&mut self.read).poll_read(cx, buf)
        {
            return core::task::Poll::Ready(read);
        }
        self.cut.as_mut().poll(cx).map(|()| {
            Err(std::io::Error::new(
                tokio::io::ErrorKind::ConnectionAborted,
                "the test cut the stream",
            ))
        })
    }
}

impl StreamSource for Staged {
    type Write = TestWrite<tokio::io::DuplexStream>;
    type Read = Severed;

    async fn open(&self, _ask: &Ask) -> Result<Opened<Self::Write, Self::Read>, Unopened> {
        *self.opened.borrow_mut() += 1;
        let stage = self.stages.borrow_mut().pop_front();
        let (said, cut): (_, core::pin::Pin<Box<dyn Future<Output = ()>>>) = match stage {
            Some(Stage::Says(said)) => (said, Box::pin(core::future::pending())),
            Some(Stage::SaysThenCut(said)) => (said, Box::pin(self.cut.clone().cancelled_owned())),
            Some(Stage::Meets(unopened)) => return Err(unopened),
            Some(Stage::Hold) | None => core::future::pending().await,
        };
        let (write, up) = tokio::io::duplex(64 * 1024);
        let (mut down, read) = tokio::io::duplex(64 * 1024);
        down.write_all(&said).await.unwrap();
        self.far.borrow_mut().extend([up, down]);
        Ok(Opened {
            info: bifrost::ConnInfo::default(),
            write: write.into(),
            read: Severed { read, cut },
        })
    }
}

/// An origin's `200` head and the first half of its body, the rest still to come.
async fn half_a_body() -> Vec<u8> {
    let mut said = Vec::new();
    ::fetch::http::FetchResponse::Ok {
        status: 200,
        headers: vec![("Content-Type".to_owned(), "text/plain".to_owned())],
    }
    .write(&mut said)
    .await
    .unwrap();
    said.extend_from_slice(b"the first half");
    said
}

/// One local client at `addr` that sends `head` and reads until what it has holds `until`: the client,
/// still open, and what it read.
async fn reading_until(addr: SocketAddr, head: &str, until: &[u8]) -> (TcpStream, Vec<u8>) {
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(head.as_bytes()).await.unwrap();
    let mut read = Vec::new();
    while !read.windows(until.len()).any(|seen| seen == until) {
        let mut chunk = [0; 512];
        let n = client.read(&mut chunk).await.unwrap();
        assert_ne!(n, 0, "the answer ended early");
        read.extend_from_slice(&chunk[..n]);
    }
    (client, read)
}

/// On both paths, a request whose open ends the run leaves the clients still waiting with an answer: one
/// waiting for its answer gets a `502` naming the line the run ends with, and one mid-body is reset, never
/// closed cleanly as if its body were whole. An ended standing ends it through the shared ending, and the
/// machine's `NotAdmitted` through its own arm, whose `403` goes to the request that met it and whose
/// line, the refusal without its cause, to the one waiting. A client that has sent nothing, so has not
/// shown the token, gets the close alone: nothing that names the machine or the ending.
#[test]
fn a_run_ending_request_answers_the_waiting_clients() {
    on_a_big_stack(async || {
        let mut served = Served::new("proxy-waiting").await;
        let rig = Rig::default();
        // Answers status, so `serve` here is neither stalled nor gone; no Open reaches it.
        let resident = routed(&mut served, |_| Reply::Stall, &rig);
        let socket = swoosh::node_client::UidSocket::resolve(&served.home).unwrap();
        let contacts = book();
        let nas = machine(&contacts, "me/nas");
        let cmd = proxy(&[]);
        let bound = crate::probe_route_tests::bound();
        let own = Route::Own {
            bound: &bound,
            this: crate::commands::through_serve::tests::nas(),
        };
        let dial = Dial {
            machine: &nas,
            service: &cmd.service,
            contacts: &contacts,
        };
        let serve = Route::Serve {
            dial: &dial,
            socket: &socket,
        };
        let said = half_a_body().await;
        let not_admitted = OpenRefusal::Peer(PeerRefusal::NotAdmitted);
        let endings = [
            (OpenRefusal::StandingEnded, "HTTP/1.1 502 Bad Gateway"),
            (not_admitted.clone(), "HTTP/1.1 403 Forbidden"),
        ];
        for ((path, route), (ending, status)) in [("own", &own), ("serve", &serve)]
            .into_iter()
            .flat_map(|route| endings.iter().map(move |ending| (route, ending)))
        {
            // The last stage answers `NotAdmitted`'s question why, which the other ending never asks.
            let source = Staged::new([
                Stage::Hold,
                Stage::Says(said.clone()),
                Stage::Meets(Unopened::Refused(ending.clone())),
                Stage::Meets(Unopened::Refused(not_admitted.clone())),
            ]);
            let (ended, (waiting, (how, read), unshown)) =
                listening(&cmd, &source, route, &nas, async |listener| {
                    let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                    let local = local_at(tcp.local_addr().unwrap());
                    let head = printed(&local);
                    let failures = quiet();
                    let clients = async {
                        // Connected before the client the source's first open waits on, so accepted
                        // first: once that open is made, this one is a client the run holds.
                        let mut unshown = TcpStream::connect(local.addr).await.unwrap();
                        let waiting = tokio::spawn({
                            let (addr, head) = (local.addr, head.clone());
                            async move { got(addr, &head).await }
                        });
                        while *source.opened.borrow() < 1 {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        let (mut body, mut read) =
                            reading_until(local.addr, &head, b"the first half").await;
                        let ending = got(local.addr, &head).await;
                        assert!(ending.starts_with(status), "{ending}");
                        let how = body.read_to_end(&mut read).await;
                        let mut heard = Vec::new();
                        let _ = unshown.read_to_end(&mut heard).await;
                        (waiting.await.unwrap(), (how, read), heard)
                    };
                    tokio::time::timeout(ROW_BOUND, async {
                        tokio::join!(cmd.answer_each(tcp, &local, listener, &failures), clients)
                    })
                    .await
                    .expect("the run ended")
                })
                .await;
            match ending {
                OpenRefusal::StandingEnded => {
                    assert!(ended.is::<StandingEnded>(), "{path}: {ended:#}");
                }
                _ => assert!(
                    ended.is::<crate::commands::machine::Refused>(),
                    "{path}: {ended:#}"
                ),
            }
            assert_eq!(
                String::from_utf8_lossy(&unshown),
                "",
                "{path}: a client with no token reads nothing of the run"
            );
            assert_eq!(
                status_and_body(&waiting),
                (
                    "HTTP/1.1 502 Bad Gateway",
                    body_of(&format!("{ended:#}")).as_str()
                ),
                "{path}"
            );
            let error = how.expect_err("a reset, never a clean end");
            assert_eq!(
                error.kind(),
                tokio::io::ErrorKind::ConnectionReset,
                "{path}: {error}"
            );
            assert!(String::from_utf8_lossy(&read).starts_with("HTTP/1.1 200 OK"));
        }
        rig.stop.cancel();
        resident.await.unwrap();
    });
}

/// One client that sends the printed GET to `cmd`'s listener over `listener` and reads until what it
/// has holds `until`, then fires `cut`: what it read, and how its read ended. The run must still be
/// listening when the read ends.
async fn cut_in_flight<S: StreamSource>(
    cmd: &ProxyCmd,
    listener: &Listener<'_, S>,
    until: &[u8],
    cut: impl FnOnce(),
) -> (Vec<u8>, std::io::Result<usize>) {
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let local = local_at(tcp.local_addr().unwrap());
    let failures = quiet();
    let client = async {
        let mut client = TcpStream::connect(local.addr).await.unwrap();
        client.write_all(printed(&local).as_bytes()).await.unwrap();
        let mut read = Vec::new();
        while !until.is_empty() && !read.windows(until.len()).any(|seen| seen == until) {
            let mut chunk = [0; 512];
            let n = client.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0, "the answer ended before the cut");
            read.extend_from_slice(&chunk[..n]);
        }
        cut();
        let ended = client.read_to_end(&mut read).await;
        (read, ended)
    };
    tokio::time::timeout(ROW_BOUND, async {
        tokio::select! {
            ended = cmd.answer_each(tcp, &local, listener, &failures) => {
                panic!("the cut ended the run: {ended:#}")
            }
            read = client => read,
        }
    })
    .await
    .expect("the client's read ended")
}

/// A host cut leaves a client still waiting for its answer a `502`, its request's own failure, on both
/// paths, and the run listens on: the next request redials.
#[test]
fn a_host_cut_answers_a_waiting_proxy_client_with_its_502() {
    on_a_big_stack(async || {
        let cmd = proxy(&[]);
        let nas = machine(&book(), "me/nas");
        let bound = crate::probe_route_tests::bound();
        let route = Route::Own {
            bound: &bound,
            this: crate::commands::through_serve::tests::nas(),
        };
        let source = Staged::new([Stage::SaysThenCut(Vec::new())]);
        // Fired before the stream attaches: the download fails at its first wait.
        source.cut.cancel();
        let own = listening(&cmd, &source, &route, &nas, async |listener| {
            cut_in_flight(&cmd, listener, b"", || {}).await
        })
        .await;

        let mut served = Served::new("proxy-waiting-cut").await;
        let rig = Rig::default();
        // A spare answer keeps the resident serving, so `serve` is still there after the cut.
        let resident = scripted(&mut served, vec![Answer::Cut, Answer::Hangup], &rig);
        let serve = through(&served, &cmd, async |listener| {
            cut_in_flight(&cmd, listener, b"", || {}).await
        })
        .await;
        rig.stop.cancel();
        resident.await.unwrap();

        for (path, (read, how)) in [("own", own), ("serve", serve)] {
            how.expect("a clean end after the 502");
            let response = String::from_utf8(read).expect("utf-8");
            let (status, body) = status_and_body(&response);
            assert_eq!(status, "HTTP/1.1 502 Bad Gateway", "{path}: {response}");
            assert!(body.starts_with("proxy failed: "), "{path}: {body}");
            assert!(!body.contains('\n'), "{path}: {body}");
        }
    });
}

/// A host cut resets a client mid-body on both paths, so a body framed by the connection's end never
/// reads as whole, and the run listens on: the request's own stream fails at the cut, by own bind as a
/// transport fails a stream on a cut connection, through `serve` as the resident cuts it while it still
/// answers.
#[test]
fn a_host_cut_resets_a_proxy_client_mid_body() {
    on_a_big_stack(async || {
        let said = half_a_body().await;
        let cmd = proxy(&[]);
        let nas = machine(&book(), "me/nas");
        let bound = crate::probe_route_tests::bound();
        let route = Route::Own {
            bound: &bound,
            this: crate::commands::through_serve::tests::nas(),
        };
        let source = Staged::new([Stage::SaysThenCut(said.clone())]);
        let own = listening(&cmd, &source, &route, &nas, async |listener| {
            cut_in_flight(&cmd, listener, b"the first half", || source.cut.cancel()).await
        })
        .await;

        let mut served = Served::new("proxy-mid-body").await;
        let rig = Rig::default();
        // A spare answer keeps the resident serving, so `serve` is still there after the cut.
        let resident = scripted(
            &mut served,
            vec![Answer::SaysThenCut(said), Answer::Hangup],
            &rig,
        );
        let serve = through(&served, &cmd, async |listener| {
            cut_in_flight(&cmd, listener, b"the first half", || rig.cut.cancel()).await
        })
        .await;
        rig.stop.cancel();
        resident.await.unwrap();

        for (path, (read, how)) in [("own", own), ("serve", serve)] {
            let error = how.expect_err("a reset, never a clean end");
            assert_eq!(
                error.kind(),
                tokio::io::ErrorKind::ConnectionReset,
                "{path}: {error}"
            );
            assert!(
                String::from_utf8_lossy(&read).starts_with("HTTP/1.1 200 OK"),
                "{path}"
            );
        }
    });
}

/// By own bind a later request's `NotAdmitted` answers its client's `403` before one of your devices
/// is asked why, never after: here the follow-up gets no answer, and the `403` is already out.
#[tokio::test]
async fn a_later_not_admitted_answers_its_403_before_asking_why() {
    use swoosh::testkit::Script;

    let (peer, node) = own_nas(vec![
        Script::Refuse(bifrost::Refusal::NotAdmitted),
        Script::Silent,
    ]);
    let peers = Peers::new(&node);
    let nas = machine(&book(), "me/nas");
    let cmd = proxy(&[]);
    own(&node, &peers, &cmd, &nas, async |listener| {
        let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let local = local_at(tcp.local_addr().unwrap());
        let clients = requesting(&local, 1);
        let failures = quiet();
        let run = cmd.answer_each(tcp, &local, listener, &failures);
        tokio::pin!(run);
        let responses = tokio::time::timeout(ROW_BOUND, async {
            tokio::select! {
                biased;
                responses = clients => responses.unwrap(),
                ended = &mut run => panic!("the run ended before its client had the 403: {ended:#}"),
            }
        })
        .await
        .expect("the client had its answer");
        assert_eq!(
            status_and_body(&responses[0]).0,
            "HTTP/1.1 403 Forbidden",
            "{responses:?}"
        );
        let ended = tokio::time::timeout(ROW_BOUND, run)
            .await
            .expect("the run ended");
        assert!(ended.is::<crate::commands::machine::Refused>(), "{ended:#}");
    })
    .await;
    assert_eq!(peer.dials(), 2, "the run's session and one follow-up");
}

/// The listener table every listener shares, for `proxy`: each way a request's open gives no stream
/// ends the run where the table says, on both paths, once its client has its answer (a `403` for the
/// machine's `NotAdmitted`, a `502` naming the line for any other ending), and every other row answers
/// its client a `502`, warns once and keeps listening.
#[test]
fn one_ending_table_on_both_paths() {
    use crate::listen_route_tests::{Then, table};

    on_a_big_stack(async || {
        let mut served = Served::new("proxy-table").await;
        let rig = Rig::default();
        // Answers status, so `serve` here is neither stalled nor gone; no Open reaches it.
        let resident = routed(&mut served, |_| Reply::Stall, &rig);
        let socket = swoosh::node_client::UidSocket::resolve(&served.home).unwrap();
        let contacts = book();
        let nas = machine(&contacts, "me/nas");
        // The table's lines name `ssh`.
        let cmd = proxy(&["--service", "ssh"]);
        let bound = crate::probe_route_tests::bound();
        let own = Route::Own {
            bound: &bound,
            this: crate::commands::through_serve::tests::nas(),
        };
        let dial = Dial {
            machine: &nas,
            service: &cmd.service,
            contacts: &contacts,
        };
        let serve = Route::Serve {
            dial: &dial,
            socket: &socket,
        };
        for (at, (meets, then)) in table().into_iter().enumerate() {
            for (path, route) in [("own", &own), ("serve", &serve)] {
                let opened = RefCell::new(Vec::new());
                let source = crate::probe_route_tests::Meets {
                    meets,
                    opened: &opened,
                };
                let requests = match then {
                    Then::Ends { .. } => 1,
                    Then::Warns(_) => 2,
                };
                let mut err = Vec::new();
                let (ran, responses) = listening(&cmd, source, route, &nas, async |listener| {
                    let failures = PipeFailures::new(&nas, &mut err);
                    let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                    let local = local_at(tcp.local_addr().unwrap());
                    let clients = requesting(&local, requests);
                    let run = cmd.answer_each(tcp, &local, listener, &failures);
                    tokio::time::timeout(ROW_BOUND, async {
                        match then {
                            // The run ends once its one client has the answer.
                            Then::Ends { .. } => {
                                let (ended, responses) = tokio::join!(run, clients);
                                (Some(format!("{ended:#}")), responses.unwrap())
                            }
                            Then::Warns(_) => tokio::select! {
                                ended = run => (Some(format!("{ended:#}")), Vec::new()),
                                responses = clients => (None, responses.unwrap()),
                            },
                        }
                    })
                    .await
                    .expect("the run ended, or its clients finished")
                })
                .await;
                let err = String::from_utf8(err).unwrap();
                match then {
                    Then::Ends { own, serve } => {
                        let line = ran.unwrap_or_else(|| panic!("row {at} {path}: listening"));
                        let expected = if path == "own" { own } else { serve };
                        assert!(line.starts_with(expected), "row {at} {path}: {line}");
                        assert_eq!(err, "", "row {at} {path}: no warning first");
                        let first = body_of(&line);
                        let not_admitted =
                            format!("proxy service refused: {}", bifrost::Refusal::NotAdmitted);
                        let answer = match meets() {
                            Some(Unopened::Refused(OpenRefusal::Peer(
                                PeerRefusal::NotAdmitted,
                            ))) => ("HTTP/1.1 403 Forbidden", not_admitted.as_str()),
                            _ => ("HTTP/1.1 502 Bad Gateway", first.as_str()),
                        };
                        let [response] = responses.as_slice() else {
                            panic!("row {at} {path}: {responses:?}");
                        };
                        assert_eq!(status_and_body(response), answer, "row {at} {path}");
                    }
                    Then::Warns(clause) => {
                        assert_eq!(ran, None, "row {at} {path}: ended");
                        assert_eq!(opened.borrow().len(), 2, "row {at} {path}: both requests");
                        let warning = crate::commands::through_serve::tests::warning(clause);
                        assert_eq!(err, warning, "row {at} {path}: one warning");
                        for response in &responses {
                            let (status, body) = status_and_body(response);
                            assert_eq!(status, "HTTP/1.1 502 Bad Gateway", "row {at} {path}");
                            assert!(!body.contains('\n'), "row {at} {path}: {body}");
                        }
                    }
                }
            }
        }
        rig.stop.cancel();
        resident.await.unwrap();
    });
}

/// Through `serve`, a request's Open that gets no reply ends the run with `Unresponsive` when `serve` then
/// fails a status too, once its client has a `502` naming that line.
#[test]
fn a_confirmed_stall_ends_the_proxy() {
    on_a_big_stack(async || {
        let mut served = Served::new("proxy-stall").await;
        let rig = Rig {
            wedged: true,
            ..Rig::default()
        };
        // Answers nothing, status included, so `serve` here is stalled.
        let resident = routed(&mut served, |_| Reply::Stall, &rig);
        let socket = swoosh::node_client::UidSocket::resolve(&served.home).unwrap();
        let contacts = book();
        let nas = machine(&contacts, "me/nas");
        let cmd = proxy(&[]);
        let dial = Dial {
            machine: &nas,
            service: &cmd.service,
            contacts: &contacts,
        };
        let route = Route::Serve {
            dial: &dial,
            socket: &socket,
        };
        let opened = RefCell::new(Vec::new());
        let source = crate::probe_route_tests::Meets {
            meets: || {
                Some(Unopened::Control(
                    swoosh::serve::control_codec::ControlError::Timeout {
                        phase: "response read",
                    },
                ))
            },
            opened: &opened,
        };
        let (ended, responses, err) = listening(&cmd, source, &route, &nas, async |listener| {
            listened(&cmd, listener, 1).await
        })
        .await;
        rig.stop.cancel();
        let _ = resident.await;
        assert_eq!(
            format!("{ended:#}"),
            "swoosh serve did not answer here\n  Restart it."
        );
        assert_eq!(
            responses
                .iter()
                .map(|r| status_and_body(r))
                .collect::<Vec<_>>(),
            [(
                "HTTP/1.1 502 Bad Gateway",
                "proxy failed: swoosh serve did not answer here"
            )]
        );
        assert_eq!(err, "", "no warning first");
    });
}

/// The `502` body the terminal line `terminal` gives: `proxy failed: ` and its head, then, for an ended
/// standing whose remedy is under it, that remedy as one clause with its command.
fn body_of(terminal: &str) -> String {
    let mut lines = terminal.lines();
    let head = lines.next().unwrap_or_default();
    match (lines.next(), lines.next()) {
        (Some("  Renew it where your root is kept:"), Some(command)) => format!(
            "proxy failed: {head}; renew it where your root is kept: {}",
            command.trim()
        ),
        _ => format!("proxy failed: {head}"),
    }
}
