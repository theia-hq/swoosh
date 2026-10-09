//! `swoosh proxy <machine> <url>`: mint a local http URL whose requests leave from a machine you name.
//!
//! A URL-minting reverse proxy: a downloader (xget, curl) pulls from the local listener; each request
//! rides one bifrost stream to a cap-gated `proxy:` service on that machine; it performs the origin HTTP
//! GET/HEAD and streams the response straight back, `Range` intact so a resumable download works. The
//! machine runs the services engine named `fetch`; that name is internal and never printed.
//!
//! The local URL carries this run's credential, so the listener answers only the URL it printed: the
//! `Host` must be the listener's own address (a page that rebinds a name to loopback sends its own), the
//! path must start with a random token (another account on this machine can find the port, never the
//! token), and every request stays on the origin of the URL you named, whatever its target says. What
//! comes back from the machine is checked before it reaches a local client, and the listener holds at most
//! [`MAX_PIPES`] connections, each with [`HEAD_TIMEOUT`] to send its request.

use core::future::Future;
use core::net::{Ipv4Addr, SocketAddr};
use core::time::Duration;

use ::fetch::http::{FetchRequest, FetchResponse};
use bifrost::{Discovery, Node, Session, Transport};
use clap::Args;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::escape::escaped_report;
use swoosh::peer::{Machine, Peer};
use swoosh::reach;
use swoosh::transport::{self, ReachArgs};
use swoosh::unbound::Unbound;
use tightbeam::protocol::{Request, Response};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::commands::connect::{self, ACCEPT_RETRY, MAX_PIPES, press_ctrl_c};
use crate::commands::machine;

/// Mint a local URL that reaches an origin through a machine you name (your own exit, over the overlay).
#[derive(Debug, Args)]
pub struct ProxyCmd {
    // Positional and first, like every verb's machine: the machine is never optional, and a flag that
    // is never optional is a positional.
    #[arg(value_name = "machine", help = machine::HELP)]
    pub peer: Peer,
    /// The origin URL to reach (path and query on the local URL resolve against it).
    // Parsed here, so a URL that does not parse is a usage error before anything is dialed, and each
    // request joins onto the one parsed value instead of re-reading the text.
    #[arg(value_name = "url")]
    pub url: url::Url,
    /// which served service to reach
    // The default is taken FROM the table that knows a bare `swoosh serve` does not bind it (an
    // unscoped relay egresses under the exit node's own IP, so there is no default to inherit). Hidden,
    // with no variable: each verb's default differs, so one variable would retarget three verbs.
    #[arg(long, value_name = "service", default_value = Unbound::PROXY.name(), value_parser = swoosh::names::service, hide = true)]
    pub service: Service,
    /// The local port to listen on (default: any free port)
    #[arg(long, value_name = "n")]
    pub port: Option<u16>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl swoosh::reaching::Reaching for ProxyCmd {
    fn reach_args(&self) -> &swoosh::transport::ReachArgs {
        &self.reach
    }

    /// The peer this verb dials, for the stale-list exchange after it runs.
    fn dialed(&self) -> Option<&swoosh::peer::Peer> {
        Some(&self.peer)
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, and what it dials as. It reaches a peer and never accepts connections under the
    /// home key, so its bind must not write the key's address record (0.9.0 F1).
    ///
    /// `proxy:` is FAMILY-GATED: the owner reaching their OWN exit node presents the member badge by
    /// default (rooted at the dialing key), and a delegate types their link as the peer instead. Stating
    /// `Family` FUSES the identity to `PersistedIfPresent`, so the owner's self-badge roots at the same
    /// key the dial binds under and admits: this is the one-line fix for the owner-reaching-own-node 403
    /// (the verb used to dial `Ephemeral` + slip-only, so an owner with no slip was refused). A
    /// self-addressing `swoosh:` link in the peer slot is threaded INTO the credential so the ONE resolver
    /// owns both slots.
    ///
    /// An `anyone` link typed as the peer presents alone, under a throwaway key (`Credential::dialing`).
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::dialing(
            &self.peer,
            self.service.as_str(),
        ))
    }

    /// Uniform dispatch: unpack the reach context and run. `proxy` reads `contacts` (to resolve its peer),
    /// the `transport` label, and the resolved `present` badge; it ignores `key`.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let Some(machine) = ctx.machine else {
            eyre::bail!("internal: `proxy` ran without its machine resolved (root-dispatch bug)");
        };
        self.run_proxy(
            node,
            ctx.contacts,
            machine,
            ctx.bound,
            ctx.present,
            ctx.membership,
        )
        .await
    }
}

/// How long a local client has to send its whole request head. A connection that sends nothing holds a
/// descriptor and a slot under [`MAX_PIPES`]; this is what gives them back. The same span the engine at
/// the far end allows an origin's answer.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);

impl ProxyCmd {
    /// Dial the exit node, prove it admits this machine to the service, bind a loopback listener, print the
    /// local URL, and serve each request over its own bifrost stream until Ctrl-C. A machine that refuses
    /// the service refuses here, once, before any URL is printed.
    ///
    /// `present` is the ALREADY-RESOLVED badge from the composition root: the member badge rooted at the
    /// dialing key by default (so the owner reaching their OWN gated exit node admits), the link typed as
    /// the peer if the caller gave one. `proxy:` is family-gated, so every per-request stream presents it.
    ///
    /// The URL is the one thing on stdout, a made artifact a script reads as the first line; the lines for
    /// the person ride stderr.
    async fn run_proxy<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        machine: &Machine,
        bound: &transport::Bound,
        present: Option<Link>,
        membership: Option<Link>,
    ) -> eyre::Result<()> {
        let session = reach::dial(node, machine, &self.peer, bound).await?;
        // Admission is proven on one stream before the URL prints, so a refusal is one line and a
        // non-zero exit rather than a URL that answers every request with a 403. The stream is dropped
        // once admitted; the machine tears its half down.
        let connector = reach::gated(
            machine.key(),
            self.service.clone(),
            Option::clone(&present),
            Option::clone(&membership),
        );
        match connector.open_on(&session).await {
            Ok(_admitted) => {}
            Err(bifrost::Error::Refused(bifrost::Refusal::NotAdmitted)) => {
                let diagnosis =
                    reach::diagnose(&session, machine, &self.service, present, membership).await;
                return Err(machine::refused(machine, &self.service, diagnosis));
            }
            Err(error) => return Err(escaped_report(error.into())),
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, self.port.unwrap_or(0))).await?;
        let local = Local::new(listener.local_addr()?);
        println!("{local}");
        eprintln!(
            "Proxying {} through {}.",
            self.url,
            connect::Machine::of(contacts, session.peer())
        );
        press_ctrl_c();
        accept_each(listener, MAX_PIPES, |tcp| {
            self.serve(tcp, &local, &session, present.as_ref(), membership.as_ref())
        })
        .await
    }

    /// Serve one inbound HTTP request. A failure BEFORE any response bytes are written serves a `502` so
    /// a downloader sees a real HTTP error, not a bare connection reset; a failure once the response has
    /// begun just closes the socket (a second HTTP response into the body would corrupt it).
    async fn serve<S: Session>(
        &self,
        mut tcp: TcpStream,
        local: &Local,
        session: &S,
        present: Option<&Link>,
        membership: Option<&Link>,
    ) -> eyre::Result<()> {
        let mut responded = false;
        if let Err(error) = self
            .relay(
                &mut tcp,
                local,
                session,
                present,
                membership,
                &mut responded,
            )
            .await
        {
            if !responded {
                // A failure before any response (an open, a parse, a stream drop) is a bad-gateway
                // condition, not an authorization one, so `502`. The refusal path inside `relay` serves
                // its own `403`/`502` before returning, so a refusal never reaches this fallback.
                let _ = respond_error(
                    &mut tcp,
                    Status::BadGateway,
                    &format!("proxy failed: {error:#}"),
                )
                .await;
            }
            return Err(error);
        }
        Ok(())
    }

    /// Relay one request to the `proxy:` service and stream the response back, setting `responded` the
    /// moment any HTTP response has begun (so the caller knows a `502` is no longer safe to send).
    ///
    /// The local checks ([`Local::admit`]) run before the stream opens, so a request this run did not
    /// print the URL for never reaches the machine or carries the credential.
    async fn relay<S: Session>(
        &self,
        tcp: &mut TcpStream,
        local: &Local,
        session: &S,
        present: Option<&Link>,
        membership: Option<&Link>,
        responded: &mut bool,
    ) -> eyre::Result<()> {
        let head = tokio::time::timeout(HEAD_TIMEOUT, read_head(tcp))
            .await
            .map_err(|_| eyre::eyre!("no request within {HEAD_TIMEOUT:?}"))??;
        let parsed = parse_request(&head)?;
        let origin = match local.admit(&parsed, &self.url) {
            Ok(origin) => origin,
            Err(refused) => {
                *responded = true;
                return respond_error(tcp, refused.status(), refused.body()).await;
            }
        };
        let Parsed {
            method, headers, ..
        } = parsed;

        let (mut writer, mut reader) = session.open_bi().await?;
        // The checked writer (the same rule the library's `Connector` applies): a credential-bearing
        // request refuses, before any byte, when the selected transport's declared profile does not
        // prove the peer. This proxy path dials a raw session and bypasses `Connector`, so it carries
        // the check itself; the refusal surfaces here as the local 502 cause.
        Request {
            service: self.service.to_string(),
            capability: present.map(ToString::to_string),
            membership: membership.map(ToString::to_string),
        }
        .write_checked::<S, _>(&mut writer)
        .await?;
        if let Response::Refused(refusal) = Response::read(&mut reader).await? {
            *responded = true;
            // `NotAdmitted` is an AUTHORIZATION failure (the exit node refused YOU): serve `403`.
            // `BadRequest` and `Unavailable` are the node's own failure to serve the request and rule on
            // nothing about this caller, so they keep `502`, like a genuine origin error below. A
            // downloader can then tell "you are not allowed through this node" from "the node or origin
            // is having a bad day" by status alone, instead of reading two different failures as an
            // indistinguishable `502`.
            let status = match &refusal {
                bifrost::Refusal::NotAdmitted => Status::Forbidden,
                bifrost::Refusal::BadRequest { .. } | bifrost::Refusal::Unavailable { .. } => {
                    Status::BadGateway
                }
                // A node built on a newer bifrost can refuse with a class this build has no name for,
                // and `Refusal` is non-exhaustive precisely so that is not a build break, which makes
                // THIS the arm that has to be right. The split above is "a ruling about you" against
                // "something about them", and a refusal this build cannot read carries no ruling it can
                // read: serving `403` would invent one, and inventing an authorization answer out of a
                // message that carried none is the shape of bug the uniform refusal exists to prevent.
                // `502` claims nothing about the caller, which is the whole of what is honest here, so
                // the arm DECLINES the claim rather than guessing it and says so at `error`, the level
                // a stock `swoosh serve` filter shows, with the class text. Reaching it means this
                // binary's own pins moved past its classification, never anything a peer can drive.
                unreadable => {
                    tracing::error!(
                        refusal = %unreadable,
                        "the proxy machine refused with a class this build cannot read; serving 502 \
                         rather than guessing an authorization answer"
                    );
                    Status::BadGateway
                }
            };
            return respond_error(tcp, status, &format!("proxy service refused: {refusal}")).await;
        }

        FetchRequest {
            method,
            url: origin,
            headers,
        }
        .write(&mut writer)
        .await?;
        match FetchResponse::read(&mut reader).await? {
            FetchResponse::Ok { status, headers } => {
                // Checked before a byte of it is written, so a head the machine sent malformed is a
                // `502` from the fallback rather than lines injected into the local response.
                let head = Head::checked(status, headers)?;
                *responded = true;
                head.write(tcp).await?;
                // The body follows on the same stream; stream it to the client until the node closes.
                tokio::io::copy(&mut reader, tcp).await?;
                tcp.shutdown().await?;
            }
            FetchResponse::Error(message) => {
                *responded = true;
                respond_error(tcp, Status::BadGateway, &format!("origin error: {message}")).await?;
            }
        }
        Ok(())
    }
}

/// Accept each local connection and hand it to `serve`, all served concurrently, until the process ends.
///
/// Each request rides its own bifrost stream, so a downloader's parallel ranged GETs do not stall behind
/// one slow transfer. At most `cap` are held at once ([`MAX_PIPES`] in a run; past it, new connections
/// wait in the kernel's backlog), and a failed accept pauses for [`ACCEPT_RETRY`] rather than spinning, the same
/// bounds `forward` keeps. One failed accept or request never tears down the ones in flight.
async fn accept_each<F, Fut>(listener: TcpListener, cap: usize, mut serve: F) -> eyre::Result<()>
where
    F: FnMut(TcpStream) -> Fut,
    Fut: Future<Output = eyre::Result<()>>,
{
    let mut pipes = FuturesUnordered::new();
    // Set after a failed accept: accepting resumes once `retry` fires.
    let retry = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(retry);
    let mut paused = false;
    loop {
        tokio::select! {
            () = &mut retry, if paused => paused = false,
            // Accept only below the cap: a connection waiting for its head holds a descriptor.
            accepted = listener.accept(), if !paused && pipes.len() < cap => match accepted {
                Ok((tcp, _)) => pipes.push(serve(tcp)),
                Err(error) => {
                    tracing::warn!(%error, "local accept failed; still listening");
                    retry.as_mut().reset(tokio::time::Instant::now() + ACCEPT_RETRY);
                    paused = true;
                }
            },
            Some(result) = pipes.next(), if !pipes.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "proxy request ended");
                }
            }
        }
    }
}

/// The loopback listener this run printed, and the only requests it answers: those sent to its own
/// address, under its own random path token.
struct Local {
    /// The listener's address, which a request's `Host` must name.
    addr: SocketAddr,
    /// The first path segment of every request this run answers: 128 random bits, printed only in the URL.
    token: String,
}

impl Local {
    /// The listener at `addr`, with a fresh token.
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            token: data_encoding::HEXLOWER.encode(&rand::random::<[u8; 16]>()),
        }
    }

    /// The origin URL one request asks for, or the reason this listener refuses it, served before
    /// anything is dialed.
    ///
    /// In order: the `Host` must be this listener's address, so a page that rebinds its own name to
    /// loopback is refused; the target must be one this listener answers ([`rest`](Self::rest)); and the
    /// composed URL must still be on the base's origin, whatever else the target holds (a `\` the URL
    /// grammar reads as `/`, say).
    fn admit(&self, request: &Parsed, base: &url::Url) -> Result<String, Refused> {
        let mut hosts = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"));
        let host = hosts.next().map(|(_, value)| value.as_str());
        if !host.is_some_and(|host| self.is_host(host)) || hosts.next().is_some() {
            return Err(Refused::Host);
        }
        origin_url(base, self.rest(&request.target)?)
    }

    /// Whether `host` names this listener: its address, or on port 80 its address with no port, which is
    /// how a client writes the `Host` for http's default port.
    fn is_host(&self, host: &str) -> bool {
        host == self.addr.to_string()
            || (self.addr.port() == 80 && host == self.addr.ip().to_string())
    }

    /// What follows the token in a target this listener answers. It must be origin-form (`/…`), so an
    /// absolute-form target (`http://elsewhere/`) cannot name another site; it must start with the token;
    /// and what follows the token must not start `//`, which a URL join reads as a new host.
    fn rest<'t>(&self, target: &'t str) -> Result<&'t str, Refused> {
        if !target.starts_with('/') {
            return Err(Refused::Target);
        }
        let Some(rest) = self.after_token(target) else {
            return Err(Refused::Token);
        };
        if rest.starts_with("//") {
            return Err(Refused::Target);
        }
        Ok(rest)
    }

    /// What follows `/<token>` in `target`, when the token is the whole first segment: empty, or starting
    /// with `/` or `?`. Compared without an early exit, so a local process timing its guesses learns
    /// nothing of the token from how long a wrong one took.
    fn after_token<'t>(&self, target: &'t str) -> Option<&'t str> {
        let segment = target.get(1..=self.token.len())?;
        let rest = target.get(self.token.len() + 1..)?;
        let differs = segment
            .bytes()
            .zip(self.token.bytes())
            .fold(0_u8, |acc, (left, right)| acc | (left ^ right));
        let ends = rest.is_empty() || rest.starts_with('/') || rest.starts_with('?');
        (differs == 0 && ends).then_some(rest)
    }
}

impl core::fmt::Display for Local {
    /// The local URL, as printed: `http://127.0.0.1:<port>/<token>/`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "http://{}/{}/", self.addr, self.token)
    }
}

/// A request the local listener refuses before anything is dialed. Its body names no part of the
/// request and nothing of this run, so a refused page learns only that it was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    /// The `Host` is not this listener's address, or there is more than one.
    Host,
    /// The path does not start with this run's token.
    Token,
    /// The target is not origin-form, does not join onto the URL this run was given, or would leave
    /// that URL's origin.
    Target,
}

impl Refused {
    /// The status a downloader reads.
    fn status(self) -> Status {
        match self {
            Refused::Host | Refused::Target => Status::BadRequest,
            Refused::Token => Status::NotFound,
        }
    }

    /// The body a downloader reads.
    fn body(self) -> &'static str {
        match self {
            Refused::Host | Refused::Token => "use the URL swoosh proxy printed",
            Refused::Target => "this URL reaches only the site swoosh proxy was started with",
        }
    }
}

/// The origin URL for one request, from what follows the token: the base as given for a root request
/// (empty, or `/`), else that path and query joined onto the base, so a download hits the exact file the
/// base names and an API proxy forwards the path.
///
/// Joined as a URL rather than string-concatenated: joining merges the two paths per the URL grammar, so
/// a base with a trailing slash and a target with a leading one (`https://x/` + `/a`) yield `https://x/a`,
/// not the `https://x//a` a raw `format!` produces. A root request keeps the base as parsed: the base
/// already names the exact resource (the download case), and joining `/` would discard any path it
/// carries. A joined URL must stay on the base's origin (scheme, host and port), read by the same parser
/// that joined it, so the check and the request cannot disagree on the host; a target that does not join,
/// or that leaves the origin, is the client's bad request.
fn origin_url(base: &url::Url, target: &str) -> Result<String, Refused> {
    if target == "/" || target.is_empty() {
        return Ok(base.as_str().to_owned());
    }
    let url = base.join(target).map_err(|_| Refused::Target)?;
    let origin = base.origin();
    if !origin.is_tuple() || origin != url.origin() {
        return Err(Refused::Target);
    }
    Ok(url.into())
}

/// Read an HTTP request head (up to the blank line) one byte at a time. Bounded so a client that never
/// sends the terminator cannot grow this without limit.
async fn read_head(tcp: &mut TcpStream) -> eyre::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if tcp.read(&mut byte).await? == 0 {
            break;
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 64 * 1024 {
            eyre::bail!("request head too large");
        }
    }
    Ok(head)
}

/// A parsed inbound request head: the pieces we relay onward to the proxy service.
struct Parsed {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

/// Parse the method, request target (path + query), and headers from a request head.
fn parse_request(head: &[u8]) -> eyre::Result<Parsed> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    if request.parse(head)?.is_partial() {
        eyre::bail!("incomplete request head");
    }
    let method = request
        .method
        .ok_or_else(|| eyre::eyre!("no method in request"))?
        .to_owned();
    let target = request
        .path
        .ok_or_else(|| eyre::eyre!("no path in request"))?
        .to_owned();
    let headers = request
        .headers
        .iter()
        .filter(|header| !header.name.is_empty())
        .map(|header| {
            (
                header.name.to_owned(),
                String::from_utf8_lossy(header.value).into_owned(),
            )
        })
        .collect();
    Ok(Parsed {
        method,
        target,
        headers,
    })
}

/// A response head from the machine, checked so it can be written to a local client as it is: a final
/// status, and header lines that are each one line. The machine at the far end writes these fields, and a
/// hostile one could put a line break in a value to split the response or re-add the framing headers this
/// proxy sets itself.
#[derive(Debug)]
struct Head {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Head {
    /// Check a head as it came off the wire. A status outside `200..=599` is refused (an informational
    /// one has no place on a closed response), and so is a header whose name is not an HTTP token or
    /// whose value holds a CR, an LF or a NUL. The framing headers this proxy sets itself are dropped.
    fn checked(status: u16, headers: Vec<(String, String)>) -> Result<Self, BadHead> {
        if !(200..=599).contains(&status) {
            return Err(BadHead::Status(status));
        }
        let mut kept = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            let token = !name.is_empty() && name.bytes().all(is_tchar);
            if !token || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
                return Err(BadHead::Header);
            }
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "connection" | "transfer-encoding" | "keep-alive"
            ) {
                continue;
            }
            kept.push((name, value));
        }
        Ok(Self {
            status,
            headers: kept,
        })
    }

    /// Write the status line and headers to the client, then `Connection: close`, so the client reads the
    /// body to EOF.
    async fn write(&self, tcp: &mut TcpStream) -> eyre::Result<()> {
        let mut head = format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status));
        for (name, value) in &self.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("Connection: close\r\n\r\n");
        tcp.write_all(head.as_bytes()).await?;
        Ok(())
    }
}

/// Whether `byte` may appear in an HTTP header name (RFC 9110 `tchar`).
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// A response head from the machine this proxy will not pass on.
#[derive(Debug, thiserror::Error)]
enum BadHead {
    /// A status that is not a final one.
    #[error("the machine answered with an invalid status {0}")]
    Status(u16),
    /// A header name that is not a token, or a value with a line break or a NUL.
    #[error("the machine answered with an invalid header")]
    Header,
}

/// An error status a `proxy` serves, chosen so a downloader can tell the failure apart by status
/// alone: a request this listener refuses is the client's (`400`, or `404` without the token), a dial the
/// exit node did not admit is authorization (`403`), a node that could not serve the request or a bad
/// upstream is a gateway failure (`502`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// The request is not one this listener answers: the wrong `Host`, or a target that leaves the origin.
    BadRequest,
    /// The exit node did not admit YOU: an authorization failure, not a bad gateway.
    Forbidden,
    /// The path does not carry this run's token.
    NotFound,
    /// The node could not serve the request, the origin failed, or the node's refusal is one this build
    /// cannot read: a gateway failure, and never a claim about the caller's authority.
    BadGateway,
}

impl Status {
    /// The status line pieces (`code`, `reason`) for this error status.
    fn parts(self) -> (u16, &'static str) {
        match self {
            Status::BadRequest => (400, "Bad Request"),
            Status::Forbidden => (403, "Forbidden"),
            Status::NotFound => (404, "Not Found"),
            Status::BadGateway => (502, "Bad Gateway"),
        }
    }
}

/// Serve an error status with a short reason, so a downloader sees a real HTTP error (distinguishable by
/// status), not a hang. An unadmitted dial serves `403`; a node that could not serve the request, or a
/// genuine origin failure, serves `502`.
async fn respond_error(tcp: &mut TcpStream, status: Status, message: &str) -> eyre::Result<()> {
    let (code, reason) = status.parts();
    let body = message.as_bytes();
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tcp.write_all(head.as_bytes()).await?;
    tcp.write_all(body).await?;
    tcp.shutdown().await?;
    Ok(())
}

/// A reason phrase for the common statuses; empty for the rest (clients ignore it, but the frame stays
/// well-formed).
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        404 => "Not Found",
        416 => "Range Not Satisfiable",
        _ => "",
    }
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
