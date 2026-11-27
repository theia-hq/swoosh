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

use core::cell::OnceCell;
use core::net::{Ipv4Addr, SocketAddr};
use core::ops::ControlFlow;
use core::time::Duration;

use ::fetch::http::{FetchRequest, FetchResponse};
use bifrost::Refusal;
use clap::Args;
use nauthy::Service;
use swoosh::contacts::Contacts;
use swoosh::escape::{Escaped, escaped_report};
use swoosh::peer::{Machine, Peer};
use swoosh::peers::Hints;
use swoosh::serve::control_codec::{OpenLane, OpenRefusal, PeerRefusal};
use swoosh::streams::{Ask, StreamSource, Unopened};
use swoosh::transport::ReachArgs;
use swoosh::unbound::Unbound;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::commands::connect::{
    self, Failure, Listener, MAX_PIPES, Over, PipeFailures, accept_each, press_ctrl_c,
};
use crate::commands::machine;
use crate::commands::route::{Pipe, Route};
use crate::commands::through_serve::{StandingEnded, raise_open_files};

/// Mint a local URL that reaches an origin through a machine you name (your own exit, over the overlay).
#[derive(Debug, Args)]
pub struct ProxyCmd {
    // Positional and first, like every verb's machine: the machine is never optional, and a flag that
    // is never optional is a positional.
    #[arg(value_name = "machine", help = machine::HELP)]
    pub peer: Peer,
    /// The origin URL; request path and query go after it
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
        swoosh::reaching::BindRole::Dialing(self.credential())
    }
}

/// How long a local client has to send its whole request head. A connection that sends nothing holds a
/// descriptor and a slot under [`MAX_PIPES`]; this is what gives them back. The same span the engine at
/// the far end allows an origin's answer.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// The lane a request's stream rides: a downloader's parallel requests are a fan-out, so they never take
/// the places the run's other streams to the machine need on Main. Each request rides its own stream, so
/// parallel ranged GETs do not stall behind one slow transfer.
const PROXY_LANE: OpenLane = OpenLane::Bulk;

impl ProxyCmd {
    /// What this run dials as: the one value that picks its bind and what its streams present.
    pub(crate) fn credential(&self) -> swoosh::credential::Credential {
        swoosh::credential::Credential::dialing(&self.peer, self.service.as_str())
    }

    /// The one stream every request asks of `machine`, admission included.
    fn ask(&self, machine: &Machine) -> Ask {
        Ask {
            peer: machine.key(),
            hints: Hints::NONE,
            service: Service::clone(&self.service),
            lane: PROXY_LANE,
            slip: self.peer.self_present(),
        }
    }

    /// `proxy <machine> <url>`, on either path: prove the gate admits the ask, bind a loopback listener,
    /// print the local URL on `out` and the start lines naming `machine` as `contacts` names it, then
    /// answer each request over its own stream from `source`, each outcome worded by `route`, until a
    /// request's open ends the run. A machine that refuses the service refuses here, once, before any URL
    /// is printed.
    ///
    /// The URL is the one thing on `out`, stdout in a run: a made artifact a script reads as the first
    /// line. The lines for the person ride stderr.
    pub(crate) async fn proxy<S: StreamSource>(
        &self,
        source: S,
        route: &Route<'_>,
        machine: &Machine,
        contacts: &Contacts,
        out: &mut impl std::io::Write,
    ) -> eyre::Result<()> {
        let ask = self.ask(machine);
        let listener = Listener {
            source: &source,
            ask: &ask,
            route,
            machine,
        };
        listener.admit().await?;
        raise_open_files();
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, self.port.unwrap_or(0))).await?;
        let local = Local::new(tcp.local_addr()?);
        writeln!(out, "{local}")?;
        out.flush()?;
        eprintln!(
            "Proxying {} through {}.",
            self.url,
            connect::Machine::of(contacts, machine.key())
        );
        press_ctrl_c();
        let failures = PipeFailures::new(machine, std::io::stderr());
        Err(self.answer_each(tcp, &local, &listener, &failures).await)
    }

    /// Answer each request `tcp` accepts through `listener` until one ends the run: the line it ends
    /// with. A request that ends it answers its own client first, and the loop then drops the requests in
    /// flight: a client still waiting for its answer gets a `502` naming the line as it goes, if the
    /// write needs no wait, and one mid-body is reset ([`Client`]).
    async fn answer_each<S: StreamSource>(
        &self,
        tcp: TcpListener,
        local: &Local,
        listener: &Listener<'_, S>,
        failures: &PipeFailures<impl std::io::Write>,
    ) -> eyre::Report {
        let unanswered = OnceCell::new();
        let over = accept_each(tcp, MAX_PIPES, |client| {
            self.answer(client, local, listener, failures, &unanswered)
        })
        .await;
        listener.ending(over).await
    }

    /// Answer one local connection: its failure goes to the log and the listener stays up, unless the
    /// request's open said the run is over ([`Pipe`]), or `serve` went under its stream, which ends it.
    /// A request whose stream did not open also goes to `failures`.
    async fn answer<S: StreamSource>(
        &self,
        tcp: TcpStream,
        local: &Local,
        listener: &Listener<'_, S>,
        failures: &PipeFailures<impl std::io::Write>,
        unanswered: &OnceCell<String>,
    ) -> ControlFlow<Over> {
        match self
            .serve(Client::new(tcp, unanswered), local, listener, failures)
            .await
        {
            Ok(flow) => flow,
            Err(error) => {
                tracing::warn!(%error, "proxy request ended");
                ControlFlow::Continue(())
            }
        }
    }

    /// Serve one inbound HTTP request. A failure BEFORE any response bytes are written serves a `502` so
    /// a downloader sees a real HTTP error, not a bare connection reset; a failure once the response has
    /// begun only ends the connection, with a reset mid-body (a second HTTP response into the body would
    /// corrupt it, and a clean close would pass a short body as whole). Breaks with why the run is over
    /// once the request's client has its answer.
    async fn serve<S: StreamSource>(
        &self,
        mut client: Client<'_>,
        local: &Local,
        listener: &Listener<'_, S>,
        failures: &PipeFailures<impl std::io::Write>,
    ) -> eyre::Result<ControlFlow<Over>> {
        let relayed = self.relay(&mut client, local, listener, failures).await;
        if let Err(error) = &relayed
            && matches!(client.reply, Reply::Unadmitted | Reply::None)
        {
            // A failure before any response (an open, a parse, a stream drop) is a bad-gateway
            // condition, not an authorization one, so `502`, admitted or not: its body is this
            // request's own failure, never the run's. The paths inside `relay` that answer for
            // themselves set `reply` first, so a refusal never reaches this fallback.
            client.reply = Reply::Whole;
            let _ = respond_error(&mut client.tcp, Status::BadGateway, &failed(error)).await;
        }
        relayed
    }

    /// Relay one request to the `proxy:` service and stream the response back, moving `client`'s
    /// `reply` on as its answer goes: to [`Reply::None`] once the request is admitted, then on the
    /// moment any HTTP response has begun (so the caller knows a `502` is no longer safe to send), and
    /// again once an origin's body has ended cleanly. A request that ends the run sets `unanswered` to
    /// the `502` body every other waiting admitted client gets, before it breaks.
    ///
    /// The local checks ([`Local::admit`]) run before the stream opens, so a request this run did not
    /// print the URL for never reaches the machine or carries the credential. A stream that opened is a
    /// carried pipe to `failures`, whatever ends it; one that did not open is a failed one, unless it
    /// ends the run.
    async fn relay<S: StreamSource>(
        &self,
        client: &mut Client<'_>,
        local: &Local,
        listener: &Listener<'_, S>,
        failures: &PipeFailures<impl std::io::Write>,
    ) -> eyre::Result<ControlFlow<Over>> {
        let head = tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client.tcp))
            .await
            .map_err(|_| eyre::eyre!("no request within {HEAD_TIMEOUT:?}"))??;
        let parsed = parse_request(&head)?;
        let origin = match local.admit(&parsed, &self.url) {
            Ok(origin) => origin,
            Err(refused) => {
                client.reply = Reply::Whole;
                respond_error(&mut client.tcp, refused.status(), refused.body()).await?;
                return Ok(ControlFlow::Continue(()));
            }
        };
        // Only now may the run's end tell this client anything of the run.
        client.reply = Reply::None;
        let Parsed {
            method, headers, ..
        } = parsed;

        let opened = match listener.source.open(listener.ask).await {
            Ok(opened) => opened,
            Err(unopened) => return client.unopened_request(unopened, listener, failures).await,
        };
        failures.carried();
        let (mut writer, mut reader) = (opened.write, opened.read);
        let Client { tcp, reply, .. } = &mut *client;
        // Once the stream opened, a failure may be `serve` stopping under it.
        let fetched: eyre::Result<()> = async {
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
                    *reply = Reply::Body;
                    head.write(tcp).await?;
                    // The body follows on the same stream; stream it to the client until the node closes.
                    tokio::io::copy(&mut reader, tcp).await?;
                    tcp.shutdown().await?;
                    *reply = Reply::Whole;
                }
                FetchResponse::Error(message) => {
                    *reply = Reply::Whole;
                    let body = format!("origin error: {}", Escaped(&message));
                    respond_error(tcp, Status::BadGateway, &body).await?;
                }
            }
            Ok(())
        }
        .await;
        match fetched {
            Ok(()) => Ok(ControlFlow::Continue(())),
            Err(error) => match listener.route.stopped().await {
                // `serve` stopped under the request: the run ends here rather than at the next
                // request's open.
                Some(stopped) => Ok(client.ends(stopped).await),
                // A request whose stream opened is carried, whatever ends it: the log alone. Escaped
                // here, as its cause can carry the machine's text into the fallback's `502`.
                None => Err(escaped_report(error)),
            },
        }
    }
}

impl Client<'_> {
    /// Answer a request whose stream did not open, by what `unopened` does to the run, the table every
    /// listener shares ([`Route::pipe`]): the machine's `NotAdmitted` is a `403` and ends the run, its
    /// line worded once the loop has stopped, so the one question it asks waits for no client. Any
    /// other ending, and a `serve` confirmed stalled, is a `502` naming the line the run ends with.
    /// Anything else fails that request alone: the machine's refusal its own `502`, the rest the
    /// fallback's.
    async fn unopened_request<S: StreamSource>(
        &mut self,
        unopened: Unopened,
        listener: &Listener<'_, S>,
        failures: &PipeFailures<impl std::io::Write>,
    ) -> eyre::Result<ControlFlow<Over>> {
        match listener.route.pipe(unopened, listener.machine).await {
            // An AUTHORIZATION failure (the exit node refused YOU): `403`, so a downloader can tell
            // "you are not allowed through this node" from "the node or origin is having a bad day" by
            // status alone. The run ends even when its client went before the answer.
            Pipe::Ends(
                not_admitted @ Unopened::Refused(OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
            ) => {
                self.reply = Reply::Whole;
                let body = format!("proxy service refused: {}", Refusal::NotAdmitted);
                let _ = respond_error(&mut self.tcp, Status::Forbidden, &body).await;
                // The run's own line waits for the question it asks, so a client still waiting is
                // told the refusal without its cause.
                let _ = self.unanswered.set(failed(&machine::refused(
                    listener.machine,
                    &listener.ask.service,
                    None,
                )));
                Ok(ControlFlow::Break(Over::Ends(not_admitted)))
            }
            Pipe::Ends(unopened) => {
                let line = listener.ending(Over::Ends(unopened)).await;
                Ok(self.ends(line).await)
            }
            Pipe::Stalled(line) => Ok(self.ends(line).await),
            Pipe::Failed(failure, line) => {
                // `BadRequest` and `Unavailable` are the node's own failure to serve the request and
                // rule on nothing about this caller, so they keep `502`, with the machine's text,
                // escaped as the clause already is. A refusal this build cannot read is not one of
                // them: it claims nothing about the caller, so it takes the fallback's `502` like any
                // failed open.
                let refused = match &failure {
                    Some(Failure::Refused(refusal)) => {
                        Some(format!("proxy service refused: {refusal}"))
                    }
                    Some(Failure::Unreachable | Failure::Interrupted(_) | Failure::Busy) | None => {
                        None
                    }
                };
                failures.failed(failure, &line);
                match refused {
                    Some(body) => {
                        self.reply = Reply::Whole;
                        respond_error(&mut self.tcp, Status::BadGateway, &body).await?;
                        Ok(ControlFlow::Continue(()))
                    }
                    None => Err(line),
                }
            }
        }
    }

    /// End the run with `line` from a request whose client has no answer yet: it gets a `502` naming
    /// the line, and so does every other admitted client still waiting as the loop drops it.
    async fn ends(&mut self, line: eyre::Report) -> ControlFlow<Over> {
        let body = failed(&line);
        if self.reply == Reply::None {
            self.reply = Reply::Whole;
            let _ = respond_error(&mut self.tcp, Status::BadGateway, &body).await;
        }
        let _ = self.unanswered.set(body);
        ControlFlow::Break(Over::Line(line))
    }
}

/// The body of a failed request's `502`: one line, `proxy failed: ` and the first line of the error, its
/// head. An ended standing's remedy is the detail under that head, so a program reading the body, which
/// never sees the terminal, gets it after the head as one clause. Every other detail line addresses the
/// person at the terminal and stays there.
fn failed(error: &eyre::Report) -> String {
    let text = format!("{error:#}");
    let head = text.lines().next().unwrap_or_default();
    match ended_remedy(error) {
        Some(remedy) => format!("proxy failed: {head}; {}", clause(&remedy)),
        None => format!("proxy failed: {head}"),
    }
}

/// The remedy an ended standing names, keyed to the machine it names; `None` for any other error, and for
/// an ended standing that could not tell which key `serve` runs as.
fn ended_remedy(error: &eyre::Report) -> Option<String> {
    error
        .chain()
        .find_map(|cause| {
            if let Some(StandingEnded(node)) = cause.downcast_ref::<StandingEnded>() {
                return *node;
            }
            match cause.downcast_ref::<swoosh::reaching::ResolveError>() {
                Some(swoosh::reaching::ResolveError::Ended { node, .. }) => Some(*node),
                _ => None,
            }
        })
        .map(swoosh::badge::remedy)
}

/// A detail block's first sentence as one clause after a head: lowercase, no closing mark, and the
/// command it introduces after `: ` when the next line is that command.
fn clause(detail: &str) -> String {
    let mut lines = detail.lines().map(str::trim);
    let sentence = lines.next().unwrap_or_default();
    let mut chars = sentence.chars();
    let lowered: String = chars
        .next()
        .map(|first| first.to_lowercase().chain(chars).collect())
        .unwrap_or_default();
    match lowered.strip_suffix(':') {
        Some(lead) => match lines.next().filter(|line| line.starts_with("swoosh ")) {
            Some(command) => format!("{lead}: {command}"),
            None => lead.to_owned(),
        },
        None => lowered.trim_end_matches('.').to_owned(),
    }
}

/// One local client's connection, and how far its answer got, so that a client dropped mid-answer
/// (another request ended the run under it, or its body broke) never reads a cut answer as a whole one.
struct Client<'u> {
    tcp: TcpStream,
    reply: Reply,
    /// The `502` body for an admitted client the run ended under before its answer began: set by the
    /// request that ended it.
    unanswered: &'u OnceCell<String>,
}

/// How far a client's answer got.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reply {
    /// Nothing written, and no request admitted ([`Local::admit`]): a `502` for its own failure is
    /// still safe, and the run's end tells it nothing, as a client without the token learns nothing
    /// of the run.
    Unadmitted,
    /// An admitted request, nothing written yet: a `502` is still safe.
    None,
    /// An origin's head is out and its body, framed by the connection's end, is still coming.
    Body,
    /// A whole answer: an error framed by its length, or a body that ended cleanly.
    Whole,
}

impl<'u> Client<'u> {
    fn new(tcp: TcpStream, unanswered: &'u OnceCell<String>) -> Self {
        Self {
            tcp,
            reply: Reply::Unadmitted,
            unanswered,
        }
    }
}

impl Drop for Client<'_> {
    /// A body framed by the connection's end is cut with a reset, never a clean close, so a downloader
    /// does not keep a short file as whole. An admitted client the run's end left unanswered gets its
    /// `502` if the socket takes it at once: no wait, so no clock, and a client that reads nothing gets
    /// the close alone. A client not yet admitted gets the close alone, so the run's line, which names
    /// the machine, never reaches a client that has not shown the token.
    fn drop(&mut self) {
        match (self.reply, self.unanswered.get()) {
            (Reply::Body, _) => {
                if let Err(error) = self.tcp.set_zero_linger() {
                    tracing::debug!(%error, "a broken answer's reset could not be set");
                }
            }
            (Reply::None, Some(body)) => {
                let _ = self
                    .tcp
                    .try_write(error_response(Status::BadGateway, body).as_bytes());
            }
            (Reply::Unadmitted, _) | (Reply::None, None) | (Reply::Whole, _) => {}
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
    tcp.write_all(error_response(status, message).as_bytes())
        .await?;
    tcp.shutdown().await?;
    Ok(())
}

/// An error status and its one-line body as a whole response, framed by its length.
fn error_response(status: Status, message: &str) -> String {
    let (code, reason) = status.parts();
    format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{message}",
        message.len()
    )
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
