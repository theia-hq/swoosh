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
use core::future::Future;
use core::net::{Ipv4Addr, SocketAddr};
use core::ops::ControlFlow;
use core::time::Duration;

use ::fetch::http::{FetchRequest, FetchResponse};
use bifrost::{Discovery, Node, Refusal, Session, Transport};
use clap::Args;
use nauthy::{Link, Service};
use swoosh::contacts::Contacts;
use swoosh::home::Home;
use swoosh::node_client::UidSocket;
use swoosh::peer::{Machine, Peer};
use swoosh::peers::{Hints, Lane, OpenError, Peers, Presents, SessionEnd};
use swoosh::reach;
use swoosh::serve::control_codec::OpenRefusal;
use swoosh::transport::{self, ReachArgs};
use swoosh::unbound::Unbound;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::commands::connect::{self, MAX_PIPES, accept_each, press_ctrl_c};
use crate::commands::machine;
use crate::commands::through_serve::{self, Dial, Routed, Unattached, Unpiped};

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
    async fn run<'n: 'p, 'p, T: Transport, D: Discovery>(
        self,
        node: &'n Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
        peers: &'p Peers<'n, T, D>,
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
            peers,
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
    #[expect(
        clippy::too_many_arguments,
        reason = "the uniform reach context, unpacked"
    )]
    async fn run_proxy<'n, T: Transport, D: Discovery>(
        self,
        node: &'n Node<T, D>,
        peers: &Peers<'n, T, D>,
        contacts: &Contacts,
        machine: &Machine,
        bound: &transport::Bound,
        present: Option<Link>,
        membership: Option<Link>,
    ) -> eyre::Result<()> {
        let (rode, latest) = tokio::sync::mpsc::unbounded_channel();
        let exit = OwnExit {
            node,
            peers,
            rode,
            machine,
            service: Service::clone(&self.service),
            presents: Presents::resolved(
                &self.peer,
                Option::clone(&present),
                Option::clone(&membership),
            ),
            present,
            membership,
        };
        // Admission is proven on one stream before the URL prints, so a refusal is one line and a
        // non-zero exit rather than a URL that answers every request with a 403. The stream is dropped
        // once admitted; the machine tears its half down.
        match exit.held().await {
            Ok(_admitted) => {}
            Err(OpenError::Open(bifrost::Error::Refused(bifrost::Refusal::NotAdmitted))) => {
                return Err(exit.refused().await);
            }
            Err(error) => return Err(reach::open_failed(&self.peer, error, bound)),
        }
        // By own bind a host cut ends the run, as it ends `forward`'s port.
        let cut = async {
            connect::session_cut(latest).await;
            connect::ConnectionLost.into()
        };
        self.listen(&exit, &connect::Machine::of(contacts, machine.key()), cut)
            .await
    }

    /// Run through the `serve` at `home` when one answers there: `machine` as resolved, `slip` the link
    /// typed as it, if one was, and `contacts` to name it. Admission is proven on one Open before the URL
    /// prints, as by own bind, and each request then rides an Open of its own.
    ///
    /// # Errors
    ///
    /// The control socket cannot be trusted; never an own bind then.
    pub async fn through_serve(
        &self,
        home: &Home,
        machine: &Machine,
        slip: Option<Link>,
        contacts: &Contacts,
    ) -> eyre::Result<Routed> {
        let Some((socket, connected)) = through_serve::serve(home).await? else {
            return Ok(Routed::OwnBind);
        };
        let dial = Dial {
            machine,
            service: &self.service,
            slip,
            reach: &self.reach,
            contacts,
        };
        if let Err(refused) = dial.admit(&socket, connected).await {
            return Ok(Routed::Ran(Err(refused)));
        }
        through_serve::raise_open_files();
        let exit = ServeExit {
            dial: &dial,
            socket: &socket,
        };
        let named = connect::Machine::of(contacts, machine.key());
        // Through `serve` there is no session to watch: the run ends when a request finds it over.
        let never = core::future::pending();
        Ok(Routed::Ran(self.listen(&exit, &named, never).await))
    }

    /// Bind the loopback listener, print the local URL and the start lines naming `machine`, then answer
    /// each request through `exit` until the run ends ([`answer_each`](Self::answer_each)).
    async fn listen(
        &self,
        exit: &impl Exit,
        machine: &connect::Machine,
        cut: impl Future<Output = eyre::Report>,
    ) -> eyre::Result<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, self.port.unwrap_or(0))).await?;
        let local = Local::new(listener.local_addr()?);
        println!("{local}");
        eprintln!("Proxying {} through {machine}.", self.url);
        press_ctrl_c();
        Err(self.answer_each(listener, &local, exit, cut).await)
    }

    /// Answer each request `listener` accepts through `exit` until a request finds the run over, or
    /// `cut` resolves to the line the run ends with: the line it ends with, worded by `exit`.
    ///
    /// A cut drops the requests in flight: a client still waiting for its answer gets a `502` naming the
    /// cut as it goes, if the write needs no wait, and one mid-body is reset ([`Client`]).
    async fn answer_each(
        &self,
        listener: TcpListener,
        local: &Local,
        exit: &impl Exit,
        cut: impl Future<Output = eyre::Report>,
    ) -> eyre::Report {
        let unanswered = OnceCell::new();
        let cut = async {
            let line = cut.await;
            // Set as the cut resolves, before the select drops the requests in flight, so each client
            // still waiting reads it as it goes.
            let _ = unanswered.set(failed(&line));
            line
        };
        let answering = accept_each(listener, MAX_PIPES, |tcp| {
            self.answer(tcp, local, exit, &unanswered)
        });
        let ended = tokio::select! {
            // The cut first: a request that broke with its session is polled only after the run has
            // ended on `connection lost`, so no line of the request's carries the cut's reason.
            biased;
            ended = cut => ended,
            ended = answering => ended,
        };
        exit.ended(ended).await
    }

    /// Answer one local connection: its failure goes to the log and the listener stays up, unless the
    /// request found the run over ([`Unopened`] says when), which ends it with that line.
    async fn answer(
        &self,
        tcp: TcpStream,
        local: &Local,
        exit: &impl Exit,
        unanswered: &OnceCell<String>,
    ) -> ControlFlow<eyre::Report> {
        match self.serve(Client::new(tcp, unanswered), local, exit).await {
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
    /// corrupt it, and a clean close would pass a short body as whole). Breaks with
    /// the line the run ends with once the request's client has its answer.
    async fn serve(
        &self,
        mut client: Client<'_>,
        local: &Local,
        exit: &impl Exit,
    ) -> eyre::Result<ControlFlow<eyre::Report>> {
        let relayed = self
            .relay(&mut client.tcp, local, exit, &mut client.reply)
            .await;
        if let Err(error) = &relayed
            && client.reply == Reply::None
        {
            // A failure before any response (an open, a parse, a stream drop) is a bad-gateway
            // condition, not an authorization one, so `502`. The refusal path inside `relay` serves its
            // own `403`/`502` before returning, so a refusal never reaches this fallback.
            client.reply = Reply::Whole;
            let _ = respond_error(&mut client.tcp, Status::BadGateway, &failed(error)).await;
        }
        relayed
    }

    /// Relay one request to the `proxy:` service and stream the response back, setting `reply` the
    /// moment any HTTP response has begun (so the caller knows a `502` is no longer safe to send), and
    /// again once an origin's body has ended cleanly.
    ///
    /// The local checks ([`Local::admit`]) run before the stream opens, so a request this run did not
    /// print the URL for never reaches the machine or carries the credential.
    async fn relay(
        &self,
        tcp: &mut TcpStream,
        local: &Local,
        exit: &impl Exit,
        reply: &mut Reply,
    ) -> eyre::Result<ControlFlow<eyre::Report>> {
        let head = tokio::time::timeout(HEAD_TIMEOUT, read_head(tcp))
            .await
            .map_err(|_| eyre::eyre!("no request within {HEAD_TIMEOUT:?}"))??;
        let parsed = parse_request(&head)?;
        let origin = match local.admit(&parsed, &self.url) {
            Ok(origin) => origin,
            Err(refused) => {
                *reply = Reply::Whole;
                respond_error(tcp, refused.status(), refused.body()).await?;
                return Ok(ControlFlow::Continue(()));
            }
        };
        let Parsed {
            method, headers, ..
        } = parsed;

        let (mut writer, mut reader) = match exit.open().await {
            Ok(halves) => halves,
            Err(Unopened::Refused { refusal, ends }) => {
                *reply = Reply::Whole;
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
                let answered =
                    respond_error(tcp, status, &format!("proxy service refused: {refusal}")).await;
                // A run-ending refusal ends the run even when its client went before the answer.
                return match ends {
                    Some(line) => Ok(ControlFlow::Break(line)),
                    None => answered.map(|()| ControlFlow::Continue(())),
                };
            }
            Err(Unopened::Over(line)) => {
                *reply = Reply::Whole;
                let _ = respond_error(tcp, Status::BadGateway, &failed(&line)).await;
                return Ok(ControlFlow::Break(line));
            }
            Err(Unopened::Failed(error)) => return Err(error),
        };
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
                    respond_error(tcp, Status::BadGateway, &format!("origin error: {message}"))
                        .await?;
                }
            }
            Ok(())
        }
        .await;
        match fetched {
            Ok(()) => Ok(ControlFlow::Continue(())),
            Err(error) => match exit.stopped().await {
                // `serve` stopped under the request: its client's `502` says so, if none has begun, and
                // the run ends here rather than at the next request's Open.
                Some(stopped) => {
                    if *reply == Reply::None {
                        *reply = Reply::Whole;
                        let _ = respond_error(tcp, Status::BadGateway, &failed(&stopped)).await;
                    }
                    Ok(ControlFlow::Break(stopped))
                }
                None => Err(error),
            },
        }
    }
}

/// Where a run's requests leave from: one admitted stream per request, each on the Bulk lane, since a
/// downloader's parallel requests are a fan-out and never take the slots the run's other streams to the
/// machine need. Each request rides its own stream, so parallel ranged GETs do not stall behind one slow
/// transfer.
trait Exit {
    /// One admitted stream for the run's service, or why none opened.
    fn open(
        &self,
    ) -> impl Future<Output = Result<(impl AsyncWrite + Unpin, impl AsyncRead + Unpin), Unopened>>;

    /// `serve`'s own line when it is gone, asked after a request's open stream broke: `None` while it
    /// answers, and always by own bind, which holds no `serve`.
    fn stopped(&self) -> impl Future<Output = Option<eyre::Report>>;

    /// The line the run ends with, from the one its loop broke with: by own bind a later
    /// `NotAdmitted` ([`connect::NotAdmittedLater`]) is worded only now, once per run, after its client
    /// had its `403`.
    fn ended(&self, line: eyre::Report) -> impl Future<Output = eyre::Report>;
}

/// Why a request's stream did not open, and whether the run goes on.
enum Unopened {
    /// The machine refused the request: the local client gets the status that refusal reads as. `ends`
    /// is the line the run ends with after that answer, when every later request would meet the same
    /// refusal ([`Unpiped::Ends`]).
    Refused {
        refusal: Refusal,
        ends: Option<eyre::Report>,
    },
    /// The run is over ([`Unpiped::Ends`] for anything but the machine's refusal): the local client gets a
    /// `502` saying why, then the run ends with this line.
    Over(eyre::Report),
    /// Anything else: the local client gets a `502` saying so, and the listener stays up.
    Failed(eyre::Report),
}

/// The body of a failed request's `502`: one line, `proxy failed: ` and the first line of the error,
/// which for an ended standing carries its remedy. The lines below it address the person at the
/// terminal and stay there.
fn failed(error: &eyre::Report) -> String {
    let error = format!("{error:#}");
    format!("proxy failed: {}", error.lines().next().unwrap_or_default())
}

/// The machine every request leaves from by own bind, and what each request's stream presents to it:
/// `presents` keys the held session, and `present` and `membership` are the same two slots, for the
/// follow-up a `NotAdmitted` asks. Each stream's session watch goes to `rode`, for the run's
/// [`session_cut`](connect::session_cut).
struct OwnExit<'p, 'n, T: Transport, D: Discovery> {
    node: &'n Node<T, D>,
    peers: &'p Peers<'n, T, D>,
    rode: tokio::sync::mpsc::UnboundedSender<SessionEnd<T::Session>>,
    machine: &'p Machine,
    service: Service,
    presents: Presents,
    present: Option<Link>,
    membership: Option<Link>,
}

impl<T: Transport, D: Discovery> OwnExit<'_, '_, T, D> {
    /// One admitted stream on the held Bulk session, its failure as the lane gives it, its session's
    /// watch sent to `rode`.
    async fn held(&self) -> Result<(impl AsyncWrite + Unpin, impl AsyncRead + Unpin), OpenError> {
        let (_, end, writer, reader) = self
            .peers
            .open_attached(
                self.machine.key(),
                Hints::NONE,
                Service::clone(&self.service),
                Lane::Bulk,
                Presents::clone(&self.presents),
            )
            .await?;
        // A failed send means nothing watches: a test's exit, or a run already over.
        let _ = self.rode.send(end);
        Ok((writer, reader))
    }

    /// The dial refusal a `NotAdmitted` ends the run with, the first request's and a later one's alike.
    /// The follow-up asks over a connection of its own, once per run, after the loop.
    async fn refused(&self) -> eyre::Report {
        let diagnosis = reach::diagnose_over(
            self.node,
            self.machine,
            &self.service,
            Option::clone(&self.present),
            Option::clone(&self.membership),
        )
        .await;
        machine::refused(self.machine, &self.service, diagnosis)
    }
}

impl<T: Transport, D: Discovery> Exit for OwnExit<'_, '_, T, D> {
    async fn open(&self) -> Result<(impl AsyncWrite + Unpin, impl AsyncRead + Unpin), Unopened> {
        match self.held().await {
            Ok(halves) => Ok(halves),
            // A later `NotAdmitted` ends the run, as through `serve`; any other refusal is that
            // request's alone.
            Err(error) if connect::ends_the_run(&error) => Err(Unopened::Refused {
                refusal: Refusal::NotAdmitted,
                ends: Some(connect::NotAdmittedLater.into()),
            }),
            Err(OpenError::Open(bifrost::Error::Refused(refusal))) => Err(Unopened::Refused {
                refusal,
                ends: None,
            }),
            Err(error) => Err(Unopened::Failed(error.into())),
        }
    }

    async fn stopped(&self) -> Option<eyre::Report> {
        None
    }

    async fn ended(&self, line: eyre::Report) -> eyre::Report {
        if line.is::<connect::NotAdmittedLater>() {
            return self.refused().await;
        }
        line
    }
}

/// The machine every request leaves from through `serve`: an Open per request, on a control connection
/// of its own.
struct ServeExit<'d> {
    dial: &'d Dial<'d>,
    socket: &'d UidSocket,
}

impl Exit for ServeExit<'_> {
    async fn open(&self) -> Result<(impl AsyncWrite + Unpin, impl AsyncRead + Unpin), Unopened> {
        match self.dial.pipe(self.socket).await {
            Ok(stream) => Ok((stream.write, stream.read)),
            // The machine's own refusal reads as the own bind's does, so a downloader sees one status
            // for one refusal on both paths.
            Err(Unpiped::Pipe(Unattached::Refused(OpenRefusal::Peer(refusal)))) => {
                Err(Unopened::Refused {
                    refusal: refusal.into(),
                    ends: None,
                })
            }
            Err(Unpiped::Pipe(unattached)) => Err(Unopened::Failed(
                self.dial.unattached(unattached, self.socket).await,
            )),
            Err(Unpiped::Ends(Unattached::Refused(OpenRefusal::Peer(refusal)))) => {
                let ends = self
                    .dial
                    .unattached(
                        Unattached::Refused(OpenRefusal::Peer(refusal.clone())),
                        self.socket,
                    )
                    .await;
                Err(Unopened::Refused {
                    refusal: refusal.into(),
                    ends: Some(ends),
                })
            }
            Err(Unpiped::Ends(unattached)) => Err(Unopened::Over(
                self.dial.unattached(unattached, self.socket).await,
            )),
        }
    }

    async fn stopped(&self) -> Option<eyre::Report> {
        self.dial.stopped(self.socket).await
    }

    async fn ended(&self, line: eyre::Report) -> eyre::Report {
        line
    }
}

/// One local client's connection, and how far its answer got, so that a client dropped mid-answer
/// (a cut ended the run under it, or its body broke) never reads a cut answer as a whole one.
struct Client<'u> {
    tcp: TcpStream,
    reply: Reply,
    /// The `502` body for a client the run ended under before its answer began: set by the cut alone.
    unanswered: &'u OnceCell<String>,
}

/// How far a client's answer got.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reply {
    /// Nothing written yet: a `502` is still safe.
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
            reply: Reply::None,
            unanswered,
        }
    }
}

impl Drop for Client<'_> {
    /// A body framed by the connection's end is cut with a reset, never a clean close, so a downloader
    /// does not keep a short file as whole. A client the cut left unanswered gets its `502` if the socket
    /// takes it at once: no wait, so no clock, and a client that reads nothing gets the close alone.
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
            (Reply::None, None) | (Reply::Whole, _) => {}
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
