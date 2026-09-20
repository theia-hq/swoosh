//! `swoosh fetch <url>`: mint a local http URL whose fetches egress at a node you name.
//!
//! A URL-minting reverse proxy: a downloader (xget, curl) pulls from the local listener; each request
//! rides one bifrost stream to a cap-gated `fetch:` service on the `--via` node; that node performs the
//! origin HTTP GET/HEAD and streams the response straight back, `Range` intact so a resumable download
//! works. It stays scoped to the one origin you named (a reverse proxy for one origin, not an open VPN).

use core::net::Ipv4Addr;

use ::fetch::http::{FetchRequest, FetchResponse};
use bifrost::{Discovery, Node, Session, Transport};
use clap::Args;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use nauthy::Link;
use swoosh::contacts::Contacts;
use swoosh::peer::Peer;
use swoosh::reach::{self, Reached};
use swoosh::transport::{self, ReachArgs};
use swoosh::unbound::Unbound;
use tightbeam::protocol::{Request, Response};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// Mint a local URL that fetches an origin through a node you name (your own janus, over the overlay).
#[derive(Debug, Args)]
pub struct FetchCmd {
    /// The origin URL to fetch (path and query on the local URL resolve against it).
    #[arg(value_name = "url")]
    pub url: String,
    /// the node to fetch through: a petname (`usa`, `alice/box`), a raw node id, or a `sheer:` link
    #[arg(long, value_name = "peer")]
    pub via: Peer,
    /// which served service to reach
    // The default is taken FROM the table that knows a bare `swoosh serve` does not bind it (an
    // unscoped relay egresses under the exit node's own IP, so there is no default to inherit), so
    // the name this verb dials and the name a failed request teaches the `serve` line for are one
    // value.
    #[arg(long, value_name = "service", default_value = Unbound::FETCH.name())]
    pub service: String,
    /// present a `sheer:` capability link to reach a gated node
    #[arg(
        long,
        value_name = "link",
        long_help = "Optional: your own devices need no link; this machine's membership badge is \
                     presented automatically. Pass a `sheer:` link only to reach as a delegate."
    )]
    pub present: Option<Link>,
    /// Pin the local listener port (default: an OS-assigned free port).
    #[arg(long, value_name = "port")]
    pub port: Option<u16>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl swoosh::reaching::Reaching for FetchCmd {
    fn reach_args(&self) -> &swoosh::transport::ReachArgs {
        &self.reach
    }

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        self.via.reject_redundant_present(self.present.as_ref())
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, and what it dials as. It reaches a peer and never accepts connections under the
    /// home key, so its bind must not write the key's address record (0.9.0 F1).
    ///
    /// `fetch:` is FAMILY-GATED: the owner reaching their OWN exit node presents the member badge by
    /// default (rooted at the dialing key), and a delegate may override with `--present <slip>`. Stating
    /// `Family` FUSES the identity to `PersistedIfPresent`, so the owner's self-badge roots at the same
    /// key the dial binds under and admits: this is the one-line fix for the owner-reaching-own-node 403
    /// (the verb used to dial `Ephemeral` + slip-only, so an owner with no slip was refused). The effective
    /// slip is the FOLD of a self-addressing `sheer:` link in the `--via` peer with an explicit `--present`,
    /// threaded INTO the credential so the ONE resolver owns both slots.
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::Family {
            present: self.via.self_present().or_else(|| self.present.clone()),
        })
    }

    /// Uniform dispatch: unpack the reach context and run. `fetch` reads `contacts` (to resolve `--via`),
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
        self.run_fetch(node, ctx.contacts, ctx.bound, ctx.present, ctx.membership)
            .await
    }
}

impl FetchCmd {
    /// Dial the exit node, bind a loopback listener, print the local URL, and serve each request over its
    /// own bifrost stream until Ctrl-C.
    ///
    /// `present` is the ALREADY-RESOLVED badge from the composition root: the member badge rooted at the
    /// dialing key by default (so the owner reaching their OWN gated exit node admits), a `--present` slip
    /// if the caller gave one. `fetch:` is family-gated, so every per-request stream presents it.
    async fn run_fetch<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        bound: &transport::Bound,
        present: Option<Link>,
        membership: Option<Link>,
    ) -> eyre::Result<()> {
        // The redundant-present conflict is rejected ONCE in the composition root via
        // `Reaching::reject_redundant_present`, before this runs.
        let Reached { session, label } = reach::dial(node, contacts, &self.via, bound).await?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, self.port.unwrap_or(0))).await?;
        let addr = listener.local_addr()?;
        println!("swoosh fetch ready. local URL:\n");
        println!("    http://{addr}/\n");
        println!(
            "fetching {} via {label}. hand this URL to a downloader. ctrl-c to stop.",
            self.url
        );

        // Each request rides its own bifrost stream, served concurrently, so a downloader's parallel
        // ranged GETs do not stall behind one slow transfer. A transient local accept error is logged
        // and the listener keeps running (matching the tunnel siblings), never tearing down in-flight
        // downloads.
        let mut pipes = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (tcp, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            tracing::warn!(%error, "local accept failed; still listening");
                            continue;
                        }
                    };
                    pipes.push(self.serve(tcp, &session, present.as_ref(), membership.as_ref()));
                }
                Some(result) = pipes.next(), if !pipes.is_empty() => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "fetch request ended");
                    }
                }
            }
        }
    }

    /// Serve one inbound HTTP request. A failure BEFORE any response bytes are written serves a `502` so
    /// a downloader sees a real HTTP error, not a bare connection reset; a failure once the response has
    /// begun just closes the socket (a second HTTP response into the body would corrupt it).
    async fn serve<S: Session>(
        &self,
        mut tcp: TcpStream,
        session: &S,
        present: Option<&Link>,
        membership: Option<&Link>,
    ) -> eyre::Result<()> {
        let mut responded = false;
        if let Err(error) = self
            .relay(&mut tcp, session, present, membership, &mut responded)
            .await
        {
            if !responded {
                // A failure before any response (an open, a parse, a stream drop) is a bad-gateway
                // condition, not an authorization one, so `502`. The refusal path inside `relay` serves
                // its own `403`/`502` before returning, so a refusal never reaches this fallback.
                let _ = respond_error(
                    &mut tcp,
                    Status::BadGateway,
                    &self.body(format!("fetch failed: {error:#}")),
                )
                .await;
            }
            return Err(error);
        }
        Ok(())
    }

    /// Relay one request to the `fetch:` service and stream the response back, setting `responded` the
    /// moment any HTTP response has begun (so the caller knows a `502` is no longer safe to send).
    async fn relay<S: Session>(
        &self,
        tcp: &mut TcpStream,
        session: &S,
        present: Option<&Link>,
        membership: Option<&Link>,
        responded: &mut bool,
    ) -> eyre::Result<()> {
        let head = read_head(tcp).await?;
        let Parsed {
            method,
            target,
            headers,
        } = parse_request(&head)?;
        let origin = origin_url(&self.url, &target)?;

        let (mut writer, mut reader) = session.open_bi().await?;
        // The checked writer (the same rule the library's `Connector` applies): a credential-bearing
        // request refuses, before any byte, when the selected transport's declared profile does not
        // prove the peer. This fetch path dials a raw session and bypasses `Connector`, so it carries
        // the check itself; the refusal surfaces here as the local 502 cause.
        Request {
            service: self.service.clone(),
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
                        "the fetch node refused with a class this build cannot read; serving 502 \
                         rather than guessing an authorization answer"
                    );
                    Status::BadGateway
                }
            };
            return respond_error(
                tcp,
                status,
                &self.body(format!("fetch service refused: {refusal}")),
            )
            .await;
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
                *responded = true;
                write_response_head(tcp, status, &headers).await?;
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

    /// The body of a failure this proxy serves, with the `serve` line the exit node would need when
    /// the service was the DEFAULT one. A downloader's 403 is where this verb's refusal is actually
    /// read, so it is where the line has to land.
    ///
    /// Built from the service name THIS client requested and nothing else, and applied to every
    /// failure body alike: the refusal that came back picks the STATUS (an authorization failure is a
    /// 403, a bad day at the node or origin is a 502, which a downloader can already see), and it
    /// picks no part of this. A sentence that appeared on one refusal and not another would leak the
    /// distinction the uniform wire refusal exists to withhold.
    fn body(&self, failure: String) -> String {
        match Unbound::dialed(&self.service) {
            Some(unbound) => format!("{failure}: {}", unbound.teaching()),
            None => failure,
        }
    }
}

/// The origin URL for one request: the base as given for a root request (`/`), else the inbound path and
/// query resolved against the base, so a download hits the exact file the base names and an API proxy
/// forwards the path.
///
/// Delegates the composition to [`fetch::compose_url`], which PARSES the base and joins the target as a URL
/// rather than string-concatenating: joining merges the two paths per the URL grammar, so a base with a
/// trailing slash and a target with a leading one (`https://x/` + `/a`) yield `https://x/a`, not the
/// `https://x//a` a raw `format!` produces. A root request (`/`, or empty) keeps the base VERBATIM: the base
/// already names the exact resource (the download case), and joining `/` would discard any path the base
/// carries.
fn origin_url(base: &str, target: &str) -> eyre::Result<String> {
    if target == "/" || target.is_empty() {
        return Ok(base.to_owned());
    }
    fetch::compose_url(base, target).map_err(|error| eyre::eyre!(error))
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

/// A parsed inbound request head: the pieces we relay onward to the fetch service.
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

/// Write the response status line and headers to the client, forwarding the origin's headers verbatim
/// except the framing ones we set ourselves (`Connection: close`, so the client reads the body to EOF).
async fn write_response_head(
    tcp: &mut TcpStream,
    status: u16,
    headers: &[(String, String)],
) -> eyre::Result<()> {
    let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "connection" | "transfer-encoding" | "keep-alive"
        ) {
            continue;
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    tcp.write_all(head.as_bytes()).await?;
    Ok(())
}

/// An error status a `fetch` proxy serves, chosen so a downloader can tell the failure apart by status
/// alone: a dial the exit node did not admit is authorization (`403`), a node that could not serve the
/// request or a bad upstream is a gateway failure (`502`).
#[derive(Debug, Clone, Copy)]
enum Status {
    /// The exit node did not admit YOU: an authorization failure, not a bad gateway.
    Forbidden,
    /// The node could not serve the request, the origin failed, or the node's refusal is one this build
    /// cannot read: a gateway failure, and never a claim about the caller's authority.
    BadGateway,
}

impl Status {
    /// The status line pieces (`code`, `reason`) for this error status.
    fn parts(self) -> (u16, &'static str) {
        match self {
            Status::Forbidden => (403, "Forbidden"),
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
mod tests {
    use core::time::Duration;

    use bifrost::{Announced, Session};
    use clap::Parser as _;
    use nauthy::Identity;
    use swoosh::credential::Credential;
    use swoosh::reaching::{BindRole, Reaching as _};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::{FetchCmd, origin_url};

    #[test]
    fn root_request_uses_the_base_verbatim() {
        assert_eq!(
            origin_url("https://example.com/big.iso", "/").unwrap(),
            "https://example.com/big.iso"
        );
    }

    #[test]
    fn a_path_and_query_resolve_against_the_base() {
        assert_eq!(
            origin_url("https://api.example.com", "/users?id=5").unwrap(),
            "https://api.example.com/users?id=5"
        );
    }

    /// A base with a trailing slash and a target with a leading one compose to ONE slash, not two: the join
    /// merges the paths per the URL grammar, so `https://api.example.com/` + `/users` is
    /// `https://api.example.com/users`, never the `https://api.example.com//users` a raw `format!` yields.
    #[test]
    fn a_trailing_slash_base_and_leading_slash_target_do_not_double_the_slash() {
        assert_eq!(
            origin_url("https://api.example.com/", "/users").unwrap(),
            "https://api.example.com/users"
        );
    }

    /// A thin clap wrapper so a test can parse a `FetchCmd` from a real argv the same way the binary does.
    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        fetch: FetchCmd,
    }

    /// `swoosh fetch --via <peer>` is FAMILY-gated by default: it dials carrying the `Family` credential,
    /// so the owner reaching their OWN exit node presents the member badge (the fix for the
    /// owner-reaching-own-node 403). Before this redesign `fetch` was slip-only and an owner with no slip
    /// was refused. The identity derived from `Family` is `PersistedIfPresent`, so the self-badge roots
    /// correctly.
    #[test]
    fn fetch_is_family_gated_by_default_so_it_presents_a_badge() {
        let key = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]).to_string();
        let cmd = Wrap::try_parse_from(["swoosh", "http://example.com/x", "--via", &key])
            .expect("fetch parses")
            .fetch;
        assert!(
            matches!(
                cmd.bind_role(),
                BindRole::Dialing(Credential::Family { present: None })
            ),
            "fetch with no --present dials presenting the member badge"
        );
        assert_eq!(
            cmd.identity(),
            swoosh::identity::Identity::PersistedIfPresent,
            "a Family credential fuses the identity to PersistedIfPresent so the self-badge roots"
        );
    }

    /// A session declaring the announced profile: enough for `relay` to reach the request write, which
    /// must refuse before any byte reaches the far half.
    struct AnnouncedSession;

    impl Session for AnnouncedSession {
        type Security = Announced;
        type Write = tokio::io::WriteHalf<tokio::io::DuplexStream>;
        type Read = tokio::io::ReadHalf<tokio::io::DuplexStream>;

        fn peer(&self) -> bifrost::NodeId {
            bifrost::NodeId::from_ed25519_secret(&[0u8; 32])
        }

        async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            let (near, _far) = tokio::io::duplex(1024);
            let (read, write) = tokio::io::split(near);
            Ok((write, read))
        }

        async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
            Err(bifrost::Error::Closed)
        }

        async fn wait_closed(&self) {}
    }

    /// The line the DOWNLOADER reads. A `fetch` request that fails serves an HTTP error body, and
    /// that body is where this verb's refusal is actually read, so that is where the `serve` line the
    /// exit node would need has to land. Driven through the same announced-session refusal as the
    /// test below: this failure never reached the exit node at all and still carries the line, which
    /// is the property being held. The line is owed to the name this client SENT, never to an answer,
    /// so it can never report which refusal came back.
    #[tokio::test]
    async fn a_failed_request_names_the_serve_line_for_the_defaulted_service() {
        let defaulted = failure_body(&[]).await;
        assert!(
            defaulted.contains("swoosh serve fetch=fetch:<origin>"),
            "the defaulted service names the line that would bind it: {defaulted}"
        );

        // A service the operator NAMED is theirs; the client has nothing to teach about it and adds
        // nothing.
        let named = failure_body(&["--service", "news"]).await;
        assert!(
            !named.contains("swoosh serve"),
            "a named service gets no serve line appended: {named}"
        );
    }

    /// Drive one inbound request through `serve` over a session that refuses the credential write, and
    /// return the whole HTTP response the local downloader reads. `extra` is appended to the verb's
    /// argv, so a case can name its own `--service`.
    async fn failure_body(extra: &[&str]) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let key = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]).to_string();
        let mut argv = vec!["swoosh", "http://example.com/x", "--via", &key];
        argv.extend_from_slice(extra);
        let cmd = Wrap::try_parse_from(argv).expect("fetch parses").fetch;
        let identity = Identity::from_secret(&[7u8; 32]).unwrap();
        let link = identity
            .mint_member(
                identity.verifying_key(),
                nauthy::Request::expires_in(Duration::from_secs(3600)),
            )
            .unwrap()
            .link()
            .unwrap();
        assert!(
            cmd.serve(server, &AnnouncedSession, Some(&link), None)
                .await
                .is_err(),
            "the relay refuses the credential write"
        );

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    /// The fetch path bypasses `Connector`, so it carries the checked writer itself: presenting a
    /// credential over an announced session refuses before any byte, and the local URL serves its 502
    /// with the teaching cause instead of quietly shipping the credential to whoever answered.
    #[tokio::test]
    async fn fetch_refuses_to_present_a_credential_over_an_announced_session() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let key = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]).to_string();
        let cmd = Wrap::try_parse_from(["swoosh", "http://example.com/x", "--via", &key])
            .expect("fetch parses")
            .fetch;
        let identity = Identity::from_secret(&[7u8; 32]).unwrap();
        let link = identity
            .mint_member(
                identity.verifying_key(),
                nauthy::Request::expires_in(Duration::from_secs(3600)),
            )
            .unwrap()
            .link()
            .unwrap();

        assert!(
            cmd.serve(server, &AnnouncedSession, Some(&link), None)
                .await
                .is_err(),
            "the relay refuses the credential write"
        );

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 502 Bad Gateway"), "{text}");
        assert!(text.contains("does not prove the peer"), "{text}");
    }
}
