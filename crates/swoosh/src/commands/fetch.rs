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
use tightbeam::protocol::{Request, Response};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::contacts::Contacts;
use crate::peer::Peer;
use crate::reach::{self, Reached};
use crate::transport::{self, ReachArgs};

/// Mint a local URL that fetches an origin through a node you name (your own janus, over the overlay).
#[derive(Debug, Args)]
pub struct FetchCmd {
    /// The origin URL to fetch (path and query on the local URL resolve against it).
    #[arg(value_name = "url")]
    pub url: String,
    /// the node to fetch through: a petname (`usa`, `alice/box`), a raw node id, or a `sheer:` link
    #[arg(long, value_name = "peer")]
    pub via: Peer,
    /// present a `sheer:` cap link to a cap-gated node (a delegate's slip)
    #[arg(long, value_name = "link")]
    pub present: Option<crate::credential::SheerLink>,
    /// Pin the local listener port (default: an OS-assigned free port).
    #[arg(long, value_name = "port")]
    pub port: Option<u16>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl crate::reaching::Reaching for FetchCmd {
    fn reach_args(&self) -> &crate::transport::ReachArgs {
        &self.reach
    }

    /// `fetch:` is FAMILY-GATED: the owner reaching their OWN exit node presents the member badge by
    /// default (rooted at the dialing key), and a delegate may override with `--present <slip>`. Stating
    /// `Family` FUSES the identity to `PersistedIfPresent`, so the owner's self-badge roots at the same
    /// key the dial binds under and admits: this is the one-line fix for the owner-reaching-own-node 403
    /// (the verb used to dial `Ephemeral` + slip-only, so an owner with no slip was refused). The effective
    /// slip is the FOLD of a self-addressing `sheer:` link in the `--via` peer with an explicit `--present`,
    /// threaded INTO the credential so the ONE resolver owns both slots.
    fn credential(&self) -> crate::credential::Credential {
        crate::credential::Credential::Family {
            present: self.via.self_present().or_else(|| self.present.clone()),
        }
    }

    fn reject_redundant_present(&self) -> eyre::Result<()> {
        self.via.reject_redundant_present(self.present.as_ref())
    }

    fn identity(&self) -> crate::identity::Identity {
        self.credential().identity()
    }

    /// Uniform dispatch: unpack the reach context and run. `fetch` reads `contacts` (to resolve `--via`),
    /// the `transport` label, and the resolved `present` badge; it ignores `key`.
    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: crate::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        self.run_fetch(
            node,
            ctx.contacts,
            ctx.transport,
            ctx.present,
            ctx.membership,
        )
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
        transport: transport::Transport,
        present: Option<String>,
        membership: Option<String>,
    ) -> eyre::Result<()> {
        // The redundant-present conflict is rejected ONCE in the composition root via
        // `Reaching::reject_redundant_present`, before this runs.
        let Reached { session, label } = reach::dial(node, contacts, &self.via, transport).await?;
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
                    pipes.push(self.serve(tcp, &session, present.as_deref(), membership.as_deref()));
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
        present: Option<&str>,
        membership: Option<&str>,
    ) -> eyre::Result<()> {
        let mut responded = false;
        if let Err(error) = self
            .relay(&mut tcp, session, present, membership, &mut responded)
            .await
        {
            if !responded {
                // A failure before any response (an open, a parse, a stream drop) is a bad-gateway
                // condition, not an authorization one, so `502`. The refusal path inside `relay` serves
                // its own `403` before returning, so a refusal never reaches this fallback.
                let _ = respond_error(
                    &mut tcp,
                    Status::BadGateway,
                    &format!("fetch failed: {error:#}"),
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
        present: Option<&str>,
        membership: Option<&str>,
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
        Request {
            service: "fetch".to_owned(),
            capability: present.map(str::to_owned),
            membership: membership.map(str::to_owned),
        }
        .write(&mut writer)
        .await?;
        if let Response::Error(message) = Response::read(&mut reader).await? {
            *responded = true;
            // A gate refusal is an AUTHORIZATION failure (the exit node refused YOU), not a bad gateway,
            // so serve `403` and keep `502` for a genuine origin error below. A downloader can then tell
            // "you are not allowed through this node" from "the origin is having a bad day" by status
            // alone, instead of reading two different failures as an indistinguishable `502`.
            return respond_error(
                tcp,
                Status::Forbidden,
                &format!("fetch service refused: {message}"),
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
/// alone: a gate refusal is authorization (`403`), a bad upstream is a gateway failure (`502`).
#[derive(Debug, Clone, Copy)]
enum Status {
    /// The exit node refused YOU (a gate refusal): an authorization failure, not a bad gateway.
    Forbidden,
    /// The origin, the stream, or the node itself failed: a genuine gateway error.
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
/// status), not a hang. A gate refusal serves `403`; a genuine origin or gateway failure serves `502`.
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
    use clap::Parser as _;

    use super::{FetchCmd, origin_url};
    use crate::credential::Credential;
    use crate::reaching::Reaching as _;

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

    /// `swoosh fetch --via <peer>` is FAMILY-gated by default: its credential is `Family`, so the owner
    /// reaching their OWN exit node presents the member badge (the fix for the owner-reaching-own-node
    /// 403). Before this redesign `fetch` was `Anonymous`/slip-only and an owner with no slip was refused.
    /// The identity derived from `Family` is `PersistedIfPresent`, so the self-badge roots correctly.
    #[test]
    fn fetch_is_family_gated_by_default_so_it_presents_a_badge() {
        let key = bifrost::NodeId::from_ed25519_secret(&[5u8; 32]).to_string();
        let cmd = Wrap::try_parse_from(["swoosh", "http://example.com/x", "--via", &key])
            .expect("fetch parses")
            .fetch;
        assert!(
            matches!(cmd.credential(), Credential::Family { present: None }),
            "fetch with no --present is Family (presents the member badge), not Anonymous"
        );
        assert_eq!(
            cmd.identity(),
            crate::identity::Identity::PersistedIfPresent,
            "a Family credential fuses the identity to PersistedIfPresent so the self-badge roots"
        );
    }
}
