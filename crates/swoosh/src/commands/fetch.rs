//! `swoosh fetch <url>`: mint a local http URL whose fetches egress at a node you name.
//!
//! A URL-minting reverse proxy: a downloader (xget, curl) pulls from the local listener; each request
//! rides one bifrost stream to a cap-gated `fetch:` service on the `--via` node; that node performs the
//! origin HTTP GET/HEAD and streams the response straight back, `Range` intact so a resumable download
//! works. It stays scoped to the one origin you named (a reverse proxy for one origin, not an open VPN).

use core::net::Ipv4Addr;

use bifrost::{Discovery, Node, Session, Transport};
use clap::Args;
use tightbeam::http::{FetchRequest, FetchResponse};
use tightbeam::protocol::{Request, Response};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::contacts::{Contacts, Target};
use crate::reach::{self, Reached};
use crate::transport::{self, ReachArgs};

/// Mint a local URL that fetches an origin through a node you name (your own janus, over the overlay).
#[derive(Debug, Args)]
pub struct FetchCmd {
    /// The origin URL to fetch. Its host is fixed; the local URL's path and query resolve against it.
    pub url: String,
    /// The node to fetch through: a saved petname (`usa`, `alice/box`) or a raw key.
    #[arg(long, value_name = "peer")]
    pub via: Target,
    /// Present a `sheer:` capability link to a cap-gated node.
    #[arg(long, value_name = "link")]
    pub present: Option<String>,
    /// Pin the local listener port. Omit for an OS-assigned free port.
    #[arg(long, value_name = "port")]
    pub port: Option<u16>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

impl FetchCmd {
    /// Dial the exit node, bind a loopback listener, print the local URL, and serve each request over its
    /// own bifrost stream until Ctrl-C.
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        contacts: &Contacts,
        transport: transport::Transport,
    ) -> eyre::Result<()> {
        let Reached { session, label } = reach::dial(node, contacts, &self.via, transport).await?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, self.port.unwrap_or(0))).await?;
        let addr = listener.local_addr()?;
        println!("swoosh fetch ready. local URL:\n");
        println!("    http://{addr}/\n");
        println!(
            "fetching {} via {label}. hand this URL to a downloader. ctrl-c to stop.",
            self.url
        );

        loop {
            let (tcp, _) = listener.accept().await?;
            // One request, one stream. A failed request serves a 502 and the listener keeps going, so a
            // single bad fetch never tears the local endpoint down mid-download.
            if let Err(error) = self.serve(tcp, &session).await {
                eprintln!("fetch: {error:#}");
            }
        }
    }

    /// Serve one inbound HTTP request: relay it to the `fetch:` service and stream the response back.
    async fn serve<S: Session>(&self, mut tcp: TcpStream, session: &S) -> eyre::Result<()> {
        let head = read_head(&mut tcp).await?;
        let Parsed {
            method,
            target,
            headers,
        } = parse_request(&head)?;
        let origin = origin_url(&self.url, &target);

        let (mut writer, mut reader) = session.open_bi().await?;
        Request {
            service: "fetch".to_owned(),
            capability: self.present.clone(),
        }
        .write(&mut writer)
        .await?;
        if let Response::Error(message) = Response::read(&mut reader).await? {
            return respond_error(&mut tcp, &format!("fetch service refused: {message}")).await;
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
                write_response_head(&mut tcp, status, &headers).await?;
                // The body follows on the same stream; stream it to the client until the node closes.
                tokio::io::copy(&mut reader, &mut tcp).await?;
                tcp.shutdown().await?;
            }
            FetchResponse::Error(message) => {
                respond_error(&mut tcp, &format!("origin error: {message}")).await?;
            }
        }
        Ok(())
    }
}

/// The origin URL for one request: the base as given for a root request (`/`), else the base with the
/// inbound path and query appended, so a download hits the exact file and an API proxy forwards the path.
fn origin_url(base: &str, target: &str) -> String {
    if target == "/" || target.is_empty() {
        base.to_owned()
    } else {
        format!("{base}{target}")
    }
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
    request.parse(head)?;
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

/// Serve a `502 Bad Gateway` with a short reason, so a downloader sees a real HTTP error, not a hang.
async fn respond_error(tcp: &mut TcpStream, message: &str) -> eyre::Result<()> {
    let body = message.as_bytes();
    let head = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
    use super::origin_url;

    #[test]
    fn root_request_uses_the_base_verbatim() {
        assert_eq!(
            origin_url("https://example.com/big.iso", "/"),
            "https://example.com/big.iso"
        );
    }

    #[test]
    fn a_path_and_query_append_to_the_base() {
        assert_eq!(
            origin_url("https://api.example.com", "/users?id=5"),
            "https://api.example.com/users?id=5"
        );
    }
}
