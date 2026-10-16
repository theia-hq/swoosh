#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::any::Any;
use core::cell::Cell;
use core::net::SocketAddr;
use core::panic::AssertUnwindSafe;
use core::time::Duration;

use bifrost::{Addr, HintStream, Node, NodeId, Transport as _};
use bifrost_iroh::{Endpoint, IrohSession};
use futures::FutureExt as _;
use noq::crypto::rustls::HandshakeData;
use swoosh::identity::Secret;
use swoosh::reaching::BindRole;
use swoosh::testkit::TestRoot;
use swoosh::transport::{self, PeerHint};
use tightbeam::tunnel::{self, CancellationToken, Connector, Router};

use super::IrohBind;

const DEADLINE: Duration = Duration::from_secs(30);
const CLOSE_DEADLINE: Duration = Duration::from_secs(10);

#[tokio::test]
async fn normal_roles_ping_with_the_production_hybrid_group() {
    Row::Normal.run().await.unwrap();
}

#[tokio::test]
async fn local_roles_ping_with_the_production_hybrid_group() {
    Row::Local.run().await.unwrap();
}

#[test]
fn the_decoder_rejects_absent_and_wrong_type_records() {
    assert!(matches!(decode(None), Err(RecordError::Absent)));
    assert!(matches!(
        decode(Some(Box::new(()))),
        Err(RecordError::WrongType)
    ));
}

enum Row {
    Normal,
    Local,
}

impl Row {
    async fn run(self) -> eyre::Result<()> {
        let host_secret = Secret::ephemeral();
        let member_secret = Secret::ephemeral();
        let serving = BindRole::Serving;
        let dialing = BindRole::Dialing(swoosh::credential::Credential::Family { present: None });
        let (host_bind, member_bind) = match self {
            Self::Normal => (IrohBind::of(false, &serving), IrohBind::of(false, &dialing)),
            Self::Local => (IrohBind::of(true, &serving), IrohBind::of(true, &dialing)),
        };
        let host = tokio::time::timeout(
            DEADLINE,
            host_bind.bind(&host_secret, transport::Reach::default()),
        )
        .await??;
        let member = async {
            Ok::<_, eyre::Report>(
                tokio::time::timeout(
                    DEADLINE,
                    member_bind.bind(&member_secret, transport::Reach::default()),
                )
                .await??,
            )
        }
        .await;
        let member = match member {
            Ok(member) => member,
            Err(error) => {
                tokio::time::timeout(CLOSE_DEADLINE, host.close()).await?;
                return Err(error);
            }
        };

        // No spawned proof task can outlive this scope or lose an observer panic. Even a failing
        // assertion is held until both production endpoints have been asked to close.
        let proof = AssertUnwindSafe(exchange(&host, &member, &serving, &dialing))
            .catch_unwind()
            .await;
        let closed = tokio::time::timeout(CLOSE_DEADLINE, async {
            tokio::join!(host.close(), member.close());
        })
        .await;
        match proof {
            Ok(result) => {
                closed?;
                result
            }
            Err(panic) => {
                // A close timeout must not replace the original assertion's cause.
                let _ = closed;
                std::panic::resume_unwind(panic)
            }
        }
    }
}

async fn exchange(
    host: &Endpoint,
    member: &Endpoint,
    serving: &BindRole,
    dialing: &BindRole,
) -> eyre::Result<()> {
    let host_hints = loopback_hints(host)?;
    let member_hints = loopback_hints(member)?;
    let host_discovery = PeerHint::discovery(host, member_hints, serving);
    let member_discovery = PeerHint::discovery(member, host_hints, dialing);
    let accepted = Cell::new(0);
    let connected = Cell::new(0);
    let host = Node::new(
        ObservedIroh {
            endpoint: host,
            observations: &accepted,
        },
        host_discovery.discovery,
    );
    let member = Node::new(
        ObservedIroh {
            endpoint: member,
            observations: &connected,
        },
        member_discovery.discovery,
    );

    // The family root signs only the badge; neither transport binds under the root's key.
    let root = TestRoot::seeded(0x71);
    let badge = root.device_badge(
        member.node_id(),
        nauthy::Request::expires_in(Duration::from_secs(300)),
    )?;
    assert_ne!(root.node_id(), host.node_id());
    assert_ne!(root.node_id(), member.node_id());
    // An absent, uniquely named store is empty. No home, key file or denylist is written or removed.
    let path = std::env::temp_dir().join(format!("swoosh-iroh-group-{}", host.node_id()));
    eyre::ensure!(
        !path.exists(),
        "the synthetic denylist path is already occupied"
    );
    let gate = tunnel::resolve_gate(Some(root.node_id()), nauthy::Denylist::load(path)?)?;
    // Ping never reads the SSH host seed.
    let exposer =
        swoosh::serve::bind_entry(Router::new(gate), "ping=ping:", [0; 32], &[])?.expose()?;
    let cancel = CancellationToken::new();

    // Join instead of spawning: serving is polled beside the client, and both outcomes (including
    // panics) are retained. Each branch requests cancellation on exit; each has its own finite bound.
    let server = async {
        let result = tokio::time::timeout(
            DEADLINE,
            AssertUnwindSafe(exposer.run(&host, cancel.clone())).catch_unwind(),
        )
        .await;
        cancel.cancel();
        result
    };
    let client = async {
        let result = tokio::time::timeout(
            DEADLINE,
            AssertUnwindSafe(async {
                let service = Connector::to_node(host.node_id(), "ping".parse()?, Some(badge))
                    .open_service(&member)
                    .await?;
                let report = measure::Ping {
                    count: 1,
                    interval: Duration::ZERO,
                }
                .run(&service)
                .await?;
                eyre::ensure!(
                    report.received() == 1,
                    "the service did not return a ping reply"
                );
                Ok::<(), eyre::Report>(())
            })
            .catch_unwind(),
        )
        .await;
        cancel.cancel();
        result
    };
    let (served, pinged) = tokio::join!(server, client);
    let served = served.expect("serving must finish within its deadline");
    let pinged = pinged.expect("the ping must finish within its deadline");
    let served = served.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let pinged = pinged.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    served?;
    pinged?;
    assert!(connected.get() > 0, "the service's dial must be observed");
    assert!(accepted.get() > 0, "the service's accept must be observed");
    Ok(())
}

fn loopback_hints(endpoint: &Endpoint) -> eyre::Result<Vec<PeerHint>> {
    let addr = endpoint.local_addr();
    let hints = addr
        .hints
        .into_iter()
        .filter(|socket| socket.ip().is_loopback())
        .map(|socket| format!("{}={socket}", addr.node).parse())
        .collect::<eyre::Result<Vec<_>>>()?;
    eyre::ensure!(
        !hints.is_empty(),
        "the endpoint has no explicit loopback hint"
    );
    Ok(hints)
}

struct ObservedIroh<'a> {
    endpoint: &'a Endpoint,
    observations: &'a Cell<u32>,
}

impl ObservedIroh<'_> {
    fn observe(&self, session: IrohSession) -> IrohSession {
        decode(session.handshake_data()).expect("the actual session must negotiate X25519MLKEM768");
        if self.observations.get() == 0 {
            // Mutate detached genuine records, never construct NoQ's non-exhaustive type or cache a
            // substitute group. These negatives exercise the very decoder used above.
            let mut missing = decode(session.handshake_data()).unwrap();
            missing.negotiated_key_exchange_group = None;
            assert!(matches!(
                decode(Some(missing)),
                Err(RecordError::MissingGroup)
            ));
            let mut classical = decode(session.handshake_data()).unwrap();
            classical.negotiated_key_exchange_group = Some(rustls::NamedGroup::X25519);
            assert!(matches!(
                decode(Some(classical)),
                Err(RecordError::WrongGroup)
            ));
        }
        self.observations.set(self.observations.get() + 1);
        session
    }
}

impl bifrost::Transport for ObservedIroh<'_> {
    type Security = <Endpoint as bifrost::Transport>::Security;
    type Session = IrohSession;

    fn node_id(&self) -> NodeId {
        self.endpoint.node_id()
    }

    fn local_addr(&self) -> Addr {
        self.endpoint.local_addr()
    }

    fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.endpoint.bound_sockets()
    }

    async fn connect(&self, addr: Addr) -> Result<Self::Session, bifrost::Error> {
        self.endpoint
            .connect(addr)
            .await
            .map(|session| self.observe(session))
    }

    async fn connect_with_updates(
        &self,
        addr: Addr,
        updates: HintStream,
    ) -> Result<Self::Session, bifrost::Error> {
        self.endpoint
            .connect_with_updates(addr, updates)
            .await
            .map(|session| self.observe(session))
    }

    async fn accept(&self) -> Result<Self::Session, bifrost::Error> {
        self.endpoint
            .accept()
            .await
            .map(|session| self.observe(session))
    }

    async fn close(&self) {
        self.endpoint.close().await;
    }
}

#[derive(Debug)]
enum RecordError {
    Absent,
    WrongType,
    MissingGroup,
    WrongGroup,
}

fn decode(record: Option<Box<dyn Any>>) -> Result<Box<HandshakeData>, RecordError> {
    let record = record.ok_or(RecordError::Absent)?;
    let record = record
        .downcast::<HandshakeData>()
        .map_err(|_| RecordError::WrongType)?;
    let group = record
        .negotiated_key_exchange_group
        .ok_or(RecordError::MissingGroup)?;
    if group != rustls::NamedGroup::X25519MLKEM768 {
        return Err(RecordError::WrongGroup);
    }
    Ok(record)
}
