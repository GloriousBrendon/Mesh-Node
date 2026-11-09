//! Two nodes in one process, relays disabled, dialling each other's local
//! sockets: no internet needed. Raw iroh endpoints stand in for peers that
//! misbehave.

use iroh::endpoint::{Connection, ConnectionError, presets};
use iroh::{Endpoint, RelayMode};
use mesh_identity::{DeviceCert, DeviceKey, MeshId, RootKey};
use mesh_transport::{
    ALPN, Config, HandshakeError, Limits, MeshAddr, Node, Path, Relays, TransportError, frame,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

struct Device {
    root: RootKey,
    key: DeviceKey,
}

impl Device {
    fn new() -> Self {
        Self {
            root: RootKey::generate().unwrap(),
            key: DeviceKey::generate().unwrap(),
        }
    }
    fn id(&self) -> MeshId {
        self.root.id()
    }
    fn cert(&self, name: &str) -> DeviceCert {
        DeviceCert::issue(&self.root, &self.key.public(), name, 1).unwrap()
    }
    async fn node(&self, name: &str) -> Node {
        self.node_with(name, Limits::default()).await
    }
    async fn node_with(&self, name: &str, limits: Limits) -> Node {
        let config = Config {
            relays: Relays::Disabled,
            limits,
            services: vec!["echo".into()],
            ..Config::default()
        };
        Node::start(&self.key, &self.cert(name), config)
            .await
            .unwrap()
    }
}

/// A node's address on this machine: its loopback sockets, no relay.
fn local(device: iroh::PublicKey, sockets: Vec<SocketAddr>) -> MeshAddr {
    let direct = sockets
        .into_iter()
        .filter(SocketAddr::is_ipv4)
        .map(|s| SocketAddr::from((Ipv4Addr::LOCALHOST, s.port())))
        .collect();
    MeshAddr {
        device,
        relay: None,
        direct,
    }
}

/// The same address for a bare iroh endpoint.
fn iroh_addr(addr: &MeshAddr) -> iroh::EndpointAddr {
    iroh::EndpointAddr::from_parts(
        addr.device,
        addr.direct.iter().map(|ip| iroh::TransportAddr::Ip(*ip)),
    )
}

fn addr_of(node: &Node) -> MeshAddr {
    local(node.addr().device, node.bound_sockets())
}

/// A bare iroh endpoint speaking `mesh/1`, with whatever key the test wants.
async fn raw(key: &DeviceKey) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(mesh_transport::secret_key(key))
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap()
}

/// The handshake close code the other side ended the connection with.
async fn close_code(conn: &Connection) -> Option<u64> {
    match conn.closed().await {
        ConnectionError::ApplicationClosed(close) => Some(close.error_code.into_inner()),
        _ => None,
    }
}

#[tokio::test]
async fn connect_and_authenticate_both_sides() {
    let (alice, bob) = (Device::new(), Device::new());
    let (a, b) = (alice.node("laptop").await, bob.node("desktop").await);

    let peer = a.dial(&addr_of(&b)).await.expect("dial");
    assert_eq!((peer.id, peer.name.as_str()), (bob.id(), "desktop"));
    assert_eq!(peer.device, b.addr().device);

    let seen = b.next_peer().await.expect("bob sees alice");
    assert_eq!((seen.id, seen.name.as_str()), (alice.id(), "laptop"));
}

#[tokio::test]
async fn refuses_another_identitys_certificate() {
    let (bob, victim, mallory) = (Device::new(), Device::new(), Device::new());
    let b = bob.node("desktop").await;

    // Mallory holds her own device key but presents the victim's certificate.
    let ep = raw(&mallory.key).await;
    let conn = ep.connect(iroh_addr(&addr_of(&b)), ALPN).await.unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    frame::write_tag(&mut send, "hello").await.unwrap();
    frame::write_frame(&mut send, &victim.cert("phone").to_bytes())
        .await
        .unwrap();
    send.finish().unwrap();
    assert_eq!(close_code(&conn).await, Some(2), "key-mismatch");

    // And when she's the one being dialled, the dialler gets KeyMismatch.
    let listener = raw(&mallory.key).await;
    let victim_cert = victim.cert("phone").to_bytes();
    let target = local(listener.id(), listener.bound_sockets());
    tokio::spawn(async move {
        let conn = listener.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        frame::read_tag(&mut recv).await.unwrap();
        frame::read_frame(&mut recv).await.unwrap();
        frame::write_frame(&mut send, &victim_cert).await.unwrap();
        send.finish().unwrap();
        conn.closed().await;
    });
    let alice = Device::new();
    let a = alice.node("laptop").await;
    match a.dial(&target).await {
        Err(TransportError::Handshake(HandshakeError::KeyMismatch)) => {}
        other => panic!("expected KeyMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn refuses_garbage() {
    let bob = Device::new();
    let b = bob.node("desktop").await;
    let ep = raw(&DeviceKey::generate().unwrap()).await;
    let conn = ep.connect(iroh_addr(&addr_of(&b)), ALPN).await.unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    frame::write_tag(&mut send, "hello").await.unwrap();
    frame::write_frame(&mut send, b"not a certificate")
        .await
        .unwrap();
    send.finish().unwrap();
    assert_eq!(close_code(&conn).await, Some(1), "bad-cert");
}

#[tokio::test]
async fn a_silent_dialler_times_out() {
    // Connects to Bob and never says hello: Bob gives up after 10 s.
    let bob = Device::new();
    let b = bob.node("desktop").await;
    let ep = raw(&DeviceKey::generate().unwrap()).await;
    let conn = ep.connect(iroh_addr(&addr_of(&b)), ALPN).await.unwrap();
    assert_eq!(close_code(&conn).await, Some(3), "timeout");
}

#[tokio::test]
async fn a_silent_listener_times_out() {
    // Accepts Alice's connection and never answers: Alice's dial times out.
    let listener = raw(&DeviceKey::generate().unwrap()).await;
    let target = local(listener.id(), listener.bound_sockets());
    tokio::spawn(async move {
        let conn = listener.accept().await.unwrap().await.unwrap();
        conn.closed().await;
    });
    let a = Device::new().node("laptop").await;
    assert!(matches!(
        a.dial(&target).await,
        Err(TransportError::Timeout)
    ));
}

#[tokio::test]
async fn a_key_alone_reaches_nothing() {
    // Nothing about a device is published (D2), so its key alone is no address.
    let b = Device::new().node("desktop").await;
    let a = Device::new().node("laptop").await;
    let key_only = MeshAddr {
        device: b.addr().device,
        relay: None,
        direct: Vec::new(),
    };
    assert!(matches!(
        a.dial(&key_only).await,
        Err(TransportError::Unreachable(_))
    ));
}

#[tokio::test]
async fn start_refuses_someone_elses_certificate() {
    let (mine, theirs) = (Device::new(), Device::new());
    let result = Node::start(
        &mine.key,
        &theirs.cert("phone"),
        Config {
            relays: Relays::Disabled,
            ..Config::default()
        },
    )
    .await;
    assert!(matches!(result, Err(TransportError::CertNotOurs)));
}

#[tokio::test]
async fn ping_reports_the_path_and_reuses_the_connection() {
    let (alice, bob) = (Device::new(), Device::new());
    let (a, b) = (alice.node("laptop").await, bob.node("desktop").await);
    let pong = a.ping(&addr_of(&b)).await.expect("ping");
    assert_eq!(pong.peer.id, bob.id());
    assert_eq!(pong.path, Path::Direct, "loopback is direct");
    assert!(pong.rtt < Duration::from_secs(1), "{:?}", pong.rtt);

    a.ping(&addr_of(&b)).await.expect("second ping");
    a.dial(&addr_of(&b)).await.expect("dial");
    assert_eq!(a.status().connections, 1, "one connection, reused");
    assert!(a.status().direct);
    assert!(!a.status().online, "no relay configured");
    // Bob saw Alice connect once.
    b.next_peer().await.expect("alice");
    let again = tokio::time::timeout(Duration::from_millis(300), b.next_peer()).await;
    assert!(again.is_err(), "no second connection");
}

#[tokio::test]
async fn over_the_connection_limit_is_refused_and_others_keep_working() {
    let bob = Device::new();
    let limits = Limits {
        connections: 1,
        ..Limits::default()
    };
    let b = bob.node_with("desktop", limits).await;
    let a = Device::new().node("laptop").await;
    a.ping(&addr_of(&b)).await.expect("first fits");
    let c = Device::new().node("phone").await;
    assert!(
        matches!(
            c.ping(&addr_of(&b)).await,
            Err(TransportError::Unreachable(_))
        ),
        "second refused"
    );
    a.ping(&addr_of(&b)).await.expect("the first still works");
}

#[tokio::test]
async fn streams_per_connection_are_capped() {
    let bob = Device::new();
    let b = bob
        .node_with(
            "desktop",
            Limits {
                streams: 2,
                ..Limits::default()
            },
        )
        .await;
    let me = Device::new();
    let ep = raw(&me.key).await;
    let conn = ep.connect(iroh_addr(&addr_of(&b)), ALPN).await.unwrap();
    // Say hello properly, then hold streams open.
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    frame::write_tag(&mut send, "hello").await.unwrap();
    frame::write_frame(&mut send, &me.cert("laptop").to_bytes())
        .await
        .unwrap();
    send.finish().unwrap();
    frame::read_frame(&mut recv)
        .await
        .unwrap()
        .expect("bob's hello");
    let mut held = Vec::new();
    for _ in 0..2 {
        let (mut send, recv) = conn.open_bi().await.unwrap();
        // A ping tag with no nonce yet: Bob waits on it, keeping it open.
        frame::write_tag(&mut send, "ping").await.unwrap();
        held.push((send, recv));
    }
    let third = tokio::time::timeout(Duration::from_millis(500), conn.open_bi()).await;
    assert!(third.is_err(), "a third stream waits for one to close");
}

#[tokio::test]
async fn locking_closes_the_node() {
    let (a, b) = (
        Device::new().node("laptop").await,
        Device::new().node("desktop").await,
    );
    let addr = addr_of(&b);
    a.ping(&addr).await.expect("ping before");
    b.close().await;
    assert!(
        matches!(a.ping(&addr).await, Err(TransportError::Unreachable(_))),
        "unreachable after lock"
    );
}

#[tokio::test]
async fn service_streams_reach_the_node() {
    let (alice, bob) = (Device::new(), Device::new());
    let (a, b) = (alice.node("laptop").await, bob.node("desktop").await);
    let addr = addr_of(&b);
    tokio::spawn(async move {
        let mut stream = b.next_stream().await.expect("a stream");
        assert_eq!(
            (stream.service.as_str(), stream.peer.id),
            ("echo", alice.id())
        );
        assert!(stream.direct_ip.is_some_and(|ip| ip.is_loopback()));
        let got = frame::read_frame(&mut stream.recv).await.unwrap().unwrap();
        frame::write_frame(&mut stream.send, &got).await.unwrap();
        stream.send.finish().unwrap();
        // Keep the node alive until Alice has read the answer.
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let (peer, mut send, mut recv) = a.open(&addr, "echo").await.expect("open");
    assert_eq!(peer.name, "desktop");
    frame::write_frame(&mut send, b"hi").await.unwrap();
    send.finish().unwrap();
    assert_eq!(
        frame::read_frame(&mut recv).await.unwrap().as_deref(),
        Some(&b"hi"[..])
    );

    // A service the node doesn't offer is reset; the connection stays.
    let (_, mut send, mut recv) = a.open(&addr, "nope").await.expect("open");
    let _ = frame::write_frame(&mut send, b"x").await;
    assert!(frame::read_frame(&mut recv).await.is_err());
    a.ping(&addr).await.expect("still connected");
}

#[tokio::test]
async fn only_allowed_identities_get_in() {
    let (alice, bob, eve) = (Device::new(), Device::new(), Device::new());
    let allowed = alice.id();
    let config = Config {
        relays: Relays::Disabled,
        allow: mesh_transport::Allow::only(move |id| *id == allowed),
        ..Config::default()
    };
    let b = Node::start(&bob.key, &bob.cert("desktop"), config)
        .await
        .unwrap();
    let (a, e) = (alice.node("laptop").await, eve.node("pc").await);

    let err = e.dial(&addr_of(&b)).await.unwrap_err();
    assert!(
        matches!(err, TransportError::Handshake(HandshakeError::NotAllowed)),
        "{err:?}"
    );
    assert!(a.ping(&addr_of(&b)).await.is_ok());

    // Dropping a peer closes its connection; the next ping has to reconnect.
    b.disconnect(&alice.id());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(b.status().connections, 0);
}
