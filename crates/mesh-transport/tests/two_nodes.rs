//! Two nodes in one process, relays disabled, dialling each other's local
//! sockets: no internet needed. Raw iroh endpoints stand in for peers that
//! misbehave.

use iroh::endpoint::{Connection, ConnectionError, presets};
use iroh::{Endpoint, RelayMode};
use mesh_identity::{DeviceCert, DeviceKey, MeshId, RootKey};
use mesh_transport::{ALPN, HandshakeError, MeshAddr, Node, Relays, TransportError, frame};
use std::net::{Ipv4Addr, SocketAddr};

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
        Node::start(&self.key, &self.cert(name), Relays::Disabled)
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
    let result = Node::start(&mine.key, &theirs.cert("phone"), Relays::Disabled).await;
    assert!(matches!(result, Err(TransportError::CertNotOurs)));
}
