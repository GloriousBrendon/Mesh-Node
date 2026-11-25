//! The relay path. With an in-process relay (iroh's test relay) and direct
//! paths switched off, traffic has to go through the relay: no internet
//! needed. The `--ignored` test uses n0's real relays, as the spike did.

use mesh_identity::{DeviceCert, DeviceKey, RootKey};
use mesh_transport::{Config, MeshAddr, Node, Path, Relays, TestOptions};
use std::time::Duration;

/// A node on `relays`; `relay_only` switches its direct paths off.
async fn node(relays: Relays, relay_only: bool) -> (Node, RootKey) {
    let (root, key) = (RootKey::generate().unwrap(), DeviceKey::generate().unwrap());
    let cert = DeviceCert::issue(&root, &key.public(), "box", 1).unwrap();
    let config = Config {
        relays,
        relay_only,
        test: TEST_RELAY,
        ..Config::default()
    };
    (Node::start(&key, &cert, config).await.unwrap(), root)
}

/// Trusts iroh's in-process test relay (and nothing else changes for n0's).
const TEST_RELAY: TestOptions = TestOptions {
    trust_any_relay: true,
};

/// Key and relay only, as a ticket carries.
fn via_relay(node: &Node) -> MeshAddr {
    MeshAddr {
        direct: Vec::new(),
        ..node.addr()
    }
}

#[tokio::test]
async fn ping_goes_through_the_relay_when_direct_is_impossible() {
    let (_map, url, _server) = iroh::test_utils::run_relay_server().await.unwrap();
    let (a, _) = node(Relays::Custom(vec![url.clone()]), true).await;
    let (b, bob) = node(Relays::Custom(vec![url.clone()]), true).await;
    assert!(
        b.online(Duration::from_secs(10)).await,
        "bob reaches the test relay"
    );
    assert_eq!(b.status().relay, Some(url));

    let addr = via_relay(&b);
    assert!(addr.direct.is_empty() && addr.relay.is_some());
    let pong = a.ping(&addr).await.expect("ping through the relay");
    assert_eq!((pong.peer.id, pong.path), (bob.id(), Path::Relay));
    assert!(b.status().online && !b.status().direct);
}

#[tokio::test]
#[ignore = "uses the internet (n0's public relays)"]
async fn real_relays() {
    let (a, _) = node(Relays::Default, false).await;
    let (b, bob) = node(Relays::Default, false).await;
    assert!(
        b.online(Duration::from_secs(20)).await,
        "bob reaches an n0 relay"
    );
    let addr = via_relay(&b);
    for i in 0..5 {
        let pong = a.ping(&addr).await.expect("ping");
        assert_eq!(pong.peer.id, bob.id());
        eprintln!(
            "ping {i}: {:?} via {:?} ({:?})",
            pong.rtt,
            pong.path,
            b.status().relay
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// A seed on a fixed port with its relay (SPEC-seed D8c), and the service a
/// client opens on it.
async fn fixed_seed(url: &iroh::RelayUrl) -> (Node, MeshAddr) {
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let (root, key) = (RootKey::generate().unwrap(), DeviceKey::generate().unwrap());
    let cert = DeviceCert::issue(&root, &key.public(), "seed", 1).unwrap();
    let config = Config {
        relays: Relays::Custom(vec![url.clone()]),
        services: vec!["ask".into()],
        port: Some(port),
        test: TEST_RELAY,
        ..Config::default()
    };
    let seed = Node::start(&key, &cert, config).await.unwrap();
    assert!(seed.online(Duration::from_secs(10)).await);
    let addr = MeshAddr {
        direct: vec![([127, 0, 0, 1], port).into()],
        ..via_relay(&seed)
    };
    (seed, addr)
}

const WAIT: Duration = Duration::from_secs(2);

#[tokio::test]
async fn direct_first_arrives_direct_on_the_first_stream() {
    let (_map, url, _server) = iroh::test_utils::run_relay_server().await.unwrap();
    let (seed, addr) = fixed_seed(&url).await;
    let (client, _) = node(Relays::Custom(vec![url]), false).await;
    client
        .open_direct_first(&addr, "ask", WAIT)
        .await
        .expect("opens");
    let stream = seed.next_stream().await.unwrap();
    assert!(stream.direct_ip.is_some(), "the first stream came by relay");
}

/// A seed's direct address that doesn't answer (a network that drops it):
/// the caller tries it for the wait, then gets through by the relay.
#[tokio::test]
async fn direct_first_falls_back_to_the_relay() {
    let (_map, url, _server) = iroh::test_utils::run_relay_server().await.unwrap();
    let (_seed, addr) = fixed_seed(&url).await;
    let closed = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let unanswered = MeshAddr {
        direct: vec![closed],
        ..addr
    };
    let (client, _) = node(Relays::Custom(vec![url]), false).await;
    let started = std::time::Instant::now();
    client
        .open_direct_first(&unanswered, "ask", WAIT)
        .await
        .expect("gets through");
    assert!(started.elapsed() >= WAIT, "it tried direct first");
}

/// A relay-only caller (the helper's throwaway node, SPEC-connection-privacy
/// P9) can't go direct, so it doesn't wait to try: it goes by the relay at
/// once, even to a seed whose ticket has a direct address.
#[tokio::test]
async fn a_relay_only_caller_skips_the_direct_try() {
    let (_map, url, _server) = iroh::test_utils::run_relay_server().await.unwrap();
    let (seed, addr) = fixed_seed(&url).await;
    let (client, _) = node(Relays::Custom(vec![url]), true).await;
    assert!(client.online(Duration::from_secs(10)).await);
    let started = std::time::Instant::now();
    client
        .open_direct_first(&addr, "ask", WAIT)
        .await
        .expect("gets through");
    assert!(started.elapsed() < WAIT, "it waited for a direct path");
    let stream = seed.next_stream().await.unwrap();
    assert!(stream.direct_ip.is_none());
}

/// A relay-only seed (SPEC-seed D8c as changed): its address has no direct
/// part, so a caller goes straight to the relay, with no direct-first wait,
/// and arrives relayed.
#[tokio::test]
async fn a_relay_only_seed_is_reached_through_its_relay_at_once() {
    let (_map, url, _server) = iroh::test_utils::run_relay_server().await.unwrap();
    let (root, key) = (RootKey::generate().unwrap(), DeviceKey::generate().unwrap());
    let cert = DeviceCert::issue(&root, &key.public(), "seed", 1).unwrap();
    let config = Config {
        relays: Relays::Custom(vec![url.clone()]),
        services: vec!["ask".into()],
        relay_only: true,
        test: TEST_RELAY,
        ..Config::default()
    };
    let seed = Node::start(&key, &cert, config).await.unwrap();
    assert!(seed.online(Duration::from_secs(10)).await);
    assert!(seed.bound_sockets().is_empty(), "no socket to reach it by");
    let addr = seed.addr();
    assert!(addr.direct.is_empty(), "{addr:?}");
    assert!(!addr.ticket_with_direct().unwrap().contains("addr="));

    let (client, _) = node(Relays::Custom(vec![url]), false).await;
    let long = Duration::from_secs(30);
    let started = std::time::Instant::now();
    client
        .open_direct_first(&addr, "ask", long)
        .await
        .expect("gets through");
    assert!(started.elapsed() < WAIT, "it waited for a direct path");
    let stream = seed.next_stream().await.unwrap();
    assert!(stream.direct_ip.is_none(), "the seed was reached direct");
    let pong = client.ping(&addr).await.unwrap();
    assert_eq!(pong.path, Path::Relay);
}

#[tokio::test]
async fn relay_only_refuses_a_fixed_port() {
    let (root, key) = (RootKey::generate().unwrap(), DeviceKey::generate().unwrap());
    let cert = DeviceCert::issue(&root, &key.public(), "seed", 1).unwrap();
    let config = Config {
        relay_only: true,
        port: Some(7842),
        ..Config::default()
    };
    assert!(matches!(
        Node::start(&key, &cert, config).await,
        Err(mesh_transport::TransportError::RelayOnlyWithPort)
    ));
}
