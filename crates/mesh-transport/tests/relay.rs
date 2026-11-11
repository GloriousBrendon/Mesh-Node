//! The relay path. With an in-process relay (iroh's test relay) and direct
//! paths switched off, traffic has to go through the relay: no internet
//! needed. The `--ignored` test uses n0's real relays, as the spike did.

use mesh_identity::{DeviceCert, DeviceKey, RootKey};
use mesh_transport::{Config, MeshAddr, Node, Path, Relays, TestOptions};
use std::time::Duration;

async fn node(relays: Relays, test: TestOptions) -> (Node, RootKey) {
    let (root, key) = (RootKey::generate().unwrap(), DeviceKey::generate().unwrap());
    let cert = DeviceCert::issue(&root, &key.public(), "box", 1).unwrap();
    let config = Config {
        relays,
        test,
        ..Config::default()
    };
    (Node::start(&key, &cert, config).await.unwrap(), root)
}

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
    let test = TestOptions {
        trust_any_relay: true,
        relay_only: true,
    };
    let (a, _) = node(Relays::Custom(vec![url.clone()]), test).await;
    let (b, bob) = node(Relays::Custom(vec![url.clone()]), test).await;
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
    let (a, _) = node(Relays::Default, TestOptions::default()).await;
    let (b, bob) = node(Relays::Default, TestOptions::default()).await;
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
        test: TestOptions {
            trust_any_relay: true,
            relay_only: false,
        },
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
    let test = TestOptions {
        trust_any_relay: true,
        relay_only: false,
    };
    let (client, _) = node(Relays::Custom(vec![url]), test).await;
    client
        .open_direct_first(&addr, "ask", WAIT)
        .await
        .expect("opens");
    let stream = seed.next_stream().await.unwrap();
    assert!(stream.direct_ip.is_some(), "the first stream came by relay");
}

#[tokio::test]
async fn direct_first_falls_back_to_the_relay() {
    let (_map, url, _server) = iroh::test_utils::run_relay_server().await.unwrap();
    let (seed, addr) = fixed_seed(&url).await;
    // A network that blocks UDP: the client can use the relay only.
    let test = TestOptions {
        trust_any_relay: true,
        relay_only: true,
    };
    let (client, _) = node(Relays::Custom(vec![url]), test).await;
    assert!(client.online(Duration::from_secs(10)).await);
    let started = std::time::Instant::now();
    client
        .open_direct_first(&addr, "ask", WAIT)
        .await
        .expect("gets through");
    assert!(started.elapsed() >= WAIT, "it tried direct first");
    let stream = seed.next_stream().await.unwrap();
    assert!(stream.direct_ip.is_none());
}
