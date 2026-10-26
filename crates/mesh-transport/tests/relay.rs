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
