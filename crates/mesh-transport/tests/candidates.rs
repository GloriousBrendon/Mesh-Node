//! A relay-only caller sends a seed no hole-punch candidates (SPEC-seed
//! D10b, SPEC-connection-privacy P9). iroh 1.x sends each side's candidate
//! addresses inside the connection, even to a relay-only seed, which then
//! tries them and logs "no valid transport available" for each `Ip(..)`
//! path at trace level: that's the seed holding a caller's IP. A normal
//! caller is the control: it shows the count sees candidates when sent.

use mesh_identity::{DeviceCert, DeviceKey, RootKey};
use mesh_transport::{Config, Node, Relays, TestOptions};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// Tries at a caller's IP addresses, process-wide.
static RECEIVED: AtomicUsize = AtomicUsize::new(0);

/// Counts a relay-only node's tries at `Ip(..)` paths, and nothing else.
struct Count;

impl Subscriber for Count {
    fn enabled(&self, meta: &Metadata<'_>) -> bool {
        meta.target().starts_with("iroh")
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        /// "no valid transport available" for an `Ip(..)` path.
        #[derive(Default)]
        struct IpTry(bool, bool);
        impl Visit for IpTry {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                let value = format!("{value:?}");
                match field.name() {
                    "message" => self.0 = value == "no valid transport available",
                    "network_path" => self.1 = value.starts_with("Ip("),
                    _ => {}
                }
            }
        }
        let mut seen = IpTry::default();
        event.record(&mut seen);
        if seen.0 && seen.1 {
            RECEIVED.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

async fn node(url: &iroh::RelayUrl, relay_only: bool, services: Vec<String>) -> Node {
    let (root, key) = (RootKey::generate().unwrap(), DeviceKey::generate().unwrap());
    let cert = DeviceCert::issue(&root, &key.public(), "box", 1).unwrap();
    let config = Config {
        relays: Relays::Custom(vec![url.clone()]),
        relay_only,
        services,
        test: TestOptions {
            trust_any_relay: true,
        },
        ..Config::default()
    };
    let node = Node::start(&key, &cert, config).await.unwrap();
    assert!(node.online(Duration::from_secs(10)).await);
    node
}

/// Candidates seen while `caller` asks a relay-only seed one thing.
async fn received_while_asking(caller_relay_only: bool) -> usize {
    let (_map, url, _server) = iroh::test_utils::run_relay_server().await.unwrap();
    let seed = node(&url, true, vec!["ask".into()]).await;
    let caller = node(&url, caller_relay_only, Vec::new()).await;
    let before = RECEIVED.load(Ordering::SeqCst);
    caller.open(&seed.addr(), "ask").await.expect("opens");
    let stream = seed.next_stream().await.unwrap();
    assert!(stream.direct_ip.is_none(), "the seed was reached direct");
    // Candidates follow the handshake; give them time to arrive.
    tokio::time::sleep(Duration::from_secs(3)).await;
    caller.close().await;
    seed.close().await;
    RECEIVED.load(Ordering::SeqCst) - before
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_only_caller_sends_a_seed_no_candidates() {
    tracing::subscriber::set_global_default(Count).unwrap();
    assert_eq!(received_while_asking(true).await, 0, "candidates were sent");
    assert!(
        received_while_asking(false).await > 0,
        "the control saw no candidates, so the check sees nothing"
    );
}
