//! The spike behind SPEC-connection-privacy P3: what a peer learns from a
//! normal endpoint and from a relay-only one, and whether refusing a peer
//! keeps your addresses from it. The watcher is a normal node (as an attacker
//! would run), and iroh's `qnt::init` event says how many of the victim's
//! candidate addresses it holds. Victims are dialled by key and relay only,
//! as an address record gives them.

use iroh::endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, presets};
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl};
use mesh_identity::{DeviceCert, DeviceKey, RootKey};
use mesh_transport::{Allow, Config, MeshAddr, Node, Relays, TestOptions};
use std::sync::Mutex;
use std::time::Duration;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// Per `qnt::init` event: the remote's short ID and how many candidate
/// addresses of its this node holds. Only a dialler starts NAT traversal,
/// so these are the watchers' views of the victims.
static SEEN: Mutex<Vec<(String, usize)>> = Mutex::new(Vec::new());

struct Count;

impl Subscriber for Count {
    fn enabled(&self, meta: &Metadata<'_>) -> bool {
        meta.target() == "iroh::_events::qnt::init"
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        #[derive(Default)]
        struct Init(String, usize);
        impl Visit for Init {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                let value = format!("{value:?}");
                match field.name() {
                    "remote" => self.0 = value,
                    "remote_candidates" if value != "{}" => self.1 = value.matches(',').count() + 1,
                    _ => {}
                }
            }
        }
        let mut seen = Init::default();
        event.record(&mut seen);
        SEEN.lock().unwrap().push((seen.0, seen.1));
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

fn config(url: &RelayUrl, relay_only: bool, allow: Allow) -> Config {
    Config {
        relays: Relays::Custom(vec![url.clone()]),
        relay_only,
        allow,
        services: vec!["ask".into()],
        test: TestOptions {
            trust_any_relay: true,
        },
        ..Config::default()
    }
}

async fn node(url: &RelayUrl, relay_only: bool, allow: Allow) -> Node {
    let (root, key) = (RootKey::generate().unwrap(), DeviceKey::generate().unwrap());
    let cert = DeviceCert::issue(&root, &key.public(), "box", 1).unwrap();
    let node = Node::start(&key, &cert, config(url, relay_only, allow))
        .await
        .unwrap();
    assert!(node.online(Duration::from_secs(10)).await);
    node
}

/// As an address record gives it: key and relay, no IPs.
fn by_record(node: &Node) -> MeshAddr {
    MeshAddr {
        direct: Vec::new(),
        ..node.addr()
    }
}

/// Refuses (`true`) or accepts every connection in iroh's own hook, before
/// Mesh's hello.
#[derive(Debug)]
struct Hook(bool);

impl EndpointHooks for Hook {
    async fn after_handshake<'a>(&'a self, _conn: &'a Connection) -> AfterHandshakeOutcome {
        if self.0 {
            AfterHandshakeOutcome::Reject {
                error_code: 6u32.into(),
                reason: b"not-allowed".to_vec(),
            }
        } else {
            AfterHandshakeOutcome::Accept
        }
    }
}

/// A plain iroh endpoint with `Hook(reject)`, and its address by record.
async fn hooked(url: &RelayUrl, reject: bool) -> (Endpoint, MeshAddr) {
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(RelayMap::from_iter([url.clone()])))
        .ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify())
        .alpns(vec![mesh_transport::ALPN.to_vec()])
        .hooks(Hook(reject))
        .bind()
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), endpoint.online())
        .await
        .unwrap();
    // Accepted connections are held open (no hello comes back, so the
    // watcher's dial fails, but the connection is up meanwhile).
    let accepting = endpoint.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(incoming) = accepting.accept().await {
            if let Ok(conn) = incoming.await {
                held.push(conn);
            }
        }
    });
    let addr = MeshAddr {
        device: endpoint.id(),
        relay: Some(url.clone()),
        direct: Vec::new(),
    };
    (endpoint, addr)
}

/// The most candidates a normal watcher held for `victim` in the 3 s after
/// dialling it.
async fn candidates_from(watcher: &Node, victim: MeshAddr) -> usize {
    let short = victim.device.fmt_short().to_string();
    let _ = watcher.dial(&victim).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let seen = SEEN.lock().unwrap();
    seen.iter()
        .filter(|(r, _)| *r == short)
        .map(|(_, n)| *n)
        .max()
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spike, about 64 s: cargo test -p mesh-transport --test two_endpoints -- --ignored --nocapture"]
async fn two_endpoints_spike() {
    tracing::subscriber::set_global_default(Count).unwrap();
    let (_map, url, _server) = iroh::test_utils::run_relay_server().await.unwrap();

    // (a) A relay-only victim gives a peer nothing.
    let watcher = node(&url, false, Allow::default()).await;
    let relay_only = node(&url, true, Allow::default()).await;
    let a = candidates_from(&watcher, by_record(&relay_only)).await;

    // Control: a normal victim that accepts the watcher.
    let watcher = node(&url, false, Allow::default()).await;
    let normal = node(&url, false, Allow::default()).await;
    let control = candidates_from(&watcher, by_record(&normal)).await;

    // (b1) A normal victim that refuses in Mesh's hello (`Config::allow`).
    let watcher = node(&url, false, Allow::default()).await;
    let refusing = node(&url, false, Allow::only(|_, _| false)).await;
    let b_allow = candidates_from(&watcher, by_record(&refusing)).await;

    // (b2) A normal victim that refuses in iroh's `after_handshake` hook.
    let watcher = node(&url, false, Allow::default()).await;
    let (_refusing_hook, refusing_addr) = hooked(&url, true).await;
    let b_hook = candidates_from(&watcher, refusing_addr).await;

    // Control for (b2): the same plain endpoint, accepting.
    let watcher = node(&url, false, Allow::default()).await;
    let (_accepting_hook, accepting_addr) = hooked(&url, false).await;
    let hook_control = candidates_from(&watcher, accepting_addr).await;

    // (c) Two endpoints of one device, different keys, one relay: both stay
    // reachable, again and again, while both are up.
    let direct = node(&url, false, Allow::default()).await;
    let relayed = node(&url, true, Allow::default()).await;
    let caller = node(&url, false, Allow::default()).await;
    let mut c = true;
    for _ in 0..5 {
        c &= caller.ping(&by_record(&direct)).await.is_ok();
        c &= caller.ping(&by_record(&relayed)).await.is_ok();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    c &= direct.status().online && relayed.status().online;

    eprintln!(
        "SPIKE (a) relay-only={a} control={control} (b1) allow-refused={b_allow} \
         (b2) hook-refused={b_hook} hook-control={hook_control} (c) both reachable={c}"
    );
    assert!(
        control > 0,
        "the control saw no candidates, so the check sees nothing"
    );
    assert!(hook_control > 0, "the hook control saw no candidates");
    assert_eq!(a, 0, "(a) a relay-only endpoint sent candidates");
    assert!(c, "(c) two endpoints on one relay evicted each other");
    // (b) isn't asserted: a refusal in `Allow` always leaked (2 of 2 seen),
    // and one in the hook raced the candidates and leaked in 2 runs of 3
    // (2026-11-26). Refusing never reliably keeps your addresses back.
}
