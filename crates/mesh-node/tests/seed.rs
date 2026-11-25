//! A `mesh-node seed` process on a loopback relay, and a client holding,
//! fetching and revoking friend codes over a real connection. Then the seed
//! stops on SIGTERM, starts again and still remembers. Then two helpers
//! share a friend code through it, as two Mesh installs do.

use std::time::Duration;

use mesh_identity::{DeviceCert, DeviceKey, FriendCode, HeldCode, RootKey};
use mesh_transport::{Config, MeshAddr, Node, Relays, frame};

mod common;
use common::{Helper, Relay, Seed, temp_dir};
use serde_json::Value;

const WEEK: u64 = 7 * 86_400;

/// A Mesh device on the same relay.
async fn client(relay: &Relay) -> (Node, RootKey) {
    let (root, key) = (RootKey::generate().unwrap(), DeviceKey::generate().unwrap());
    let cert = DeviceCert::issue(&root, &key.public(), "laptop", 1).unwrap();
    let config = Config {
        relays: Relays::Custom(vec![relay.url.parse().unwrap()]),
        ..Config::default()
    };
    let node = Node::start(&key, &cert, config).await.unwrap();
    assert!(node.online(Duration::from_secs(10)).await);
    (node, root)
}

/// One request, one answer.
async fn ask(node: &Node, seed: &MeshAddr, service: &str, request: &[u8]) -> Vec<u8> {
    let (_, mut send, mut recv) = node.open(seed, service).await.expect("open");
    frame::write_frame(&mut send, request).await.unwrap();
    send.finish().unwrap();
    frame::read_frame(&mut recv)
        .await
        .unwrap()
        .expect("an answer")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn a_seed_holds_and_answers_codes() {
    let dir = std::env::temp_dir().join(format!("mesh-seed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let relay = Relay::start();
    let mut seed = Seed::start(&dir, &relay);
    let ticket = seed.ticket();
    let addr = MeshAddr::from_ticket(&ticket).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("seed.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the key is the owner's only");
    }

    let (once, once_held, id) = relay.runtime.block_on(async {
        let (alice, root) = client(&relay).await;
        let (bob, _) = client(&relay).await;

        // Alice holds a single-use code; Bob resolves it once.
        let once = FriendCode::generate().unwrap();
        let held = HeldCode::new(&root, &once, now(), Some(WEEK), Some(1)).unwrap();
        assert_eq!(ask(&alice, &addr, "code-hold", held.as_bytes()).await, [0]);
        assert_eq!(
            ask(&alice, &addr, "code-hold", held.as_bytes()).await,
            [0],
            "repeat"
        );
        let found = ask(&bob, &addr, "code-get", &held.lookup_id()).await;
        assert_eq!(found[0], 0);
        let record = HeldCode::from_bytes(&found[1..])
            .unwrap()
            .open(&once, now())
            .unwrap();
        assert_eq!(record.root(), root.id());
        // Looking it up again is fine; a friend request uses it up
        // (SPEC-social D1), and only Alice can read the request.
        assert_eq!(ask(&bob, &addr, "code-get", &held.lookup_id()).await[0], 0);
        let knock = request(&root, &once);
        assert_eq!(ask(&bob, &addr, "knock-put", &knock).await, [0]);
        assert_eq!(ask(&bob, &addr, "knock-put", &knock).await, [1], "used");
        assert_eq!(
            ask(&bob, &addr, "code-get", &held.lookup_id()).await,
            [1],
            "used"
        );
        let mine = mesh_identity::CodeRevoke::new(&root, &once).to_bytes();
        let theirs = mesh_identity::CodeRevoke::new(&RootKey::generate().unwrap(), &once);
        assert_eq!(ask(&bob, &addr, "knock-get", &theirs.to_bytes()).await, [1]);
        let mut box_ = vec![0, 0];
        box_.extend_from_slice(&(knock.len() as u16).to_be_bytes());
        box_.extend_from_slice(&knock);
        assert_eq!(ask(&alice, &addr, "knock-get", &mine).await, box_);

        // Revoked: gone for Bob, and Alice can't hold it again.
        let kept = FriendCode::generate().unwrap();
        let kept_held = HeldCode::new(&root, &kept, now(), None, None).unwrap();
        assert_eq!(
            ask(&alice, &addr, "code-hold", kept_held.as_bytes()).await,
            [0]
        );
        let revoke = mesh_identity::CodeRevoke::new(&root, &kept);
        assert_eq!(
            ask(&alice, &addr, "code-revoke", &revoke.to_bytes()).await,
            [0]
        );
        assert_eq!(
            ask(&bob, &addr, "code-get", &kept_held.lookup_id()).await,
            [1]
        );
        assert_eq!(
            ask(&alice, &addr, "code-hold", kept_held.as_bytes()).await,
            [1],
            "gone"
        );

        assert_eq!(ask(&bob, &addr, "code-hold", b"junk").await, [5], "bad");
        (once, held, root.id())
    });
    let log = seed.stop();

    // Started again: the same key, and it still remembers.
    let mut seed = Seed::start(&dir, &relay);
    assert_eq!(seed.ticket(), ticket, "same key");
    relay.runtime.block_on(async {
        let (alice, _) = client(&relay).await;
        assert_eq!(
            ask(&alice, &addr, "code-hold", once_held.as_bytes()).await,
            [1],
            "still used"
        );
    });
    let log = [log, seed.stop()].concat().join("\n");

    // Counts only: no ID, code or lookup ID in the log.
    let hex: String = once_held
        .lookup_id()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for secret in [id.to_string(), once.to_string(), hex] {
        assert!(!log.contains(&secret), "{secret} reached the log:\n{log}");
    }
    drop(relay.runtime);
    let _ = std::fs::remove_dir_all(dir);
}

const PASSWORD: &str = "correct horse battery staple";

/// A friend request from a new identity to `owner`, through `code`.
fn request(owner: &RootKey, code: &FriendCode) -> Vec<u8> {
    let (root, device) = (RootKey::generate().unwrap(), DeviceKey::generate().unwrap());
    let cert = DeviceCert::issue(&root, &device.public(), "pc", now()).unwrap();
    let devices = mesh_identity::DeviceList::first(&root, cert).unwrap();
    let from = mesh_identity::KnockFrom {
        root: &root,
        device: &device,
        devices: &devices,
        name: "Bob",
    };
    mesh_identity::seal_knock(&from, &owner.id(), &code.lookup_id(), "", now()).unwrap()
}

impl Helper {
    /// Reads events until a `meshCodes` that satisfies `done`.
    fn codes_until(&mut self, done: impl Fn(&[Value]) -> bool) -> Vec<Value> {
        loop {
            let (binding, payload) = self.event();
            assert_eq!(binding, "meshCodes", "unexpected {payload}");
            let codes = payload["codes"].as_array().unwrap().clone();
            if done(&codes) {
                return codes;
            }
        }
    }

    /// Makes a code and waits until a seed holds it.
    fn held_code(&mut self, uses: &str) -> String {
        let code = self.expect("codeCreate", &["", uses], "meshCodes")["created"]
            .as_str()
            .unwrap()
            .to_owned();
        self.codes_until(|codes| codes.iter().any(|c| c["code"] == code && c["held"] == true));
        code
    }
}

#[test]
fn two_helpers_share_a_code_through_the_seed() {
    let (dir_s, dir_a, dir_b) = (temp_dir("seed"), temp_dir("code-a"), temp_dir("code-b"));
    let relay = Relay::start();
    let mut seed = Seed::start(&dir_s, &relay);
    let ticket = seed.ticket();
    let with_seed = ["--seed", ticket.as_str()];
    let mut a = Helper::start_with(&dir_a, &relay, &with_seed);
    let mut b = Helper::start_with(&dir_b, &relay, &with_seed);
    assert_eq!(a.event().0, "meshIdentity");
    assert_eq!(b.event().0, "meshIdentity");
    let id_a = a.expect("idCreate", &["alice", PASSWORD], "meshIdentity")["id"].clone();
    assert_eq!(a.event().0, "meshCodes");
    b.expect("idCreate", &["bob", PASSWORD], "meshIdentity");
    assert_eq!(b.event().0, "meshCodes");

    // A single-use code: Bob resolves it to Alice's ID once.
    let once = a.held_code("1");
    let resolved = b.expect("codeResolve", &[&once], "meshResolved");
    assert_eq!(
        (&resolved["id"], resolved["code"].as_str()),
        (&id_a, Some(&*once))
    );
    // Looking it up doesn't use it; a friend request would (tests/social.rs).
    let again = b.expect(
        "codeResolve",
        &[&format!("mesh://code/{once}")],
        "meshResolved",
    );
    assert_eq!(again["id"], id_a);

    // Revoked: Bob finds nothing (the revoke goes out in the background).
    let kept = a.held_code("unlimited");
    assert_eq!(
        b.expect("codeResolve", &[&kept], "meshResolved")["id"],
        id_a
    );
    a.expect("codeRevoke", &[&kept], "meshCodes");
    let mut gone = false;
    for _ in 0..10 {
        let (binding, payload) = b.call("codeResolve", &[&kept]);
        if binding == "meshError" {
            assert_eq!(payload["kind"], "not-found");
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(gone, "the revoke reached the seed");

    // Guessing: Bob's lookups are capped.
    let mut slowed = false;
    for _ in 0..15 {
        let (_, payload) = b.call("codeResolve", &["0000-0000"]);
        if payload["kind"] == "slow-down" {
            slowed = true;
            break;
        }
        assert_eq!(payload["kind"], "not-found");
    }
    assert!(slowed, "the seed slowed Bob down");

    // A code made while the seed is down is held once it's back.
    let log = seed.stop();
    let late = a.expect("codeCreate", &["", ""], "meshCodes")["created"]
        .as_str()
        .unwrap()
        .to_owned();
    let codes = a.codes_until(|codes| codes.iter().any(|c| c["code"] == late));
    assert!(
        codes
            .iter()
            .any(|c| c["code"] == late && c["held"] == false),
        "nobody holds it"
    );
    let mut seed = Seed::start(&dir_s, &relay);
    seed.ticket();
    a.expect("idLock", &[], "meshIdentity");
    a.expect("idUnlock", &["alice", PASSWORD], "meshIdentity");
    a.codes_until(|codes| codes.iter().any(|c| c["code"] == late && c["held"] == true));

    let stderr = a.quit() + &b.quit();
    assert!(!stderr.contains(PASSWORD));
    let log = [log, seed.stop()].concat().join("\n");
    for secret in [id_a.as_str().unwrap(), &once, &kept, &late] {
        assert!(!log.contains(secret), "{secret} reached the seed's log");
    }
    drop(relay.runtime);
    for dir in [dir_s, dir_a, dir_b] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A power cut can leave a store half written. Address records are put
/// again within 30 minutes, so a damaged `addrs.bin` starts empty instead
/// of stopping the seed (audit finding 4).
#[test]
fn a_damaged_address_file_starts_empty() {
    let dir = temp_dir("seed-damaged");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("addrs.bin"), b"half a file").unwrap();
    let relay = Relay::start();
    let mut seed = Seed::start(&dir, &relay);
    seed.ticket();
    let log = seed.stop().join("\n");
    assert!(log.contains("address records were damaged"), "{log}");
    drop(relay.runtime);
    let _ = std::fs::remove_dir_all(dir);
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A seed on a fixed port, its address in its ticket (SPEC-seed D8c).
fn fixed_seed(dir: &std::path::Path, relay: &Relay) -> (Seed, String, u16) {
    let port = free_port();
    let (port_arg, public) = (port.to_string(), format!("127.0.0.1:{port}"));
    let args = [
        "--port",
        &port_arg,
        "--public",
        &public,
        "--report-every",
        "2",
    ];
    let mut seed = Seed::start_with(dir, relay, &args);
    let ticket = seed.ticket();
    assert!(ticket.contains(&format!("addr={public}")), "{ticket}");
    (seed, ticket, port)
}

/// The first report that saw any caller.
fn callers(seed: &mut Seed) -> String {
    seed.line_with(|l| l.contains("callers") && !l.contains("callers 0 direct, 0 relayed, 0 both"))
}

/// The helper calls seeds from a relay-only node (SPEC-connection-privacy
/// P9), so even a seed with a fixed public address gets every caller by
/// the relay, and the caller's address never reaches it.
#[test]
fn a_fixed_port_seeds_callers_arrive_relayed() {
    let (dir_s, dir_a) = (temp_dir("fixed-seed"), temp_dir("fixed-a"));
    let relay = Relay::start();
    let (mut seed, ticket, _) = fixed_seed(&dir_s, &relay);
    let mut a = Helper::start_with(&dir_a, &relay, &["--seed", &ticket]);
    assert_eq!(a.event().0, "meshIdentity");
    a.expect("idCreate", &["alice", PASSWORD], "meshIdentity");
    assert_eq!(a.event().0, "meshCodes");
    a.held_code("1");
    let line = callers(&mut seed);
    assert!(
        line.contains("callers 0 direct, 1 relayed, 0 both ways"),
        "{line}"
    );
    a.quit();
    seed.stop();
    for dir in [dir_s, dir_a] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A count from a seed's report lines: the sum of the number before `what`.
fn reported(lines: &[String], what: &str) -> u64 {
    (lines.iter())
        .filter(|l| l.starts_with("mesh-node seed: last hour ") && !l.contains("last hour mail "))
        .flat_map(|l| l.split([',', ';', '(']))
        .filter_map(|part| {
            let n = part.trim().strip_suffix(what)?.trim_end();
            n.rsplit(' ').next()?.parse::<u64>().ok()
        })
        .sum()
}

/// The home seed's setup (SPEC-seed D8c as changed): relay-only, so its
/// ticket shows no address and every caller arrives relayed, and it still
/// answers pings, codes, friend requests and address records.
#[test]
fn a_relay_only_seed_serves_everyone_through_its_relay() {
    let dirs = ["ro-seed", "ro-a", "ro-b"].map(temp_dir);
    let relay = Relay::start();
    let args = ["--relay-only", "--report-every", "2"];
    let mut seed = Seed::start_with(&dirs[0], &relay, &args);
    let ticket = seed.ticket();
    assert!(!ticket.contains("addr="), "{ticket}");
    let addr = MeshAddr::from_ticket(&ticket).unwrap();
    let pong = relay.runtime.block_on(async {
        let (node, _) = client(&relay).await;
        node.ping(&addr).await.expect("a ping through the relay")
    });
    assert_eq!(pong.path, mesh_transport::Path::Relay);

    // Short records, so they're put again every 2 s.
    let with_seed = ["--seed", ticket.as_str(), "--record-ttl", "8"];
    let mut a = Helper::start_with(&dirs[1], &relay, &with_seed);
    let mut b = Helper::start_with(&dirs[2], &relay, &with_seed);
    assert_eq!(a.event().0, "meshIdentity");
    assert_eq!(b.event().0, "meshIdentity");
    let id_a = a.expect("idCreate", &["alice", PASSWORD], "meshIdentity")["id"].clone();
    assert_eq!(a.event().0, "meshCodes");
    let id_b = b.expect("idCreate", &["bob", PASSWORD], "meshIdentity")["id"].clone();
    assert_eq!(b.event().0, "meshCodes");
    let code = a.held_code("1");
    assert_eq!(
        b.expect("codeResolve", &[&code], "meshResolved")["id"],
        id_a
    );

    // Friends: the request and both address records go through the seed.
    let (id_a, id_b) = (id_a.as_str().unwrap(), id_b.as_str().unwrap());
    a.expect("friendAdd", &[id_b, ""], "meshSocial");
    b.expect("friendAdd", &[id_a, ""], "meshSocial");
    fn friends_with(id: &str) -> impl Fn(&Value) -> bool + '_ {
        move |s| {
            s["friends"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["id"] == id)
        }
    }
    a.social_until(friends_with(id_b));
    b.social_until(friends_with(id_a));

    let mut seen = Vec::new();
    while reported(&seen, "address puts") == 0 || reported(&seen, "address gets") == 0 {
        seen.push(seed.line_with(|l| l.contains("last hour ")));
    }
    let (_, _) = (a.quit(), b.quit());
    let log = seed.stop();
    for what in ["address puts", "address gets", "relayed"] {
        assert!(reported(&log, what) > 0, "no {what}: {log:?}");
    }
    assert_eq!(reported(&log, "direct"), 0, "a caller came direct: {log:?}");
    assert!(log.iter().any(|l| l.contains("relay-only")), "{log:?}");
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// `--relay-only` won't start with a fixed port or public address, nor
/// without exactly one relay to put in its ticket.
#[test]
fn relay_only_refuses_a_port_and_more_than_one_relay() {
    let dir = temp_dir("ro-refused");
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_mesh-node"))
            .args(["seed", "--data"])
            .arg(&dir)
            .args(args)
            .output()
            .unwrap()
    };
    let relay = ["--relay", "https://euc1-1.relay.n0.iroh.link."];
    for args in [
        &[&relay[..], &["--relay-only", "--port", "7842"]].concat()[..],
        &[
            &relay[..],
            &["--relay-only", "--public", "203.0.113.5:7842"],
        ]
        .concat(),
        &["--relay-only"],
        &[&relay[..], &relay, &["--relay-only"]].concat(),
    ] {
        let out = run(args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {err}");
        assert!(err.contains("--relay-only"), "{args:?}: {err}");
    }
    let _ = std::fs::remove_dir_all(dir);
}
