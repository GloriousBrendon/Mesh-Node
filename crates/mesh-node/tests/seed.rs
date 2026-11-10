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
