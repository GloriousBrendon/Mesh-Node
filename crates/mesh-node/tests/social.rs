//! Social (SPEC-social "Process test"): a seed and helpers on a loopback
//! relay. Friend requests go only through a live code and wait on the seed
//! while the owner is locked; accept makes friends on both sides; decline is
//! silent; a blocked sender's requests never show; two people who add each
//! other by ID are friends once their devices connect. The seed's files and
//! log hold no ID, name or note.

use mesh_identity::MeshId;
use serde_json::Value;

mod common;
use common::{Helper, Relay, Seed, temp_dir};

const PASSWORD: &str = "correct horse battery staple";
/// Short records, so refreshes come every 2 s.
const TTL: &str = "8";

fn helper(dir: &std::path::Path, relay: &Relay, seed: &str, name: &str) -> (Helper, String) {
    let mut h = Helper::start_with(dir, relay, &["--seed", seed, "--record-ttl", TTL]);
    assert_eq!(h.event().0, "meshIdentity");
    let id = h.expect("idCreate", &[name, PASSWORD], "meshIdentity")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(h.event().0, "meshCodes");
    h.net_state("online");
    (h, id)
}

/// Whether `list` in a `meshSocial` has `id`.
fn has(social: &Value, list: &str, id: &str) -> bool {
    social[list]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["id"] == id)
}

impl Helper {
    /// A code a seed holds.
    fn code(&mut self, uses: &str) -> String {
        let code = self.expect("codeCreate", &["", uses], "meshCodes")["created"]
            .as_str()
            .unwrap()
            .to_owned();
        loop {
            let (binding, payload) = self.event();
            assert_eq!(binding, "meshCodes", "unexpected {payload}");
            let held = payload["codes"].as_array().unwrap().iter();
            if held.clone().any(|c| c["code"] == code && c["held"] == true) {
                return code;
            }
        }
    }

    /// Adds the code's owner (social R3-1): on our side only.
    fn add_by_code(&mut self, code: &str, owner: &str) {
        let social = self.expect("friendRequest", &[code], "meshSocial");
        assert!(has(&social, "outgoing", owner), "{social}");
    }

    /// Locks and unlocks, which collects the requests left with our codes.
    fn relock(&mut self, name: &str) {
        self.expect("idLock", &[], "meshIdentity");
        self.expect("idUnlock", &[name, PASSWORD], "meshIdentity");
        assert_eq!(self.event().0, "meshCodes");
    }

    fn until(&mut self, list: &str, id: &str) -> Value {
        self.social_until(|s| has(s, list, id))
    }

    fn list(&mut self) -> Value {
        self.expect("socialList", &[], "meshSocial")
    }
}

/// SPEC-social revision 3: a code only gives someone your ID. Using it adds
/// them on your side; nothing shows on theirs. Friends once both have.
#[test]
fn friends_when_both_have_added_each_other() {
    let dirs = ["seed", "alice", "bob", "carol", "dave"].map(|n| temp_dir(&format!("social-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice");
    let (mut bob, id_b) = helper(&dirs[2], &relay, &ticket, "bob");
    let (mut carol, id_c) = helper(&dirs[3], &relay, &ticket, "carol");
    let (mut dave, id_d) = helper(&dirs[4], &relay, &ticket, "dave");

    // Alice uses Bob's code: Bob is hers as `outgoing`; Bob sees nothing,
    // and doesn't let her in.
    let bobs = bob.code("unlimited");
    alice.add_by_code(&bobs, &id_b);
    let mine = alice.code("1");
    let own = alice.expect("friendRequest", &[&mine], "meshError");
    assert_eq!(own["kind"], "self", "{own}");
    std::thread::sleep(std::time::Duration::from_secs(3));
    let social = bob.list();
    for list in ["friends", "incoming", "outgoing", "blocked"] {
        assert!(!has(&social, list, &id_a), "{list}: {social}");
    }
    let refused = bob.expect("netPingId", &[&id_a], "meshError");
    assert_eq!(refused["kind"], "not-a-contact");

    // Bob uses Alice's code: friends on both sides.
    let alices = alice.code("unlimited");
    bob.add_by_code(&alices, &id_a);
    alice.until("friends", &id_b);
    bob.until("friends", &id_a);
    assert_eq!(alice.expect("netPingId", &[&id_b], "meshPing")["id"], id_b);

    // Carol adds Bob by code and Bob never adds her: nothing, ever. Bob
    // blocks Dave, who added him; Dave stays `outgoing`, unseen.
    carol.add_by_code(&bobs, &id_b);
    dave.add_by_code(&bobs, &id_b);
    let social = bob.expect("block", &[&id_d], "meshSocial");
    assert!(has(&social, "blocked", &id_d) && !has(&social, "incoming", &id_c));
    bob.relock("bob");
    let social = bob.list();
    assert!(!has(&social, "friends", &id_c) && !has(&social, "outgoing", &id_c));
    assert!(has(&carol.list(), "outgoing", &id_b));

    // Add by ID on both sides: friends once their devices connect.
    carol.expect("friendAdd", &[&id_a, "Al"], "meshSocial");
    alice.expect("friendAdd", &[&id_c, ""], "meshSocial");
    carol.until("friends", &id_a);
    alice.until("friends", &id_c);

    let stderr = [alice, bob, carol, dave].map(Helper::quit).concat();
    assert!(!stderr.contains(PASSWORD));
    let log = seed.stop().join("\n");
    let stored: Vec<u8> = ["codes.bin", "addrs.bin", "knocks.bin"]
        .iter()
        // No request is ever sent now, so there may be no knocks.bin.
        .flat_map(|f| std::fs::read(dirs[0].join(f)).unwrap_or_default())
        .collect();
    for id in [&id_a, &id_b, &id_c, &id_d] {
        assert!(!log.contains(id.as_str()), "an ID reached the seed's log");
        let raw = MeshId::parse(id).unwrap().to_bytes();
        assert!(
            !stored.windows(32).any(|w| w == raw),
            "an ID is in the seed's files"
        );
    }
    for text in ["alice", "dave"] {
        assert!(!log.contains(text));
        assert!(
            !stored.windows(text.len()).any(|w| w == text.as_bytes()),
            "{text} is stored"
        );
    }
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn own_devices_keep_the_same_lists() {
    let dirs = ["seed", "alice", "desk", "laptop"].map(|n| temp_dir(&format!("sync-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice");
    let (mut desk, id_b) = helper(&dirs[2], &relay, &ticket, "bob");
    alice.expect("friendAdd", &[&id_b, ""], "meshSocial");
    desk.expect("friendAdd", &[&id_a, ""], "meshSocial");
    desk.until("friends", &id_a);

    // The laptop starts from a backup; then the desk blocks someone.
    let backup = dirs[2].join("bob.mkb");
    let backup = backup.to_str().unwrap();
    desk.expect("idExport", &[backup, "bob", PASSWORD], "meshDone");
    let mut laptop =
        Helper::start_with(&dirs[3], &relay, &["--seed", &ticket, "--record-ttl", TTL]);
    assert_eq!(laptop.event().0, "meshIdentity");
    laptop.expect(
        "idImport",
        &[backup, "bob", PASSWORD, PASSWORD],
        "meshIdentity",
    );
    assert_eq!(laptop.event().0, "meshCodes");
    let stranger = mesh_identity::RootKey::generate().unwrap().id().to_string();
    desk.expect("block", &[&stranger], "meshSocial");

    // The laptop finds the desk through the seed and takes the block in.
    laptop.until("blocked", &stranger);
    assert!(has(&laptop.list(), "friends", &id_a));

    // A change on the laptop reaches the desk.
    laptop.expect("friendRename", &[&id_a, "Ali"], "meshSocial");
    desk.social_until(|s| s["friends"][0]["nick"] == "Ali");
    laptop.expect("unblock", &[&stranger], "meshSocial");
    desk.social_until(|s| !has(s, "blocked", &stranger));

    let stderr = [alice, desk, laptop].map(Helper::quit).concat();
    assert!(!stderr.contains(PASSWORD));
    seed.stop();
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// What `meshSocial` says about friend `id`.
fn presence(social: &Value, id: &str) -> String {
    let friends = social["friends"].as_array().unwrap();
    let friend = friends.iter().find(|f| f["id"] == id);
    friend
        .map_or("absent", |f| f["presence"].as_str().unwrap())
        .to_owned()
}

fn sees(h: &mut Helper, id: &str, what: &str) {
    h.social_until(|s| presence(s, id) == what);
}

#[test]
fn friends_see_presence() {
    let dirs = ["seed", "alice", "bob"].map(|n| temp_dir(&format!("presence-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice");
    let (mut bob, id_b) = helper(&dirs[2], &relay, &ticket, "bob");
    alice.expect("friendAdd", &[&id_b, ""], "meshSocial");
    bob.expect("friendAdd", &[&id_a, ""], "meshSocial");
    sees(&mut alice, &id_b, "online");
    sees(&mut bob, &id_a, "online");
    // Added by ID, no request: each learns the other's name from presence.
    alice.social_until(|s| s["friends"][0]["name"] == "bob");
    bob.social_until(|s| s["friends"][0]["name"] == "alice");

    // Bob's status shows on Alice's side.
    bob.expect("statusSet", &["dnd"], "meshSocial");
    sees(&mut alice, &id_b, "dnd");
    bob.expect("statusSet", &["online"], "meshSocial");
    sees(&mut alice, &id_b, "online");
    bob.expect("activity", &["idle"], "meshSocial");
    sees(&mut alice, &id_b, "idle");
    bob.expect("activity", &["active"], "meshSocial");
    sees(&mut alice, &id_b, "online");

    // Invisible: offline to Alice, but she can still reach him.
    let social = bob.expect("statusSet", &["invisible"], "meshSocial");
    assert_eq!(social["status"], "invisible");
    sees(&mut alice, &id_b, "offline");
    assert_eq!(alice.expect("netPingId", &[&id_b], "meshPing")["id"], id_b);

    // Alice locks: Bob sees her go.
    alice.expect("idLock", &[], "meshIdentity");
    sees(&mut bob, &id_a, "offline");

    let stderr = [alice, bob].map(Helper::quit).concat();
    assert!(!stderr.contains(PASSWORD));
    seed.stop();
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}
