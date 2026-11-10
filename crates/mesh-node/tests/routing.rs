//! Routing (SPEC-routing "Process test"): a seed and three helpers on
//! loopback relays. Contacts find each other by ID through the seed's address
//! records; a one-sided contact and a removed one can't; a device that moves
//! to another relay is found again. The seed's file and log hold no ID and
//! no relay URL.

use std::time::Duration;

use mesh_identity::MeshId;

mod common;
use common::{Helper, Relay, Seed, temp_dir};
use serde_json::Value;

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

impl Helper {
    /// Adds someone by ID; the answer lists them as asked (or as a friend,
    /// if they'd connected already).
    fn add(&mut self, id: &str, name: &str) {
        let social = self.expect("friendAdd", &[id, name], "meshSocial");
        let listed = |list: &str| {
            social[list]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["id"] == id)
        };
        assert!(listed("outgoing") || listed("friends"), "{social}");
    }

    fn published(&mut self) {
        self.net(|n| n["published"] == true);
    }

    /// Pings by ID until it answers, as a person retrying would (records
    /// arrive every couple of seconds).
    fn ping_id(&mut self, id: &str) -> Value {
        for _ in 0..20 {
            let (binding, payload) = self.call("netPingId", &[id]);
            if binding == "meshPing" {
                // The contact's new address and "seen" are saved, then listed.
                self.social_until(|s| {
                    s["friends"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|f| f["id"] == id)
                });
                return payload;
            }
            assert_eq!(binding, "meshError", "{payload}");
            assert_eq!(payload["kind"], "unreachable", "{payload}");
            std::thread::sleep(Duration::from_millis(500));
        }
        panic!("never reached {id}");
    }

    fn unreachable(&mut self, id: &str) {
        let err = self.expect("netPingId", &[id], "meshError");
        assert_eq!(
            (err["fn"].as_str(), err["kind"].as_str()),
            (Some("netPingId"), Some("unreachable")),
            "{err}"
        );
    }
}

#[test]
fn contacts_reach_each_other_by_id() {
    let (dir_s, dir_a, dir_b, dir_c) = (
        temp_dir("route-seed"),
        temp_dir("route-a"),
        temp_dir("route-b"),
        temp_dir("route-c"),
    );
    let relay = Relay::start();
    let mut seed = Seed::start(&dir_s, &relay);
    let ticket = seed.ticket();
    let (mut a, id_a) = helper(&dir_a, &relay, &ticket, "alice");
    let (mut b, id_b) = helper(&dir_b, &relay, &ticket, "bob");
    let (mut c, _) = helper(&dir_c, &relay, &ticket, "carol");

    // Not a contact yet: nothing to look for.
    let err = b.expect("netPingId", &[&id_a], "meshError");
    assert_eq!(err["kind"], "not-a-contact");

    a.add(&id_b, "Bob");
    b.add(&id_a, "Alice");
    a.published();
    let pong = b.ping_id(&id_a);
    assert_eq!(pong["id"], id_a);
    // Reached: Alice is Bob's friend now, seen just now.
    // Waits it out: Alice's presence (and her name) may answer first.
    b.social_until(|s| s["friends"][0]["seen"].is_u64());
    // And the other way, by ID too.
    b.published();
    assert_eq!(a.ping_id(&id_b)["id"], id_b);

    // Carol added Alice, but Alice never added Carol: no record for her,
    // and Alice's device wouldn't take her anyway.
    c.add(&id_a, "Alice");
    c.unreachable(&id_a);

    // Alice removes Bob: his cached address is refused at once, and the
    // records he could still find lead to the same refusal.
    a.expect("friendRemove", &[&id_b], "meshSocial");
    b.unreachable(&id_a);
    std::thread::sleep(Duration::from_secs(9));
    b.unreachable(&id_a);

    // Alice adds Bob back, then moves to another relay. Bob finds her again
    // through her new record, after his cached address fails.
    a.add(&id_b, "Bob");
    let elsewhere = Relay::start();
    a.quit();
    let mut a = Helper::start_with(
        &dir_a,
        &elsewhere,
        &["--seed", &ticket, "--record-ttl", TTL],
    );
    assert_eq!(a.event().0, "meshIdentity");
    a.expect("idUnlock", &["alice", PASSWORD], "meshIdentity");
    assert_eq!(a.event().0, "meshCodes");
    let online = a.net_state("online");
    assert_eq!(
        online["relay"].as_str(),
        Some(&*format!("{}/", elsewhere.url))
    );
    a.published();
    assert_eq!(b.ping_id(&id_a)["id"], id_a);

    let stderr = a.quit() + &b.quit() + &c.quit();
    assert!(!stderr.contains(PASSWORD));
    let log = seed.stop().join("\n");
    let stored = std::fs::read(dir_s.join("addrs.bin")).unwrap();
    assert!(!stored.is_empty());
    for id in [&id_a, &id_b] {
        assert!(!log.contains(id.as_str()), "an ID reached the seed's log");
        let raw = MeshId::parse(id).unwrap().to_bytes();
        assert!(
            !stored.windows(32).any(|w| w == raw),
            "an ID is in the seed's file"
        );
    }
    // The seed's log names its own relay (its ticket), never anyone else's.
    assert!(!log.contains(elsewhere.url.trim_start_matches("http://")));
    for url in [&relay.url, &elsewhere.url] {
        let host = url.trim_start_matches("http://");
        assert!(
            !stored.windows(host.len()).any(|w| w == host.as_bytes()),
            "a relay URL is in the seed's file"
        );
    }
    drop((relay.runtime, elsewhere.runtime));
    for dir in [dir_s, dir_a, dir_b, dir_c] {
        let _ = std::fs::remove_dir_all(dir);
    }
}
