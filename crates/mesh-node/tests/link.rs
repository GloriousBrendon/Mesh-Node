//! Linking (PLAN-link): a new device joins an identity by typing a link code
//! shown on an existing one. They meet through an address record on the
//! seed, run SPAKE2 over a throwaway link node, and the new device gets the
//! identity, its friends and a place in the device list. Removing it keeps
//! it out again. No code, name or ID reaches any log.

use serde_json::Value;

mod common;
use common::{Helper, Relay, Seed, temp_dir};

const PASSWORD: &str = "correct horse battery staple";
const LAPTOP_PASSWORD: &str = "copper lantern drifts sideways";
/// Short records, so refreshes come every 2 s.
const TTL: &str = "8";
const LAPTOP: &str = "Kitchen laptop";

fn start(dir: &std::path::Path, relay: &Relay, seed: &str) -> Helper {
    let mut h = Helper::start_with(dir, relay, &["--seed", seed, "--record-ttl", TTL]);
    assert_eq!(h.event().0, "meshIdentity");
    h
}

fn helper(dir: &std::path::Path, relay: &Relay, seed: &str, name: &str) -> (Helper, String) {
    let mut h = start(dir, relay, seed);
    let id = h.expect("idCreate", &[name, PASSWORD], "meshIdentity")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(h.event().0, "meshCodes");
    h.net_state("online");
    (h, id)
}

fn has(social: &Value, list: &str, id: &str) -> bool {
    social[list]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["id"] == id)
}

/// The next event that isn't a codes list.
fn next(h: &mut Helper) -> (String, Value) {
    loop {
        let event = h.event();
        if event.0 != "meshCodes" {
            return event;
        }
    }
}

#[test]
fn a_new_device_links_with_a_code() {
    let dirs = ["seed", "desk", "bob", "laptop", "other"].map(|n| temp_dir(&format!("link-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut desk, id_a) = helper(&dirs[1], &relay, &ticket, "alice");
    let (mut bob, id_b) = helper(&dirs[2], &relay, &ticket, "bob");
    desk.expect("friendAdd", &[&id_b, ""], "meshSocial");
    bob.expect("friendAdd", &[&id_a, ""], "meshSocial");
    desk.social_until(|s| has(s, "friends", &id_b));

    // Linking needs an identity on one side and none on the other.
    let mut laptop = start(&dirs[3], &relay, &ticket);
    let err = laptop.expect("linkStart", &[], "meshError");
    assert_eq!(err["kind"], "locked", "{err}");

    let shown = desk.expect("linkStart", &[], "meshLink");
    let code = shown["code"].as_str().unwrap().to_owned();
    assert!(shown["expires"].as_u64().unwrap() > 0);

    // A wrong code finds nothing on the seed; the right one still works.
    let wrong = if code.starts_with('0') { "1" } else { "0" }.to_owned() + &code[1..];
    let err = laptop.expect("linkJoin", &[&wrong, LAPTOP], "meshError");
    assert_eq!(err["kind"], "not-found", "{err}");

    laptop.send("linkJoin", &[&code, LAPTOP]);
    let (binding, asked) = next(&mut desk);
    assert_eq!(binding, "meshLinkConfirm", "{asked}");
    assert_eq!(asked["name"], LAPTOP);
    desk.expect("linkConfirm", &["true"], "meshLinkDone");
    let identity = next(&mut desk);
    assert_eq!(identity.0, "meshIdentity");
    assert_eq!(identity.1["devices"].as_array().unwrap().len(), 2);

    let (binding, received) = next(&mut laptop);
    assert_eq!(binding, "meshLinkReceived", "{received}");
    assert_eq!(received["username"], "alice");
    // The password rules apply as on any new keystore.
    let err = laptop.expect("linkFinish", &["alice", "short"], "meshError");
    assert_eq!(err["kind"], "weak-password", "{err}");
    let mine = laptop.expect("linkFinish", &["alice", LAPTOP_PASSWORD], "meshIdentity");
    assert_eq!(mine["state"], "unlocked");
    assert_eq!(mine["id"], id_a.as_str());
    let devices = mine["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 2);
    let key = devices.iter().find(|d| d["thisDevice"] == true).unwrap()["key"].clone();
    assert_eq!(laptop.event().0, "meshCodes");
    laptop.net_state("online");

    // The laptop has Alice's friends, and reaches Bob by ID.
    laptop.social_until(|s| has(s, "friends", &id_b));
    loop {
        let (binding, payload) = laptop.call("netPingId", &[&id_b]);
        if binding == "meshPing" {
            break;
        }
        assert_eq!(binding, "meshError", "{payload}");
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // The code is spent: nobody else links with it.
    let mut other = start(&dirs[4], &relay, &ticket);
    let err = other.expect("linkJoin", &[&code, "Another"], "meshError");
    assert!(
        ["not-found", "unreachable"].contains(&err["kind"].as_str().unwrap()),
        "{err}"
    );

    // Removed, the laptop can't reach the desk any more (audit finding 2).
    let after = desk.expect("deviceRemove", &[key.as_str().unwrap()], "meshIdentity");
    assert_eq!(after["devices"].as_array().unwrap().len(), 1);
    let ticket_a = desk.expect("netTicket", &[], "meshTicket")["ticket"].clone();
    let err = laptop.expect("netPing", &[ticket_a.as_str().unwrap()], "meshError");
    assert_eq!(err["kind"], "unreachable", "{err}");

    let stderr = [desk, bob, laptop, other].map(Helper::quit).concat();
    let seed_log = seed.stop().concat();
    for secret in [
        code.as_str(),
        LAPTOP,
        PASSWORD,
        LAPTOP_PASSWORD,
        id_a.as_str(),
    ] {
        assert!(!stderr.contains(secret), "a helper logged {secret:?}");
        assert!(!seed_log.contains(secret), "the seed logged {secret:?}");
    }
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}
