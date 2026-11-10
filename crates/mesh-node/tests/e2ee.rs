//! E2ee (SPEC-e2ee "Process test"): a seed and helpers on a loopback relay.
//! Test notes reach a friend who was locked when they were sent, the
//! sender's other device, and both of a reader's devices; groups reach every
//! member; a removed device and a dropped member get nothing after. The
//! seed's files and log, and every helper's stderr, hold no ID or note text.

use std::time::{Duration, Instant};

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

/// A second device for `from`'s identity, restored from its backup.
fn second_device(
    from: &mut Helper,
    name: &str,
    dir: &std::path::Path,
    relay: &Relay,
    seed: &str,
) -> Helper {
    std::fs::create_dir_all(dir).unwrap();
    let backup = dir.join("backup.mkb");
    let backup = backup.to_str().unwrap();
    from.expect("idExport", &[backup, name, PASSWORD], "meshDone");
    let mut h = Helper::start_with(dir, relay, &["--seed", seed, "--record-ttl", TTL]);
    assert_eq!(h.event().0, "meshIdentity");
    h.expect(
        "idImport",
        &[backup, name, PASSWORD, PASSWORD],
        "meshIdentity",
    );
    assert_eq!(h.event().0, "meshCodes");
    h.net_state("online");
    h
}

fn has(social: &Value, list: &str, id: &str) -> bool {
    social[list]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["id"] == id)
}

fn befriend(a: &mut Helper, id_a: &str, b: &mut Helper, id_b: &str) {
    a.expect("friendAdd", &[id_b, ""], "meshSocial");
    b.expect("friendAdd", &[id_a, ""], "meshSocial");
    a.social_until(|s| has(s, "friends", id_b));
    b.social_until(|s| has(s, "friends", id_a));
    // Each has the other's keys once a note gets through both ways.
    let (ab, ba) = (format!("{id_a} to {id_b}"), format!("{id_b} to {id_a}"));
    a.note(&[id_b], &ab, None);
    b.note_with(&ab);
    b.note(&[id_a], &ba, None);
    a.note_with(&ba);
}

impl Helper {
    /// Sends a note, waiting out `no-keys` while the reader's keys are on
    /// their way (records come every couple of seconds).
    fn note(&mut self, ids: &[&str], text: &str, group: Option<&str>) -> Value {
        let ids = ids.join(" ");
        let started = Instant::now();
        loop {
            let mut args = vec![ids.as_str(), text];
            args.extend(group);
            let (mut binding, mut payload) = self.call("e2eeNote", &args);
            while binding == "meshCodes" {
                (binding, payload) = self.event();
            }
            if binding == "meshNoteSent" {
                return payload;
            }
            assert_eq!(binding, "meshError", "{payload}");
            assert_eq!(payload["kind"], "no-keys", "{payload}");
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "never got keys"
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    /// How many devices this identity lists.
    fn device_count(&mut self) -> usize {
        let identity = self.expect("idStatus", &[], "meshIdentity");
        identity["devices"].as_array().unwrap().len()
    }

    /// Waits until this device knows of `n` devices of its own.
    fn knows_devices(&mut self, n: usize) {
        let started = Instant::now();
        while self.device_count() < n {
            assert!(started.elapsed() < Duration::from_secs(30), "never saw {n}");
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    /// Whether a note with this text came.
    fn got(&self, text: &str) -> bool {
        self.notes.iter().any(|n| n["text"] == text)
    }
}

#[test]
fn notes_reach_every_device_even_after_a_wait() {
    let dirs = ["seed", "alice", "laptop", "bob", "phone"].map(|n| temp_dir(&format!("e2ee-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice");
    let (mut bob, id_b) = helper(&dirs[3], &relay, &ticket, "bob");
    befriend(&mut alice, &id_a, &mut bob, &id_b);
    let mut laptop = second_device(&mut alice, "alice", &dirs[2], &relay, &ticket);
    // Alice's desk takes in the laptop from its records.
    alice.knows_devices(2);

    // Live: Bob reads it, and Alice's laptop gets her own copy.
    alice.note(&[&id_b], "hello bob", None);
    let note = bob.note_with("hello bob");
    assert_eq!(note["from"], id_a);
    assert_eq!(note["with"], id_a);
    assert_eq!(note["path"], "live");
    assert!(note["group"].is_null());
    let copy = laptop.note_with("hello bob");
    assert_eq!(
        (&copy["from"], &copy["with"]),
        (&Value::from(&*id_a), &Value::from(&*id_b))
    );

    // Bob locks; the note waits on Alice's desk until he's back.
    bob.expect("idLock", &[], "meshIdentity");
    alice.social_until(|s| {
        s["friends"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == id_b && f["presence"] == "offline")
    });
    alice.note(&[&id_b], "while you were out", None);
    bob.expect("idUnlock", &["bob", PASSWORD], "meshIdentity");
    assert_eq!(bob.event().0, "meshCodes");
    let note = bob.note_with("while you were out");
    assert_eq!(
        (note["from"].as_str(), note["path"].as_str()),
        (Some(&*id_a), Some("waited"))
    );
    laptop.note_with("while you were out");

    // Bob replies, from a second device of his own: both of Alice's get it,
    // and so does his first.
    let mut phone = second_device(&mut bob, "bob", &dirs[4], &relay, &ticket);
    phone.knows_devices(2);
    // Alice's devices need the phone's keys before it can be read.
    phone.note(&[&id_a], "back now", None);
    for h in [&mut alice, &mut laptop, &mut bob] {
        let note = h.note_with("back now");
        assert_eq!(note["from"], id_b);
    }

    let stderr = [alice, laptop, bob, phone].map(Helper::quit).concat();
    check_nothing_leaked(
        seed,
        &dirs[0],
        &stderr,
        &[&id_a, &id_b],
        &["hello bob", "back now"],
    );
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn groups_reach_members_and_removals_cut_off() {
    let dirs = ["seed", "alice", "laptop", "bob", "carol"].map(|n| temp_dir(&format!("group-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice");
    let (mut bob, id_b) = helper(&dirs[3], &relay, &ticket, "bob");
    let (mut carol, id_c) = helper(&dirs[4], &relay, &ticket, "carol");
    befriend(&mut alice, &id_a, &mut bob, &id_b);
    befriend(&mut alice, &id_a, &mut carol, &id_c);
    befriend(&mut bob, &id_b, &mut carol, &id_c);
    let mut laptop = second_device(&mut alice, "alice", &dirs[2], &relay, &ticket);
    alice.knows_devices(2);

    // A group of the three: each one's note reaches the other two, and
    // Alice's laptop.
    let sent = alice.note(&[&id_b, &id_c], "hi all", None);
    let group = sent["conversation"].as_str().unwrap().to_owned();
    for h in [&mut bob, &mut carol, &mut laptop] {
        let note = h.note_with("hi all");
        assert_eq!(note["conversation"], group);
        assert_eq!(note["group"].as_array().unwrap().len(), 3);
    }
    bob.note(&[&id_a, &id_c], "from bob", Some(&group));
    carol.note(&[&id_a, &id_b], "from carol", Some(&group));
    for h in [&mut alice, &mut laptop] {
        h.note_with("from bob");
        h.note_with("from carol");
    }
    carol.note_with("from bob");
    bob.note_with("from carol");

    // Carol is dropped: Alice's next group note, and Bob's after he takes in
    // the new list, go only to Bob's or Alice's devices (desk and laptop).
    let sent = alice.note(&[&id_b], "without carol", Some(&group));
    assert_eq!(sent["devices"], 2, "bob and alice's laptop");
    bob.note_with("without carol");
    let sent = bob.note(&[&id_a], "bob without carol", Some(&group));
    assert_eq!(sent["devices"], 2, "alice's desk and laptop");
    alice.note_with("bob without carol");
    // Once a later 1:1 note is in, nothing earlier is still on its way.
    alice.note(&[&id_c], "marker", None);
    carol.note_with("marker");
    for text in ["without carol", "bob without carol"] {
        assert!(!carol.got(text), "carol read {text}");
    }

    // Alice removes her laptop: her next notes, 1:1 and group, skip it.
    let sent = alice.note(&[&id_b], "before the laptop goes", None);
    assert_eq!(sent["devices"], 2, "bob and the laptop");
    let identity = alice.expect("idStatus", &[], "meshIdentity");
    let devices = identity["devices"].as_array().unwrap();
    let key = devices.iter().find(|d| d["thisDevice"] == false).unwrap()["key"].clone();
    let after = alice.expect("deviceRemove", &[key.as_str().unwrap()], "meshIdentity");
    assert_eq!(after["devices"].as_array().unwrap().len(), 1);
    let sent = alice.note(&[&id_b], "after the laptop", None);
    assert_eq!(sent["devices"], 1, "only bob");
    let sent = alice.note(&[&id_b], "group after the laptop", Some(&group));
    assert_eq!(sent["devices"], 1, "only bob");
    bob.note_with("after the laptop");
    bob.note_with("group after the laptop");
    laptop.note_with("before the laptop goes");

    let stderr = [alice, laptop, bob, carol].map(Helper::quit).concat();
    check_nothing_leaked(
        seed,
        &dirs[0],
        &stderr,
        &[&id_a, &id_b, &id_c],
        &["hi all", "from bob"],
    );
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// The seed's files and log, and the helpers' stderr, hold no ID and no
/// note text (D15).
fn check_nothing_leaked(
    seed: Seed,
    dir: &std::path::Path,
    stderr: &str,
    ids: &[&str],
    texts: &[&str],
) {
    let log = seed.stop().join("\n");
    let stored: Vec<u8> = ["codes.bin", "addrs.bin", "knocks.bin"]
        .iter()
        .filter_map(|f| std::fs::read(dir.join(f)).ok())
        .flatten()
        .collect();
    assert!(!stderr.contains(PASSWORD));
    for id in ids {
        assert!(!log.contains(id), "an ID reached the seed's log");
        assert!(!stderr.contains(id), "an ID reached a helper's stderr");
        let raw = MeshId::parse(id).unwrap().to_bytes();
        assert!(
            !stored.windows(32).any(|w| w == raw),
            "an ID is in the seed's files"
        );
    }
    for text in texts {
        assert!(!log.contains(text) && !stderr.contains(text));
        assert!(
            !stored.windows(text.len()).any(|w| w == text.as_bytes()),
            "{text} is stored"
        );
    }
}
