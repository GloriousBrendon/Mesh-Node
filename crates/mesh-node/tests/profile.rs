//! Profiles (SPEC-profile PR1, PR3, PR15): Alice publishes a profile from a
//! folder; Bob, her friend, is offered it when they're connected, takes it,
//! fetches its files and opens them; a new version replaces it; Carol,
//! befriended later, gets it when she connects; once Bob
//! removes her as a friend, her profile is gone from his device.

use serde_json::Value;
use std::path::Path;

mod common;
use common::{Helper, Relay, Seed, temp_dir};

const PASSWORD: &str = "correct horse battery staple";
const TTL: &str = "8";

fn helper(dir: &Path, relay: &Relay, seed: &str, name: &str) -> (Helper, String) {
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

fn has(social: &Value, list: &str, id: &str) -> bool {
    social[list]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["id"] == id)
}

/// The next `binding` event that `done` accepts; other events are skipped.
fn until(h: &mut Helper, binding: &str, done: impl Fn(&Value) -> bool) -> Value {
    let started = std::time::Instant::now();
    loop {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "no {binding} came"
        );
        let (got, payload) = h.event();
        if got == binding && done(&payload) {
            return payload;
        }
    }
}

/// Sends a command and waits for its answer (or its error).
fn ask(h: &mut Helper, func: &str, args: &[&str]) -> (String, Value) {
    h.send(func, args);
    let started = std::time::Instant::now();
    loop {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "{func}: no answer"
        );
        let (got, payload) = h.event();
        if (got == "meshProfile" && payload["fn"] == func) || got == "meshError" {
            return (got, payload);
        }
    }
}

fn write_profile(dir: &Path, bio: &str, avatar: &[u8]) {
    std::fs::create_dir_all(dir).unwrap();
    let toml = format!(
        "follow_rice = true\n[theme]\naccent = \"#d88f92\"\n[[block]]\nkind = \"bio\"\ntext = \"{bio}\"\n[[block]]\nkind = \"gallery\"\n"
    );
    std::fs::write(dir.join("profile.toml"), toml).unwrap();
    std::fs::write(dir.join("avatar.png"), avatar).unwrap();
    std::fs::write(dir.join("gallery-1.png"), vec![7u8; 150_000]).unwrap();
    std::fs::write(dir.join("gallery-2.png"), vec![9u8; 10]).unwrap();
    // Not a profile file: left out.
    std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
}

/// `profileGet`'s files, by slot and in order, read from their paths.
fn files(profile: &Value) -> Vec<(String, Vec<u8>)> {
    profile["assets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let path = a["path"]
                .as_str()
                .unwrap_or_else(|| panic!("not opened: {a}"));
            (
                a["slot"].as_str().unwrap().to_owned(),
                std::fs::read(path).unwrap(),
            )
        })
        .collect()
}

#[test]
fn a_friend_gets_your_profile_and_loses_it_when_unfriended() {
    let dirs = ["seed", "alice", "bob", "alice-profile", "carol"]
        .map(|n| temp_dir(&format!("profile-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice");
    let (mut bob, id_b) = helper(&dirs[2], &relay, &ticket, "bob");

    // Nobody has a profile yet.
    let (got, err) = ask(&mut bob, "profileGet", &[&id_a]);
    assert_eq!(
        (got.as_str(), err["kind"].as_str()),
        ("meshError", Some("not-found"))
    );

    alice.expect("friendAdd", &[&id_b, ""], "meshSocial");
    bob.expect("friendAdd", &[&id_a, ""], "meshSocial");
    alice.social_until(|s| has(s, "friends", &id_b));
    bob.social_until(|s| has(s, "friends", &id_a));

    // A profile over the caps is refused before anything is kept.
    let folder = &dirs[3];
    write_profile(folder, "too big", &vec![1u8; 8_000_001]);
    let (got, err) = ask(&mut alice, "profileSet", &[folder.to_str().unwrap()]);
    assert_eq!(
        (got.as_str(), err["kind"].as_str()),
        ("meshError", Some("too-long")),
        "{err}"
    );

    write_profile(folder, "Frontman of Nagbreek.", b"avatar, first");
    let (got, set) = ask(&mut alice, "profileSet", &[folder.to_str().unwrap()]);
    assert_eq!(
        (got.as_str(), set["version"].as_u64()),
        ("meshProfile", Some(1)),
        "{set}"
    );

    // Bob, connected, is offered it, takes it and fetches its files.
    until(&mut bob, "meshProfile", |p| {
        p["id"] == *id_a && p["version"] == 1 && p["complete"] == true
    });
    let (_, profile) = ask(&mut bob, "profileGet", &[&id_a]);
    assert_eq!(profile["version"], 1);
    assert!(
        profile["toml"]
            .as_str()
            .unwrap()
            .contains("Frontman of Nagbreek.")
    );
    assert_eq!(
        files(&profile),
        vec![
            ("avatar".to_owned(), b"avatar, first".to_vec()),
            ("gallery".to_owned(), vec![7u8; 150_000]),
            ("gallery".to_owned(), vec![9u8; 10]),
        ]
    );

    // Alice sees her own.
    let (_, own) = ask(&mut alice, "profileGet", &[&id_a]);
    assert_eq!(own["version"], 1);

    // A new version replaces it.
    write_profile(folder, "Mixing tonight.", b"avatar, second");
    let (_, set) = ask(&mut alice, "profileSet", &[folder.to_str().unwrap()]);
    assert_eq!(set["version"], 2);
    until(&mut bob, "meshProfile", |p| {
        p["id"] == *id_a && p["version"] == 2 && p["complete"] == true
    });
    let (_, profile) = ask(&mut bob, "profileGet", &[&id_a]);
    assert!(
        profile["toml"]
            .as_str()
            .unwrap()
            .contains("Mixing tonight.")
    );
    assert_eq!(
        files(&profile)[0],
        ("avatar".to_owned(), b"avatar, second".to_vec())
    );
    let opened = profile["assets"][0]["path"].as_str().unwrap().to_owned();

    // A friend made after she published is offered it when they connect.
    let (mut carol, id_c) = helper(&dirs[4], &relay, &ticket, "carol");
    let (got, _) = ask(&mut carol, "profileGet", &[&id_a]);
    assert_eq!(got, "meshError", "not a friend yet");
    alice.expect("friendAdd", &[&id_c, ""], "meshSocial");
    carol.expect("friendAdd", &[&id_a, ""], "meshSocial");
    until(&mut carol, "meshProfile", |p| {
        p["id"] == *id_a && p["version"] == 2 && p["complete"] == true
    });
    let (_, profile) = ask(&mut carol, "profileGet", &[&id_a]);
    assert_eq!(
        files(&profile)[0],
        ("avatar".to_owned(), b"avatar, second".to_vec())
    );

    // Unfriended: her profile and its opened files are gone from Bob's device.
    bob.expect("friendRemove", &[&id_a], "meshSocial");
    let (got, err) = ask(&mut bob, "profileGet", &[&id_a]);
    assert_eq!(
        (got.as_str(), err["kind"].as_str()),
        ("meshError", Some("not-found"))
    );
    assert!(!Path::new(&opened).exists(), "the opened copy is removed");

    alice.quit();
    bob.quit();
    carol.quit();
    seed.stop();
}
