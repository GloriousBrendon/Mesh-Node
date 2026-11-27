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

/// A real picture, as the decoder takes it (PR8): `side` pixels square, in
/// a color of its own.
fn png(shade: u8, side: u32) -> Vec<u8> {
    let picture = image::RgbaImage::from_pixel(side, side, image::Rgba([shade, 40, 90, 255]));
    let mut bytes = Vec::new();
    picture
        .write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .unwrap();
    bytes
}

fn write_profile(dir: &Path, bio: &str, avatar: &[u8]) {
    std::fs::create_dir_all(dir).unwrap();
    let toml = format!(
        "follow_rice = true\n[theme]\naccent = \"#d88f92\"\n[[block]]\nkind = \"bio\"\ntext = \"{bio}\"\n[[block]]\nkind = \"gallery\"\n"
    );
    std::fs::write(dir.join("profile.toml"), toml).unwrap();
    std::fs::write(dir.join("avatar.png"), avatar).unwrap();
    std::fs::write(dir.join("gallery-1.png"), png(7, 300)).unwrap();
    // Not a picture at all: a friend sees a placeholder.
    std::fs::write(dir.join("gallery-2.png"), b"not a picture").unwrap();
    // Not a profile file: left out.
    std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
}

/// `profileGet`'s files, by slot and in order, read from their paths;
/// a placeholder (the decoder refused it) as no bytes.
fn files(profile: &Value) -> Vec<(String, Vec<u8>)> {
    profile["assets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let bytes = match a["path"].as_str() {
                Some(path) => std::fs::read(path).unwrap(),
                None if a["placeholder"] == true => Vec::new(),
                None => panic!("not opened: {a}"),
            };
            (a["slot"].as_str().unwrap().to_owned(), bytes)
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

    write_profile(folder, "Frontman of Nagbreek.", &png(1, 16));
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
            ("avatar".to_owned(), png(1, 16)),
            ("gallery".to_owned(), png(7, 300)),
            ("gallery".to_owned(), Vec::new()),
        ]
    );

    // Alice sees her own.
    let (_, own) = ask(&mut alice, "profileGet", &[&id_a]);
    assert_eq!(own["version"], 1);

    // A new version replaces it.
    write_profile(folder, "Mixing tonight.", &png(2, 16));
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
    assert_eq!(files(&profile)[0], ("avatar".to_owned(), png(2, 16)));
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
    assert_eq!(files(&profile)[0], ("avatar".to_owned(), png(2, 16)));

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

/// Sends a Top 8 command and waits for its `meshTop8` (or its error).
fn top8(h: &mut Helper, func: &str, args: &[&str]) -> (String, Value) {
    h.send(func, args);
    let started = std::time::Instant::now();
    loop {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "{func}: no answer"
        );
        let (got, payload) = h.event();
        if (got == "meshTop8" && payload["event"]["fn"] == func) || got == "meshError" {
            return (got, payload);
        }
    }
}

/// SPEC-profile PR11: Alice may show Bob in her Top 8 only once he says
/// yes; Carol, Alice's friend but not Bob's, sees the name he gave and his
/// avatar, never his ID; once he withdraws, he's gone from her profile.
#[test]
fn a_top8_ask_accept_and_withdraw() {
    let dirs = [
        "seed",
        "alice",
        "bob",
        "carol",
        "alice-profile",
        "bob-profile",
    ]
    .map(|n| temp_dir(&format!("top8-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice");
    let (mut bob, id_b) = helper(&dirs[2], &relay, &ticket, "bob");
    let (mut carol, id_c) = helper(&dirs[3], &relay, &ticket, "carol");
    for (b, id_b) in [(&mut bob, &id_b), (&mut carol, &id_c)] {
        alice.expect("friendAdd", &[id_b, ""], "meshSocial");
        b.expect("friendAdd", &[&id_a, ""], "meshSocial");
        alice.social_until(|s| has(s, "friends", id_b));
        b.social_until(|s| has(s, "friends", &id_a));
    }
    // Bob has a profile with an avatar, and Alice holds it.
    write_profile(&dirs[5], "Bob's.", &png(3, 16));
    ask(&mut bob, "profileSet", &[dirs[5].to_str().unwrap()]);
    until(&mut alice, "meshProfile", |p| {
        p["id"] == *id_b && p["complete"] == true
    });
    write_profile(&dirs[4], "Alice's.", &png(4, 16));
    ask(&mut alice, "profileSet", &[dirs[4].to_str().unwrap()]);

    // Not before he says yes.
    let (got, err) = top8(&mut alice, "top8Set", &[&id_b]);
    assert_eq!(
        (got.as_str(), err["kind"].as_str()),
        ("meshError", Some("not-allowed"))
    );

    top8(&mut alice, "top8Ask", &[&id_b]);
    until(&mut bob, "meshTop8", |t| {
        t["event"]["event"] == "ask" && t["asks"][0] == *id_a
    });
    top8(&mut bob, "top8Answer", &[&id_a, "true", "Bobby"]);
    until(&mut alice, "meshTop8", |t| {
        t["event"]["event"] == "yes" && t["mayShow"][0]["name"] == "Bobby"
    });
    let (_, set) = top8(&mut alice, "top8Set", &[&id_b]);
    assert_eq!(set["shown"][0], *id_b);

    // Carol sees "Bobby" and his avatar in Alice's profile, not his ID.
    until(&mut carol, "meshProfile", |p| {
        p["id"] == *id_a && p["version"] == 2 && p["complete"] == true
    });
    let (_, profile) = ask(&mut carol, "profileGet", &[&id_a]);
    assert_eq!(profile["top8"][0]["name"], "Bobby", "{profile}");
    let avatar = profile["top8"][0]["avatar"].as_str().unwrap();
    assert_eq!(std::fs::read(avatar).unwrap(), png(3, 16));
    assert!(!profile.to_string().contains(&id_b), "no ID in {profile}");

    // He withdraws: Alice's profile drops him, and Carol's copy follows.
    top8(&mut bob, "top8Withdraw", &[&id_a]);
    until(&mut alice, "meshTop8", |t| {
        t["event"]["event"] == "withdrawn" && t["shown"].as_array().unwrap().is_empty()
    });
    until(&mut carol, "meshProfile", |p| {
        p["id"] == *id_a && p["version"] == 3
    });
    let (_, profile) = ask(&mut carol, "profileGet", &[&id_a]);
    assert_eq!(profile["top8"], serde_json::json!([]), "{profile}");

    alice.quit();
    bob.quit();
    carol.quit();
    seed.stop();
}
