//! dm (SPEC-dm), 1:1 so far: two friends chat through the commands. A
//! message is stored, delivered on the live connection and acknowledged;
//! the reader is told of it, opens the chat and sees it; edits, reactions
//! and deletes reach the other side; read state clears unread; "sent" shows
//! once the other device took it. No text reaches any log.

use serde_json::Value;
use std::path::PathBuf;
use std::time::{Duration, Instant};

mod common;
use common::{Helper, Relay, Seed, temp_dir};

const PASSWORD: &str = "correct horse battery staple";
/// Short records, so refreshes come every 2 s.
const TTL: &str = "8";
const HELLO: &str = "hello from the hike";

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

/// Sends a command and waits for its answer, skipping updates that come
/// by themselves meanwhile (a chat list, another page).
fn ask(h: &mut Helper, func: &str, args: &[&str], binding: &str) -> Value {
    h.send(func, args);
    let started = std::time::Instant::now();
    loop {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "{func}: no {binding}"
        );
        let (got, payload) = h.event();
        if got == binding || got == "meshError" {
            assert_eq!(got, binding, "{func} answered {payload}");
            return payload;
        }
    }
}

fn texts(messages: &Value) -> Vec<String> {
    let events = messages["events"].as_array().unwrap();
    events
        .iter()
        .map(|e| e["text"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn two_friends_chat() {
    let dirs = ["seed", "alice", "bob"].map(|n| temp_dir(&format!("dm-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice");
    let (mut bob, id_b) = helper(&dirs[2], &relay, &ticket, "bob");

    // Only friends can be messaged.
    let err = ask(&mut alice, "dmSend", &[&id_b, HELLO], "meshError");
    assert_eq!(err["kind"], "not-a-friend", "{err}");
    alice.expect("friendAdd", &[&id_b, ""], "meshSocial");
    bob.expect("friendAdd", &[&id_a, ""], "meshSocial");
    alice.social_until(|s| has(s, "friends", &id_b));
    bob.social_until(|s| has(s, "friends", &id_a));

    let sent = ask(&mut alice, "dmSend", &[&id_b, HELLO], "meshDmMessages");
    assert_eq!(
        (sent["id"].as_str(), texts(&sent)),
        (Some(&*id_b), vec![HELLO.to_owned()])
    );
    let hello = sent["events"][0]["id"].as_str().unwrap().to_owned();

    // Bob hasn't the chat open: he's told, then opens it.
    let told = until(&mut bob, "meshDmNotify", |_| true);
    assert_eq!(
        (told["id"].as_str(), told["text"].as_str()),
        (Some(&*id_a), Some(HELLO))
    );
    let open = ask(&mut bob, "dmOpen", &[&id_a], "meshDmMessages");
    assert_eq!(texts(&open), [HELLO]);
    assert_eq!(open["events"][0]["from"], id_a.as_str());

    // Typing goes over the live connection only (D10).
    alice.send("dmTyping", &[&id_b]);
    let typing = until(&mut bob, "meshDmTyping", |_| true);
    assert_eq!(
        (typing["id"].as_str(), typing["who"][0].as_str()),
        (Some(&*id_a), Some(&*id_a))
    );

    // "Sent" once Bob's device took it.
    let sent = until(&mut alice, "meshDmMessages", |m| {
        m["events"][0]["sent"] == true
    });
    assert_eq!(texts(&sent), [HELLO]);

    // Bob replies; Alice's list shows one unread, and reading clears it.
    ask(&mut bob, "dmSend", &[&id_a, "hi back"], "meshDmMessages");
    // Alice's chat with Bob is open (she sent in it): the page, not a note.
    until(&mut alice, "meshDmMessages", |m| {
        texts(m).contains(&"hi back".to_owned())
    });
    let chats = ask(&mut alice, "dmList", &[], "meshDmChats");
    let chat = &chats["chats"][0];
    assert_eq!(
        (
            chat["id"].as_str(),
            chat["kind"].as_str(),
            chat["unread"].as_u64()
        ),
        (Some(&*id_b), Some("direct"), Some(1))
    );
    let opened = ask(&mut alice, "dmOpen", &[&id_b], "meshDmMessages");
    let reply = opened["events"][1]["id"].as_str().unwrap().to_owned();
    let read = ask(&mut alice, "dmRead", &[&id_b, &reply], "meshDmChats");
    assert_eq!(read["chats"][0]["unread"], 0);

    // An edit and a reaction reach Bob, who has the chat open.
    ask(
        &mut alice,
        "dmEdit",
        &[&hello, "hello, edited"],
        "meshDmMessages",
    );
    let edited = until(&mut bob, "meshDmMessages", |m| {
        texts(m).contains(&"hello, edited".to_owned())
    });
    assert_eq!(edited["events"][0]["edited"], true);
    ask(
        &mut alice,
        "dmReact",
        &[&reply, "👍", "true"],
        "meshDmMessages",
    );
    let reacted = until(&mut bob, "meshDmMessages", |m| {
        m["events"][1]["reactions"][0]["emoji"] == "👍"
    });
    assert_eq!(
        reacted["events"][1]["reactions"][0]["who"][0],
        id_a.as_str()
    );
    // Only the author edits.
    let err = ask(&mut bob, "dmEdit", &[&hello, "not mine"], "meshError");
    assert_eq!(err["kind"], "not-author", "{err}");
    // A delete for everyone takes it off Bob's screen.
    ask(&mut alice, "dmDelete", &[&hello, "true"], "meshDmMessages");
    until(&mut bob, "meshDmMessages", |m| {
        !texts(m).iter().any(|t| t.starts_with("hello"))
    });

    let stderr = [alice, bob].map(Helper::quit).concat();
    let seed_log = seed.stop().concat();
    for secret in [HELLO, "hi back", "hello, edited"] {
        assert!(!stderr.contains(secret), "a helper logged {secret:?}");
        assert!(!seed_log.contains(secret), "the seed logged {secret:?}");
    }
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Makes every pair of helpers friends.
fn all_friends(people: &mut [(&mut Helper, &str)]) {
    for i in 0..people.len() {
        for j in 0..people.len() {
            if i != j {
                let other = people[j].1.to_owned();
                people[i].0.expect("friendAdd", &[&other, ""], "meshSocial");
            }
        }
    }
    for i in 0..people.len() {
        for j in 0..people.len() {
            if i != j {
                let other = people[j].1.to_owned();
                people[i].0.social_until(|s| has(s, "friends", &other));
            }
        }
    }
}

/// A group DM over the 1:1 sessions (e2ee D6): created, messaged both
/// ways, renamed; only the creator removes; a removed member is out.
#[test]
fn a_group_of_three() {
    let dirs = ["seed", "alice", "bob", "carol"].map(|n| temp_dir(&format!("group-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice");
    let (mut bob, id_b) = helper(&dirs[2], &relay, &ticket, "bob");
    let (mut carol, id_c) = helper(&dirs[3], &relay, &ticket, "carol");
    all_friends(&mut [(&mut alice, &id_a), (&mut bob, &id_b), (&mut carol, &id_c)]);

    let stranger = mesh_identity::RootKey::generate().unwrap().id().to_string();
    let err = ask(
        &mut alice,
        "dmGroupCreate",
        &[&format!("{id_b},{stranger}"), "hike"],
        "meshError",
    );
    assert_eq!(err["kind"], "not-a-friend", "{err}");
    let made = ask(
        &mut alice,
        "dmGroupCreate",
        &[&format!("{id_b},{id_c}"), "hike"],
        "meshDmChats",
    );
    let group = made["chats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "group")
        .unwrap();
    assert_eq!(
        (
            group["name"].as_str(),
            group["members"].as_array().unwrap().len()
        ),
        (Some("hike"), 3)
    );
    let g = group["id"].as_str().unwrap().to_owned();

    ask(&mut alice, "dmSend", &[&g, "hi all"], "meshDmMessages");
    for h in [&mut bob, &mut carol] {
        let told = until(h, "meshDmNotify", |n| n["text"] == "hi all");
        assert_eq!(
            (told["id"].as_str(), told["from"].as_str()),
            (Some(&*g), Some(&*id_a))
        );
    }
    carol.send("dmTyping", &[&g]);
    let typing = until(&mut alice, "meshDmTyping", |_| true);
    assert_eq!(
        (typing["id"].as_str(), typing["who"][0].as_str()),
        (Some(&*g), Some(&*id_c))
    );
    ask(
        &mut carol,
        "dmSend",
        &[&g, "hello from Carol"],
        "meshDmMessages",
    );
    until(&mut bob, "meshDmNotify", |n| {
        n["text"] == "hello from Carol"
    });
    until(&mut alice, "meshDmMessages", |m| {
        texts(m).contains(&"hello from Carol".to_owned())
    });

    // Bob renames it; only Alice, the creator, removes.
    ask(&mut bob, "dmGroupRename", &[&g, "trip"], "meshDmChats");
    until(&mut alice, "meshDmChats", |c| {
        c["chats"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "trip")
    });
    let err = ask(&mut bob, "dmGroupRemove", &[&g, &id_c], "meshError");
    assert_eq!(err["kind"], "not-creator", "{err}");
    ask(&mut alice, "dmGroupRemove", &[&g, &id_c], "meshDmChats");

    // Carol learns she's out, and can't send to it any more.
    let out = |c: &Value| {
        let chats = c["chats"].as_array().unwrap();
        chats
            .iter()
            .any(|c| c["members"].as_array().is_some_and(|m| m.len() == 2))
    };
    until(&mut carol, "meshDmChats", out);
    let err = ask(&mut carol, "dmSend", &[&g, "still here?"], "meshError");
    assert_eq!(err["kind"], "not-member", "{err}");
    ask(&mut alice, "dmSend", &[&g, "just us"], "meshDmMessages");
    until(&mut bob, "meshDmNotify", |n| n["text"] == "just us");

    let stderr = [alice, bob, carol].map(Helper::quit).concat();
    for secret in ["hi all", "hello from Carol", "just us", "hike"] {
        assert!(!stderr.contains(secret), "a helper logged {secret:?}");
    }
    seed.stop();
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A file goes by chunks from a device in the chat that has it (D12): the
/// message carries its key, hash, size, name and type; the reader fetches
/// it when asked. With nobody connected who has it, it's unavailable.
#[test]
fn a_file_goes_by_chunks() {
    let dirs = ["seed", "alice", "bob"].map(|n| temp_dir(&format!("file-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice");
    let (mut bob, id_b) = helper(&dirs[2], &relay, &ticket, "bob");
    all_friends(&mut [(&mut alice, &id_a), (&mut bob, &id_b)]);

    let plain: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let source = dirs[1].join("trail.pdf");
    std::fs::write(&source, &plain).unwrap();
    let sent = ask(
        &mut alice,
        "dmSendFile",
        &[&id_b, source.to_str().unwrap()],
        "meshDmMessages",
    );
    let file = &sent["events"][0]["attachments"][0];
    assert_eq!(
        (
            file["name"].as_str(),
            file["mime"].as_str(),
            file["size"].as_u64()
        ),
        (Some("trail.pdf"), Some("application/pdf"), Some(300_000))
    );
    let event = sent["events"][0]["id"].as_str().unwrap().to_owned();

    let told = until(&mut bob, "meshDmNotify", |_| true);
    assert_eq!(told["text"], "trail.pdf");
    let got = ask(&mut bob, "dmFetch", &[&id_a, &event, "0"], "meshDmFile");
    let path = got["path"].as_str().unwrap();
    assert_eq!(std::fs::read(path).unwrap(), plain, "the same bytes");

    // Delete for everyone: no copy is left on disk, opened or sealed, but
    // Alice's own source.
    ask(&mut alice, "dmDelete", &[&event, "true"], "meshDmMessages");
    let copies = || {
        let mut found = Vec::new();
        let mut walk = vec![dirs[1].clone(), dirs[2].clone()];
        while let Some(dir) = walk.pop() {
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk.push(path);
                } else if path != source
                    && (path.file_name() == Some("trail.pdf".as_ref())
                        || path.extension() == Some("blob".as_ref()))
                {
                    found.push(path);
                }
            }
        }
        found
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while !copies().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        copies(),
        Vec::<PathBuf>::new(),
        "copies left after the delete"
    );

    // A second file, then Alice goes: nobody connected has it.
    let other = dirs[1].join("notes.txt");
    std::fs::write(&other, b"only on alice").unwrap();
    // Pages also come by themselves ("sent" changing): wait for this one.
    alice.send("dmSendFile", &[&id_b, other.to_str().unwrap()]);
    let has_notes = |m: &Value| {
        let events = m["events"].as_array().unwrap();
        events
            .iter()
            .any(|e| e["attachments"][0]["name"] == "notes.txt")
    };
    let sent = until(&mut alice, "meshDmMessages", has_notes);
    let events = sent["events"].as_array().unwrap();
    let second = events
        .iter()
        .find(|e| e["attachments"][0]["name"] == "notes.txt")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    until(&mut bob, "meshDmNotify", |n| n["text"] == "notes.txt");
    let stderr = alice.quit();
    let err = ask(&mut bob, "dmFetch", &[&id_a, &second, "0"], "meshError");
    assert_eq!(err["kind"], "unavailable", "{err}");

    let stderr = stderr + &bob.quit();
    assert!(!stderr.contains("trail.pdf") && !stderr.contains("notes.txt"));
    seed.stop();
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A member's message that came before their add (answered `failed`)
/// goes again by itself once the add arrives (D7): Dave writes to a group
/// Alice just added him to, while her laptop holds it without him. Only
/// her desk tells the laptop of her own change, and does so later.
#[test]
fn a_message_before_the_add_shows_once_it_lands() {
    let dirs = ["seed", "desk", "laptop", "bob", "dave"].map(|n| temp_dir(&format!("early-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut desk, id_a) = helper(&dirs[1], &relay, &ticket, "alice");
    let (mut bob, id_b) = helper(&dirs[3], &relay, &ticket, "bob");
    let (mut dave, id_d) = helper(&dirs[4], &relay, &ticket, "dave");
    all_friends(&mut [(&mut desk, &id_a), (&mut bob, &id_b), (&mut dave, &id_d)]);

    // Alice links her laptop.
    let mut laptop =
        Helper::start_with(&dirs[2], &relay, &["--seed", &ticket, "--record-ttl", TTL]);
    assert_eq!(laptop.event().0, "meshIdentity");
    let code = desk.expect("linkStart", &[], "meshLink")["code"]
        .as_str()
        .unwrap()
        .to_owned();
    laptop.send("linkJoin", &[&code, "laptop"]);
    until(&mut desk, "meshLinkConfirm", |_| true);
    desk.send("linkConfirm", &["true"]);
    until(&mut laptop, "meshLinkReceived", |_| true);
    laptop.send("linkFinish", &["alice", PASSWORD]);
    until(&mut laptop, "meshIdentity", |i| i["state"] == "unlocked");
    until(&mut laptop, "meshCodes", |_| true);
    laptop.net_state("online");
    laptop.social_until(|s| has(s, "friends", &id_d));

    // A group of Alice and Bob, on both of Alice's devices.
    let made = ask(&mut desk, "dmGroupCreate", &[&id_b, "trip"], "meshDmChats");
    let g = made["chats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "group")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let members = |n: usize| {
        let g = g.clone();
        move |c: &Value| {
            (c["chats"].as_array().unwrap().iter())
                .any(|c| c["id"] == g.as_str() && c["members"].as_array().unwrap().len() == n)
        }
    };
    until(&mut laptop, "meshDmChats", members(2));

    // The laptop is away while the desk adds Dave, who writes at once.
    ask(&mut laptop, "idLock", &[], "meshIdentity");
    ask(&mut desk, "dmGroupAdd", &[&g, &id_d], "meshDmChats");
    until(&mut dave, "meshDmChats", members(3));
    ask(&mut dave, "dmSend", &[&g, "hi from Dave"], "meshDmMessages");
    until(&mut bob, "meshDmNotify", |n| n["text"] == "hi from Dave");

    // The desk goes; the laptop comes back and gets Dave's message before
    // it knows he's in: refused for now.
    ask(&mut desk, "idLock", &[], "meshIdentity");
    laptop.send("idUnlock", &["alice", PASSWORD]);
    until(&mut laptop, "meshIdentity", |i| i["state"] == "unlocked");
    std::thread::sleep(Duration::from_secs(5));

    // The desk comes back and passes the add on; Dave sends nothing more.
    desk.send("idUnlock", &["alice", PASSWORD]);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let page = ask(&mut laptop, "dmOpen", &[&g], "meshDmMessages");
        if texts(&page).contains(&"hi from Dave".to_owned()) {
            break;
        }
        assert!(Instant::now() < deadline, "Dave's message never showed");
        std::thread::sleep(Duration::from_secs(1));
    }

    let stderr = [desk, laptop, bob, dave].map(Helper::quit).concat();
    assert!(
        stderr.contains("chat events refused"),
        "it was refused first"
    );
    assert!(!stderr.contains("hi from Dave"));
    seed.stop();
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}
