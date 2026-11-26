//! Drives the `mesh-node` binary over stdio, as Mesh-Voice does: create →
//! lock → unlock → codes → safety number → export/import, checking each
//! event, and that no password ever reaches stderr; then two helpers ping
//! each other through a relay on loopback.

use serde_json::{Value, json};

mod common;
use common::{Helper as Node, Relay, temp_dir};

const USER: &str = "Brendon";
const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "violet lantern drifts upriver";
const BACKUP_PASSWORD: &str = "seventeen quiet harbour owls";
/// Starts like an ID but is far too short.
const SHORT_ID: &str = "mesh1";

#[test]
fn identity_over_stdio() {
    let (dir_a, dir_b) = (temp_dir("a"), temp_dir("b"));
    let backup = dir_a.join("backup.mks");
    let relay = Relay::start();

    let mut a = Node::start(&dir_a, &relay);
    assert_eq!(
        a.event(),
        (
            "meshIdentity".into(),
            json!({ "state": "none", "keyring": keyring() })
        )
    );

    // Weak passwords get the policy's verdict, and creating with one fails.
    let verdict = a.expect("idCheckPassword", &[USER, "password1"], "meshPassword");
    assert_eq!(verdict["ok"], false);
    let err = a.expect("idCreate", &[USER, "brendon12345"], "meshError");
    assert_eq!(
        (err["fn"].as_str(), err["kind"].as_str()),
        (Some("idCreate"), Some("weak-password"))
    );

    let created = a.expect("idCreate", &[USER, PASSWORD], "meshIdentity");
    assert_eq!(created["state"], "unlocked");
    assert_eq!(created["username"], USER);
    assert_eq!(created["devices"][0]["thisDevice"], true);
    let id = created["id"].as_str().unwrap().to_owned();
    assert!(id.starts_with("mesh1"));
    assert_eq!(a.event().0, "meshCodes");

    // Locked: nothing about the identity, and identity commands refuse.
    assert_eq!(a.expect("idLock", &[], "meshIdentity")["state"], "locked");
    assert!(
        a.expect("idStatus", &[], "meshIdentity")
            .get("id")
            .is_none()
    );
    assert_eq!(a.expect("codeList", &[], "meshError")["kind"], "locked");
    assert_eq!(
        a.expect("idUnlock", &[USER, NEW_PASSWORD], "meshError")["kind"],
        "cannot-unlock"
    );
    assert_eq!(
        a.expect("idUnlock", &["brendon", PASSWORD], "meshIdentity")["id"],
        id
    );
    assert_eq!(a.event().0, "meshCodes");

    a.expect(
        "idChangePassword",
        &[USER, PASSWORD, NEW_PASSWORD],
        "meshDone",
    );

    // Codes: create with the defaults and with choices, list, revoke.
    let made = a.expect("codeCreate", &["", ""], "meshCodes");
    let first = made["created"].as_str().unwrap().to_owned();
    assert_eq!(made["codes"][0]["maxUses"], 1);
    let made = a.expect("codeCreate", &["86400", "unlimited"], "meshCodes");
    assert_eq!(made["codes"].as_array().unwrap().len(), 2);
    assert!(made["codes"][1]["maxUses"].is_null());
    assert_eq!(
        a.expect("codeCreate", &["5", "1"], "meshError")["kind"],
        "code-not-a-choice"
    );
    let left = a.expect("codeRevoke", &[&first.to_lowercase()], "meshCodes");
    assert_eq!(left["codes"].as_array().unwrap().len(), 1);
    assert_ne!(left["codes"][0]["code"], first);
    assert_eq!(a.expect("codeList", &[], "meshCodes"), left);

    // Parsing: a typo names its kind; a link parses back to the ID.
    let typo = format!(
        "{}{}",
        &id[..id.len() - 1],
        if id.ends_with('q') { 'p' } else { 'q' }
    );
    assert_eq!(
        a.expect("parseId", &[&typo], "meshError")["kind"],
        "id-checksum"
    );
    assert_eq!(
        a.expect("parseId", &[SHORT_ID], "meshError")["kind"],
        "id-length"
    );
    let link = created["link"].as_str().unwrap();
    assert_eq!(a.expect("parseId", &[link], "meshParsed")["id"], id);
    assert_eq!(
        a.expect("parseId", &[&format!("mesh://code/{first}")], "meshParsed")["kind"],
        "code"
    );

    // Backup: the username must be this identity's; the password passes the policy.
    let path = backup.to_str().unwrap();
    assert_eq!(
        a.expect("idExport", &[path, "someone", BACKUP_PASSWORD], "meshError")["kind"],
        "wrong-username"
    );
    a.expect("idExport", &[path, USER, BACKUP_PASSWORD], "meshDone");
    assert_eq!(a.expect("bogus", &[], "meshError")["kind"], "unknown-fn");

    // The restored device: same ID, a new device key, its own password.
    let mut b = Node::start(&dir_b, &relay);
    assert_eq!(b.event().1["state"], "none");
    let restored = b.expect(
        "idImport",
        &[path, USER, BACKUP_PASSWORD, PASSWORD],
        "meshIdentity",
    );
    assert_eq!(restored["id"], id);
    let devices = restored["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[1]["thisDevice"], true);
    assert_eq!(b.event().0, "meshCodes");

    // The safety number is the same from both sides.
    let b_id = restored["id"].as_str().unwrap();
    let other = b.expect("idCreate", &[USER, PASSWORD], "meshError");
    assert_eq!(other["kind"], "already-exists");
    let from_b = b.expect("safetyNumber", &[&id], "meshSafety");
    let from_a = a.expect("safetyNumber", &[b_id], "meshSafety");
    assert_eq!(from_a["number"], from_b["number"]);
    assert_eq!(from_a["number"].as_str().unwrap().len(), 71);
    assert_eq!(
        a.expect(
            "safetyNumber",
            &[&format!("mesh://code/{first}")],
            "meshError"
        )["kind"],
        "not-an-id"
    );

    let stderr = a.quit() + &b.quit();
    for secret in [PASSWORD, NEW_PASSWORD, BACKUP_PASSWORD] {
        assert!(!stderr.contains(secret), "a password reached stderr");
    }
    let _ = std::fs::remove_dir_all(dir_a);
    let _ = std::fs::remove_dir_all(dir_b);
}

#[test]
fn two_helpers_ping_through_a_relay() {
    let (dir_a, dir_b) = (temp_dir("ping-a"), temp_dir("ping-b"));
    let relay = Relay::start();
    let (mut a, mut b) = (Node::start(&dir_a, &relay), Node::start(&dir_b, &relay));
    assert_eq!(a.event().0, "meshIdentity");
    assert_eq!(b.event().0, "meshIdentity");

    // Locked: no networking.
    assert_eq!(a.expect("netTicket", &[], "meshError")["kind"], "locked");
    a.send("netStatus", &[]);
    assert_eq!(a.net_state("off")["connections"], 0);

    let id_a = a.expect("idCreate", &["alice", PASSWORD], "meshIdentity")["id"].clone();
    let id_b = b.expect("idCreate", &["bob", NEW_PASSWORD], "meshIdentity")["id"].clone();
    assert_eq!(a.event().0, "meshCodes");
    assert_eq!(b.event().0, "meshCodes");
    let online = a.net_state("online");
    b.net_state("online");
    // What the UI sees: the relay, and no IP address of this device.
    assert_eq!(online["relay"].as_str(), Some(&*format!("{}/", relay.url)));
    let mut keys: Vec<_> = online.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "connections",
            "direct",
            "directCount",
            "hideIp",
            "keys",
            "paths",
            "published",
            "relay",
            "relayedCount",
            "state"
        ]
    );

    // Only contacts get in (SPEC-routing D9): a stranger's ping is refused.

    let ticket_a = a.expect("netTicket", &[], "meshTicket")["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    let ticket_b = b.expect("netTicket", &[], "meshTicket")["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(ticket_a.starts_with("mesh://node/"), "{ticket_a}");

    let refused = b.expect("netPing", &[&ticket_a], "meshError");
    assert_eq!(refused["kind"], "unreachable");
    let (sa, sb) = (id_a.as_str().unwrap(), id_b.as_str().unwrap());
    let social = a.expect("friendAdd", &[sb, "Bob"], "meshSocial");
    assert_eq!(social["outgoing"][0]["nick"], "Bob");
    b.expect("friendAdd", &[sa, "Alice"], "meshSocial");

    let pong = b.expect("netPing", &[&ticket_a], "meshPing");
    assert_eq!(pong["id"], id_a);
    assert!(pong["ms"].as_f64().unwrap() >= 0.0);
    assert!(["direct", "relay"].contains(&pong["path"].as_str().unwrap()));
    let pong = a.expect("netPing", &[&ticket_b], "meshPing");
    assert_eq!(pong["id"], id_b);
    // One connection between them, reused both ways.
    a.net(|n| n["connections"] == 1);
    b.net(|n| n["connections"] == 1);

    assert_eq!(
        b.expect("netPing", &["mesh://node/nope"], "meshError")["kind"],
        "bad-ticket"
    );

    // Alice locks: her node closes, and Bob can't reach her any more.
    assert_eq!(a.expect("idLock", &[], "meshIdentity")["state"], "locked");
    a.net_state("off");
    let err = b.expect("netPing", &[&ticket_a], "meshError");
    assert_eq!(
        (err["fn"].as_str(), err["kind"].as_str()),
        (Some("netPing"), Some("unreachable"))
    );

    let stderr = a.quit() + &b.quit();
    for secret in [PASSWORD, NEW_PASSWORD] {
        assert!(!stderr.contains(secret), "a password reached stderr");
    }
    drop(relay.runtime);
    let _ = std::fs::remove_dir_all(dir_a);
    let _ = std::fs::remove_dir_all(dir_b);
}

/// Whatever this machine's keyring status is; the test doesn't depend on one.
fn keyring() -> Value {
    match mesh_identity::keyring_status() {
        Ok(()) => Value::Null,
        Err(reason) => Value::String(reason),
    }
}
