//! Fixed vectors for every Mesh format. Once v1 ships, changing one of these
//! is a breaking format change: old keystores, IDs or records stop working.
//! Where possible each vector comes from an independent source, not this crate.

use ed25519_dalek::VerifyingKey;
use mesh_identity::{
    CodeRevoke, DeviceCert, DeviceList, FriendCode, HeldCode, Link, MeshId, RootKey, SafetyNumber,
};

/// RFC 8032 §7.1 test 1 secret key; its public key is published there.
const RFC8032_SECRET: [u8; 32] =
    hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const RFC8032_PUBLIC: [u8; 32] =
    hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
/// That public key as bech32m with prefix `mesh`, computed with the BIP-350
/// reference code (Python), not the Rust bech32 crate.
const RFC8032_MESH_ID: &str = "mesh16adfsqvzky9t042tlmfujeq88g8wzuhnm2nzxfd0qgdx3ac82ydqjtyyll";

#[test]
fn id_text_of_a_known_key() {
    let root = RootKey::from_secret_bytes(RFC8032_SECRET);
    assert_eq!(root.id().to_bytes(), RFC8032_PUBLIC);
    assert_eq!(root.id().to_string(), RFC8032_MESH_ID);
    assert_eq!(MeshId::parse(RFC8032_MESH_ID).unwrap(), root.id());
    assert_eq!(
        Link::parse(&format!("mesh://id/{RFC8032_MESH_ID}")).unwrap(),
        Link::Id(root.id())
    );
}

/// RFC 8032 §7.1 test 2 public key, used as a device key.
const RFC8032_TEST2_PUBLIC: [u8; 32] =
    hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
/// 2026-10-22 00:00 UTC.
const CREATED_AT: u64 = 1_792_627_200;
/// A "Laptop" certificate for the test 2 key, laid out and signed by OpenSSL
/// (`pkeyutl -sign -rawin`) over `mesh/v1/device-cert\0` + the body.
const CERT_HEX: &str = "01d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c000000006ad9520000064c6170746f7022969f1f98743a53a0f67dc1b6b11608b1ab2d9c84cdc90a610ba2235a9ffda6de734a4c144d6c8f91b4342d446b2906b0744ca048d35f3b58384f1244fabf0e";
/// A seq-1 list holding that certificate, nothing revoked; also from OpenSSL.
const LIST_HEX: &str = "01d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a00000000000000010001009101d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c000000006ad9520000064c6170746f7022969f1f98743a53a0f67dc1b6b11608b1ab2d9c84cdc90a610ba2235a9ffda6de734a4c144d6c8f91b4342d446b2906b0744ca048d35f3b58384f1244fabf0e000059d63bd32ddab81deed962aa43718cf3b152d62a4a262bb4fc723d2558b3ca4602f25e7b1bc9b91ceffe10d4134fca12e9039833eba9a9e0da3f42d1f630df06";

#[test]
fn device_cert_and_list_layouts() {
    let root = RootKey::from_secret_bytes(RFC8032_SECRET);
    let device = VerifyingKey::from_bytes(&RFC8032_TEST2_PUBLIC).unwrap();
    let cert = DeviceCert::issue(&root, &device, "Laptop", CREATED_AT).unwrap();
    assert_eq!(hex(&cert.to_bytes()), CERT_HEX);
    assert_eq!(DeviceCert::from_bytes(&unhex(CERT_HEX)).unwrap(), cert);
    let list = DeviceList::first(&root, cert).unwrap();
    assert_eq!(hex(&list.to_bytes()), LIST_HEX);
    assert_eq!(DeviceList::from_bytes(&unhex(LIST_HEX)).unwrap(), list);
}

/// The safety number for the RFC 8032 test 1 and test 2 keys, computed with
/// the Python `blake3` package.
const SAFETY_1_2: &str = "19256 56656 35643 41587 80798 88066 37649 59233 71793 03060 32272 11953";

#[test]
fn safety_number_of_a_known_pair() {
    let a = MeshId::from_bytes(&RFC8032_PUBLIC).unwrap();
    let b = MeshId::from_bytes(&RFC8032_TEST2_PUBLIC).unwrap();
    assert_eq!(SafetyNumber::new(&a, &b).to_string(), SAFETY_1_2);
    assert_eq!(SafetyNumber::new(&b, &a).to_string(), SAFETY_1_2);
}

/// A 7-day, single-use record for code `K7QM-3XPA` owned by the RFC 8032 test
/// 1 key, sealed with nonce 00..17, and its revoke; computed with the Python
/// `argon2-cffi`, `pynacl` and `blake3` packages, not this crate.
const CODE: &str = "K7QM-3XPA";
const CODE_LOOKUP_ID: &str = "093be1285368acf2d4ec090a6f94e2ad";
const HELD_HEX: &str = "093be1285368acf2d4ec090a6f94e2ad000000006ae28c8000000001ac767dc78fb2c6888af3b7cef592be01247b93c4bdd5f0082ed25bd74ed79401000102030405060708090a0b0c0d0e0f101112131415161754bc4927aad8d6a3e67a2fe9a5610c37910c48abd2da2e213cba6cacc304e3f2ed8d413b3431087f495cf69cb3beeace1f5f65d6addad097433bab4e2aeecacb792089ae444bca9917c13a04d3118852723a6ff5ea752127e9c9a041eb11c073ecc477bd6fef9538135cc7052f55d3da097065e3cecd6aeb8d041e0f6f3f6f5d06ea5bc122eccc50c27253d4abb0a7a7f843a6d45a";
const REVOKE_HEX: &str = "093be1285368acf2d4ec090a6f94e2ad9ec6255a34676c1f935aa6fb2c6fe8e4486443bffd43fe0801e3c2424f0fbb95";

#[test]
fn friend_code_derivation_and_record_layout() {
    let root = RootKey::from_secret_bytes(RFC8032_SECRET);
    let code = FriendCode::parse(CODE).unwrap();
    let held = HeldCode::from_bytes(&unhex(HELD_HEX)).unwrap();
    assert_eq!(hex(&held.lookup_id()), CODE_LOOKUP_ID);
    let record = held.open(&code, CREATED_AT).unwrap();
    assert_eq!(record.root(), root.id());
    assert_eq!(record.created_at(), CREATED_AT);
    assert_eq!(record.expires_at(), Some(CREATED_AT + 7 * 86_400));
    assert_eq!(record.max_uses(), Some(1));
    let revoke = CodeRevoke::new(&root, &code);
    assert_eq!(hex(&revoke.to_bytes()), REVOKE_HEX);
    assert!(held.is_revoked_by(&revoke));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not lowercase hex"),
    }
}
