//! Fixed vectors for every Mesh format. Once v1 ships, changing one of these
//! is a breaking format change: old keystores, IDs or records stop working.
//! Where possible each vector comes from an independent source, not this crate.

use mesh_identity::{Link, MeshId, RootKey};

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
