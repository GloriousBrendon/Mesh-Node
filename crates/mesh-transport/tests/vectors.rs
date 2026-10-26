//! Fixed inputs → fixed outputs for every on-wire format. Once v1 ships, a
//! change here is a breaking format change.

use mesh_transport::MeshAddr;

#[test]
fn ticket() {
    let addr = MeshAddr {
        device: iroh::SecretKey::from_bytes(&[3; 32]).public(),
        relay: "https://euc1-1.relay.n0.iroh.link./".parse().unwrap(),
    };
    // The key is OpenSSL's Ed25519 public key for 32 bytes of 0x03.
    assert_eq!(
        addr.ticket(),
        "mesh://node/ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1\
         ?relay=https://euc1-1.relay.n0.iroh.link./"
    );
    assert_eq!(MeshAddr::from_ticket(&addr.ticket()), Ok(addr));
}
