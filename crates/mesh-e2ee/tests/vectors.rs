//! Fixed vectors for the e2ee formats. Once v1 ships, changing one of these
//! is a breaking format change: sealed mail and stored envelopes stop
//! opening. These come from this crate (no independent blake3 and
//! XChaCha20-Poly1305 tool was at hand); they pin the layout against change.

use mesh_e2ee::{Envelope, EnvelopeType, Inside, Kind, open_sealed};
use mesh_identity::DeviceKey;

/// A test note "hello" in conversation 5a…5a from list seq 1: the first 40
/// bytes; the rest of the 256 is zero padding.
const INSIDE_HEAD_HEX: &str =
    "015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0500000000000000010000000568656c6c6f0000000000";

/// The olm-type envelope "payload", sealed to the device whose secret is
/// 9d…9d, behind the 16-byte address ad…ad, from the throwaway secret 11…11
/// with nonce 24…24.
const SEALED_HEX: &str = "adadadadadadadadadadadadadadadadd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737242424242424242424242424242424242424242424242424d25ad3f9371b55d9fa9ddc4f62b0d177e67a5f991282dbae1b";

#[test]
fn inside_layout() {
    let inside = Inside {
        conversation: [0x5a; 16],
        kind: Kind::TestNote,
        seq: 1,
        body: b"hello".to_vec(),
    };
    let bytes = inside.to_bytes().unwrap();
    assert_eq!(bytes.len(), 256);
    assert_eq!(hex(&bytes[..40]), INSIDE_HEAD_HEX);
    assert!(bytes[40..].iter().all(|&b| b == 0));
    assert_eq!(Inside::from_bytes(&bytes).unwrap(), inside);
}

#[test]
fn sealed_layout() {
    let reader = DeviceKey::from_secret_bytes([0x9d; 32]);
    let throwaway = DeviceKey::from_secret_bytes([0x11; 32]);
    let sealed = unhex(SEALED_HEX);
    assert_eq!(&sealed[..16], &[0xad; 16]);
    assert_eq!(&sealed[16..48], throwaway.public().as_bytes());
    assert_eq!(&sealed[48..72], &[0x24; 24]);
    let envelope = open_sealed(&reader, 16, &sealed).unwrap();
    assert_eq!(
        Envelope::from_bytes(&envelope).unwrap(),
        Envelope {
            kind: EnvelopeType::Olm,
            payload: b"payload".to_vec()
        }
    );
    assert_eq!(envelope, [&[1, 2][..], b"payload"].concat());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
