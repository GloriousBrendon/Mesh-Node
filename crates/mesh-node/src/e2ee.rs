//! End-to-end encryption in the helper (SPEC-e2ee): this device's e2ee
//! field rides in each address record it leaves (D4), the fields in friends'
//! records feed the bundle directory, and envelopes travel over the `e2ee`
//! service, one per frame (`flags u8 | envelope`; bit 0 says it waited).

use std::time::Duration;

use crate::routing::{self, Target};
use mesh_e2ee::E2ee;
use mesh_identity::{AddrRecord, MeshId};
use mesh_transport::{MeshAddr, Node, ServiceStream};

/// One stream's frames: each frame's flags and its envelope.
pub type Frames = Vec<(u8, Vec<u8>)>;

/// The transport service envelopes travel on.
pub const SERVICE: &str = "e2ee";
/// The frame flag for an envelope that waited for its reader.
pub const WAITED: u8 = 1;
/// A test note's text, in UTF-8 bytes (its body is `at u64 | text`).
pub const MAX_NOTE: usize = mesh_e2ee::MAX_BODY - 8;

/// A test note's body: when it was written, then the text.
pub fn note_body(at: u64, text: &str) -> Vec<u8> {
    [&at.to_be_bytes()[..], text.as_bytes()].concat()
}

/// A test note's time and text, if the body is one.
pub fn read_note(body: &[u8]) -> Option<(u64, String)> {
    let (at, text) = body.split_first_chunk::<8>()?;
    Some((
        u64::from_be_bytes(*at),
        String::from_utf8(text.to_vec()).ok()?,
    ))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A conversation ID written as 32 hex characters.
pub fn parse_conversation(text: &str) -> Option<[u8; 16]> {
    let text = text.as_bytes();
    if text.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in text.chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
/// The longest frame: the largest envelope, with room for Olm's overhead.
pub const MAX_FRAME: usize = mesh_e2ee::MAX_INSIDE + 1024;
/// How long a device has to take what we send it.
const SEND_TIMEOUT: Duration = Duration::from_secs(20);

/// Each contact's records on the seeds, for their e2ee fields.
// ponytail: one seed stream per contact; batch them when contact lists grow.
pub async fn fetch(
    anon: &Node,
    seeds: &[MeshAddr],
    targets: Vec<Target>,
    now: u64,
) -> Vec<(MeshId, Vec<AddrRecord>)> {
    let mut found = Vec::new();
    for target in targets {
        if let Ok((records, _)) = routing::find(anon, seeds, &target, now).await {
            found.push((target.id, records));
        }
    }
    found
}

/// Takes in the e2ee fields of `id`'s records. True if they gave us a
/// device we had no keys for.
pub fn learn(e2ee: &mut E2ee, id: &MeshId, records: &[AddrRecord]) -> bool {
    let knew = e2ee.devices_known(id);
    for record in records.iter().filter(|r| !r.e2ee.is_empty()) {
        if e2ee
            .learn(id, &record.devices, &record.device, &record.e2ee)
            .is_err()
        {
            eprintln!("mesh-node: a contact's record had e2ee keys that didn't check out");
        }
    }
    e2ee.devices_known(id) > knew
}

/// Sends frames to one device over the `e2ee` service. True once it took them.
pub async fn send(node: &Node, addr: &MeshAddr, frames: &[Vec<u8>]) -> bool {
    let sent = async {
        let (_, mut send, _recv) = node.open(addr, SERVICE).await.ok()?;
        for frame in frames {
            mesh_transport::frame::write_frame(&mut send, frame)
                .await
                .ok()?;
        }
        send.finish().ok()?;
        send.stopped().await.ok()
    };
    matches!(tokio::time::timeout(SEND_TIMEOUT, sent).await, Ok(Some(_)))
}

/// Reads one `e2ee` stream's frames: each is the flags and the envelope.
pub async fn read(stream: &mut ServiceStream) -> Frames {
    let mut frames = Vec::new();
    loop {
        let read = mesh_transport::frame::read_frame(&mut stream.recv);
        match tokio::time::timeout(SEND_TIMEOUT, read).await {
            Ok(Ok(Some(frame))) if frame.len() > 1 && frame.len() <= MAX_FRAME => {
                frames.push((frame[0], frame[1..].to_vec()));
            }
            _ => return frames,
        }
    }
}
