//! End-to-end encryption in the helper (SPEC-e2ee): this device's e2ee
//! field rides in each address record it leaves (D4), the fields in friends'
//! records feed the bundle directory, and envelopes travel over the `e2ee`
//! service, one per frame (`flags u8 | envelope`; bit 0 says it waited).

use std::collections::HashMap;
use std::time::Duration;

use crate::routing::{self, Target};
use mesh_e2ee::E2ee;
use mesh_identity::{AddrRecord, MeshId};
use mesh_transport::{MeshAddr, Node};

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
/// Frames read from one stream at most (each up to `MAX_FRAME`).
pub const MAX_FRAMES: usize = 256;
/// Envelopes kept for one device that isn't connected.
pub const MAX_WAITING: usize = 256;
/// How long a device has to take what we send it.
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(20);

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

/// Sends frames to one device over the `e2ee` service, `MAX_FRAMES` to a
/// stream as the reader takes them. True once it took them all.
pub async fn send(node: &Node, addr: &MeshAddr, frames: &[Vec<u8>]) -> bool {
    for batch in frames.chunks(MAX_FRAMES) {
        let sent = async {
            let (_, mut send, _recv) = node.open(addr, SERVICE).await.ok()?;
            for frame in batch {
                mesh_transport::frame::write_frame(&mut send, frame)
                    .await
                    .ok()?;
            }
            send.finish().ok()?;
            send.stopped().await.ok()
        };
        if !matches!(tokio::time::timeout(SEND_TIMEOUT, sent).await, Ok(Some(_))) {
            return false;
        }
    }
    true
}

/// Reads one `e2ee` stream's frames: each is the flags and the envelope.
/// At most `MAX_FRAMES`; the sender sends the rest on another stream.
pub async fn read(recv: &mut (impl tokio::io::AsyncRead + Unpin)) -> Frames {
    let mut frames = Vec::new();
    while frames.len() < MAX_FRAMES {
        let read = mesh_transport::frame::read_frame(recv);
        match tokio::time::timeout(SEND_TIMEOUT, read).await {
            Ok(Ok(Some(frame))) if frame.len() > 1 && frame.len() <= MAX_FRAME => {
                frames.push((frame[0], frame[1..].to_vec()));
            }
            _ => return frames,
        }
    }
    frames
}

/// Keeps envelopes for a device that isn't connected: the newest
/// `MAX_WAITING`, so one that stays away can't grow it without end.
// ponytail: in memory until `dm` keeps waiting events on disk (D5).
pub fn wait(
    waiting: &mut HashMap<[u8; 32], Vec<Vec<u8>>>,
    device: [u8; 32],
    envelopes: Vec<Vec<u8>>,
) {
    let queue = waiting.entry(device).or_default();
    queue.extend(envelopes);
    let over = queue.len().saturating_sub(MAX_WAITING);
    queue.drain(..over);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One friend's stream, or one device that stays away, can't fill this
    /// device's memory (audit finding 13).
    #[tokio::test]
    async fn a_stream_and_a_waiting_queue_have_caps() {
        let mut sent = Vec::new();
        for i in 0..MAX_FRAMES + 50 {
            let frame = [&[0u8][..], &(i as u32).to_be_bytes()].concat();
            mesh_transport::frame::write_frame(&mut sent, &frame)
                .await
                .unwrap();
        }
        let frames = read(&mut &sent[..]).await;
        assert_eq!(frames.len(), MAX_FRAMES);

        let mut waiting = HashMap::new();
        let device = [1; 32];
        wait(
            &mut waiting,
            device,
            (0..MAX_WAITING as u32)
                .map(|i| i.to_be_bytes().to_vec())
                .collect(),
        );
        wait(&mut waiting, device, vec![b"newest".to_vec()]);
        let queue = &waiting[&device];
        assert_eq!(queue.len(), MAX_WAITING);
        assert_eq!(queue.last().unwrap(), b"newest", "the oldest goes");
        assert_eq!(queue[0], 1u32.to_be_bytes());
    }
}
