//! The history store (SPEC-dm D11). Each chat is a folder named by a keyed
//! hash of its conversation ID, holding segment files of up to 512 sealed
//! events and a sealed index. Every event is sealed with XChaCha20-Poly1305
//! under a key derived from the keystore's data key, with the conversation,
//! the segment number and the event's position as associated data, so a
//! damaged, moved or swapped file is refused.
//!
//! Appends add to the newest segment and are synced to disk before they
//! return, once per call. In the newest segment, the first record that is
//! too short, has a bad length or doesn't open ends the file: a crash can
//! leave a torn record, zeros or junk there. The next append cuts it off.
//! Older segments stay strict: any such record is damage. Rewriting a
//! segment (a delete, D3) seals it again and replaces it atomically.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// Events in one segment file (D11).
pub const SEGMENT_EVENTS: usize = 512;
const SEAL_CONTEXT: &str = "mesh/v1/dm-store";
const NAME_CONTEXT: &str = "mesh/v1/dm-store-name";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const INDEX: &str = "index";

pub type Conversation = [u8; 16];

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("a chat history file is damaged")]
    Damaged,
    #[error("couldn't read or write the chat history: {0}")]
    Io(#[from] std::io::Error),
}

/// Every chat's history under one directory.
pub struct Store {
    root: PathBuf,
    seal: Zeroizing<[u8; 32]>,
    names: Zeroizing<[u8; 32]>,
}

/// One chat's files.
pub struct ChatFiles {
    dir: PathBuf,
    seal: Zeroizing<[u8; 32]>,
    conversation: Conversation,
    segments: u32,
    /// Events in the newest segment, and the bytes they take.
    last: (usize, u64),
    /// Segment files read since opening (tests check opening reads one).
    pub reads: usize,
}

impl Store {
    pub fn new(root: &Path, data_key: &[u8; 32]) -> Self {
        Self {
            root: root.to_owned(),
            seal: Zeroizing::new(blake3::derive_key(SEAL_CONTEXT, data_key)),
            names: Zeroizing::new(blake3::derive_key(NAME_CONTEXT, data_key)),
        }
    }

    /// A chat's files; reads only its newest segment.
    pub fn open(&self, conversation: &Conversation) -> Result<ChatFiles, StoreError> {
        let name = blake3::keyed_hash(&self.names, conversation);
        let hex: String = name.as_bytes()[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let dir = self.root.join(hex);
        let mut segments = 0;
        match fs::read_dir(&dir) {
            Ok(entries) => {
                for entry in entries {
                    let name = entry?.file_name();
                    let n = name.to_str().and_then(|n| n.strip_suffix(".seg"));
                    if let Some(n) = n.and_then(|n| n.parse::<u32>().ok()) {
                        segments = segments.max(n + 1);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let mut files = ChatFiles {
            dir,
            seal: self.seal.clone(),
            conversation: *conversation,
            segments,
            last: (0, 0),
            reads: 0,
        };
        if let Some(newest) = segments.checked_sub(1) {
            let (events, len) = files.records(newest)?;
            files.last = (events.len(), len);
        }
        Ok(files)
    }
}

impl ChatFiles {
    /// How many segment files the chat has.
    pub fn segments(&self) -> u32 {
        self.segments
    }

    /// The events in segment `n`, oldest first.
    pub fn read(&mut self, n: u32) -> Result<Vec<Vec<u8>>, StoreError> {
        Ok(self.records(n)?.0)
    }

    fn path(&self, n: u32) -> PathBuf {
        self.dir.join(format!("{n:08}.seg"))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&Key::from(*self.seal))
    }

    /// What every sealed thing in this chat is bound to.
    fn aad(&self, segment: u32, position: u32) -> [u8; 24] {
        let mut aad = [0u8; 24];
        aad[..16].copy_from_slice(&self.conversation);
        aad[16..20].copy_from_slice(&segment.to_be_bytes());
        aad[20..].copy_from_slice(&position.to_be_bytes());
        aad
    }

    /// One record: `len u32 | nonce | sealed`.
    fn seal(&self, segment: u32, position: u32, event: &[u8]) -> Result<Vec<u8>, StoreError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| std::io::Error::other(e.to_string()))?;
        let aad = self.aad(segment, position);
        let sealed = self
            .cipher()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: event,
                    aad: &aad,
                },
            )
            .map_err(|_| StoreError::Damaged)?;
        let len = u32::try_from(sealed.len()).map_err(|_| StoreError::Damaged)?;
        Ok([&len.to_be_bytes()[..], &nonce, &sealed].concat())
    }

    /// Segment `n`'s events and the bytes they take. A torn record is
    /// allowed at the end of the newest segment only.
    fn records(&mut self, n: u32) -> Result<(Vec<Vec<u8>>, u64), StoreError> {
        let bytes = match fs::read(self.path(n)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        self.reads += 1;
        let newest = n + 1 == self.segments;
        let mut events = Vec::new();
        let mut at = 0usize;
        while at < bytes.len() {
            let torn = || {
                if newest {
                    Ok(())
                } else {
                    Err(StoreError::Damaged)
                }
            };
            let Some(head) = bytes.get(at..at + 4 + NONCE_LEN) else {
                torn()?;
                break;
            };
            let len = u32::from_be_bytes(head[..4].try_into().expect("4 bytes")) as usize;
            let Some(sealed) = bytes.get(at + 4 + NONCE_LEN..at + 4 + NONCE_LEN + len) else {
                torn()?;
                break;
            };
            if len < TAG_LEN {
                torn()?;
                break;
            }
            let nonce: [u8; NONCE_LEN] = head[4..].try_into().expect("24 bytes");
            let position = u32::try_from(events.len()).map_err(|_| StoreError::Damaged)?;
            let aad = self.aad(n, position);
            let opened = self.cipher().decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: sealed,
                    aad: &aad,
                },
            );
            // In the newest segment, a record that doesn't open is where a
            // crash stopped the file (zeros or junk): the end.
            let Ok(event) = opened else {
                torn()?;
                break;
            };
            events.push(event);
            at += 4 + NONCE_LEN + len;
        }
        if events.len() > SEGMENT_EVENTS {
            return Err(StoreError::Damaged);
        }
        Ok((events, at as u64))
    }

    /// Where the next `count` appended events will be kept: segment and
    /// position.
    pub fn next_places(&self, count: usize) -> Vec<(u32, u32)> {
        let (mut segment, mut used) = match self.segments.checked_sub(1) {
            Some(newest) if self.last.0 < SEGMENT_EVENTS => (newest, self.last.0),
            _ => (self.segments, 0),
        };
        (0..count)
            .map(|_| {
                if used == SEGMENT_EVENTS {
                    (segment, used) = (segment + 1, 0);
                }
                used += 1;
                (segment, used as u32 - 1)
            })
            .collect()
    }

    /// Adds events, starting new segments as they fill, and syncs them to
    /// disk before returning.
    pub fn append(&mut self, events: &[Vec<u8>]) -> Result<(), StoreError> {
        if events.is_empty() {
            return Ok(());
        }
        fs::create_dir_all(&self.dir)?;
        let mut rest = events;
        while !rest.is_empty() {
            if self.segments == 0 || self.last.0 == SEGMENT_EVENTS {
                self.segments += 1;
                self.last = (0, 0);
            }
            let n = self.segments - 1;
            let room = SEGMENT_EVENTS - self.last.0;
            let (now, later) = rest.split_at(room.min(rest.len()));
            let mut out = Vec::new();
            for (i, event) in now.iter().enumerate() {
                let position = u32::try_from(self.last.0 + i).expect("under 512");
                out.extend(self.seal(n, position, event)?);
            }
            let mut file = open_segment(&self.path(n))?;
            // Cuts off a torn record a crash left.
            file.set_len(self.last.1)?;
            std::io::Seek::seek(&mut file, std::io::SeekFrom::End(0))?;
            file.write_all(&out)?;
            file.sync_data()?;
            if self.last.1 == 0 {
                sync_dir(&self.dir)?;
            }
            self.last = (self.last.0 + now.len(), self.last.1 + out.len() as u64);
            rest = later;
        }
        Ok(())
    }

    /// Seals segment `n` again with each event as `keep` returns it (`None`
    /// drops it), and replaces the file atomically.
    pub fn rewrite(
        &mut self,
        n: u32,
        keep: impl FnMut(Vec<u8>) -> Option<Vec<u8>>,
    ) -> Result<(), StoreError> {
        let kept: Vec<Vec<u8>> = self.records(n)?.0.into_iter().filter_map(keep).collect();
        let mut out = Vec::new();
        for (i, event) in kept.iter().enumerate() {
            let position = u32::try_from(i).expect("under 512");
            out.extend(self.seal(n, position, event)?);
        }
        mesh_identity::write_atomically(&self.path(n), &out)?;
        if n + 1 == self.segments {
            self.last = (kept.len(), out.len() as u64);
        }
        Ok(())
    }

    /// The chat's index (its name, members, last activity, unread count, as
    /// the caller encodes them), if written.
    pub fn index(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let bytes = match fs::read(self.dir.join(INDEX)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let (nonce, sealed) = bytes
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(StoreError::Damaged)?;
        let aad = self.aad(u32::MAX, u32::MAX);
        let plain = self
            .cipher()
            .decrypt(
                &XNonce::from(*nonce),
                Payload {
                    msg: sealed,
                    aad: &aad,
                },
            )
            .map_err(|_| StoreError::Damaged)?;
        Ok(Some(plain))
    }

    pub fn write_index(&self, bytes: &[u8]) -> Result<(), StoreError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| std::io::Error::other(e.to_string()))?;
        // The index's own slot: no segment has number u32::MAX.
        let aad = self.aad(u32::MAX, u32::MAX);
        let sealed = self
            .cipher()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: bytes,
                    aad: &aad,
                },
            )
            .map_err(|_| StoreError::Damaged)?;
        mesh_identity::write_atomically(&self.dir.join(INDEX), &[&nonce[..], &sealed].concat())?;
        Ok(())
    }
}

/// A segment file to append to, readable by us alone.
fn open_segment(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// A new file's name is durable only once its directory is synced (Unix).
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [9; 32];
    const CHAT: Conversation = [1; 16];

    fn store(name: &str) -> (Store, PathBuf) {
        let dir = std::env::temp_dir().join(format!("mesh-dm-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        (Store::new(&dir, &KEY), dir)
    }

    fn events(range: std::ops::Range<u32>) -> Vec<Vec<u8>> {
        range.map(|i| format!("event {i}").into_bytes()).collect()
    }

    fn everything(files: &mut ChatFiles) -> Vec<Vec<u8>> {
        let mut all = Vec::new();
        for n in 0..files.segments() {
            all.extend(files.read(n).unwrap());
        }
        all
    }

    fn segment_path(dir: &Path, n: u32) -> PathBuf {
        let chat = fs::read_dir(dir).unwrap().next().unwrap().unwrap().path();
        chat.join(format!("{n:08}.seg"))
    }

    #[test]
    fn append_and_reopen() {
        let (store, dir) = store("reopen");
        let mut files = store.open(&CHAT).unwrap();
        assert_eq!(files.segments(), 0);
        files.append(&events(0..3)).unwrap();
        files.append(&events(3..4)).unwrap();
        let mut again = store.open(&CHAT).unwrap();
        assert_eq!(everything(&mut again), events(0..4));
        // Another chat, and another data key, see nothing of it.
        assert_eq!(store.open(&[2; 16]).unwrap().segments(), 0);
        let other = Store::new(&dir, &[8; 32]);
        assert_eq!(other.open(&CHAT).unwrap().segments(), 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn opening_reads_only_the_newest_segment() {
        let (store, dir) = store("newest");
        let mut files = store.open(&CHAT).unwrap();
        let n = 2 * SEGMENT_EVENTS as u32 + 5;
        files.append(&events(0..n)).unwrap();
        let mut again = store.open(&CHAT).unwrap();
        assert_eq!((again.segments(), again.reads), (3, 1));
        assert_eq!(again.read(2).unwrap(), events(2 * SEGMENT_EVENTS as u32..n));
        assert_eq!(again.read(0).unwrap().len(), SEGMENT_EVENTS);
        // It goes on filling the newest one.
        again.append(&events(n..n + 1)).unwrap();
        assert_eq!(store.open(&CHAT).unwrap().read(2).unwrap().len(), 6);
        let _ = fs::remove_dir_all(dir);
    }

    /// Edit a message, then delete it: neither text is left (D3, D11).
    #[test]
    fn a_rewrite_leaves_neither_the_text_nor_its_edit() {
        let (store, dir) = store("scrub");
        let mut files = store.open(&CHAT).unwrap();
        let mut first = vec![b"secret one".to_vec()];
        first.extend(events(1..SEGMENT_EVENTS as u32));
        files.append(&first).unwrap();
        files
            .append(&[b"secret two".to_vec(), b"later".to_vec()])
            .unwrap();
        assert_eq!(files.segments(), 2, "the edit is in a later segment");
        let gone = |e: Vec<u8>| (!e.starts_with(b"secret")).then_some(e);
        files.rewrite(0, gone).unwrap();
        files.rewrite(1, gone).unwrap();
        let all = everything(&mut store.open(&CHAT).unwrap());
        assert!(all.iter().all(|e| !e.starts_with(b"secret")));
        assert_eq!(all.len(), SEGMENT_EVENTS);
        for n in 0..2 {
            let raw = fs::read(segment_path(&dir, n)).unwrap();
            assert!(!raw.windows(6).any(|w| w == b"secret"));
        }
        // Nothing is left beside the files either.
        let chat = segment_path(&dir, 0).parent().unwrap().to_owned();
        assert_eq!(fs::read_dir(chat).unwrap().count(), 2);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_damaged_or_swapped_file_is_refused() {
        let (store, dir) = store("damaged");
        let mut files = store.open(&CHAT).unwrap();
        // Three segments: the strict checks are for the older ones.
        files
            .append(&events(0..2 * SEGMENT_EVENTS as u32 + 3))
            .unwrap();
        // Segment 0 copied over segment 1: positions and number don't match.
        let (zero, one) = (segment_path(&dir, 0), segment_path(&dir, 1));
        let saved = fs::read(&one).unwrap();
        fs::copy(&zero, &one).unwrap();
        assert!(matches!(
            store.open(&CHAT).and_then(|mut f| f.read(1)),
            Err(StoreError::Damaged)
        ));
        fs::write(&one, saved).unwrap();
        // A flipped byte in the middle.
        let mut bytes = fs::read(&zero).unwrap();
        bytes[100] ^= 1;
        fs::write(&zero, bytes).unwrap();
        assert!(matches!(
            store.open(&CHAT).unwrap().read(0),
            Err(StoreError::Damaged)
        ));
        // Another chat's file moved in.
        let mut other = store.open(&[2; 16]).unwrap();
        other.append(&events(0..3)).unwrap();
        drop(other);
        let mut theirs = None;
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path().join("00000000.seg");
            if path != zero {
                theirs = Some(path);
            }
        }
        fs::copy(theirs.unwrap(), &one).unwrap();
        assert!(matches!(
            store.open(&CHAT).and_then(|mut f| f.read(1)),
            Err(StoreError::Damaged)
        ));
        let _ = fs::remove_dir_all(dir);
    }

    /// What some filesystems leave after a power cut: the file grew, but the
    /// last record's bytes are zeros or junk. The newest segment ends at the
    /// first record that doesn't open, and the next append cuts it off.
    #[test]
    fn a_newest_segment_ending_in_zeros_or_junk_opens() {
        let (store, dir) = store("junk");
        let mut files = store.open(&CHAT).unwrap();
        files.append(&events(0..3)).unwrap();
        let path = segment_path(&dir, 0);
        let good = fs::read(&path).unwrap();
        let record = good.len() / 3;
        // A full-length record of junk: a real record's length, then noise.
        let mut junk_record = good[..4].to_vec();
        junk_record.extend((0..record - 4).map(|i| (i * 7 + 3) as u8));
        for tail in [vec![0u8; 4096], junk_record] {
            fs::write(&path, [&good[..], &tail].concat()).unwrap();
            let mut again = store.open(&CHAT).unwrap();
            assert_eq!(again.read(0).unwrap(), events(0..3));
            again.append(&events(3..4)).unwrap();
            assert_eq!(store.open(&CHAT).unwrap().read(0).unwrap(), events(0..4));
            fs::write(&path, &good).unwrap();
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_crash_mid_append_keeps_what_came_before() {
        let (store, dir) = store("crash");
        let mut files = store.open(&CHAT).unwrap();
        files.append(&events(0..3)).unwrap();
        let path = segment_path(&dir, 0);
        let whole = fs::read(&path).unwrap().len();
        files.append(&events(3..4)).unwrap();
        // The last record torn halfway, as a power cut would leave it.
        let torn = fs::read(&path).unwrap();
        let cut = whole + (torn.len() - whole) / 2;
        fs::write(&path, &torn[..cut]).unwrap();
        let mut again = store.open(&CHAT).unwrap();
        assert_eq!(again.read(0).unwrap(), events(0..3));
        again.append(&events(4..5)).unwrap();
        let mut events_now = events(0..3);
        events_now.extend(events(4..5));
        assert_eq!(store.open(&CHAT).unwrap().read(0).unwrap(), events_now);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn the_index_is_sealed_too() {
        let (store, dir) = store("index");
        let files = store.open(&CHAT).unwrap();
        assert_eq!(files.index().unwrap(), None);
        files.write_index(b"hike chat, 3 unread").unwrap();
        assert_eq!(
            store.open(&CHAT).unwrap().index().unwrap().unwrap(),
            b"hike chat, 3 unread"
        );
        let chat = fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
        let raw = fs::read(chat.join(INDEX)).unwrap();
        assert!(!raw.windows(4).any(|w| w == b"hike"));
        let _ = fs::remove_dir_all(dir);
    }
}
