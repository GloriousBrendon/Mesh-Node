//! File encryption (SPEC-dm D12): a random key per file, XChaCha20-Poly1305
//! in 64 KiB chunks, each bound to its number and the file's size. A reader
//! checks each chunk by its tag as it arrives, then the whole encrypted
//! file's blake3 hash and its size at the end, so a cut-off file or a
//! swapped chunk is refused.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// Plain bytes per chunk (D12).
pub const CHUNK: usize = 64 * 1024;
/// The largest file (D12, Q2): 100 MB.
pub const MAX_FILE: u64 = 100 * 1000 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlobError {
    #[error("the file is bigger than 100 MB")]
    TooBig,
    #[error("a piece of the file is damaged or in the wrong place")]
    BadChunk,
    #[error("the file has more pieces than its size allows")]
    TooLong,
    #[error("the file stopped short")]
    Short,
    #[error("the file isn't the one the message names")]
    WrongHash,
    #[error("couldn't get randomness from the system")]
    Random,
}

/// How many chunks a file of `size` bytes has.
pub fn chunks(size: u64) -> u64 {
    size.div_ceil(CHUNK as u64)
}

/// Encrypts a file chunk by chunk.
pub struct Sealer {
    key: Zeroizing<[u8; 32]>,
    size: u64,
    index: u64,
    hasher: blake3::Hasher,
}

impl Sealer {
    /// A fresh key for a file of `size` bytes.
    pub fn new(size: u64) -> Result<Self, BlobError> {
        if size > MAX_FILE {
            return Err(BlobError::TooBig);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|_| BlobError::Random)?;
        Ok(Self {
            key,
            size,
            index: 0,
            hasher: blake3::Hasher::new(),
        })
    }

    /// The key the message carries.
    pub fn key(&self) -> [u8; 32] {
        *self.key
    }

    /// The next chunk: `CHUNK` bytes, or fewer for the last.
    pub fn chunk(&mut self, plain: &[u8]) -> Result<Vec<u8>, BlobError> {
        if self.index >= chunks(self.size) {
            return Err(BlobError::TooLong);
        }
        if plain.len() != expected(self.size, self.index) {
            return Err(BlobError::BadChunk);
        }
        let aad = aad(self.index, self.size);
        let sealed = cipher(&self.key)
            .encrypt(
                &nonce(self.index),
                Payload {
                    msg: plain,
                    aad: &aad,
                },
            )
            .map_err(|_| BlobError::BadChunk)?;
        self.hasher.update(&sealed);
        self.index += 1;
        Ok(sealed)
    }

    /// The encrypted file's hash, once every chunk is sealed.
    pub fn finish(self) -> Result<[u8; 32], BlobError> {
        if self.index < chunks(self.size) {
            return Err(BlobError::Short);
        }
        Ok(*self.hasher.finalize().as_bytes())
    }
}

/// Decrypts and checks a file chunk by chunk, in order.
pub struct Opener {
    key: Zeroizing<[u8; 32]>,
    size: u64,
    hash: [u8; 32],
    index: u64,
    hasher: blake3::Hasher,
}

impl Opener {
    pub fn new(key: [u8; 32], hash: [u8; 32], size: u64) -> Result<Self, BlobError> {
        if size > MAX_FILE {
            return Err(BlobError::TooBig);
        }
        Ok(Self {
            key: Zeroizing::new(key),
            size,
            hash,
            index: 0,
            hasher: blake3::Hasher::new(),
        })
    }

    /// The next chunk's plain bytes, if its tag checks out.
    pub fn chunk(&mut self, sealed: &[u8]) -> Result<Vec<u8>, BlobError> {
        if self.index >= chunks(self.size) {
            return Err(BlobError::TooLong);
        }
        let aad = aad(self.index, self.size);
        let plain = cipher(&self.key)
            .decrypt(
                &nonce(self.index),
                Payload {
                    msg: sealed,
                    aad: &aad,
                },
            )
            .map_err(|_| BlobError::BadChunk)?;
        if plain.len() != expected(self.size, self.index) {
            return Err(BlobError::BadChunk);
        }
        self.hasher.update(sealed);
        self.index += 1;
        Ok(plain)
    }

    /// Every chunk came and the whole file is the one named.
    pub fn finish(self) -> Result<(), BlobError> {
        if self.index < chunks(self.size) {
            return Err(BlobError::Short);
        }
        // blake3::Hash compares in constant time.
        if self.hasher.finalize() != blake3::Hash::from_bytes(self.hash) {
            return Err(BlobError::WrongHash);
        }
        Ok(())
    }
}

fn parse_hash(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Chunk `index`'s plain length in a file of `size` bytes.
fn expected(size: u64, index: u64) -> usize {
    let start = index * CHUNK as u64;
    (size - start).min(CHUNK as u64) as usize
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&Key::from(*key))
}

/// The chunk's number as its nonce: every file has a fresh key, so no nonce
/// repeats under one key.
fn nonce(index: u64) -> XNonce {
    let mut nonce = [0u8; 24];
    nonce[..8].copy_from_slice(&index.to_be_bytes());
    XNonce::from(nonce)
}

fn aad(index: u64, size: u64) -> [u8; 16] {
    let mut aad = [0u8; 16];
    aad[..8].copy_from_slice(&index.to_be_bytes());
    aad[8..].copy_from_slice(&size.to_be_bytes());
    aad
}

/// The most kept files take on disk, together (D13).
pub const MAX_KEPT: u64 = 10 * 1000 * 1000 * 1000;
/// A sealed chunk's length: the plain chunk and its tag.
const SEALED_CHUNK: u64 = CHUNK as u64 + 16;
const META_FORMAT: u8 = 1;
const NOTE_CONTEXT: &str = "mesh/v1/dm-kept";

/// Which chats hold a kept file, and whether we sent it (D13).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Kept {
    pub ours: bool,
    pub chats: Vec<crate::Where>,
}

/// Files kept sealed on disk, by their hash (D13): ones sent here and ones
/// fetched, so this device can pass them on to others in the chat.
pub struct Blobs {
    dir: std::path::PathBuf,
    /// Seals each file's note, which names its chats.
    seal: zeroize::Zeroizing<[u8; 32]>,
}

fn blob_path(dir: &std::path::Path, hash: &[u8; 32], ext: &str) -> std::path::PathBuf {
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    dir.join(format!("{hex}.{ext}"))
}

/// Sealed chunk `index` of the file kept in `dir`, if there; needs no key.
pub fn read_chunk(
    dir: &std::path::Path,
    hash: &[u8; 32],
    index: u64,
) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::{Read, Seek};
    let mut file = match std::fs::File::open(blob_path(dir, hash, "blob")) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let start = index.saturating_mul(SEALED_CHUNK);
    if start >= file.metadata()?.len() {
        return Ok(None);
    }
    file.seek(std::io::SeekFrom::Start(start))?;
    let mut chunk = Vec::with_capacity(SEALED_CHUNK as usize);
    file.take(SEALED_CHUNK).read_to_end(&mut chunk)?;
    Ok(Some(chunk))
}

impl Blobs {
    pub fn new(dir: &std::path::Path, data_key: &[u8; 32]) -> Self {
        Self {
            dir: dir.to_owned(),
            seal: zeroize::Zeroizing::new(blake3::derive_key(NOTE_CONTEXT, data_key)),
        }
    }

    fn path(&self, hash: &[u8; 32], ext: &str) -> std::path::PathBuf {
        blob_path(&self.dir, hash, ext)
    }

    fn cipher(&self) -> chacha20poly1305::XChaCha20Poly1305 {
        use chacha20poly1305::KeyInit;
        chacha20poly1305::XChaCha20Poly1305::new(&(*self.seal).into())
    }

    /// Seals the file at `source` with a fresh key and keeps it as ours, for
    /// `chat`: its key, the encrypted file's hash and the plain size.
    pub fn add_file(
        &self,
        source: &std::path::Path,
        chat: crate::Where,
    ) -> std::io::Result<([u8; 32], [u8; 32], u64)> {
        use std::io::{Read, Write};
        let size = std::fs::metadata(source)?.len();
        let mut sealer = Sealer::new(size).map_err(std::io::Error::other)?;
        std::fs::create_dir_all(&self.dir)?;
        let tmp = self.dir.join(format!("sending-{}.tmp", std::process::id()));
        let mut out = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        let mut input = std::io::BufReader::new(std::fs::File::open(source)?);
        let mut buffer = vec![0u8; CHUNK];
        for index in 0..chunks(size) {
            let len = expected(size, index);
            input.read_exact(&mut buffer[..len])?;
            out.write_all(
                &sealer
                    .chunk(&buffer[..len])
                    .map_err(std::io::Error::other)?,
            )?;
        }
        let key = sealer.key();
        let hash = sealer.finish().map_err(std::io::Error::other)?;
        out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        std::fs::rename(&tmp, self.path(&hash, "blob"))?;
        self.write_kept(&hash, true, chat)?;
        Ok((key, hash, size))
    }

    fn write_kept(&self, hash: &[u8; 32], ours: bool, chat: crate::Where) -> std::io::Result<()> {
        let mut kept = self.kept(hash)?.unwrap_or_default();
        kept.ours |= ours;
        if !kept.chats.contains(&chat) {
            kept.chats.push(chat);
        }
        let mut plain = vec![META_FORMAT];
        plain.extend(postcard::to_stdvec(&kept).expect("to memory"));
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|e| std::io::Error::other(e.to_string()))?;
        // Bound to its file, so a note can't be moved to another.
        let payload = chacha20poly1305::aead::Payload {
            msg: &plain,
            aad: hash,
        };
        let sealed = chacha20poly1305::aead::Aead::encrypt(&self.cipher(), &nonce.into(), payload)
            .map_err(|_| std::io::Error::other("couldn't seal a kept file's note"))?;
        mesh_identity::write_atomically(&self.path(hash, "kept"), &[&nonce[..], &sealed].concat())
    }

    /// Keeps a file fetched from someone, chunk by chunk as they came, once
    /// the caller has checked it whole (`Opener::finish`).
    pub fn add_fetched(
        &self,
        hash: &[u8; 32],
        chunks: &[Vec<u8>],
        chat: crate::Where,
    ) -> std::io::Result<()> {
        mesh_identity::write_atomically(&self.path(hash, "blob"), &chunks.concat())?;
        self.write_kept(hash, false, chat)
    }

    pub fn has(&self, hash: &[u8; 32]) -> bool {
        self.path(hash, "blob").exists()
    }

    /// Sealed chunk `index` of a kept file.
    pub fn chunk(&self, hash: &[u8; 32], index: u64) -> std::io::Result<Option<Vec<u8>>> {
        read_chunk(&self.dir, hash, index)
    }

    /// Which chats hold a kept file, and whether it's ours.
    pub fn kept(&self, hash: &[u8; 32]) -> std::io::Result<Option<Kept>> {
        let bytes = match std::fs::read(self.path(hash, "kept")) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let damaged = || std::io::Error::other("a kept file's note is damaged");
        let (nonce, sealed) = bytes.split_first_chunk::<24>().ok_or_else(damaged)?;
        let payload = chacha20poly1305::aead::Payload {
            msg: sealed,
            aad: hash,
        };
        let plain = chacha20poly1305::aead::Aead::decrypt(&self.cipher(), nonce.into(), payload)
            .map_err(|_| damaged())?;
        match plain.split_first() {
            Some((&META_FORMAT, rest)) => postcard::from_bytes(rest)
                .map(Some)
                .map_err(|_| std::io::Error::other("a kept file's note is damaged")),
            _ => Err(std::io::Error::other(
                "a kept file's note is from a newer Mesh or damaged",
            )),
        }
    }

    /// Marks a kept file as just opened, so it's dropped last of its kind.
    pub fn opened(&self, hash: &[u8; 32]) -> std::io::Result<()> {
        let file = std::fs::File::options()
            .write(true)
            .open(self.path(hash, "blob"))?;
        file.set_modified(std::time::SystemTime::now())
    }

    /// Drops a kept file (its message was deleted, D3).
    pub fn remove(&self, hash: &[u8; 32]) -> std::io::Result<()> {
        for ext in ["blob", "kept"] {
            match std::fs::remove_file(self.path(hash, ext)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        Ok(())
    }

    /// Drops kept files, oldest-opened first and ours last, until they take
    /// at most `cap` bytes together.
    pub fn evict(&self, cap: u64) -> std::io::Result<()> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let mut kept = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(hex) = name.to_str().and_then(|n| n.strip_suffix(".blob")) else {
                continue;
            };
            let Some(hash) = parse_hash(hex) else {
                continue;
            };
            let meta = entry.metadata()?;
            let ours = self.kept(&hash).ok().flatten().is_some_and(|k| k.ours);
            kept.push((ours, meta.modified()?, meta.len(), hash));
        }
        let mut total: u64 = kept.iter().map(|k| k.2).sum();
        kept.sort_by_key(|k| (k.0, k.1));
        for (_, _, len, hash) in kept {
            if total <= cap {
                break;
            }
            self.remove(&hash)?;
            total -= len;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 251) as u8).collect()
    }

    fn seal(plain: &[u8]) -> ([u8; 32], [u8; 32], Vec<Vec<u8>>) {
        let mut sealer = Sealer::new(plain.len() as u64).unwrap();
        let key = sealer.key();
        let sealed: Vec<Vec<u8>> = plain
            .chunks(CHUNK)
            .map(|c| sealer.chunk(c).unwrap())
            .collect();
        (key, sealer.finish().unwrap(), sealed)
    }

    fn open(
        key: [u8; 32],
        hash: [u8; 32],
        size: usize,
        sealed: &[Vec<u8>],
    ) -> Result<Vec<u8>, BlobError> {
        let mut opener = Opener::new(key, hash, size as u64)?;
        let mut plain = Vec::new();
        for c in sealed {
            plain.extend(opener.chunk(c)?);
        }
        opener.finish()?;
        Ok(plain)
    }

    #[test]
    fn round_trip() {
        for size in [0, 5, CHUNK, 2 * CHUNK + 5] {
            let plain = file(size);
            let (key, hash, sealed) = seal(&plain);
            assert_eq!(sealed.len() as u64, chunks(size as u64));
            assert_eq!(open(key, hash, size, &sealed).unwrap(), plain);
        }
    }

    #[test]
    fn a_bad_chunk_is_refused_as_it_arrives() {
        let plain = file(2 * CHUNK + 5);
        let (key, hash, mut sealed) = seal(&plain);
        sealed[1][10] ^= 1;
        let mut opener = Opener::new(key, hash, plain.len() as u64).unwrap();
        assert!(opener.chunk(&sealed[0]).is_ok());
        assert_eq!(opener.chunk(&sealed[1]), Err(BlobError::BadChunk));
        // Swapped chunks fail too: each is bound to its number.
        let (key, hash, mut sealed) = seal(&plain);
        sealed.swap(0, 1);
        assert_eq!(
            open(key, hash, plain.len(), &sealed),
            Err(BlobError::BadChunk)
        );
    }

    #[test]
    fn short_long_or_another_file_is_refused() {
        let plain = file(2 * CHUNK + 5);
        let (key, hash, sealed) = seal(&plain);
        assert_eq!(
            open(key, hash, plain.len(), &sealed[..2]),
            Err(BlobError::Short)
        );
        let mut extra = sealed.clone();
        extra.push(sealed[2].clone());
        assert_eq!(
            open(key, hash, plain.len(), &extra),
            Err(BlobError::TooLong)
        );
        assert_eq!(
            open(key, [0; 32], plain.len(), &sealed),
            Err(BlobError::WrongHash)
        );
        // A size that doesn't match is a different binding: the tags fail.
        assert_eq!(
            open(key, hash, plain.len() + 1, &sealed),
            Err(BlobError::BadChunk)
        );
        assert_eq!(
            open([1; 32], hash, plain.len(), &sealed),
            Err(BlobError::BadChunk),
            "the wrong key"
        );
        assert_eq!(Sealer::new(MAX_FILE + 1).err(), Some(BlobError::TooBig));
    }

    fn blobs(name: &str) -> (Blobs, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("mesh-blobs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (Blobs::new(&dir, &[3; 32]), dir)
    }

    /// The note of which chats hold a file is sealed: a 1:1's friend isn't
    /// named on disk, and another data key can't read it.
    #[test]
    fn the_kept_note_names_no_friend() {
        let (b, dir) = blobs("note");
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("photo.jpg");
        std::fs::write(&source, file(10)).unwrap();
        let (_, hash, _) = b.add_file(&source, CHAT).unwrap();
        let (_, other, sealed) = seal(&file(20));
        b.add_fetched(&other, &sealed, CHAT).unwrap();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes.windows(32).any(|w| w == [7; 32]), "names the friend");
        }
        assert_eq!(b.kept(&hash).unwrap().unwrap().chats, vec![CHAT]);
        assert!(
            Blobs::new(&dir, &[4; 32]).kept(&hash).is_err(),
            "another key"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    const CHAT: crate::Where = crate::Where::Direct([7; 32]);

    #[test]
    fn a_sent_file_is_kept_and_served_by_chunk() {
        let (b, dir) = blobs("sent");
        std::fs::create_dir_all(&dir).unwrap();
        let plain = file(2 * CHUNK + 5);
        let source = dir.join("photo.jpg");
        std::fs::write(&source, &plain).unwrap();
        let (key, hash, size) = b.add_file(&source, CHAT).unwrap();
        assert!(b.has(&hash) && size == plain.len() as u64);
        let mut opener = Opener::new(key, hash, size).unwrap();
        let mut back = Vec::new();
        for i in 0..chunks(size) {
            back.extend(opener.chunk(&b.chunk(&hash, i).unwrap().unwrap()).unwrap());
        }
        opener.finish().unwrap();
        assert_eq!(back, plain);
        assert_eq!(b.chunk(&hash, chunks(size)).unwrap(), None, "past the end");
        assert_eq!(
            b.kept(&hash).unwrap(),
            Some(Kept {
                ours: true,
                chats: vec![CHAT]
            })
        );
        // Nothing of the plain file is kept.
        let raw = std::fs::read(b.path(&hash, "blob")).unwrap();
        assert!(!raw.windows(32).any(|w| plain.windows(32).next() == Some(w)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_fetched_file_is_kept_and_a_delete_drops_it() {
        let (b, dir) = blobs("fetched");
        let plain = file(CHUNK + 1);
        let (_, hash, sealed) = seal(&plain);
        b.add_fetched(&hash, &sealed, CHAT).unwrap();
        assert_eq!(b.chunk(&hash, 1).unwrap(), Some(sealed[1].clone()));
        assert!(!b.kept(&hash).unwrap().unwrap().ours);
        b.remove(&hash).unwrap();
        assert!(!b.has(&hash) && b.kept(&hash).unwrap().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Past the cap, the oldest-opened go first, and files we sent last.
    #[test]
    fn eviction_keeps_ours_and_the_recently_opened() {
        let (b, dir) = blobs("evict");
        let mut hashes = Vec::new();
        for i in 0..3u8 {
            let (_, hash, sealed) = seal(&vec![i; 1000]);
            b.add_fetched(&hash, &sealed, CHAT).unwrap();
            hashes.push(hash);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("mine");
        std::fs::write(&source, vec![9; 1000]).unwrap();
        let (_, mine, _) = b.add_file(&source, CHAT).unwrap();
        b.opened(&hashes[0]).unwrap();
        // Room for two: the oldest-opened of the others go, ours stays.
        b.evict(2 * 1016).unwrap();
        assert!(b.has(&mine) && b.has(&hashes[0]));
        assert!(!b.has(&hashes[1]) && !b.has(&hashes[2]));
        let _ = std::fs::remove_dir_all(dir);
    }
}
