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
}
