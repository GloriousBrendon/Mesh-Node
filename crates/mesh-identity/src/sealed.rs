//! A small file of the helper's own, sealed with XChaCha20-Poly1305 under a
//! key derived from the keystore's data key for its `context`, written
//! atomically. Its format number is its first byte, outside the seal, so a
//! newer file is refused unread and left on disk (mailbox *Formats*).
//!
//! ```text
//! file = format u8 | nonce [24] | sealed (contents) + 16 tag
//! ```

use std::path::Path;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

use crate::keystore::write_atomically;

#[derive(Debug, thiserror::Error)]
pub enum SealedError {
    #[error("written by a newer mesh-node")]
    Newer,
    #[error("damaged")]
    Damaged,
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

fn cipher(data_key: &[u8; 32], context: &str) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&Key::from(blake3::derive_key(context, data_key)))
}

/// Writes `contents` sealed to `path`, as `format`.
pub fn write_sealed(
    path: &Path,
    data_key: &[u8; 32],
    context: &str,
    format: u8,
    contents: &[u8],
) -> Result<(), SealedError> {
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| SealedError::Damaged)?;
    let aad = [context.as_bytes(), &[format]].concat();
    let sealed = cipher(data_key, context)
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: contents,
                aad: &aad,
            },
        )
        .map_err(|_| SealedError::Damaged)?;
    let bytes = [&[format][..], &nonce, &sealed].concat();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    Ok(write_atomically(path, &bytes)?)
}

/// The contents of the file at `path` and its format, `None` if there's no
/// file. A format above `newest` is `Newer`, and the file is left as it is.
pub fn read_sealed(
    path: &Path,
    data_key: &[u8; 32],
    context: &str,
    newest: u8,
) -> Result<Option<(u8, Vec<u8>)>, SealedError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let (&format, rest) = bytes.split_first().ok_or(SealedError::Damaged)?;
    if format > newest {
        return Err(SealedError::Newer);
    }
    let (nonce, sealed) = rest.split_first_chunk::<24>().ok_or(SealedError::Damaged)?;
    let aad = [context.as_bytes(), &[format]].concat();
    let contents = cipher(data_key, context)
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: sealed,
                aad: &aad,
            },
        )
        .map_err(|_| SealedError::Damaged)?;
    Ok(Some((format, contents)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_newer_and_damaged() {
        let dir = std::env::temp_dir().join(format!("mesh-sealed-{}", std::process::id()));
        let path = dir.join("file");
        let key = [3; 32];
        assert!(read_sealed(&path, &key, "ctx", 1).unwrap().is_none());
        write_sealed(&path, &key, "ctx", 1, b"hello").unwrap();
        assert_eq!(
            read_sealed(&path, &key, "ctx", 1).unwrap(),
            Some((1, b"hello".to_vec()))
        );
        assert!(matches!(
            read_sealed(&path, &[4; 32], "ctx", 1),
            Err(SealedError::Damaged)
        ));
        assert!(matches!(
            read_sealed(&path, &key, "other", 1),
            Err(SealedError::Damaged)
        ));
        write_sealed(&path, &key, "ctx", 2, b"later").unwrap();
        assert!(matches!(
            read_sealed(&path, &key, "ctx", 1),
            Err(SealedError::Newer)
        ));
        assert!(path.exists(), "a newer file is left on disk");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] = 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(
            matches!(
                read_sealed(&path, &key, "ctx", 1),
                Err(SealedError::Damaged)
            ),
            "the format is sealed in"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
