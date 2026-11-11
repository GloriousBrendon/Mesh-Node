//! The seed stores' files (codes, address records, requests): a format byte,
//! then the entries, in postcard. Written atomically. A damaged file is an
//! error, never silently replaced.

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The format the stores without their own use.
pub const FORMAT_V1: u8 = 1;

#[derive(Serialize, Deserialize)]
struct File<T> {
    format: u8,
    entries: Vec<T>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("the {0} store {1} is damaged; move it aside to start empty")]
    Corrupt(&'static str, PathBuf),
    #[error("couldn't save the {0} store: {1}")]
    Write(&'static str, std::io::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The entries saved at `path`, none if there's no file. `valid` checks
/// each one: a file that fails it is damaged.
pub fn load<T: DeserializeOwned>(
    path: &Path,
    what: &'static str,
    format: u8,
    valid: impl Fn(&T) -> bool,
) -> Result<Vec<T>, StoreError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let corrupt = || StoreError::Corrupt(what, path.to_owned());
    let file: File<T> = postcard::from_bytes(&bytes).map_err(|_| corrupt())?;
    if file.format != format || !file.entries.iter().all(valid) {
        return Err(corrupt());
    }
    Ok(file.entries)
}

/// The file's bytes for `entries` (references serialise as the values do).
pub fn encode<T: Serialize>(format: u8, entries: Vec<T>) -> Vec<u8> {
    let file = File { format, entries };
    postcard::to_stdvec(&file).expect("serialising to memory")
}

/// The format byte of the file at `path`, none if there's no file or it's
/// empty (postcard writes a `u8` as itself, first).
pub fn format(path: &Path) -> Result<Option<u8>, StoreError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes.first().copied()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// A store's file as it was when taken, to write without holding the store.
pub struct Snapshot {
    pub path: PathBuf,
    pub what: &'static str,
    pub bytes: Vec<u8>,
}

impl Snapshot {
    /// Writes it so that a crash leaves the old file or the new one.
    pub fn write(&self) -> Result<(), StoreError> {
        mesh_identity::write_atomically(&self.path, &self.bytes)
            .map_err(|e| StoreError::Write(self.what, e))
    }
}
