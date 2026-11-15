//! An append-only log on the seed's disk (seed D9 as changed by mailbox):
//! one per mail store (claims, records, envelopes). Storing appends a
//! record; nothing is rewritten for it. The log is compacted (written anew
//! with only what's live, synced, renamed, the folder synced) at start and
//! when its dead bytes pass its live ones.
//!
//! ```text
//! log    = "MLOG" | format u8 | record*
//! record = len u32 | payload [len]
//! ```
//!
//! A record cut short at the end (a crash mid-append) is dropped and the
//! file trimmed to the last whole one. A newer format stops the seed; a
//! payload its store can't read means the file is damaged.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"MLOG";
/// The logs' format (mailbox *Formats*).
pub const FORMAT: u8 = 1;
const HEADER: u64 = MAGIC.len() as u64 + 1;
/// The longest record: the largest envelope and its store's few bytes.
const MAX_RECORD: u32 = 2 * 1024 * 1024;
/// Dead bytes under this never start a compaction.
const COMPACT_MIN: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("{0} was written by a newer mesh-node")]
    Newer(PathBuf),
    #[error("{0} is damaged")]
    Damaged(PathBuf),
    #[error("{0}: {1}")]
    Io(PathBuf, std::io::Error),
}

pub struct Log {
    path: PathBuf,
    file: File,
    /// Where the next record goes.
    end: u64,
    /// Bytes of records still live, as the store counts them.
    pub live: u64,
}

/// Where a payload sits in the log: its offset and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct At {
    pub offset: u64,
    pub len: u32,
}

impl Log {
    /// Opens the log at `path` (made empty if missing), handing each record
    /// to `each` with where it sits; `each` says false for one it can't read.
    pub fn open(path: &Path, mut each: impl FnMut(At, &[u8]) -> bool) -> Result<Log, LogError> {
        let io = |e| LogError::Io(path.to_owned(), e);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(io)?;
        let size = file.metadata().map_err(io)?.len();
        if size == 0 {
            file.write_all(MAGIC).map_err(io)?;
            file.write_all(&[FORMAT]).map_err(io)?;
            file.sync_all().map_err(io)?;
            return Ok(Log {
                path: path.to_owned(),
                file,
                end: HEADER,
                live: 0,
            });
        }
        let mut reader = BufReader::new(&file);
        let mut head = [0u8; HEADER as usize];
        if reader.read_exact(&mut head).is_err() || &head[..4] != MAGIC {
            return Err(LogError::Damaged(path.to_owned()));
        }
        if head[4] > FORMAT {
            return Err(LogError::Newer(path.to_owned()));
        }
        if head[4] != FORMAT {
            return Err(LogError::Damaged(path.to_owned()));
        }
        let mut at = HEADER;
        let mut payload = Vec::new();
        loop {
            let mut len = [0u8; 4];
            if at + 4 > size || reader.read_exact(&mut len).is_err() {
                break;
            }
            let len = u32::from_be_bytes(len);
            if len > MAX_RECORD {
                return Err(LogError::Damaged(path.to_owned()));
            }
            if at + 4 + u64::from(len) > size {
                break;
            }
            payload.resize(len as usize, 0);
            reader.read_exact(&mut payload).map_err(io)?;
            if !each(
                At {
                    offset: at + 4,
                    len,
                },
                &payload,
            ) {
                return Err(LogError::Damaged(path.to_owned()));
            }
            at += 4 + u64::from(len);
        }
        drop(reader);
        if at < size {
            // A record cut short by a crash: everything before it stands.
            file.set_len(at).map_err(io)?;
            file.sync_all().map_err(io)?;
        }
        Ok(Log {
            path: path.to_owned(),
            file,
            end: at,
            live: 0,
        })
    }

    /// Appends one record; `sync` waits for the disk.
    pub fn append(&mut self, payload: &[u8], sync: bool) -> std::io::Result<At> {
        let len = u32::try_from(payload.len())
            .ok()
            .filter(|l| *l <= MAX_RECORD)
            .ok_or_else(|| std::io::Error::other("record too long"))?;
        self.file.seek(SeekFrom::Start(self.end))?;
        let mut record = Vec::with_capacity(4 + payload.len());
        record.extend_from_slice(&len.to_be_bytes());
        record.extend_from_slice(payload);
        self.file.write_all(&record)?;
        if sync {
            self.file.sync_data()?;
        }
        let at = At {
            offset: self.end + 4,
            len,
        };
        self.end += record.len() as u64;
        Ok(at)
    }

    /// The payload at `at`.
    pub fn read(&mut self, at: At) -> std::io::Result<Vec<u8>> {
        let mut out = vec![0u8; at.len as usize];
        self.file.seek(SeekFrom::Start(at.offset))?;
        self.file.read_exact(&mut out)?;
        Ok(out)
    }

    /// Bytes the log holds that nothing live uses.
    pub fn dead(&self) -> u64 {
        self.end.saturating_sub(HEADER + self.live)
    }

    /// Whether it's time to compact.
    pub fn wants_compacting(&self) -> bool {
        self.dead() > self.live && self.dead() > COMPACT_MIN
    }

    /// Writes the log anew with only `keep`, in that order, each either
    /// bytes to write or a payload already in the log; the new places of
    /// each, in the same order.
    pub fn compact(&mut self, keep: &[Keep]) -> std::io::Result<Vec<At>> {
        let mut tmp = self.path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let mut places = Vec::with_capacity(keep.len());
        {
            let mut out = BufWriter::new(File::create(&tmp)?);
            out.write_all(MAGIC)?;
            out.write_all(&[FORMAT])?;
            let mut at = HEADER;
            for k in keep {
                let payload = match k {
                    Keep::Bytes(b) => b.clone(),
                    Keep::At(old) => self.read(*old)?,
                };
                out.write_all(&(payload.len() as u32).to_be_bytes())?;
                out.write_all(&payload)?;
                places.push(At {
                    offset: at + 4,
                    len: payload.len() as u32,
                });
                at += 4 + payload.len() as u64;
            }
            out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        if let Some(dir) = self.path.parent() {
            #[cfg(unix)]
            File::open(dir)?.sync_all()?;
            #[cfg(not(unix))]
            let _ = dir;
        }
        self.file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        self.end = places
            .last()
            .map_or(HEADER, |p| p.offset + u64::from(p.len));
        Ok(places)
    }
}

/// What a compaction keeps: new bytes, or a payload where it is.
pub enum Keep {
    Bytes(Vec<u8>),
    At(At),
}

/// Moves a damaged log aside (`.damaged`), so the seed can start without it.
pub fn move_aside(path: &Path) -> std::io::Result<()> {
    let mut aside = path.as_os_str().to_owned();
    aside.push(".damaged");
    std::fs::rename(path, aside)
}

#[cfg(test)]
pub(crate) fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mesh-maillog-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = FOLDERS.try_with(|f| f.failed.set(true));
            default(info)
        }));
    });
    FOLDERS.with(|f| f.made.borrow_mut().push(dir.clone()));
    dir
}

#[cfg(test)]
thread_local! {
    static FOLDERS: Folders = Folders::default();
}

/// The folders this test thread made: removed as it ends, if it passed.
#[cfg(test)]
#[derive(Default)]
struct Folders {
    made: std::cell::RefCell<Vec<PathBuf>>,
    failed: std::cell::Cell<bool>,
}

#[cfg(test)]
impl Drop for Folders {
    fn drop(&mut self) {
        if !self.failed.get() {
            for dir in self.made.take() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn tests_contain(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test that passes leaves no folder behind (the mail store's grow to
    /// 54 MB); one that fails keeps its own.
    #[test]
    fn a_passing_test_leaves_no_folder() {
        let made = |name: &'static str, fails: bool| {
            std::thread::spawn(move || {
                let dir = temp(name);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("log"), b"x").unwrap();
                assert!(!fails, "a failing test");
                dir
            })
            .join()
        };
        let passed = made("folder-pass", false).unwrap();
        assert!(!passed.exists(), "{passed:?} is still there");
        assert!(made("folder-fail", true).is_err());
        let failed =
            std::env::temp_dir().join(format!("mesh-maillog-{}-folder-fail", std::process::id()));
        assert!(failed.exists(), "a failed test's folder is kept");
        std::fs::remove_dir_all(failed).unwrap();
    }

    fn all(path: &Path) -> Result<Vec<Vec<u8>>, LogError> {
        let mut got = Vec::new();
        Log::open(path, |_, p| {
            got.push(p.to_vec());
            true
        })?;
        Ok(got)
    }

    #[test]
    fn appends_survive_a_reopen_and_a_torn_tail() {
        let path = temp("torn").join("log");
        let mut log = Log::open(&path, |_, _| true).unwrap();
        let one = log.append(b"one", true).unwrap();
        log.append(b"two", false).unwrap();
        assert_eq!(log.read(one).unwrap(), b"one");
        drop(log);
        assert_eq!(all(&path).unwrap(), [b"one".to_vec(), b"two".to_vec()]);
        // A crash mid-append: a length with half its payload.
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[0, 0, 0, 9, b'x']).unwrap();
        drop(file);
        assert_eq!(all(&path).unwrap().len(), 2, "everything before it stands");
        let mut log = Log::open(&path, |_, _| true).unwrap();
        log.append(b"three", true).unwrap();
        drop(log);
        assert_eq!(all(&path).unwrap().len(), 3, "trimmed, then appended after");
    }

    #[test]
    fn newer_and_damaged() {
        let dir = temp("formats");
        std::fs::create_dir_all(&dir).unwrap();
        let newer = dir.join("newer");
        std::fs::write(&newer, [b'M', b'L', b'O', b'G', FORMAT + 1]).unwrap();
        assert!(matches!(all(&newer), Err(LogError::Newer(_))));
        let junk = dir.join("junk");
        std::fs::write(&junk, b"not a log at all").unwrap();
        assert!(matches!(all(&junk), Err(LogError::Damaged(_))));
        // A record its store can't read.
        let bad = dir.join("bad");
        Log::open(&bad, |_, _| true)
            .unwrap()
            .append(b"?", true)
            .unwrap();
        assert!(matches!(
            Log::open(&bad, |_, _| false),
            Err(LogError::Damaged(_))
        ));
        move_aside(&junk).unwrap();
        assert!(dir.join("junk.damaged").exists() && !junk.exists());
    }

    #[test]
    fn compaction_keeps_what_its_told() {
        let path = temp("compact").join("log");
        let mut log = Log::open(&path, |_, _| true).unwrap();
        let a = log.append(b"a", true).unwrap();
        log.append(b"gone", true).unwrap();
        let places = log
            .compact(&[Keep::At(a), Keep::Bytes(b"new".to_vec())])
            .unwrap();
        assert_eq!(log.read(places[0]).unwrap(), b"a");
        assert_eq!(log.read(places[1]).unwrap(), b"new");
        log.append(b"after", true).unwrap();
        drop(log);
        assert_eq!(
            all(&path).unwrap(),
            [b"a".to_vec(), b"new".to_vec(), b"after".to_vec()]
        );
    }
}
