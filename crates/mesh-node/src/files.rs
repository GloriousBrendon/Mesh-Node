//! Files in dm (SPEC-dm D12, D13). A sent file is sealed into this
//! device's kept files with a fresh key, and the message carries the key,
//! the encrypted file's hash, its size, name and type. A reader fetches it
//! on the `blob` service, chunk by chunk, from any connected device in the
//! chat that has it, checking each chunk by its tag and the whole by its
//! hash and size; it then keeps it too, so it can pass it on. A device
//! answers only people in a chat that holds that file, at most
//! `MAX_BLOB_STREAMS` streams at once per device. A child of `helper`.

use super::*;
use mesh_dm::Where;
use mesh_dm::blob::{BlobError, Blobs, MAX_KEPT, Opener, chunks, read_chunk};
use mesh_dm::event::{Attachment, Body, EventId, MAX_PREVIEW};

/// The transport service files move on.
pub(super) const BLOB: &str = "blob";
/// Streams one device may have open on `blob` at once (D12).
pub(super) const MAX_BLOB_STREAMS: usize = 8;
/// How long a device has to answer one chunk.
const CHUNK_WAIT: Duration = Duration::from_secs(20);

/// A file that came (its chunks, sealed and checked) or didn't, and what it
/// was for: the chat, the message and attachment, and the attachment.
pub(super) type Fetched = (Where, String, usize, Attachment, Option<Vec<Vec<u8>>>);

/// A file's type from its name: the common ones, else bytes.
pub(super) fn mime_of(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        Some("mp4") => "video/mp4",
        Some("mp3") => "audio/mpeg",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
}

/// A chunk request: the file's hash and the chunk's number.
fn request(hash: &[u8; 32], index: u64) -> Vec<u8> {
    [&hash[..], &index.to_be_bytes()].concat()
}

/// Asks one device for every chunk of `file`, checking each as it comes and
/// the whole at the end. `None` if it hasn't the file or anything is wrong.
/// The files a message carries, by hash.
fn files_in(body: &Body) -> Vec<[u8; 32]> {
    match body {
        Body::Text { attachments, .. } => attachments.iter().map(|a| a.hash).collect(),
        _ => Vec::new(),
    }
}

// ponytail: a file's sealed chunks gather in memory, up to 100 MB (MAX_FILE) per fetch at once; write them to a temp file as they come if that's too much.
pub(super) async fn fetch_from(
    node: &crate::nodes::Nodes,
    addr: &MeshAddr,
    file: &Attachment,
) -> Option<Vec<Vec<u8>>> {
    let (_, mut send, mut recv) = node.open(addr, BLOB).await.ok()?;
    let mut opener = Opener::new(file.key, file.hash, file.size).ok()?;
    let mut sealed = Vec::new();
    for index in 0..chunks(file.size) {
        mesh_transport::frame::write_frame(&mut send, &request(&file.hash, index))
            .await
            .ok()?;
        let read = mesh_transport::frame::read_frame(&mut recv);
        let chunk = tokio::time::timeout(CHUNK_WAIT, read).await.ok()?.ok()??;
        opener.chunk(&chunk).ok()?;
        sealed.push(chunk);
    }
    let _ = send.finish();
    opener.finish().ok()?;
    Some(sealed)
}

/// Answers a `blob` stream: once the helper says the asker may have that
/// file, each chunk asked for (an empty frame for one past the end).
pub(super) async fn serve_blob(
    mut stream: mesh_transport::ServiceStream,
    dir: PathBuf,
    back: tokio::sync::mpsc::UnboundedSender<Back>,
    open: Arc<std::sync::Mutex<HashMap<[u8; 32], usize>>>,
) {
    let device = *stream.peer.device.as_bytes();
    {
        let mut open = open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = open.entry(device).or_default();
        if *count >= MAX_BLOB_STREAMS {
            let _ = stream.send.reset(0u32.into());
            return;
        }
        *count += 1;
    }
    let mut allowed: Option<[u8; 32]> = None;
    loop {
        let read = mesh_transport::frame::read_frame(&mut stream.recv);
        let Ok(Ok(Some(asked))) = tokio::time::timeout(CHUNK_WAIT, read).await else {
            break;
        };
        let Ok((hash, index)) = <[u8; 40]>::try_from(&asked[..]).map(|a| {
            let (hash, index) = a.split_at(32);
            let hash: [u8; 32] = hash.try_into().expect("32 bytes");
            (hash, u64::from_be_bytes(index.try_into().expect("8 bytes")))
        }) else {
            break;
        };
        if allowed != Some(hash) {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let _ = back.send(Back::BlobAsk(Box::new((stream.peer.id, hash, tx))));
            if rx.await != Ok(true) {
                break;
            }
            allowed = Some(hash);
        }
        let chunk = (read_chunk(&dir, &hash, index).ok().flatten()).unwrap_or_default();
        if mesh_transport::frame::write_frame(&mut stream.send, &chunk)
            .await
            .is_err()
        {
            break;
        }
    }
    let _ = stream.send.finish();
    let mut open = open
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(count) = open.get_mut(&device) {
        *count = count.saturating_sub(1);
    }
}

impl Helper {
    pub(super) fn blobs_dir(&self) -> PathBuf {
        self.path.parent().unwrap_or(Path::new(".")).join("blobs")
    }

    /// The kept files; their notes are sealed with the data key, so only
    /// while unlocked.
    pub(super) fn blobs(&self) -> Result<Blobs, Fail> {
        let store = (self.store.as_ref()).ok_or_else(|| Fail("locked", "locked".to_owned()))?;
        Ok(Blobs::new(&self.blobs_dir(), store.data_key()))
    }

    /// Whether `id` may fetch the kept file `hash`: they're in a chat that
    /// holds it (one of ours, a 1:1 with them, a group they're in).
    pub(super) fn may_fetch(&self, id: &MeshId, hash: &[u8; 32]) -> bool {
        let me = self.store.as_ref().map(Keystore::id);
        let Ok(Ok(Some(kept))) = self.blobs().map(|b| b.kept(hash)) else {
            return false;
        };
        kept.chats.iter().any(|at| {
            Some(*id) == me
                || match at {
                    Where::Direct(p) => *p == id.to_bytes(),
                    // A group's members, or a Space's: its files are kept
                    // under the Space's ID (Task 11b).
                    Where::Group(g) => {
                        (self.dm.as_ref())
                            .and_then(|h| h.members(at))
                            .is_some_and(|m| m.contains(&id.to_bytes()))
                            || (self.space_version(g))
                                .is_some_and(|v| v.state.members.contains_key(&id.to_bytes()))
                    }
                }
        })
    }

    /// The files whose messages these delete takes, to drop with them (D13).
    pub(super) fn files_of_deleted(
        &mut self,
        events: &[mesh_dm::event::Event],
    ) -> Vec<Option<(EventId, Vec<[u8; 32]>)>> {
        let Some(history) = &mut self.dm else {
            return vec![None; events.len()];
        };
        (events.iter())
            .map(|e| match &e.body {
                Body::Delete { target, .. } => {
                    (history.event(target).ok().flatten()).map(|e| (*target, files_in(&e.body)))
                }
                _ => None,
            })
            .collect()
    }

    /// Drops a deleted message's kept files and any copy opened from them.
    pub(super) fn drop_file(&self, (message, hashes): &(EventId, Vec<[u8; 32]>)) {
        for hash in hashes {
            if let Ok(Err(e)) = self.blobs().map(|b| b.remove(hash)) {
                eprintln!("mesh-node: couldn't drop a kept file: {e}");
            }
        }
        let prefix = format!("{}-", e2ee::hex(message));
        self.clear_opened(|name| name.starts_with(&prefix));
    }

    pub(super) fn opened_dir(&self) -> PathBuf {
        self.path.parent().unwrap_or(Path::new(".")).join("files")
    }

    /// Removes the opened copies `which` names (by folder), the only
    /// plaintext outside the sealed store; all of them at unlock and lock.
    pub(super) fn clear_opened(&self, which: impl Fn(&str) -> bool) {
        let entries = std::fs::read_dir(self.opened_dir()).into_iter().flatten();
        let failed = (entries.flatten())
            .filter(|e| which(&e.file_name().to_string_lossy()))
            .filter(|e| std::fs::remove_dir_all(e.path()).is_err())
            .count();
        if failed > 0 {
            eprintln!("mesh-node: couldn't remove {failed} opened files");
        }
    }

    /// `dmSendFile(chat, path, preview?)` and `dmFetch(chat, message, index)`.
    pub(super) fn files_command(&mut self, func: &str, args: &[String]) -> Result<(), Fail> {
        let arg = |i: usize| {
            args.get(i)
                .map(String::as_str)
                .ok_or_else(|| Fail("bad-args", format!("{func} is missing argument {}", i + 1)))
        };
        let at = self.dm_chat(arg(0)?)?;
        let blobs = self.blobs()?;
        match func {
            "dmSendFile" => {
                let attachment = self.keep_attachment(arg(1)?, args.get(2), at)?;
                let body = Body::Text {
                    text: String::new(),
                    reply_to: None,
                    attachments: vec![attachment],
                };
                self.dm_open = Some(at);
                self.dm_send_body(&at, body)
            }
            "dmFetch" => {
                let message = arg(1)?.to_owned();
                let index: usize = arg(2)?
                    .parse()
                    .map_err(|_| Fail("bad-args", "that isn't an attachment".to_owned()))?;
                let event_id = e2ee::parse_conversation(&message)
                    .ok_or_else(|| Fail("bad-args", "that isn't a message ID".to_owned()))?;
                let history = self
                    .dm
                    .as_mut()
                    .ok_or_else(|| Fail("unavailable", "no history".to_owned()))?;
                let event = history.event(&event_id).ok().flatten();
                let Some(mesh_dm::event::Event {
                    body: Body::Text { attachments, .. },
                    ..
                }) = event
                else {
                    return Err(Fail("not-found", "no such message".to_owned()));
                };
                let file = (attachments.get(index).cloned())
                    .ok_or_else(|| Fail("not-found", "no such attachment".to_owned()))?;
                if blobs.has(&file.hash) {
                    return self.open_file(&at, &message, index, &file);
                }
                // From any connected device in the chat (ours too).
                let people = self.dm_recipients(&at);
                self.fetch_attachment(at, message, index, file, people)
            }
            _ => Err(Fail("unknown-fn", format!("unknown command {func}"))),
        }
    }

    /// Keeps the file at `source` for `at` and makes its attachment, with
    /// the preview Mesh-Voice made at `preview` if it fits (D12).
    pub(super) fn keep_attachment(
        &self,
        source: &str,
        preview: Option<&String>,
        at: Where,
    ) -> Result<Attachment, Fail> {
        let blobs = self.blobs()?;
        let source = Path::new(source);
        let name = (source.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (key, hash, size) = blobs.add_file(source, at).map_err(|e| {
            let too_big = e.get_ref().and_then(|e| e.downcast_ref::<BlobError>());
            let kind = if too_big == Some(&BlobError::TooBig) {
                "too-long"
            } else {
                "io"
            };
            Fail(kind, format!("couldn't keep that file: {e}"))
        })?;
        if let Err(e) = blobs.evict(MAX_KEPT) {
            eprintln!("mesh-node: couldn't make room for kept files: {e}");
        }
        let preview = (preview.filter(|p| !p.is_empty()))
            .and_then(|p| std::fs::read(p).ok())
            .filter(|p| p.len() <= MAX_PREVIEW);
        Ok(Attachment {
            key,
            hash,
            size,
            mime: mime_of(&name).to_owned(),
            name,
            preview,
        })
    }

    /// A kept file, opened (`meshDmFile`), or fetched from a connected
    /// device of `people` or our own and then opened.
    pub(super) fn fetch_attachment(
        &mut self,
        at: Where,
        message: String,
        index: usize,
        file: Attachment,
        mut people: Vec<MeshId>,
    ) -> Result<(), Fail> {
        if self.blobs()?.has(&file.hash) {
            return self.open_file(&at, &message, index, &file);
        }
        people.extend(self.store.as_ref().map(Keystore::id));
        let Some(net) = &self.net else {
            return Err(Fail("unavailable", "not connected".to_owned()));
        };
        let addrs: Vec<MeshAddr> = people.iter().flat_map(|p| net.node.connected(p)).collect();
        let (node, back) = (net.node.clone(), self.back.clone());
        tokio::spawn(async move {
            let mut got = None;
            // ponytail: one device after another, one chunk at a time; ask several at once if big files feel slow.
            for addr in addrs {
                got = fetch_from(&node, &addr, &file).await;
                if got.is_some() {
                    break;
                }
            }
            let _ = back.send(Back::Fetched(Box::new((at, message, index, file, got))));
        });
        Ok(())
    }

    /// A fetch finished: keep the file and open it, or say it's unavailable.
    pub(super) fn fetched(&mut self, (at, message, index, file, got): Fetched) {
        let Some(sealed) = got else {
            return emit(
                "meshError",
                json!({ "fn": "dmFetch", "kind": "unavailable", "message": "nobody connected has that file" }),
            );
        };
        let Ok(blobs) = self.blobs() else { return };
        if let Err(e) = blobs
            .add_fetched(&file.hash, &sealed, at)
            .and_then(|()| blobs.evict(MAX_KEPT))
        {
            eprintln!("mesh-node: couldn't keep a fetched file: {e}");
        }
        if let Err(Fail(kind, message)) = self.open_file(&at, &message, index, &file) {
            emit(
                "meshError",
                json!({ "fn": "dmFetch", "kind": kind, "message": message }),
            );
        }
    }

    /// Opens a kept file into the cache for its app: `meshDmFile {path}`.
    fn open_file(
        &mut self,
        at: &Where,
        message: &str,
        index: usize,
        file: &Attachment,
    ) -> Result<(), Fail> {
        let blobs = self.blobs()?;
        let io = |e: std::io::Error| Fail("io", format!("couldn't open that file: {e}"));
        let mut opener = Opener::new(file.key, file.hash, file.size)
            .map_err(|e| Fail("unavailable", e.to_string()))?;
        let mut plain = Vec::with_capacity(file.size as usize);
        for i in 0..chunks(file.size) {
            let chunk = blobs
                .chunk(&file.hash, i)
                .map_err(io)?
                .ok_or_else(|| Fail("unavailable", "the kept file is short".to_owned()))?;
            plain.extend(
                opener
                    .chunk(&chunk)
                    .map_err(|e| Fail("unavailable", e.to_string()))?,
            );
        }
        opener
            .finish()
            .map_err(|e| Fail("unavailable", e.to_string()))?;
        // The only plaintext outside the sealed store: the cache a file's
        // app opens it from (dm *Never*).
        let safe: String = (file.name.chars())
            .map(|c| {
                if c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let dir = self.opened_dir().join(format!("{message}-{index}"));
        std::fs::create_dir_all(&dir).map_err(io)?;
        let path = dir.join(if safe.is_empty() {
            "file".to_owned()
        } else {
            safe
        });
        std::fs::write(&path, &plain).map_err(io)?;
        let _ = blobs.opened(&file.hash);
        emit(
            "meshDmFile",
            json!({ "id": super::dm::chat_text(at), "message": message, "index": index, "path": path.to_string_lossy() }),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deleted message takes every one of its files with it (D13).
    #[test]
    fn every_attachment_of_a_message() {
        let file = |hash| Attachment {
            key: [0; 32],
            hash,
            size: 1,
            name: "a".to_owned(),
            mime: "text/plain".to_owned(),
            preview: None,
        };
        let body = Body::Text {
            text: String::new(),
            reply_to: None,
            attachments: vec![file([1; 32]), file([2; 32])],
        };
        assert_eq!(files_in(&body), [[1; 32], [2; 32]]);
        assert!(files_in(&Body::Read { up_to: [0; 16] }).is_empty());
    }
}
