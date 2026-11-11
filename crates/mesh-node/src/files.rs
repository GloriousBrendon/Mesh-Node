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
use mesh_dm::blob::{Blobs, MAX_KEPT, Opener, chunks};
use mesh_dm::event::{Attachment, Body, MAX_PREVIEW};

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
fn mime_of(name: &str) -> &'static str {
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
async fn fetch_from(node: &Node, addr: &MeshAddr, file: &Attachment) -> Option<Vec<Vec<u8>>> {
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
    let blobs = Blobs::new(&dir);
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
        let chunk = blobs.chunk(&hash, index).ok().flatten().unwrap_or_default();
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

    /// Whether `id` may fetch the kept file `hash`: they're in a chat that
    /// holds it (one of ours, a 1:1 with them, a group they're in).
    pub(super) fn may_fetch(&self, id: &MeshId, hash: &[u8; 32]) -> bool {
        let me = self.store.as_ref().map(Keystore::id);
        let Ok(Some(kept)) = Blobs::new(&self.blobs_dir()).kept(hash) else {
            return false;
        };
        kept.chats.iter().any(|at| {
            Some(*id) == me
                || match at {
                    Where::Direct(p) => *p == id.to_bytes(),
                    Where::Group(_) => (self.dm.as_ref())
                        .and_then(|h| h.members(at))
                        .is_some_and(|m| m.contains(&id.to_bytes())),
                }
        })
    }

    /// The files whose messages these delete takes, to drop with them (D13).
    pub(super) fn files_of_deleted(
        &mut self,
        events: &[mesh_dm::event::Event],
    ) -> Vec<Option<[u8; 32]>> {
        let Some(history) = &mut self.dm else {
            return vec![None; events.len()];
        };
        (events.iter())
            .map(|e| match &e.body {
                Body::Delete { target, .. } => match history.event(target) {
                    Ok(Some(mesh_dm::event::Event {
                        body: Body::Text { attachments, .. },
                        ..
                    })) => attachments.first().map(|a| a.hash),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    pub(super) fn drop_file(&self, hash: &[u8; 32]) {
        if let Err(e) = Blobs::new(&self.blobs_dir()).remove(hash) {
            eprintln!("mesh-node: couldn't drop a kept file: {e}");
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
        let blobs = Blobs::new(&self.blobs_dir());
        match func {
            "dmSendFile" => {
                let source = Path::new(arg(1)?);
                let name = (source.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let (key, hash, size) = blobs.add_file(source, at).map_err(|e| {
                    let kind = if e.to_string().contains("100 MB") {
                        "too-long"
                    } else {
                        "io"
                    };
                    Fail(kind, format!("couldn't keep that file: {e}"))
                })?;
                if let Err(e) = blobs.evict(MAX_KEPT) {
                    eprintln!("mesh-node: couldn't make room for kept files: {e}");
                }
                // A preview Mesh-Voice made, if it fits (D12).
                let preview = (args.get(2).filter(|p| !p.is_empty()))
                    .and_then(|p| std::fs::read(p).ok())
                    .filter(|p| p.len() <= MAX_PREVIEW);
                let attachment = Attachment {
                    key,
                    hash,
                    size,
                    mime: mime_of(&name).to_owned(),
                    name,
                    preview,
                };
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
                let mut people = self.dm_recipients(&at);
                people.extend(self.store.as_ref().map(Keystore::id));
                let Some(net) = &self.net else {
                    return Err(Fail("unavailable", "not connected".to_owned()));
                };
                let addrs: Vec<MeshAddr> =
                    people.iter().flat_map(|p| net.node.connected(p)).collect();
                let (node, back) = (net.node.clone(), self.back.clone());
                tokio::spawn(async move {
                    let mut got = None;
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
            _ => Err(Fail("unknown-fn", format!("unknown command {func}"))),
        }
    }

    /// A fetch finished: keep the file and open it, or say it's unavailable.
    pub(super) fn fetched(&mut self, (at, message, index, file, got): Fetched) {
        let Some(sealed) = got else {
            return emit(
                "meshError",
                json!({ "fn": "dmFetch", "kind": "unavailable", "message": "nobody connected has that file" }),
            );
        };
        let blobs = Blobs::new(&self.blobs_dir());
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
        let blobs = Blobs::new(&self.blobs_dir());
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
        let dir = self
            .path
            .parent()
            .unwrap_or(Path::new("."))
            .join("files")
            .join(format!("{message}-{index}"));
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
