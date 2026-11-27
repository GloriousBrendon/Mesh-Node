//! Profiles (SPEC-profile PR1, PR3, PR14, PR15): publishing ours, offering
//! it to friends and our own devices when they connect, taking theirs, and
//! fetching the files a profile shows. A child of `helper`.
//!
//! On the `profile` service the side with a profile opens a stream and
//! sends its version (8 bytes); the other answers one byte, 1 to want the
//! manifest and 0 not; on 1 the manifest follows in one frame. Like
//! presence and account sync (social D11, D12) it rides the device-to-device
//! connection, which is end-to-end encrypted and authenticated by device
//! key. The files are sealed with their own keys and move on `blob`.
//!
//! Kept on disk, sealed with the data key: our manifest (`profile/own`)
//! and the friends' we hold (`profile/friends`). A friend's files are kept
//! under the chat with them, ours under ours.

use super::*;
use mesh_dm::Where;
use mesh_dm::event::Attachment;
use mesh_dm::profile::{Asset, Manifest, ProfileError, Slot};
use mesh_identity::{read_sealed, write_sealed};

/// The transport service profiles are offered on.
pub(super) const SERVICE: &str = "profile";
/// How long a friend has to answer an offer, or send the manifest.
const PROFILE_WAIT: Duration = Duration::from_secs(20);
/// The sealed files' contexts and format.
const OWN_CONTEXT: &str = "mesh/v1/profile-own";
const FRIENDS_CONTEXT: &str = "mesh/v1/profile-friends";
const FORMAT: u8 = 1;

/// A friend's profile file that came, or didn't: whose, and the file.
pub(super) type ProfileFetched = (MeshId, Asset, Option<Vec<Vec<u8>>>);

/// The kind of file from its name's extension, as `profileSet` reads a folder.
fn mime_of(name: &str) -> Option<&'static str> {
    let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
    Some(match ext.as_str() {
        "png" => "image/png",
        "apng" => "image/apng",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "ogg" | "opus" | "oga" => "audio/ogg",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        _ => return None,
    })
}

/// A file's slot from its name in the profile folder: `avatar.*`,
/// `banner.*`, `background.*`, `song.*`, or `gallery*` (in name order).
fn slot_of(name: &str) -> Option<Slot> {
    let stem = name.split('.').next()?.to_ascii_lowercase();
    Some(match stem.as_str() {
        "avatar" => Slot::Avatar,
        "banner" => Slot::Banner,
        "background" => Slot::Background,
        "song" => Slot::Song,
        s if s.starts_with("gallery") => Slot::Gallery,
        _ => return None,
    })
}

fn slot_name(slot: Slot) -> &'static str {
    match slot {
        Slot::Avatar => "avatar",
        Slot::Banner => "banner",
        Slot::Background => "background",
        Slot::Gallery => "gallery",
        Slot::Song => "song",
    }
}

fn extension(mime: &str) -> &'static str {
    match mime {
        "image/png" | "image/apng" => "png",
        "image/jpeg" => "jpg",
        "image/webp" => "webp",
        "image/gif" => "gif",
        "audio/ogg" => "ogg",
        "audio/mpeg" => "mp3",
        "audio/flac" => "flac",
        _ => "bin",
    }
}

/// A profile file as the blob code knows files.
fn attachment(asset: &Asset) -> Attachment {
    Attachment {
        key: asset.key,
        hash: asset.hash,
        size: asset.size,
        name: String::new(),
        mime: asset.mime.clone(),
        preview: None,
    }
}

fn fail(e: ProfileError) -> Fail {
    let kind = match e {
        ProfileError::TooBig(_) | ProfileError::BundleTooBig | ProfileError::SongTooLong => {
            "too-long"
        }
        ProfileError::TooLong(_) | ProfileError::TomlTooLong | ProfileError::TooMany(_) => {
            "too-long"
        }
        _ => "bad-args",
    };
    Fail(kind, e.to_string())
}

/// Offers `manifest` (version first) on one connected device.
async fn offer(node: crate::nodes::Nodes, addr: MeshAddr, version: u64, manifest: Vec<u8>) {
    let sent = async {
        let (_, mut send, mut recv) = node.open(&addr, SERVICE).await.ok()?;
        mesh_transport::frame::write_frame(&mut send, &version.to_be_bytes())
            .await
            .ok()?;
        let answer = mesh_transport::frame::read_frame(&mut recv).await.ok()??;
        if answer == [1] {
            mesh_transport::frame::write_frame(&mut send, &manifest)
                .await
                .ok()?;
        }
        send.finish().ok()?;
        send.stopped().await.ok()
    };
    let _ = tokio::time::timeout(PROFILE_WAIT, sent).await;
}

/// Answers one device's offer: asks the helper whether it wants that
/// version, then takes the manifest to it.
pub(super) async fn serve(
    mut stream: mesh_transport::ServiceStream,
    back: tokio::sync::mpsc::UnboundedSender<Back>,
) {
    let (id, device) = (stream.peer.id, *stream.peer.device.as_bytes());
    let got = async {
        let version = mesh_transport::frame::read_frame(&mut stream.recv)
            .await
            .ok()??;
        let version = u64::from_be_bytes(version.try_into().ok()?);
        let (tx, rx) = tokio::sync::oneshot::channel();
        back.send(Back::ProfileOffer(Box::new((id, version, tx))))
            .ok()?;
        let want = rx.await.unwrap_or(false);
        mesh_transport::frame::write_frame(&mut stream.send, &[u8::from(want)])
            .await
            .ok()?;
        if !want {
            return Some(());
        }
        let bytes = mesh_transport::frame::read_frame(&mut stream.recv)
            .await
            .ok()??;
        back.send(Back::Profile(Box::new((id, device, bytes)))).ok()
    };
    let _ = tokio::time::timeout(PROFILE_WAIT, got).await;
    let _ = stream.send.finish();
}

impl Helper {
    fn profile_dir(&self) -> PathBuf {
        self.path.parent().unwrap_or(Path::new(".")).join("profile")
    }

    /// Our manifest, if we've published one (on any of our devices).
    pub(super) fn own_profile(&self) -> Option<Manifest> {
        let store = self.store.as_ref()?;
        let path = self.profile_dir().join("own");
        match read_sealed(&path, store.data_key(), OWN_CONTEXT, FORMAT) {
            Ok(Some((_, bytes))) => Manifest::from_bytes(&bytes).ok(),
            Ok(None) => None,
            Err(e) => {
                eprintln!("mesh-node: couldn't read our profile: {e}");
                None
            }
        }
    }

    fn save_own_profile(&self, manifest: &Manifest) -> Result<(), Fail> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| Fail("locked", "locked".to_owned()))?;
        let bytes = manifest.to_bytes().map_err(fail)?;
        write_sealed(
            &self.profile_dir().join("own"),
            store.data_key(),
            OWN_CONTEXT,
            FORMAT,
            &bytes,
        )
        .map_err(|e| Fail("io", format!("couldn't save the profile: {e}")))
    }

    /// The friends' manifests we hold, by their ID's bytes.
    fn friend_profiles(&self) -> HashMap<[u8; 32], Manifest> {
        let Some(store) = self.store.as_ref() else {
            return HashMap::new();
        };
        let path = self.profile_dir().join("friends");
        let bytes = match read_sealed(&path, store.data_key(), FRIENDS_CONTEXT, FORMAT) {
            Ok(Some((_, bytes))) => bytes,
            Ok(None) => return HashMap::new(),
            Err(e) => {
                eprintln!("mesh-node: couldn't read friends' profiles: {e}");
                return HashMap::new();
            }
        };
        let entries: Vec<([u8; 32], Vec<u8>)> = postcard::from_bytes(&bytes).unwrap_or_default();
        (entries.into_iter())
            .filter_map(|(id, m)| Some((id, Manifest::from_bytes(&m).ok()?)))
            .collect()
    }

    fn save_friend_profiles(&self, all: &HashMap<[u8; 32], Manifest>) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        let entries: Vec<([u8; 32], Vec<u8>)> = (all.iter())
            .filter_map(|(id, m)| Some((*id, m.to_bytes().ok()?)))
            .collect();
        let bytes = postcard::to_stdvec(&entries).expect("to memory");
        let path = self.profile_dir().join("friends");
        if let Err(e) = write_sealed(&path, store.data_key(), FRIENDS_CONTEXT, FORMAT, &bytes) {
            eprintln!("mesh-node: couldn't save friends' profiles: {e}");
        }
    }

    /// `profileSet(folder)`, `profileGet(id)`.
    pub(super) fn profile_command(&mut self, func: &str, args: &[String]) -> Result<(), Fail> {
        let arg = |i: usize| {
            args.get(i)
                .map(String::as_str)
                .ok_or_else(|| Fail("bad-args", format!("{func} is missing argument {}", i + 1)))
        };
        match func {
            "profileSet" => self.profile_set(Path::new(arg(0)?)),
            "profileGet" => self.profile_get(&parse_id(arg(0)?)?),
            _ => Err(Fail("unknown-fn", format!("unknown command {func}"))),
        }
    }

    /// Publishes the profile in `folder`: its `profile.toml` and the files
    /// named for their slots, as the next version (PR2).
    fn profile_set(&mut self, folder: &Path) -> Result<(), Fail> {
        let io = |e: std::io::Error| Fail("io", format!("couldn't read the profile: {e}"));
        let toml = std::fs::read_to_string(folder.join("profile.toml")).map_err(io)?;
        let mut files: Vec<(Slot, PathBuf, &'static str)> = Vec::new();
        let mut names: Vec<String> = (std::fs::read_dir(folder).map_err(io)?.flatten())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names {
            if let (Some(slot), Some(mime)) = (slot_of(&name), mime_of(&name)) {
                files.push((slot, folder.join(&name), mime));
            }
        }
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| Fail("locked", "locked".to_owned()))?;
        let me = store.id();
        let device = store.device_key().public();
        let cert = (store.devices().devices().iter())
            .find(|c| *c.device() == device)
            .cloned()
            .ok_or_else(|| Fail("unavailable", "this device isn't on our list".to_owned()))?;
        // The caps first, before keeping any file.
        let declared: Vec<Asset> = (files.iter())
            .map(|(slot, path, mime)| {
                let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(u64::MAX);
                Ok(Asset {
                    slot: *slot,
                    key: [0; 32],
                    hash: [0; 32],
                    size,
                    mime: (*mime).to_owned(),
                    seconds: None,
                })
            })
            .collect::<Result<_, Fail>>()?;
        let draft = Manifest {
            format: mesh_dm::profile::PROFILE_FORMAT,
            version: 0,
            toml: toml.clone(),
            assets: declared,
            cert: Vec::new(),
            signature: Vec::new(),
        };
        draft.check().map_err(fail)?;

        let blobs = self.blobs()?;
        let mut assets = Vec::new();
        for (slot, path, mime) in &files {
            let (key, hash, size) = blobs
                .add_file(path, Where::Direct(me.to_bytes()))
                .map_err(|e| Fail("io", format!("couldn't keep a profile file: {e}")))?;
            assets.push(Asset {
                slot: *slot,
                key,
                hash,
                size,
                mime: (*mime).to_owned(),
                seconds: None,
            });
        }
        let old = self.own_profile();
        let version = old.as_ref().map_or(1, |m| m.version + 1);
        let manifest =
            Manifest::signed(version, toml, assets, store.device_key(), &cert).map_err(fail)?;
        self.save_own_profile(&manifest)?;
        if let Some(old) = old {
            self.drop_profile_files(&old, &manifest);
        }
        emit(
            "meshProfile",
            json!({ "fn": "profileSet", "id": me.to_string(), "version": version }),
        );
        self.offer_profile_all();
        Ok(())
    }

    /// Drops `old`'s kept files that `new` no longer shows.
    fn drop_profile_files(&self, old: &Manifest, new: &Manifest) {
        let Ok(blobs) = self.blobs() else { return };
        for asset in &old.assets {
            if !new.assets.iter().any(|a| a.hash == asset.hash)
                && let Err(e) = blobs.remove(&asset.hash)
            {
                eprintln!("mesh-node: couldn't drop an old profile file: {e}");
            }
        }
    }

    /// `profileGet(id)`: the profile we hold for `id` (a friend, or us),
    /// its files opened into the cache: `meshProfile` with each file's
    /// path, or none while it's still coming.
    fn profile_get(&mut self, id: &MeshId) -> Result<(), Fail> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| Fail("locked", "locked".to_owned()))?;
        let me = store.id();
        let manifest = if *id == me {
            self.own_profile()
        } else {
            self.friend_profiles().remove(&id.to_bytes())
        };
        let manifest =
            manifest.ok_or_else(|| Fail("not-found", "no profile for them".to_owned()))?;
        let blobs = self.blobs()?;
        let dir = self.opened_dir().join(format!(
            "profile-{}-v{}",
            e2ee::hex(&id.to_bytes()[..8]),
            manifest.version
        ));
        // Only this version's copy stays.
        let prefix = format!("profile-{}-", e2ee::hex(&id.to_bytes()[..8]));
        self.clear_opened(|name| name.starts_with(&prefix));
        let mut shown = Vec::new();
        let mut counts: HashMap<&'static str, usize> = HashMap::new();
        for asset in &manifest.assets {
            let n = counts.entry(slot_name(asset.slot)).or_default();
            *n += 1;
            let path = if blobs.has(&asset.hash) {
                let name = format!("{}-{n}.{}", slot_name(asset.slot), extension(&asset.mime));
                self.open_profile_file(&dir, &name, asset).ok()
            } else {
                None
            };
            shown.push(json!({
                "slot": slot_name(asset.slot),
                "mime": asset.mime,
                "size": asset.size,
                "seconds": asset.seconds,
                "path": path.map(|p| p.to_string_lossy().into_owned()),
            }));
        }
        emit(
            "meshProfile",
            json!({
                "fn": "profileGet",
                "id": id.to_string(),
                "version": manifest.version,
                "toml": manifest.toml,
                "assets": shown,
            }),
        );
        Ok(())
    }

    /// Opens one kept profile file into `dir` as `name`.
    fn open_profile_file(&self, dir: &Path, name: &str, asset: &Asset) -> Result<PathBuf, Fail> {
        let blobs = self.blobs()?;
        let unavailable = |e: mesh_dm::blob::BlobError| Fail("unavailable", e.to_string());
        let io = |e: std::io::Error| Fail("io", format!("couldn't open a profile file: {e}"));
        let mut opener =
            mesh_dm::blob::Opener::new(asset.key, asset.hash, asset.size).map_err(unavailable)?;
        let mut plain = Vec::with_capacity(asset.size as usize);
        for i in 0..mesh_dm::blob::chunks(asset.size) {
            let chunk = (blobs.chunk(&asset.hash, i).map_err(io)?)
                .ok_or_else(|| Fail("unavailable", "the kept file is short".to_owned()))?;
            plain.extend(opener.chunk(&chunk).map_err(unavailable)?);
        }
        opener.finish().map_err(unavailable)?;
        std::fs::create_dir_all(dir).map_err(io)?;
        let path = dir.join(name);
        std::fs::write(&path, &plain).map_err(io)?;
        Ok(path)
    }

    /// Offers our profile to every connected friend and own device.
    fn offer_profile_all(&self) {
        let Some(store) = &self.store else { return };
        let mut ids = vec![store.id()];
        ids.extend(
            (store.account().entries().iter())
                .filter(|e| e.kind == Kind::Friend)
                .map(|e| e.id()),
        );
        for id in ids {
            self.offer_profile(&id);
        }
    }

    /// Offers our profile to each of `id`'s connected devices, if `id` is a
    /// friend or us (PR1).
    pub(super) fn offer_profile(&self, id: &MeshId) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        if *id != store.id() && store.account().kind(id) != Some(Kind::Friend) {
            return;
        }
        let Some(manifest) = self.own_profile() else {
            return;
        };
        let Ok(bytes) = manifest.to_bytes() else {
            return;
        };
        let this = store.device_key().public();
        for addr in net.node.connected(id) {
            if addr.device.as_bytes() == this.as_bytes() {
                continue;
            }
            tokio::spawn(offer(
                net.node.clone(),
                addr,
                manifest.version,
                bytes.clone(),
            ));
        }
    }

    /// A device offers `version` of its person's profile: wanted if it's a
    /// friend's or ours and newer than what we hold.
    pub(super) fn profile_offered(&self, id: &MeshId, version: u64) -> bool {
        let Some(store) = &self.store else {
            return false;
        };
        let held = if *id == store.id() {
            self.own_profile().map(|m| m.version)
        } else if store.account().kind(id) == Some(Kind::Friend) {
            self.friend_profiles()
                .get(&id.to_bytes())
                .map(|m| m.version)
        } else {
            return false;
        };
        // An equal version from another of our devices may still win the
        // tie (PR14); the manifest settles it.
        held.is_none_or(|held| version >= held)
    }

    /// A device sent its person's manifest: kept if it checks out and
    /// replaces what we hold, then its files are fetched.
    pub(super) fn profile_heard(&mut self, id: MeshId, device: [u8; 32], bytes: &[u8]) {
        let Some(store) = &self.store else { return };
        let Ok(manifest) = Manifest::from_bytes(bytes) else {
            return eprintln!("mesh-node: a device sent a damaged profile");
        };
        let own = id == store.id();
        let list = if own {
            Some(store.devices().clone())
        } else if store.account().kind(&id) == Some(Kind::Friend) {
            store.contact(&id).and_then(|c| c.devices())
        } else {
            return;
        };
        let author_ok = match &list {
            Some(list) => manifest.check_from(list).is_ok(),
            // No list of theirs yet: the device we're talking to must have
            // signed it, and be theirs (the handshake said so).
            None => manifest
                .author()
                .is_some_and(|a| a.person == id.to_bytes() && a.device == device),
        };
        if !author_ok {
            return eprintln!("mesh-node: a profile didn't check out");
        }
        if own {
            let old = self.own_profile();
            if old.as_ref().is_some_and(|o| !manifest.replaces(o)) {
                return;
            }
            if self.save_own_profile(&manifest).is_err() {
                return;
            }
            if let Some(old) = old {
                self.drop_profile_files(&old, &manifest);
            }
        } else {
            let mut all = self.friend_profiles();
            let old = all.get(&id.to_bytes()).cloned();
            if old.as_ref().is_some_and(|o| !manifest.replaces(o)) {
                return;
            }
            all.insert(id.to_bytes(), manifest.clone());
            self.save_friend_profiles(&all);
            if let Some(old) = old {
                self.drop_profile_files(&old, &manifest);
            }
        }
        emit(
            "meshProfile",
            json!({ "id": id.to_string(), "version": manifest.version, "changed": true }),
        );
        self.fetch_profile_files(id, &manifest);
    }

    /// Fetches the files of `id`'s manifest we haven't kept, from `id`'s
    /// connected devices (or our own, for ours).
    fn fetch_profile_files(&self, id: MeshId, manifest: &Manifest) {
        let (Ok(blobs), Some(net)) = (self.blobs(), &self.net) else {
            return;
        };
        let addrs = net.node.connected(&id);
        for asset in manifest.assets.iter().filter(|a| !blobs.has(&a.hash)) {
            let (node, back, addrs, asset) = (
                net.node.clone(),
                self.back.clone(),
                addrs.clone(),
                asset.clone(),
            );
            tokio::spawn(async move {
                let mut got = None;
                for addr in addrs {
                    got = files::fetch_from(&node, &addr, &attachment(&asset)).await;
                    if got.is_some() {
                        break;
                    }
                }
                let _ = back.send(Back::ProfileFetched(Box::new((id, asset, got))));
            });
        }
    }

    /// A profile file came (kept under its person's chat) or didn't. Once
    /// every file of the profile is kept, Aflos is told.
    pub(super) fn profile_fetched(&mut self, (id, asset, got): ProfileFetched) {
        let Some(sealed) = got else {
            return eprintln!("mesh-node: a profile file didn't come");
        };
        let Ok(blobs) = self.blobs() else { return };
        if let Err(e) = blobs
            .add_fetched(&asset.hash, &sealed, Where::Direct(id.to_bytes()))
            .and_then(|()| blobs.evict(mesh_dm::blob::MAX_KEPT))
        {
            return eprintln!("mesh-node: couldn't keep a profile file: {e}");
        }
        let me = self.store.as_ref().map(Keystore::id);
        let manifest = if Some(id) == me {
            self.own_profile()
        } else {
            self.friend_profiles().remove(&id.to_bytes())
        };
        if let Some(m) = manifest
            && m.assets.iter().all(|a| blobs.has(&a.hash))
        {
            emit(
                "meshProfile",
                json!({ "id": id.to_string(), "version": m.version, "complete": true }),
            );
        }
    }

    /// Whether `id` may fetch `hash` as a profile file: it's one of ours
    /// and they're a friend (PR1).
    pub(super) fn may_fetch_profile(&self, id: &MeshId, hash: &[u8; 32]) -> bool {
        let Some(store) = &self.store else {
            return false;
        };
        store.account().kind(id) == Some(Kind::Friend)
            && self
                .own_profile()
                .is_some_and(|m| m.assets.iter().any(|a| a.hash == *hash))
    }

    /// Forgets the profiles of anyone who's no longer a friend, with their
    /// files and opened copies (PR15).
    pub(super) fn profile_prune(&self) {
        let Some(store) = &self.store else { return };
        let mut all = self.friend_profiles();
        let gone: Vec<[u8; 32]> = (all.keys())
            .filter(|id| {
                MeshId::from_bytes(id)
                    .map_or(true, |id| store.account().kind(&id) != Some(Kind::Friend))
            })
            .copied()
            .collect();
        if gone.is_empty() {
            return;
        }
        let blobs = self.blobs().ok();
        for id in &gone {
            if let (Some(m), Some(blobs)) = (all.remove(id), &blobs) {
                for asset in &m.assets {
                    let _ = blobs.remove(&asset.hash);
                }
            }
            let prefix = format!("profile-{}-", e2ee::hex(&id[..8]));
            self.clear_opened(|name| name.starts_with(&prefix));
        }
        self.save_friend_profiles(&all);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_in_the_profile_folder() {
        assert_eq!(slot_of("avatar.gif"), Some(Slot::Avatar));
        assert_eq!(slot_of("Gallery-02.PNG"), Some(Slot::Gallery));
        assert_eq!(slot_of("song.opus"), Some(Slot::Song));
        assert_eq!(slot_of("profile.toml"), None);
        assert_eq!(mime_of("song.opus"), Some("audio/ogg"));
        assert_eq!(mime_of("avatar.JPG"), Some("image/jpeg"));
        assert_eq!(mime_of("avatar.svg"), None);
        assert_eq!(mime_of("noextension"), None);
    }
}
