//! Spaces in the helper (SPEC-spaces). Task 5: who the Spaces held make
//! reachable. Peers aren't account entries (S2 as changed 2026-11-14): at
//! unlock they're worked out from each Space's chain alone, without its
//! log (S11), and handed to the keystore beside the contacts.

use std::path::Path;

use mesh_dm::space::SpaceId;
use mesh_dm::space_store::{SpaceHistory, SpaceList};
use mesh_identity::MeshId;

use super::Helper;

/// Every current member of every Space in `spaces`, from their chains alone.
/// A Space whose chain doesn't read is left out and said so (counts only).
pub(super) fn space_members(root: &Path, data_key: &[u8; 32], spaces: &[SpaceId]) -> Vec<MeshId> {
    let mut members: Vec<MeshId> = Vec::new();
    for space in spaces {
        let chain = match SpaceHistory::read_chain(root, data_key, space) {
            Ok(chain) => chain,
            Err(e) => {
                eprintln!("mesh-node: a Space's changes didn't read: {e}");
                continue;
            }
        };
        let Some(version) = chain.version(space) else {
            continue;
        };
        let ids = version.state.members.keys();
        members.extend(ids.filter_map(|m| MeshId::from_bytes(m).ok()));
    }
    members.sort_by_key(|m| m.to_bytes());
    members.dedup();
    members
}

impl Helper {
    /// Opens the list of Spaces and works out the peers, as networking
    /// starts: before the allow-list and the first records.
    pub(super) fn open_spaces(&mut self) {
        let Some(store) = &mut self.store else { return };
        let data = self.path.parent().unwrap_or(Path::new("."));
        let root = data.join("dm");
        let list = SpaceList::open(&root, store.data_key())
            .inspect_err(|e| eprintln!("mesh-node: the list of Spaces didn't open: {e}"))
            .ok();
        let members = list
            .as_ref()
            .map(|l| space_members(&root, store.data_key(), l.spaces()))
            .unwrap_or_default();
        if let Err(e) = store.set_peers(members) {
            eprintln!("mesh-node: the Spaces' members didn't fit: {e}");
        }
        self.spaces = list;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_dm::Sender;
    use mesh_dm::space::{Change, SpaceBody, SpaceChange, SpaceEvent, space_id};
    use mesh_identity::{DeviceCert, DeviceKey, RootKey};

    const KEY: [u8; 32] = [7; 32];
    const NOW: u64 = 1_800_000_000_000;

    /// A Space made by a new owner with `members` added, stored under `root`.
    fn space_with(root: &Path, members: &[MeshId]) -> (SpaceId, MeshId) {
        let owner = RootKey::generate().unwrap();
        let device = DeviceKey::generate().unwrap();
        let cert = DeviceCert::issue(&owner, &device.public(), "d", 1).unwrap();
        let nonce = mesh_dm::space::nonce().unwrap();
        let id = space_id(&owner.id().to_bytes(), &nonce);
        let me = Sender {
            person: owner.id().to_bytes(),
            device: device.public().to_bytes(),
        };
        let mut h = SpaceHistory::open(root, &KEY, me, id).unwrap();
        let mut changes = vec![Change::Create {
            name: "s".into(),
            nonce,
            display: "o".into(),
        }];
        changes.extend(members.iter().map(|m| Change::Add {
            who: m.to_bytes(),
            display: "m".into(),
        }));
        let mut after = None;
        for (i, change) in changes.into_iter().enumerate() {
            let event_id = [i as u8 + 1; 16];
            let body = SpaceBody::Change(SpaceChange { after, change });
            let seq = NOW + i as u64;
            let e =
                SpaceEvent::signed(id, event_id, (seq, seq, i as u64 + 1), body, &device, &cert);
            h.store(&e, me, NOW, NOW).unwrap();
            after = Some(event_id);
        }
        (id, owner.id())
    }

    #[test]
    fn the_members_of_every_space_held() {
        let root = std::env::temp_dir().join(format!("mesh-node-spaces-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (a, b, c) = (
            RootKey::generate().unwrap().id(),
            RootKey::generate().unwrap().id(),
            RootKey::generate().unwrap().id(),
        );
        let (one, owner_one) = space_with(&root, &[a, b]);
        let (two, owner_two) = space_with(&root, &[b, c]);
        let mut members = space_members(&root, &KEY, &[one, two, [9; 16]]);
        members.sort_by_key(|m| m.to_bytes());
        let mut expected = vec![a, b, c, owner_one, owner_two];
        expected.sort_by_key(|m| m.to_bytes());
        expected.dedup();
        assert_eq!(members, expected, "both Spaces' members, once each");
        assert!(space_members(&root, &KEY, &[]).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
