//! Routing (SPEC-routing): reaching a contact by ID. Each device leaves an
//! encrypted address record per contact on the seeds (D2–D4), and finds a
//! contact by trying the address that last worked, then the seeds' records
//! for them (D8). Seed requests go from the throwaway node (seed D7b).

use std::cmp::Reverse;
use std::sync::Arc;

use crate::addrs::{Get, Put};
use crate::seed;
use mesh_identity::{
    AddrRecord, DeviceList, Keystore, LastAddr, MeshId, PairKeys, day_of, open_addr, seal_addr,
};
use mesh_transport::{MeshAddr, Node, Pong, RelayUrl};

/// How long a record lasts (D4); `--record-ttl` shortens it for tests.
pub const RECORD_TTL: u64 = 2 * 3600;
/// How often records are refreshed, at most (D4).
pub const REFRESH_EVERY: u64 = 30 * 60;

/// This device's record for each contact, and one under the self pair for
/// our other devices (SPEC-social D11), on `relay`. `field` gives each one's
/// e2ee field (SPEC-e2ee D4). With `only`, just that contact's record.
pub fn records(
    store: &Keystore,
    relay: &RelayUrl,
    now: u64,
    ttl: u64,
    only: Option<&MeshId>,
    mut field: impl FnMut(&MeshId) -> Vec<u8>,
) -> Vec<Vec<u8>> {
    let ids = store.reachable().map(|c| c.id());
    std::iter::once(store.id())
        .chain(ids)
        .filter(|id| only.is_none_or(|only| only == id))
        .filter_map(|id| {
            let keys = store.pair_keys(&id)?;
            let sealed = seal_addr(
                &keys,
                store.device_key(),
                store.devices(),
                relay.as_str(),
                &field(&id),
                now,
                ttl,
            );
            sealed
                .inspect_err(|e| eprintln!("mesh-node: couldn't make an address record: {e}"))
                .ok()
        })
        .collect()
}

/// Puts the records on every seed: true when a seed took all of them.
pub async fn publish(anon: &Node, seeds: &[MeshAddr], records: &[Vec<u8>]) -> bool {
    let mut published = false;
    for addr in seeds {
        if let Ok(answers) = seed::ask_many(anon, addr, seed::ADDR_PUT, records).await {
            let took = |a: &Vec<u8>| a.first().copied().and_then(Put::from_byte) == Some(Put::Ok);
            published |= answers.iter().all(took);
        }
    }
    published
}

/// What the helper knows about a contact, taken from the keystore so the
/// search can run off the main loop.
pub struct Target {
    pub id: MeshId,
    pub keys: PairKeys,
    pub last: Option<LastAddr>,
    pub known: Option<DeviceList>,
}

impl Target {
    pub fn of(store: &Keystore, id: &MeshId) -> Option<Self> {
        let contact = store.reachable_contact(id)?;
        Some(Self {
            id: *id,
            keys: store.pair_keys(id)?,
            last: contact.last.clone(),
            known: contact.devices(),
        })
    }

    /// Our own identity, to find our other devices.
    pub fn own(store: &Keystore) -> Option<Self> {
        Some(Self {
            id: store.id(),
            keys: store.pair_keys(&store.id())?,
            last: None,
            known: Some(store.devices().clone()),
        })
    }
}

pub struct Reached {
    pub pong: Pong,
    /// The address that worked; `None` through an already open connection.
    pub last: Option<LastAddr>,
    /// Their device list, when the seeds gave a newer one.
    pub list: Option<DeviceList>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReachError {
    /// No record, or no device answered.
    Unreachable,
    /// Records came back, but only for devices their newest list removed.
    RevokedDevice,
}

/// Pings one of the contact's devices: an open connection first, then the
/// cached address, then every device the seeds know of, together; the first
/// to answer wins (D8).
pub async fn reach(
    node: Arc<Node>,
    anon: &Node,
    seeds: &[MeshAddr],
    target: Target,
    now: u64,
) -> Result<Reached, ReachError> {
    let current = |list: &Option<DeviceList>, device: &[u8; 32]| {
        list.as_ref()
            .is_none_or(|l| l.devices().iter().any(|c| c.device().as_bytes() == device))
    };
    for addr in node.connected(&target.id) {
        if let Ok(pong) = node.ping(&addr).await {
            // An open connection has no relay to remember; the cache keeps
            // what it had.
            return Ok(Reached {
                pong,
                last: None,
                list: None,
            });
        }
    }
    if let Some(last) = &target.last
        && current(&target.known, &last.device)
        && let Some(addr) = MeshAddr::from_parts(&last.device, &last.relay)
        && let Ok(pong) = node.ping(&addr).await
        && pong.peer.id == target.id
    {
        return Ok(Reached {
            pong,
            last: Some(last.clone()),
            list: None,
        });
    }

    let (records, newest) = find(anon, seeds, &target, now).await?;
    let mut pings = tokio::task::JoinSet::new();
    for record in records {
        let device = *record.device.as_bytes();
        let Some(addr) = MeshAddr::from_parts(&device, &record.relay) else {
            continue;
        };
        let node = node.clone();
        pings.spawn(async move {
            let last = LastAddr {
                device,
                relay: record.relay,
            };
            node.ping(&addr).await.map(|pong| (pong, last))
        });
    }
    while let Some(done) = pings.join_next().await {
        if let Ok(Ok((pong, last))) = done
            && pong.peer.id == target.id
        {
            return Ok(Reached {
                pong,
                last: Some(last),
                list: newest,
            });
        }
    }
    Err(ReachError::Unreachable)
}

/// Our other devices the seeds have records for (under the self pair), not
/// counting this one.
pub async fn own_devices(
    anon: &Node,
    seeds: &[MeshAddr],
    own: &Target,
    this: &[u8; 32],
    now: u64,
) -> Vec<MeshAddr> {
    let Ok((records, _)) = find(anon, seeds, own, now).await else {
        return Vec::new();
    };
    records
        .into_iter()
        .filter(|r| r.device.as_bytes() != this)
        .filter_map(|r| MeshAddr::from_parts(r.device.as_bytes(), &r.relay))
        .collect()
}

/// The contact's records on the seeds for today and yesterday (midnight, and
/// clocks that disagree), opened and checked: one per device, newest first,
/// only devices their newest known list still has. Also that list.
pub async fn find(
    anon: &Node,
    seeds: &[MeshAddr],
    target: &Target,
    now: u64,
) -> Result<(Vec<AddrRecord>, Option<DeviceList>), ReachError> {
    let today = day_of(now);
    let lookups =
        [today, today.saturating_sub(1)].map(|day| target.keys.lookup(&target.id, day).to_vec());
    let mut found: Vec<AddrRecord> = Vec::new();
    for addr in seeds {
        let Ok(answers) = seed::ask_many(anon, addr, seed::ADDR_GET, &lookups).await else {
            continue;
        };
        for answer in answers {
            if let Some(Get::Found(sealed)) = Get::from_bytes(&answer) {
                // Anything that doesn't open is someone else's, or junk.
                found.extend(
                    sealed
                        .iter()
                        .filter_map(|r| open_addr(&target.keys, &target.id, r, now).ok()),
                );
            }
        }
    }
    if found.is_empty() {
        return Err(ReachError::Unreachable);
    }
    let newest = found
        .iter()
        .map(|r| &r.devices)
        .chain(&target.known)
        .max_by_key(|l| l.seq())
        .cloned();
    if let Some(list) = &newest {
        found.retain(|r| list.is_current(&r.device));
    }
    if found.is_empty() {
        return Err(ReachError::RevokedDevice);
    }
    found.sort_by_key(|r| (*r.device.as_bytes(), Reverse(r.created_at)));
    found.dedup_by_key(|r| *r.device.as_bytes());
    found.sort_by_key(|r| Reverse(r.created_at));
    // A newer list than the one already known goes back to the keystore.
    let newer = newest.filter(|l| target.known.as_ref().is_none_or(|k| l.seq() > k.seq()));
    Ok((found, newer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_identity::RootKey;

    /// A change to one contact puts only their record, not everyone's
    /// (audit finding 9); a refresh still puts them all, and ours.
    #[test]
    fn one_contact_or_all_of_them() {
        let dir = std::env::temp_dir().join(format!("mesh-routing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let password = "correct horse battery staple";
        let mut store = Keystore::create(&dir.join("keystore"), "alice", password, "pc").unwrap();
        let ids: Vec<MeshId> = (0..3).map(|_| RootKey::generate().unwrap().id()).collect();
        for id in &ids {
            store.add_contact(*id, "").unwrap();
        }
        let relay: RelayUrl = "https://relay.example/".parse().unwrap();
        let all = records(&store, &relay, 1_800_000_000, RECORD_TTL, None, |_| {
            Vec::new()
        });
        assert_eq!(
            all.len(),
            ids.len() + 1,
            "every contact and our own devices"
        );
        let one = records(
            &store,
            &relay,
            1_800_000_000,
            RECORD_TTL,
            Some(&ids[1]),
            |_| Vec::new(),
        );
        assert_eq!(one.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
