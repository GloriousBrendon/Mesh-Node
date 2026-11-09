//! Contacts (SPEC-routing D7): the IDs you've added, kept in the keystore
//! (encrypted, backed up). Routing finds only contacts, and only contacts
//! find you. `social` builds requests and blocking on this list.

use serde::{Deserialize, Serialize};

use crate::device::DeviceList;
use crate::id::MeshId;

/// A contact name's limit, in UTF-8 bytes.
pub const MAX_CONTACT_NAME: usize = 64;
/// Contacts one identity can have.
pub const MAX_CONTACTS: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    id: [u8; 32],
    pub name: String,
    /// Unix seconds.
    pub added: u64,
    /// The last successful handshake with one of their devices.
    pub seen: Option<u64>,
    /// The address that last worked, tried first next time.
    pub last: Option<LastAddr>,
    /// Their newest device list seen, so an older one can't bring back a
    /// removed device.
    devices: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastAddr {
    pub device: [u8; 32],
    pub relay: String,
}

impl Contact {
    pub(crate) fn new(id: MeshId, name: String, added: u64) -> Self {
        Self {
            id: id.to_bytes(),
            name,
            added,
            seen: None,
            last: None,
            devices: None,
        }
    }

    /// Whether the stored ID is a valid key (checked on load).
    pub(crate) fn valid(&self) -> bool {
        MeshId::from_bytes(&self.id).is_ok()
    }

    pub fn id(&self) -> MeshId {
        MeshId::from_bytes(&self.id).expect("checked when added")
    }

    /// Their newest device list seen, if any.
    pub fn devices(&self) -> Option<DeviceList> {
        DeviceList::from_bytes(self.devices.as_deref()?).ok()
    }

    /// Whether `list` is at least as new as the newest seen (and theirs).
    pub fn accepts(&self, list: &DeviceList) -> bool {
        list.root() == self.id() && self.devices().is_none_or(|known| list.seq() >= known.seq())
    }

    /// Records a successful handshake through `last`, keeping `list` if it's
    /// newer.
    pub(crate) fn reached(&mut self, last: LastAddr, list: &DeviceList, now: u64) {
        if self.accepts(list) {
            self.devices = Some(list.to_bytes());
        }
        self.seen = Some(now);
        self.last = Some(last);
    }
}

/// A contact name, trimmed; `None` if empty or too long.
pub(crate) fn clean_name(name: &str) -> Option<String> {
    let name = name.trim();
    (!name.is_empty() && name.len() <= MAX_CONTACT_NAME).then(|| name.to_owned())
}
