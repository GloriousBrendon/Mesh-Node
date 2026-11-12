//! Pair keys (SPEC-routing D1, D2): what two people who added each other can
//! both work out from their IDs alone, and nobody else can. X25519 between one
//! root key and the other's ID gives the pair secret; separate blake3
//! contexts derive the lookup IDs, slots and the record key from it.
//!
//! A lookup ID is per (pair, sender, UTC day), so A→B and B→A records differ
//! and a pair's lookups can't be linked from one day to the next.

use ed25519_dalek::VerifyingKey;
use zeroize::Zeroizing;

use crate::id::{MeshId, RootKey};

const LOOKUP_CONTEXT: &str = "mesh/v1/pair-lookup";
const SLOT_CONTEXT: &str = "mesh/v1/pair-slot";
const RECORD_KEY_CONTEXT: &str = "mesh/v1/pair-record-key";
const KNOCK_SLOT_CONTEXT: &str = "mesh/v1/knock-slot";
const CONVERSATION_CONTEXT: &str = "mesh/v1/dm-conversation";
const MAIL_BOX_CONTEXT: &str = "mesh/v1/mail-box";
const MAIL_SLOT_CONTEXT: &str = "mesh/v1/mail-slot";
const MAIL_LOOKUP_CONTEXT: &str = "mesh/v1/mail-lookup";
/// A mail week (SPEC-mailbox M5): unix days / 7.
const WEEK: u64 = 7 * DAY;

/// The mail week a unix time falls in.
pub fn week_of(unix: u64) -> u64 {
    unix / WEEK
}
const DAY: u64 = 86_400;

/// The UTC day a unix time falls in.
pub fn day_of(unix: u64) -> u64 {
    unix / DAY
}

/// The keys one pair of IDs shares.
pub struct PairKeys {
    secret: Zeroizing<[u8; 32]>,
}

impl PairKeys {
    /// `None` if `their` is a weak key.
    pub fn new(mine: &RootKey, their: &MeshId) -> Option<Self> {
        Some(Self {
            secret: mine.diffie_hellman(their)?,
        })
    }

    /// Where `sender`'s records for this pair are found on `day`.
    pub fn lookup(&self, sender: &MeshId, day: u64) -> [u8; 16] {
        let hash = self
            .hasher(LOOKUP_CONTEXT)
            .update(&sender.to_bytes())
            .update(&day.to_be_bytes())
            .finalize();
        hash.as_bytes()[..16].try_into().expect("16 bytes")
    }

    /// Which slot under a lookup ID `device`'s record goes in.
    pub fn slot(&self, device: &VerifyingKey) -> [u8; 8] {
        let hash = self
            .hasher(SLOT_CONTEXT)
            .update(device.as_bytes())
            .finalize();
        hash.as_bytes()[..8].try_into().expect("8 bytes")
    }

    /// Where this pair's friend request goes under a code's lookup ID
    /// (SPEC-social D5): one per sender, so a resend replaces the last.
    pub fn knock_slot(&self, lookup_id: &[u8; 16]) -> [u8; 8] {
        let hash = self.hasher(KNOCK_SLOT_CONTEXT).update(lookup_id).finalize();
        hash.as_bytes()[..8].try_into().expect("8 bytes")
    }

    /// The pair's 1:1 conversation ID (SPEC-e2ee D10): both sides know it
    /// without asking, so two people can't end up with two chats.
    pub fn conversation(&self) -> [u8; 16] {
        let hash = self.hasher(CONVERSATION_CONTEXT).finalize();
        hash.as_bytes()[..16].try_into().expect("16 bytes")
    }

    /// The box `reader`'s mail from this pair sits in, in `week`
    /// (SPEC-mailbox M5).
    pub fn mail_box(&self, reader: &MeshId, week: u64) -> [u8; 16] {
        let hash = self
            .hasher(MAIL_BOX_CONTEXT)
            .update(&reader.to_bytes())
            .update(&week.to_be_bytes())
            .finalize();
        hash.as_bytes()[..16].try_into().expect("16 bytes")
    }

    /// Where `sender`'s mail records for this pair are found in `week`
    /// (SPEC-routing D3 as changed by mailbox).
    pub fn mail_lookup(&self, sender: &MeshId, week: u64) -> [u8; 16] {
        let hash = self
            .hasher(MAIL_LOOKUP_CONTEXT)
            .update(&sender.to_bytes())
            .update(&week.to_be_bytes())
            .finalize();
        hash.as_bytes()[..16].try_into().expect("16 bytes")
    }

    /// `device`'s slot in this pair's boxes.
    pub fn mail_slot(&self, device: &VerifyingKey) -> [u8; 8] {
        let hash = self
            .hasher(MAIL_SLOT_CONTEXT)
            .update(device.as_bytes())
            .finalize();
        hash.as_bytes()[..8].try_into().expect("8 bytes")
    }

    pub(crate) fn record_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.hasher(RECORD_KEY_CONTEXT).finalize().as_bytes())
    }

    fn hasher(&self, context: &str) -> blake3::Hasher {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(self.secret.as_ref());
        hasher
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::DeviceKey;

    #[test]
    fn both_sides_agree_and_nobody_else_does() {
        let (alice, bob, eve) = (
            RootKey::generate().unwrap(),
            RootKey::generate().unwrap(),
            RootKey::generate().unwrap(),
        );
        let ab = PairKeys::new(&alice, &bob.id()).unwrap();
        let ba = PairKeys::new(&bob, &alice.id()).unwrap();
        let eb = PairKeys::new(&eve, &bob.id()).unwrap();
        let device = DeviceKey::generate().unwrap().public();
        let day = day_of(1_800_000_000);

        assert_eq!(ab.lookup(&alice.id(), day), ba.lookup(&alice.id(), day));
        assert_eq!(ab.slot(&device), ba.slot(&device));
        assert_eq!(*ab.record_key(), *ba.record_key());
        assert_eq!(ab.conversation(), ba.conversation());
        assert_ne!(ab.conversation(), eb.conversation());

        assert_ne!(ab.lookup(&alice.id(), day), eb.lookup(&alice.id(), day));
        assert_ne!(*ab.record_key(), *eb.record_key());
    }

    #[test]
    fn direction_and_day_change_the_lookup() {
        let (alice, bob) = (RootKey::generate().unwrap(), RootKey::generate().unwrap());
        let keys = PairKeys::new(&alice, &bob.id()).unwrap();
        let day = day_of(1_800_000_000);
        assert_ne!(keys.lookup(&alice.id(), day), keys.lookup(&bob.id(), day));
        assert_ne!(
            keys.lookup(&alice.id(), day),
            keys.lookup(&alice.id(), day + 1)
        );
    }

    #[test]
    fn mail_boxes_are_the_pairs_alone_and_change_weekly() {
        let (alice, bob, eve) = (
            RootKey::generate().unwrap(),
            RootKey::generate().unwrap(),
            RootKey::generate().unwrap(),
        );
        let ab = PairKeys::new(&alice, &bob.id()).unwrap();
        let ba = PairKeys::new(&bob, &alice.id()).unwrap();
        let eb = PairKeys::new(&eve, &bob.id()).unwrap();
        let device = DeviceKey::generate().unwrap().public();
        let week = week_of(1_800_000_000);
        assert_eq!(week_of(7 * 86_400 - 1), 0);
        assert_eq!(week_of(7 * 86_400), 1);
        assert_eq!(ab.mail_box(&bob.id(), week), ba.mail_box(&bob.id(), week));
        assert_eq!(ab.mail_slot(&device), ba.mail_slot(&device));
        assert_ne!(ab.mail_box(&bob.id(), week), ab.mail_box(&alice.id(), week));
        assert_ne!(
            ab.mail_box(&bob.id(), week),
            ab.mail_box(&bob.id(), week + 1)
        );
        assert_ne!(ab.mail_box(&bob.id(), week), eb.mail_box(&bob.id(), week));
        assert_ne!(
            ab.mail_slot(&device),
            ab.slot(&device),
            "not the record slot"
        );
    }
}
