//! 1:1 sessions (D4, D5, D11): one Olm account per device, and a double
//! ratchet with each device it talks to, ours and theirs. The directory of
//! what's been seen for each person (their newest `DeviceList`, a bundle per
//! device, the one-time key they reserved for us, their fallback key) lives
//! here too, because a session may only be started or used with a device
//! that's current in it.
//!
//! The record field (D4), as it rides in an address record:
//!
//! ```text
//! bundle [137] | fallback key [32] | one-time key [32, optional]
//! ```
//!
//! An Olm envelope's payload is `sender curve key [32] | olm message`: the
//! reader needs the key to find the session, and it's never outside a seal.
//! What Olm encrypts is `sender ID [32] | sender device [32] | inside`. Only
//! the holder of the curve key can make that, so a bundle that copies
//! someone else's curve key can't pass their messages off as its own.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use ed25519_dalek::VerifyingKey;
use mesh_identity::{DeviceKey, DeviceList, MeshId, PairKeys, RootKey};
use serde::{Deserialize, Serialize};
use vodozemac::Curve25519PublicKey;
use vodozemac::olm::{
    Account, AccountPickle, DecryptionError, Message, OlmMessage, PreKeyMessage, Session,
    SessionConfig, SessionPickle,
};

use crate::E2eeError;
use crate::bundle::{Bundle, MAX_BUNDLE_LEN};
use crate::envelope::{Envelope, EnvelopeType, Inside, Kind};
use crate::group::{GroupFile, Groups};
use crate::store::{ACCOUNT, Store};

/// One-time keys kept reserved for contacts, at most (D4).
pub const MAX_ONE_TIME_KEYS: usize = 200;
/// How often the fallback key is replaced.
pub const FALLBACK_LIFE: u64 = 7 * 24 * 3600;
/// Sessions kept per device: two can exist when both sides start at once.
const SESSIONS_PER_DEVICE: usize = 4;
/// First messages remembered per person, so one isn't opened twice.
const FIRST_MESSAGES_KEPT: usize = 1000;
/// How often a device may get a fresh session after a first message we
/// couldn't open.
const UNWEDGE_EVERY: u64 = 3600;
/// The longest record field.
pub const MAX_FIELD_LEN: usize = MAX_BUNDLE_LEN + 64;
const _: () = assert!(MAX_FIELD_LEN <= mesh_identity::MAX_E2EE_FIELD);

type Key = [u8; 32];

/// Where an opened message belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conversation {
    /// A 1:1 conversation with this person (on our own devices too).
    Direct(MeshId),
    Group([u8; 16]),
}

/// An opened, checked message, ready to hand up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub conversation: Conversation,
    pub sender: MeshId,
    pub device: VerifyingKey,
    pub kind: Kind,
    pub body: Vec<u8>,
}

/// What an envelope gave: messages to hand up (none, or several when a key
/// share lets waiting ones open), and envelopes to send back to devices.
#[derive(Debug, Default)]
pub struct Received {
    pub opened: Vec<Opened>,
    pub replies: Vec<(VerifyingKey, Vec<u8>)>,
}

/// One device's keys, as its record gave them.
pub(crate) struct Keys {
    pub(crate) bundle: Bundle,
    fallback: Key,
    one_time: Option<Key>,
    /// The one-time key a session was started from, so a stale record
    /// can't hand it back.
    used: Option<Key>,
}

/// What we know about one person (or about ourselves).
pub(crate) struct Person {
    pub(crate) devices: DeviceList,
    pub(crate) keys: HashMap<Key, Keys>,
    sessions: HashMap<Key, VecDeque<Session>>,
    /// Curve keys of devices dropped from the list, to answer revoked-device.
    revoked: Vec<Key>,
    first_messages: VecDeque<String>,
}

impl Person {
    fn to_file(&self) -> PersonFile {
        PersonFile {
            devices: self.devices.to_bytes(),
            keys: (self.keys.iter())
                .map(|(device, k)| {
                    let file = KeysFile {
                        curve: k.bundle.curve,
                        ed25519: k.bundle.ed25519,
                        created_at: k.bundle.created_at,
                        fallback: k.fallback,
                        one_time: k.one_time,
                        used: k.used,
                    };
                    (*device, file)
                })
                .collect(),
            sessions: (self.sessions.iter())
                .map(|(d, s)| (*d, s.iter().map(Session::pickle).collect()))
                .collect(),
            revoked: self.revoked.clone(),
            first_messages: self.first_messages.iter().cloned().collect(),
        }
    }

    fn from_file(file: PersonFile) -> Result<Self, E2eeError> {
        let bad = E2eeError::Store;
        let mut keys = HashMap::new();
        for (device, k) in file.keys {
            let bundle = Bundle {
                device: VerifyingKey::from_bytes(&device).map_err(|_| bad)?,
                curve: k.curve,
                ed25519: k.ed25519,
                created_at: k.created_at,
            };
            let (fallback, one_time, used) = (k.fallback, k.one_time, k.used);
            keys.insert(
                device,
                Keys {
                    bundle,
                    fallback,
                    one_time,
                    used,
                },
            );
        }
        let sessions = (file.sessions.into_iter())
            .map(|(d, s)| (d, s.into_iter().map(Session::from_pickle).collect()))
            .collect();
        Ok(Self {
            devices: DeviceList::from_bytes(&file.devices).map_err(|_| bad)?,
            keys,
            sessions,
            revoked: file.revoked,
            first_messages: file.first_messages.into(),
        })
    }

    fn new(devices: DeviceList) -> Self {
        Self {
            devices,
            keys: HashMap::new(),
            sessions: HashMap::new(),
            revoked: Vec::new(),
            first_messages: VecDeque::new(),
        }
    }

    /// Current devices we can encrypt to (a session or keys), as bytes and
    /// as keys: decompressing a key costs more than encrypting a message.
    fn reachable(&self) -> Vec<(Key, VerifyingKey)> {
        self.devices
            .devices()
            .iter()
            .map(|cert| (cert.device().to_bytes(), *cert.device()))
            .filter(|(d, _)| self.keys.contains_key(d) || self.sessions.contains_key(d))
            .collect()
    }
}

/// This device's end-to-end state.
pub struct E2ee {
    /// Saves that wrote something (tests count them).
    #[cfg(test)]
    pub(crate) saves: usize,
    root: RootKey,
    device: DeviceKey,
    pub(crate) me: MeshId,
    account: Account,
    bundle: Vec<u8>,
    fallback: Key,
    fallback_at: u64,
    /// The one-time key reserved for each contact.
    reserved: HashMap<MeshId, Key>,
    pub(crate) people: HashMap<MeshId, Person>,
    /// 1:1 conversation IDs, to place our own devices' copies.
    direct: HashMap<[u8; 16], MeshId>,
    pub(crate) groups: Groups,
    /// When each device last got a fresh session from `unwedge`. In memory:
    /// a restart allowing one more is fine.
    unwedged: HashMap<Key, u64>,
    /// `None` keeps everything in memory (tests).
    store: Option<Store>,
    pub(crate) dirty: Dirty,
}

/// What changed since the last save (D12).
#[derive(Default)]
pub(crate) struct Dirty {
    pub(crate) account: bool,
    pub(crate) people: HashSet<MeshId>,
    pub(crate) groups: HashSet<[u8; 16]>,
}

#[derive(Serialize, Deserialize)]
struct AccountFile {
    device: Key,
    account: AccountPickle,
    bundle: Vec<u8>,
    fallback: Key,
    fallback_at: u64,
    reserved: Vec<(Key, Key)>,
    people: Vec<Key>,
    groups: Vec<[u8; 16]>,
    waiting: Vec<(u64, Vec<u8>)>,
    requested: Vec<Key>,
}

#[derive(Serialize, Deserialize)]
struct KeysFile {
    curve: Key,
    ed25519: Key,
    created_at: u64,
    fallback: Key,
    one_time: Option<Key>,
    used: Option<Key>,
}

#[derive(Serialize, Deserialize)]
struct PersonFile {
    devices: Vec<u8>,
    keys: Vec<(Key, KeysFile)>,
    sessions: Vec<(Key, Vec<SessionPickle>)>,
    revoked: Vec<Key>,
    first_messages: Vec<String>,
}

impl E2ee {
    /// A new Olm account for `device`, one of `devices` (our own list).
    pub fn new(
        root: &RootKey,
        device: &DeviceKey,
        devices: &DeviceList,
        now: u64,
    ) -> Result<Self, E2eeError> {
        let account = Account::new();
        let keys = account.identity_keys();
        let bundle = Bundle::sign(
            device,
            keys.curve25519.to_bytes(),
            *keys.ed25519.as_bytes(),
            now,
        );
        let mut e2ee = Self {
            root: RootKey::from_secret_bytes(*root.secret_bytes()),
            device: DeviceKey::from_secret_bytes(*device.secret_bytes()),
            me: root.id(),
            account,
            bundle,
            fallback: [0; 32],
            fallback_at: 0,
            reserved: HashMap::new(),
            people: HashMap::new(),
            direct: HashMap::new(),
            groups: Groups::default(),
            unwedged: HashMap::new(),
            store: None,
            dirty: Dirty::default(),
            #[cfg(test)]
            saves: 0,
        };
        e2ee.renew_fallback(now);
        e2ee.take_devices(&root.id(), devices);
        Ok(e2ee)
    }

    /// Opens this device's state from `<data>/e2ee/`, or starts it there.
    /// State left by another device key (a restored backup gets a new one)
    /// is cleared: sessions never come back from a backup (Q5).
    pub fn open(
        data: &Path,
        data_key: &[u8; 32],
        root: &RootKey,
        device: &DeviceKey,
        devices: &DeviceList,
        now: u64,
    ) -> Result<Self, E2eeError> {
        let store = Store::new(&data.join("e2ee"), data_key);
        let file: Option<AccountFile> = store.read(ACCOUNT)?;
        let mut e2ee = match file {
            Some(file) if file.device == device.public().to_bytes() => {
                Self::load(store, file, root, device)?
            }
            _ => {
                store.clear()?;
                let mut e2ee = Self::new(root, device, devices, now)?;
                e2ee.store = Some(store);
                e2ee.dirty.account = true;
                e2ee.dirty.people.insert(root.id());
                e2ee
            }
        };
        e2ee.take_devices(&root.id(), devices);
        e2ee.save()?;
        Ok(e2ee)
    }

    fn load(
        store: Store,
        file: AccountFile,
        root: &RootKey,
        device: &DeviceKey,
    ) -> Result<Self, E2eeError> {
        let mut people = HashMap::new();
        let mut direct = HashMap::new();
        for id in &file.people {
            let id = MeshId::from_bytes(id).map_err(|_| E2eeError::Store)?;
            let person: PersonFile = store
                .read(&store.name(b"person", &id.to_bytes()))?
                .ok_or(E2eeError::Store)?;
            if id != root.id()
                && let Some(keys) = PairKeys::new(root, &id)
            {
                direct.insert(keys.conversation(), id);
            }
            people.insert(id, Person::from_file(person)?);
        }
        let mut groups = Groups::default();
        for conversation in &file.groups {
            let group: GroupFile = store
                .read(&store.name(b"group", conversation))?
                .ok_or(E2eeError::Store)?;
            groups.load(*conversation, group)?;
        }
        groups.waiting = file.waiting;
        groups.requested = file.requested.into_iter().collect();
        let reserved = file.reserved.iter().map(|(id, key)| {
            MeshId::from_bytes(id)
                .map(|id| (id, *key))
                .map_err(|_| E2eeError::Store)
        });
        Ok(Self {
            root: RootKey::from_secret_bytes(*root.secret_bytes()),
            device: DeviceKey::from_secret_bytes(*device.secret_bytes()),
            me: root.id(),
            account: Account::from_pickle(file.account),
            bundle: file.bundle,
            fallback: file.fallback,
            fallback_at: file.fallback_at,
            reserved: reserved.collect::<Result<_, _>>()?,
            people,
            direct,
            groups,
            unwedged: HashMap::new(),
            store: Some(store),
            dirty: Dirty::default(),
            #[cfg(test)]
            saves: 0,
        })
    }

    /// Writes what changed: people and groups first, then the account that
    /// lists them. Called before any ciphertext or plaintext is handed out.
    pub(crate) fn save(&mut self) -> Result<(), E2eeError> {
        let dirty = std::mem::take(&mut self.dirty);
        #[cfg(test)]
        if dirty.account || !dirty.people.is_empty() || !dirty.groups.is_empty() {
            self.saves += 1;
        }
        let Some(store) = &self.store else {
            return Ok(());
        };
        for id in &dirty.people {
            if let Some(person) = self.people.get(id) {
                store.write(&store.name(b"person", &id.to_bytes()), &person.to_file())?;
            }
        }
        for conversation in &dirty.groups {
            if let Some(group) = self.groups.file(conversation) {
                store.write(&store.name(b"group", conversation), &group)?;
            }
        }
        if dirty.account {
            let file = AccountFile {
                device: self.device_bytes(),
                account: self.account.pickle(),
                bundle: self.bundle.clone(),
                fallback: self.fallback,
                fallback_at: self.fallback_at,
                reserved: self
                    .reserved
                    .iter()
                    .map(|(id, k)| (id.to_bytes(), *k))
                    .collect(),
                people: self.people.keys().map(MeshId::to_bytes).collect(),
                groups: self.groups.conversations(),
                waiting: self.groups.waiting.clone(),
                requested: self.groups.requested.iter().copied().collect(),
            };
            store.write(ACCOUNT, &file)?;
        }
        Ok(())
    }

    /// This device's signed bundle.
    pub fn bundle(&self) -> &[u8] {
        &self.bundle
    }

    fn renew_fallback(&mut self, now: u64) {
        self.account.generate_fallback_key();
        let key = self.account.fallback_key().into_values().next();
        self.fallback = key.expect("a fallback key was just made").to_bytes();
        self.account.mark_keys_as_published();
        self.fallback_at = now;
    }

    /// The field for this device's address record for `contact` (D4): the
    /// bundle, the fallback key and the one-time key reserved for them. Our
    /// own ID gets one too, for our other devices.
    pub fn record_field(&mut self, contact: &MeshId, now: u64) -> Result<Vec<u8>, E2eeError> {
        if now >= self.fallback_at + FALLBACK_LIFE {
            self.renew_fallback(now);
            self.dirty.account = true;
        }
        if !self.reserved.contains_key(contact) && self.reserved.len() < MAX_ONE_TIME_KEYS {
            let made = self.account.generate_one_time_keys(1);
            self.account.mark_keys_as_published();
            // At 200 the account never evicts (it holds 5,000).
            if let Some(key) = made.created.first() {
                self.reserved.insert(*contact, key.to_bytes());
            }
            self.dirty.account = true;
        }
        self.save()?;
        let mut out = self.bundle.clone();
        out.extend_from_slice(&self.fallback);
        if let Some(key) = self.reserved.get(contact) {
            out.extend_from_slice(key);
        }
        Ok(out)
    }

    /// Takes the newest device list seen for `id` (D11). A device it drops
    /// loses its keys and sessions. True when the list was newer.
    pub fn learn_devices(&mut self, id: &MeshId, devices: &DeviceList) -> Result<bool, E2eeError> {
        let newer = self.take_devices(id, devices);
        self.save()?;
        Ok(newer)
    }

    fn take_devices(&mut self, id: &MeshId, devices: &DeviceList) -> bool {
        if devices.root() != *id {
            return false;
        }
        let person = match self.people.get_mut(id) {
            Some(person) => {
                if devices.seq() <= person.devices.seq()
                    || devices.replaces(&person.devices).is_err()
                {
                    return false;
                }
                person
            }
            None => {
                if *id != self.me
                    && let Some(keys) = PairKeys::new(&self.root, id)
                {
                    self.direct.insert(keys.conversation(), *id);
                }
                self.people.insert(*id, Person::new(devices.clone()));
                self.dirty.account = true;
                self.dirty.people.insert(*id);
                return true;
            }
        };
        person.devices = devices.clone();
        let current =
            |d: &Key| VerifyingKey::from_bytes(d).is_ok_and(|key| devices.is_current(&key));
        let dropped: Vec<Key> = person
            .keys
            .keys()
            .filter(|d| !current(d))
            .copied()
            .collect();
        for device in dropped {
            if let Some(keys) = person.keys.remove(&device) {
                person.revoked.push(keys.bundle.curve);
            }
        }
        person.sessions.retain(|d, _| current(d));
        self.dirty.people.insert(*id);
        true
    }

    /// Learns a device's keys from the field of a record it left for us.
    /// `devices` is the list the record carried, `device` its device.
    pub fn learn(
        &mut self,
        id: &MeshId,
        devices: &DeviceList,
        device: &VerifyingKey,
        field: &[u8],
    ) -> Result<(), E2eeError> {
        if field.len() != MAX_BUNDLE_LEN + 32 && field.len() != MAX_FIELD_LEN {
            return Err(E2eeError::Malformed);
        }
        self.take_devices(id, devices);
        let person = self.people.get_mut(id).ok_or(E2eeError::Malformed)?;
        let bundle = Bundle::open(&field[..MAX_BUNDLE_LEN], &person.devices)?;
        if bundle.device != *device {
            return Err(E2eeError::Malformed);
        }
        let key = |at: usize| -> Key { field[at..at + 32].try_into().expect("32 bytes") };
        let fallback = key(MAX_BUNDLE_LEN);
        // The key is reserved per person, so only our first device takes it;
        // the others start on the fallback key (finding 1).
        // ponytail: until records carry one key per reader device.
        let first = self.people.get(&self.me).and_then(|me| {
            let mut ours = me.devices.devices().iter().map(|c| *c.device());
            ours.find(|d| d != device)
        });
        let takes_it = first == Some(self.device.public());
        let one_time = (field.len() == MAX_FIELD_LEN && takes_it).then(|| key(MAX_BUNDLE_LEN + 32));
        let person = self.people.get_mut(id).expect("taken above");
        let entry = person.keys.entry(device.to_bytes());
        let keys = entry.or_insert(Keys {
            bundle,
            fallback,
            one_time: None,
            used: None,
        });
        if keys.bundle.curve != bundle.curve {
            // A new account on the same device: its old sessions are useless.
            person.sessions.remove(&device.to_bytes());
            keys.used = None;
        }
        keys.bundle = bundle;
        keys.fallback = fallback;
        keys.one_time = one_time.filter(|k| keys.used != Some(*k));
        self.dirty.people.insert(*id);
        self.save()
    }

    /// Encrypts `body` for a 1:1 conversation with `peer`: once for each of
    /// their current devices and each of our other ones (D5).
    pub fn encrypt_direct(
        &mut self,
        peer: &MeshId,
        kind: Kind,
        body: &[u8],
    ) -> Result<Vec<(VerifyingKey, Vec<u8>)>, E2eeError> {
        if *peer == self.me {
            return Err(E2eeError::NotMember);
        }
        let conversation = PairKeys::new(&self.root, peer)
            .ok_or(E2eeError::NoKeys)?
            .conversation();
        let theirs = self
            .people
            .get(peer)
            .map(Person::reachable)
            .unwrap_or_default();
        if theirs.is_empty() {
            return Err(E2eeError::NoKeys);
        }
        let inside = self.inside(conversation, kind, body)?;
        let mut targets: Vec<_> = theirs.into_iter().map(|d| (*peer, d)).collect();
        targets.extend(self.own_devices().into_iter().map(|d| (self.me, d)));
        let out = targets
            .into_iter()
            .map(|(id, (device, key))| Ok((key, self.encrypt_to(&id, &device, &inside)?)))
            .collect::<Result<_, E2eeError>>()?;
        self.save()?;
        Ok(out)
    }

    /// Encrypts each body for one of `peer`'s current devices only, saving
    /// once before any ciphertext is handed out. dm sends each device what
    /// it hasn't acknowledged, device by device (SPEC-dm D5).
    pub fn encrypt_device_batch(
        &mut self,
        peer: &MeshId,
        device: &[u8; 32],
        kind: Kind,
        bodies: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, E2eeError> {
        if *peer == self.me {
            return Err(E2eeError::NotMember);
        }
        let conversation = PairKeys::new(&self.root, peer)
            .ok_or(E2eeError::NoKeys)?
            .conversation();
        let theirs = self
            .people
            .get(peer)
            .map(Person::reachable)
            .unwrap_or_default();
        let (curve, _) = theirs
            .into_iter()
            .find(|(_, key)| key.as_bytes() == device)
            .ok_or(E2eeError::NoKeys)?;
        let mut out = Vec::with_capacity(bodies.len());
        for body in bodies {
            let inside = self.inside(conversation, kind, body)?;
            out.push(self.encrypt_to(peer, &curve, &inside)?);
        }
        self.save()?;
        Ok(out)
    }

    /// Whether we can encrypt to any of `id`'s devices.
    pub fn knows(&self, id: &MeshId) -> bool {
        !self.reachable_of(id).is_empty()
    }

    /// How many of `id`'s devices we can encrypt to.
    pub fn devices_known(&self, id: &MeshId) -> usize {
        self.reachable_of(id).len()
    }

    /// `id`'s current devices we can reach.
    pub(crate) fn reachable_of(&self, id: &MeshId) -> Vec<(Key, VerifyingKey)> {
        self.people
            .get(id)
            .map(Person::reachable)
            .unwrap_or_default()
    }

    /// Our other current devices we can reach.
    pub(crate) fn own_devices(&self) -> Vec<(Key, VerifyingKey)> {
        let me = self.device_bytes();
        let mut own = self.reachable_of(&self.me);
        own.retain(|(d, _)| *d != me);
        own
    }

    pub(crate) fn inside(
        &self,
        conversation: [u8; 16],
        kind: Kind,
        body: &[u8],
    ) -> Result<Vec<u8>, E2eeError> {
        let seq = self.people.get(&self.me).map_or(0, |p| p.devices.seq());
        Inside {
            conversation,
            kind,
            seq,
            body: body.to_vec(),
        }
        .to_bytes()
    }

    /// Encrypts padded `inside` bytes over the session with one device,
    /// starting one from its keys if there's none yet.
    pub(crate) fn encrypt_to(
        &mut self,
        id: &MeshId,
        device: &Key,
        inside: &[u8],
    ) -> Result<Vec<u8>, E2eeError> {
        let plain = self.claim(inside);
        self.dirty.people.insert(*id);
        let person = self.people.get_mut(id).ok_or(E2eeError::NoKeys)?;
        if person.sessions.get(device).is_none_or(VecDeque::is_empty) {
            start_session(&self.account, person, device)?;
        }
        let sessions = person.sessions.get_mut(device).expect("a session");
        let session = sessions.front_mut().expect("a session");
        let (kind, message) = match session.encrypt(&plain).map_err(|_| E2eeError::NoKeys)? {
            OlmMessage::PreKey(m) => (EnvelopeType::OlmFirst, m.to_bytes()),
            OlmMessage::Normal(m) => (EnvelopeType::Olm, m.to_bytes()),
        };
        let mut payload = self.curve().to_vec();
        payload.extend_from_slice(&message);
        Ok(Envelope { kind, payload }.to_bytes())
    }

    /// The devices whose bundles name `curve`. Normally one; a bundle can
    /// claim someone else's curve key, so the opened message's own claim
    /// settles it.
    pub(crate) fn candidates(&self, curve: &Key) -> Result<Vec<(MeshId, Key)>, E2eeError> {
        let mut found = Vec::new();
        let mut revoked = false;
        for (id, person) in &self.people {
            let devices = person.keys.iter().filter(|(_, k)| k.bundle.curve == *curve);
            found.extend(devices.map(|(device, _)| (*id, *device)));
            revoked |= person.revoked.contains(curve);
        }
        match (found.is_empty(), revoked) {
            (false, _) => Ok(found),
            (true, true) => Err(E2eeError::RevokedDevice),
            (true, false) => Err(E2eeError::UnknownSender),
        }
    }

    /// What we encrypt: who we are, then the inside. Olm and Megolm
    /// authenticate it, so only the sending device can make the claim.
    pub(crate) fn claim(&self, inside: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + inside.len());
        out.extend_from_slice(&self.me.to_bytes());
        out.extend_from_slice(&self.device_bytes());
        out.extend_from_slice(inside);
        out
    }

    pub(crate) fn device_bytes(&self) -> Key {
        self.device.public().to_bytes()
    }

    pub(crate) fn curve(&self) -> Key {
        self.account.curve25519_key().to_bytes()
    }

    /// Opens an Olm envelope: returns who sent it and the inside.
    pub(crate) fn open_olm(
        &mut self,
        envelope: &Envelope,
    ) -> Result<(MeshId, VerifyingKey, Inside), E2eeError> {
        let curve: Key = envelope
            .payload
            .get(..32)
            .and_then(|k| k.try_into().ok())
            .ok_or(E2eeError::Malformed)?;
        let message = &envelope.payload[32..];
        let candidates = self.candidates(&curve)?;
        let message = match envelope.kind {
            EnvelopeType::OlmFirst => OlmMessage::PreKey(
                PreKeyMessage::from_bytes(message).map_err(|_| E2eeError::Malformed)?,
            ),
            EnvelopeType::Olm => {
                OlmMessage::Normal(Message::from_bytes(message).map_err(|_| E2eeError::Malformed)?)
            }
            EnvelopeType::Group => return Err(E2eeError::Malformed),
        };
        let mut found = None;
        let mut result = Err(E2eeError::CantOpen);
        'search: for (id, device) in &candidates {
            let person = self.people.get_mut(id).expect("a candidate");
            let sessions = person.sessions.entry(*device).or_default();
            for at in 0..sessions.len() {
                if let OlmMessage::PreKey(m) = &message
                    && sessions[at].session_id() != m.session_id()
                {
                    continue;
                }
                match decrypt(&mut sessions[at], &message) {
                    Ok(plain) => {
                        let session = sessions.remove(at).expect("in range");
                        sessions.push_front(session);
                        found = Some((*id, *device));
                        result = Ok(plain);
                        break 'search;
                    }
                    Err(E2eeError::Replay) => result = Err(E2eeError::Replay),
                    Err(_) => {}
                }
            }
        }
        if let (None, OlmMessage::PreKey(m)) = (found, &message) {
            if m.identity_key().to_bytes() != curve {
                return Err(E2eeError::Malformed);
            }
            let session_id = m.session_id();
            let seen = |id: &MeshId| self.people[id].first_messages.contains(&session_id);
            if candidates.iter().any(|(id, _)| seen(id)) {
                return Err(E2eeError::Replay);
            }
            let created = self
                .account
                .create_inbound_session(
                    SessionConfig::version_1(),
                    Curve25519PublicKey::from_bytes(curve),
                    m,
                )
                .map_err(|_| E2eeError::CantOpen)?;
            let one_time = m.one_time_key().to_bytes();
            self.reserved.retain(|_, k| *k != one_time);
            self.dirty.account = true;
            let (id, device) = claimed(&created.plaintext)?;
            if !candidates.contains(&(id, device)) {
                return Err(E2eeError::CantOpen);
            }
            let person = self.people.get_mut(&id).expect("a candidate");
            let sessions = person.sessions.entry(device).or_default();
            sessions.push_front(created.session);
            sessions.truncate(SESSIONS_PER_DEVICE);
            person.first_messages.push_back(session_id);
            if person.first_messages.len() > FIRST_MESSAGES_KEPT {
                person.first_messages.pop_front();
            }
            found = Some((id, device));
            result = Ok(created.plaintext);
        }
        let plain = result?;
        let found = found.expect("set with the plaintext");
        self.dirty.people.insert(found.0);
        if claimed(&plain)? != found {
            return Err(E2eeError::CantOpen);
        }
        let inside = Inside::from_bytes(&plain[64..])?;
        Ok((found.0, key_of(&found.1)?, inside))
    }

    /// Opens an envelope that came straight over a connection, or out of a
    /// seal, and checks where it belongs (D11). What it holds, and anything
    /// it means sending back, is in the answer.
    pub fn decrypt(&mut self, bytes: &[u8], now: u64) -> Result<Received, E2eeError> {
        let opened = self.open_envelope(bytes, now);
        self.save()?;
        opened
    }

    /// Opens many envelopes, then saves the state once before handing any
    /// of it up: 10,000 events mustn't mean 10,000 rewrites of the state
    /// (SPEC-dm D11). Each envelope gets its own result; a failed save fails
    /// the batch, and nothing in it is handed up.
    pub fn decrypt_batch(
        &mut self,
        envelopes: &[Vec<u8>],
        now: u64,
    ) -> Result<Vec<Result<Received, E2eeError>>, E2eeError> {
        let opened = envelopes
            .iter()
            .map(|e| self.open_envelope(e, now))
            .collect();
        self.save()?;
        Ok(opened)
    }

    /// `decrypt` without the save.
    fn open_envelope(&mut self, bytes: &[u8], now: u64) -> Result<Received, E2eeError> {
        let envelope = Envelope::from_bytes(bytes)?;
        let mut out = Received::default();
        if envelope.kind == EnvelopeType::Group {
            self.open_group(bytes, &envelope, now, &mut out)?;
            return Ok(out);
        }
        let (sender, device, inside) = match self.open_olm(&envelope) {
            Err(E2eeError::CantOpen) if envelope.kind == EnvelopeType::OlmFirst => {
                return self.unwedge(&envelope, now);
            }
            opened => opened?,
        };
        match inside.kind {
            Kind::KeyShare => self.take_share(sender, &inside, now, &mut out)?,
            Kind::KeyRequest => {
                self.answer_request(sender, device.to_bytes(), &inside, &mut out)?
            }
            _ => out.opened.push(self.place_direct(sender, device, inside)?),
        }
        Ok(out)
    }

    /// A first message from a known device that we can't open: it was
    /// started from a key we no longer hold. Answer on a fresh session, so
    /// the sender moves to it (Olm uses the newest session that worked). At
    /// most once an hour per device, since the sender's curve key is outside
    /// the encryption and anyone who can reach us could claim it.
    fn unwedge(&mut self, envelope: &Envelope, now: u64) -> Result<Received, E2eeError> {
        let curve: Key = envelope.payload[..32]
            .try_into()
            .expect("checked by open_olm");
        let [(id, device)] = self.candidates(&curve)?[..] else {
            return Err(E2eeError::CantOpen);
        };
        let current = self.people[&id].devices.is_current(&key_of(&device)?);
        let recent = self
            .unwedged
            .get(&device)
            .is_some_and(|at| now < at + UNWEDGE_EVERY);
        if !current || recent {
            return Err(E2eeError::CantOpen);
        }
        self.unwedged.insert(device, now);
        let person = self.people.get_mut(&id).expect("a candidate");
        start_session(&self.account, person, &device).map_err(|_| E2eeError::CantOpen)?;
        // A key request for no chain: the reader opens it and does nothing.
        let inside = self.inside([0; 16], Kind::KeyRequest, &[0; 36])?;
        let reply = self.encrypt_to(&id, &device, &inside)?;
        Ok(Received {
            opened: Vec::new(),
            replies: vec![(key_of(&device)?, reply)],
        })
    }

    /// Checks a 1:1 message's conversation and places it.
    fn place_direct(
        &self,
        sender: MeshId,
        device: VerifyingKey,
        inside: Inside,
    ) -> Result<Opened, E2eeError> {
        let peer = if sender == self.me {
            *self
                .direct
                .get(&inside.conversation)
                .ok_or(E2eeError::NotMember)?
        } else {
            let ours = PairKeys::new(&self.root, &sender).map(|k| k.conversation());
            if ours != Some(inside.conversation) {
                return Err(E2eeError::NotMember);
            }
            sender
        };
        Ok(Opened {
            conversation: Conversation::Direct(peer),
            sender,
            device,
            kind: inside.kind,
            body: inside.body,
        })
    }
}

/// Starts a new outbound session with `device`, in front of any others:
/// from its one-time key if we hold one, else its fallback key.
fn start_session(account: &Account, person: &mut Person, device: &Key) -> Result<(), E2eeError> {
    let keys = person.keys.get_mut(device).ok_or(E2eeError::NoKeys)?;
    let one_time = keys.one_time.take().unwrap_or(keys.fallback);
    keys.used = Some(one_time);
    let session = account
        .create_outbound_session(
            SessionConfig::version_1(),
            Curve25519PublicKey::from_bytes(keys.bundle.curve),
            Curve25519PublicKey::from_bytes(one_time),
        )
        .map_err(|_| E2eeError::NoKeys)?;
    let sessions = person.sessions.entry(*device).or_default();
    sessions.push_front(session);
    sessions.truncate(SESSIONS_PER_DEVICE);
    Ok(())
}

fn decrypt(session: &mut Session, message: &OlmMessage) -> Result<Vec<u8>, E2eeError> {
    session.decrypt(message).map_err(|e| match e {
        DecryptionError::MissingMessageKey(_) => E2eeError::Replay,
        _ => E2eeError::CantOpen,
    })
}

/// The sender a plaintext claims: root ID and device key.
pub(crate) fn claimed(plain: &[u8]) -> Result<(MeshId, Key), E2eeError> {
    let bad = E2eeError::Malformed;
    let root: &[u8; 32] = plain.get(..32).ok_or(bad)?.try_into().expect("32 bytes");
    let device: Key = plain.get(32..64).ok_or(bad)?.try_into().expect("32 bytes");
    Ok((MeshId::from_bytes(root).map_err(|_| bad)?, device))
}

pub(crate) fn key_of(device: &Key) -> Result<VerifyingKey, E2eeError> {
    VerifyingKey::from_bytes(device).map_err(|_| E2eeError::Malformed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bundle::tests::{NOW, Person as Who, person};
    use mesh_identity::DeviceCert;

    /// A person's device with its e2ee state.
    pub struct Device {
        pub who: Who,
        pub e2ee: E2ee,
    }

    pub fn device() -> Device {
        let who = person();
        let e2ee = E2ee::new(&who.root, &who.device, &who.devices, NOW).unwrap();
        Device { who, e2ee }
    }

    /// `a` learns `b`'s keys from the record `b` left for `a`.
    pub fn introduce(a: &mut Device, b: &mut Device) {
        let field = b.e2ee.record_field(&a.who.root.id(), NOW).unwrap();
        a.e2ee
            .learn(
                &b.who.root.id(),
                &b.who.devices,
                &b.who.device.public(),
                &field,
            )
            .unwrap();
    }

    pub fn friends(a: &mut Device, b: &mut Device) {
        introduce(a, b);
        introduce(b, a);
    }

    impl E2ee {
        /// Opens an envelope that holds exactly one message. One that opens
        /// nothing (a fresh session was sent back instead) is `CantOpen`.
        pub fn open1(&mut self, envelope: &[u8]) -> Result<Opened, E2eeError> {
            let mut got = self.decrypt(envelope, NOW)?;
            if got.opened.is_empty() {
                return Err(E2eeError::CantOpen);
            }
            assert_eq!(got.opened.len(), 1);
            Ok(got.opened.pop().unwrap())
        }
    }

    fn only(out: Vec<(VerifyingKey, Vec<u8>)>) -> Vec<u8> {
        assert_eq!(out.len(), 1);
        out.into_iter().next().unwrap().1
    }

    #[test]
    fn first_message_from_a_one_time_key_then_replies() {
        let (mut alice, mut bob) = (device(), device());
        friends(&mut alice, &mut bob);
        let to_bob = only(
            alice
                .e2ee
                .encrypt_direct(&bob.who.root.id(), Kind::TestNote, b"hi")
                .unwrap(),
        );
        assert_eq!(to_bob[1], EnvelopeType::OlmFirst as u8);
        let opened = bob.e2ee.open1(&to_bob).unwrap();
        assert_eq!(
            opened.conversation,
            Conversation::Direct(alice.who.root.id())
        );
        assert_eq!(opened.sender, alice.who.root.id());
        assert_eq!(opened.device, alice.who.device.public());
        assert_eq!(
            (opened.kind, &opened.body[..]),
            (Kind::TestNote, &b"hi"[..])
        );
        // Bob's reservation for Alice is spent.
        assert!(!bob.e2ee.reserved.contains_key(&alice.who.root.id()));

        let to_alice = only(
            bob.e2ee
                .encrypt_direct(&alice.who.root.id(), Kind::TestNote, b"yo")
                .unwrap(),
        );
        assert_eq!(to_alice[1], EnvelopeType::Olm as u8);
        assert_eq!(alice.e2ee.open1(&to_alice).unwrap().body, b"yo");
        let again = only(
            alice
                .e2ee
                .encrypt_direct(&bob.who.root.id(), Kind::TestNote, b"2")
                .unwrap(),
        );
        assert_eq!(again[1], EnvelopeType::Olm as u8);
        assert_eq!(bob.e2ee.open1(&again).unwrap().body, b"2");
    }

    #[test]
    fn first_message_from_the_fallback_key_and_its_replay() {
        let (mut alice, mut bob) = (device(), device());
        friends(&mut alice, &mut bob);
        // Alice's copy of Bob's one-time key is gone: only the fallback is left.
        let bob_id = bob.who.root.id();
        let keys = alice.e2ee.people.get_mut(&bob_id).unwrap();
        keys.keys.values_mut().for_each(|k| k.one_time = None);
        let first = only(
            alice
                .e2ee
                .encrypt_direct(&bob_id, Kind::TestNote, b"hi")
                .unwrap(),
        );
        assert_eq!(bob.e2ee.open1(&first).unwrap().body, b"hi");
        assert_eq!(bob.e2ee.open1(&first).unwrap_err(), E2eeError::Replay);
        // Even after Bob's session is gone, the same first message stays refused.
        bob.e2ee
            .people
            .get_mut(&alice.who.root.id())
            .unwrap()
            .sessions
            .clear();
        assert_eq!(bob.e2ee.open1(&first).unwrap_err(), E2eeError::Replay);
    }

    #[test]
    fn a_one_time_key_works_once() {
        let (mut alice, mut bob, mut carol) = (device(), device(), device());
        let (alice_id, bob_id) = (alice.who.root.id(), bob.who.root.id());
        let stale = bob.e2ee.record_field(&alice_id, NOW).unwrap();
        friends(&mut alice, &mut bob);
        friends(&mut carol, &mut bob);
        let one_time = alice.e2ee.people[&bob_id]
            .keys
            .values()
            .next()
            .unwrap()
            .one_time;
        assert!(one_time.is_some());
        let first = only(
            alice
                .e2ee
                .encrypt_direct(&bob_id, Kind::TestNote, b"1")
                .unwrap(),
        );
        bob.e2ee.open1(&first).unwrap();

        // Carol starts a session from the key Bob reserved for Alice: refused.
        let keys = carol.e2ee.people.get_mut(&bob_id).unwrap();
        keys.keys.values_mut().for_each(|k| k.one_time = one_time);
        let second = only(
            carol
                .e2ee
                .encrypt_direct(&bob_id, Kind::TestNote, b"2")
                .unwrap(),
        );
        assert_eq!(bob.e2ee.open1(&second).unwrap_err(), E2eeError::CantOpen);

        // A stale record handing Alice back the used key doesn't restore it,
        // and Bob's next record for her reserves a new one.
        let device = bob.who.device.public();
        alice
            .e2ee
            .learn(&bob_id, &bob.who.devices, &device, &stale)
            .unwrap();
        let keys = alice.e2ee.people[&bob_id].keys.values().next().unwrap();
        assert_eq!(keys.one_time, None);
        let fresh = bob.e2ee.record_field(&alice_id, NOW).unwrap();
        assert_ne!(fresh[MAX_BUNDLE_LEN + 32..], stale[MAX_BUNDLE_LEN + 32..]);
    }

    #[test]
    fn out_of_order_and_replays() {
        let (mut alice, mut bob) = (device(), device());
        friends(&mut alice, &mut bob);
        let bob_id = bob.who.root.id();
        let first = only(
            alice
                .e2ee
                .encrypt_direct(&bob_id, Kind::TestNote, b"0")
                .unwrap(),
        );
        bob.e2ee.open1(&first).unwrap();
        let reply = only(
            bob.e2ee
                .encrypt_direct(&alice.who.root.id(), Kind::TestNote, b"r")
                .unwrap(),
        );
        alice.e2ee.open1(&reply).unwrap();
        let notes: Vec<Vec<u8>> = (1..=3)
            .map(|i| {
                only(
                    alice
                        .e2ee
                        .encrypt_direct(&bob_id, Kind::TestNote, &[i])
                        .unwrap(),
                )
            })
            .collect();
        for i in [2, 0, 1] {
            assert_eq!(bob.e2ee.open1(&notes[i]).unwrap().body, [i as u8 + 1]);
        }
        for note in &notes {
            assert_eq!(bob.e2ee.open1(note).unwrap_err(), E2eeError::Replay);
        }
    }

    #[test]
    fn own_devices_get_a_copy_and_a_dropped_one_is_refused() {
        let mut alice = device();
        let mut bob = device();
        // Alice's laptop, a second device on her list.
        let laptop_key = DeviceKey::generate().unwrap();
        let cert = DeviceCert::issue(&alice.who.root, &laptop_key.public(), "laptop", NOW).unwrap();
        let two = alice
            .who
            .devices
            .with_device(&alice.who.root, cert)
            .unwrap();
        let mut laptop = Device {
            e2ee: E2ee::new(&alice.who.root, &laptop_key, &two, NOW).unwrap(),
            who: Who {
                root: RootKey::from_secret_bytes(*alice.who.root.secret_bytes()),
                device: laptop_key,
                devices: two.clone(),
            },
        };
        alice.who.devices = two.clone();
        friends(&mut alice, &mut bob);
        friends(&mut laptop, &mut bob);
        friends(&mut alice, &mut laptop);

        let bob_id = bob.who.root.id();
        let out = alice
            .e2ee
            .encrypt_direct(&bob_id, Kind::TestNote, b"hi")
            .unwrap();
        assert_eq!(out.len(), 2);
        for (device, bytes) in &out {
            // Each side files it under the other person; the laptop under Bob.
            let (opened, with) = if *device == laptop.who.device.public() {
                (laptop.e2ee.open1(bytes).unwrap(), bob_id)
            } else {
                assert_eq!(*device, bob.who.device.public());
                (bob.e2ee.open1(bytes).unwrap(), alice.who.root.id())
            };
            assert_eq!(opened.conversation, Conversation::Direct(with));
            assert_eq!(opened.sender, alice.who.root.id());
            assert_eq!(opened.body, b"hi");
        }

        // The laptop speaks to Bob first, then Alice removes it.
        let before = laptop
            .e2ee
            .encrypt_direct(&bob_id, Kind::TestNote, b"x")
            .unwrap();
        let to_bob = &before
            .iter()
            .find(|(d, _)| *d == bob.who.device.public())
            .unwrap()
            .1;
        let one = two
            .without_device(&alice.who.root, &laptop.who.device.public())
            .unwrap();
        assert!(bob.e2ee.learn_devices(&alice.who.root.id(), &one).unwrap());
        assert!(
            alice
                .e2ee
                .learn_devices(&alice.who.root.id(), &one)
                .unwrap()
        );
        assert_eq!(
            bob.e2ee.open1(to_bob).unwrap_err(),
            E2eeError::RevokedDevice
        );
        // An older list doesn't bring it back.
        assert!(!bob.e2ee.learn_devices(&alice.who.root.id(), &two).unwrap());
        // And Alice no longer encrypts to it.
        let out = alice
            .e2ee
            .encrypt_direct(&bob_id, Kind::TestNote, b"after")
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, bob.who.device.public());
    }

    #[test]
    fn refusals() {
        let (mut alice, mut bob, mut eve) = (device(), device(), device());
        friends(&mut alice, &mut bob);
        assert_eq!(
            alice
                .e2ee
                .encrypt_direct(&eve.who.root.id(), Kind::TestNote, b"x")
                .unwrap_err(),
            E2eeError::NoKeys
        );
        let to_bob = only(
            alice
                .e2ee
                .encrypt_direct(&bob.who.root.id(), Kind::TestNote, b"x")
                .unwrap(),
        );
        // Eve knows nobody: she can't tell who sent it.
        assert_eq!(
            eve.e2ee.open1(&to_bob).unwrap_err(),
            E2eeError::UnknownSender
        );
        // Eve knows Alice, but it wasn't for her.
        introduce(&mut eve, &mut alice);
        assert!(eve.e2ee.open1(&to_bob).is_err());
        // A field whose bundle isn't the record's device is refused.
        let field = bob.e2ee.record_field(&alice.who.root.id(), NOW).unwrap();
        assert!(
            alice
                .e2ee
                .learn(
                    &bob.who.root.id(),
                    &bob.who.devices,
                    &eve.who.device.public(),
                    &field
                )
                .is_err()
        );
        assert!(
            alice
                .e2ee
                .learn(
                    &bob.who.root.id(),
                    &bob.who.devices,
                    &bob.who.device.public(),
                    &field[1..]
                )
                .is_err()
        );
    }

    #[test]
    fn a_copied_curve_key_cant_take_messages() {
        let (mut alice, mut bob, eve) = (device(), device(), device());
        let (bob_id, eve_id) = (bob.who.root.id(), eve.who.root.id());
        // Eve signs a bundle naming Alice's curve key.
        let mut fake = Bundle::sign(&eve.who.device, alice.e2ee.curve(), [9; 32], NOW);
        fake.extend_from_slice(&[7; 32]);
        let eve_device = eve.who.device.public();
        bob.e2ee
            .learn(&eve_id, &eve.who.devices, &eve_device, &fake)
            .unwrap();
        introduce(&mut alice, &mut bob);
        let first = only(
            alice
                .e2ee
                .encrypt_direct(&bob_id, Kind::TestNote, b"1")
                .unwrap(),
        );
        // Bob doesn't know Alice yet: it isn't taken for Eve's.
        assert_eq!(bob.e2ee.open1(&first).unwrap_err(), E2eeError::CantOpen);

        let mut alice = device();
        let alice_id2 = alice.who.root.id();
        let mut fake = Bundle::sign(&eve.who.device, alice.e2ee.curve(), [9; 32], NOW);
        fake.extend_from_slice(&[7; 32]);
        let mut bob = device();
        bob.e2ee
            .learn(&eve_id, &eve.who.devices, &eve_device, &fake)
            .unwrap();
        friends(&mut alice, &mut bob);
        for body in [&b"1"[..], b"2"] {
            let note = only(
                alice
                    .e2ee
                    .encrypt_direct(&bob.who.root.id(), Kind::TestNote, body)
                    .unwrap(),
            );
            let opened = bob.e2ee.open1(&note).unwrap();
            assert_eq!((opened.sender, &opened.body[..]), (alice_id2, body));
        }
    }

    #[test]
    fn the_fallback_key_is_replaced_weekly() {
        let mut alice = device();
        let bob = device();
        let first = alice.e2ee.record_field(&bob.who.root.id(), NOW).unwrap();
        let same = alice
            .e2ee
            .record_field(&bob.who.root.id(), NOW + 3600)
            .unwrap();
        assert_eq!(first, same);
        let later = alice
            .e2ee
            .record_field(&bob.who.root.id(), NOW + FALLBACK_LIFE)
            .unwrap();
        assert_ne!(first[MAX_BUNDLE_LEN..][..32], later[MAX_BUNDLE_LEN..][..32]);
        assert_eq!(first[..MAX_BUNDLE_LEN], later[..MAX_BUNDLE_LEN]);
    }

    /// Alice's laptop, linked after her first device. With `alone`, the
    /// laptop's own list doesn't have the first device yet (a list still on
    /// its way), so it takes itself for her first device.
    fn laptop_of(alice: &mut Device, alone: bool) -> Device {
        let key = DeviceKey::generate().unwrap();
        let cert = DeviceCert::issue(&alice.who.root, &key.public(), "laptop", NOW).unwrap();
        let root = &alice.who.root;
        let two = alice.who.devices.with_device(root, cert.clone()).unwrap();
        let own = if alone {
            DeviceList::first(root, cert).unwrap()
        } else {
            two.clone()
        };
        let laptop = Device {
            e2ee: E2ee::new(root, &key, &own, NOW).unwrap(),
            who: Who {
                root: RootKey::from_secret_bytes(*root.secret_bytes()),
                device: key,
                devices: two.clone(),
            },
        };
        alice.who.devices = two;
        laptop
    }

    fn to(out: Vec<(VerifyingKey, Vec<u8>)>, device: &VerifyingKey) -> Vec<u8> {
        out.into_iter().find(|(d, _)| d == device).unwrap().1
    }

    #[test]
    fn two_devices_of_one_person_each_start_a_session() {
        let (mut alice, mut bob) = (device(), device());
        let mut laptop = laptop_of(&mut alice, false);
        friends(&mut alice, &mut bob);
        friends(&mut laptop, &mut bob);
        let (bob_id, bob_key) = (bob.who.root.id(), bob.who.device.public());
        let a = alice
            .e2ee
            .encrypt_direct(&bob_id, Kind::TestNote, b"desktop");
        let b = laptop
            .e2ee
            .encrypt_direct(&bob_id, Kind::TestNote, b"laptop");
        assert!(bob.e2ee.open1(&to(a.unwrap(), &bob_key)).is_ok());
        let second = bob.e2ee.open1(&to(b.unwrap(), &bob_key));
        assert!(second.is_ok(), "the second device's message was lost");
    }

    #[test]
    fn a_first_message_that_cant_open_gets_a_fresh_session_back() {
        let (mut alice, mut bob) = (device(), device());
        // Both of Alice's devices take Bob's one-time key.
        let mut laptop = laptop_of(&mut alice, true);
        friends(&mut alice, &mut bob);
        friends(&mut laptop, &mut bob);
        let (bob_id, bob_key) = (bob.who.root.id(), bob.who.device.public());
        let laptop_key = laptop.who.device.public();
        let a = alice
            .e2ee
            .encrypt_direct(&bob_id, Kind::TestNote, b"desktop");
        bob.e2ee.open1(&to(a.unwrap(), &bob_key)).unwrap();
        let lost = laptop.e2ee.encrypt_direct(&bob_id, Kind::TestNote, b"lost");
        let lost = to(lost.unwrap(), &bob_key);
        let got = bob.e2ee.decrypt(&lost, NOW).unwrap();
        assert!(got.opened.is_empty());
        let (device, reply) = got.replies.into_iter().next().expect("a reply");
        assert_eq!(device, laptop_key);
        assert!(laptop.e2ee.decrypt(&reply, NOW).unwrap().opened.is_empty());
        // The laptop now sends on Bob's session, and Bob can read it.
        let next = laptop.e2ee.encrypt_direct(&bob_id, Kind::TestNote, b"next");
        let opened = bob.e2ee.open1(&to(next.unwrap(), &bob_key)).unwrap();
        assert_eq!(opened.body, b"next");
        // The same broken message again, within the hour, gets no second
        // session: a forged one can't make Bob start sessions without end.
        assert_eq!(
            bob.e2ee.decrypt(&lost, NOW).err(),
            Some(E2eeError::CantOpen)
        );
    }
}
