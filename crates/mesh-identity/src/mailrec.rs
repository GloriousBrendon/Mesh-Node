//! Mail records (SPEC-routing D3 as changed by mailbox, SPEC-mailbox M11):
//! per (my device, contact), what a sender needs to mail this device while
//! it's away: the signed device list, the device key, the e2ee field
//! without a one-time key (bundle and fallback key), and up to
//! `MAX_HOLDERS` holders, each with since when its claims there are good
//! (M12). No relay. Sealed and signed as address records are, under a
//! weekly lookup and their own signing domain.
//!
//! ```text
//! lookup [16] | slot [8] | expires_at u64 | nonce [24]
//!             | encrypted (body | device signature [64]) + 16 tag
//! body = format u8 | lookup [16] | slot [8] | device [32] | created_at u64
//!        | expires_at u64 | list len u16 | list | e2ee len u16 | e2ee
//!        | holders u8 | (ticket len u16 | ticket | since u64)*
//! ```

use chacha20poly1305::XNonce;
use chacha20poly1305::aead::{Aead, Payload};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::addr::{
    AddrError, MAX_E2EE_FIELD, MAX_RECORD_LEN, NONCE_LEN, OUTER_LEN, Reader, addr_outer, cipher,
};
use crate::device::DeviceList;
use crate::id::{DeviceKey, MeshId, verify_device};
use crate::pair::{PairKeys, week_of};

const DOMAIN: &str = "mesh/v1/mail-record";
/// The record's format (mailbox *Formats*).
const FORMAT: u8 = 1;
/// Holders a record lists at most (mailbox *Limits*).
pub const MAX_HOLDERS: usize = 3;
/// How long a mail record lasts: the fallback key's week.
pub const MAIL_RECORD_LIFE: u64 = 7 * 86_400;

/// A holder: a seed's ticket, and since when this device's claims there
/// are good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub ticket: String,
    pub since: u64,
}

/// An opened, checked mail record.
#[derive(Debug, Clone)]
pub struct MailRecord {
    pub device: VerifyingKey,
    pub created_at: u64,
    pub expires_at: u64,
    /// The sender's device list, verified and rooted in the expected ID.
    pub devices: DeviceList,
    /// The e2ee field, opaque here.
    pub e2ee: Vec<u8>,
    pub holders: Vec<Holder>,
}

/// Seals `device`'s mail record for the pair `keys`, valid from `now` for
/// `ttl` seconds, under this week's lookup.
pub fn seal_mail_record(
    keys: &PairKeys,
    device: &DeviceKey,
    devices: &DeviceList,
    e2ee: &[u8],
    holders: &[Holder],
    now: u64,
    ttl: u64,
) -> Result<Vec<u8>, AddrError> {
    let list = devices.to_bytes();
    if list.len() > u16::MAX as usize
        || e2ee.len() > MAX_E2EE_FIELD
        || holders.len() > MAX_HOLDERS
        || holders.iter().any(|h| h.ticket.len() > u16::MAX as usize)
    {
        return Err(AddrError::TooLong);
    }
    let public = device.public();
    let lookup = keys.mail_lookup(&devices.root(), week_of(now));
    let slot = keys.slot(&public);
    let expires_at = now + ttl;

    let mut body = vec![FORMAT];
    body.extend_from_slice(&lookup);
    body.extend_from_slice(&slot);
    body.extend_from_slice(public.as_bytes());
    body.extend_from_slice(&now.to_be_bytes());
    body.extend_from_slice(&expires_at.to_be_bytes());
    body.extend_from_slice(&(list.len() as u16).to_be_bytes());
    body.extend_from_slice(&list);
    body.extend_from_slice(&(e2ee.len() as u16).to_be_bytes());
    body.extend_from_slice(e2ee);
    body.push(holders.len() as u8);
    for holder in holders {
        body.extend_from_slice(&(holder.ticket.len() as u16).to_be_bytes());
        body.extend_from_slice(holder.ticket.as_bytes());
        body.extend_from_slice(&holder.since.to_be_bytes());
    }
    let signature = device.sign(DOMAIN, &body);
    body.extend_from_slice(&signature.to_bytes());

    let mut out = Vec::with_capacity(OUTER_LEN + NONCE_LEN + body.len() + 16);
    out.extend_from_slice(&lookup);
    out.extend_from_slice(&slot);
    out.extend_from_slice(&expires_at.to_be_bytes());
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| AddrError::Random)?;
    let payload = Payload {
        msg: &body,
        aad: &out,
    };
    let sealed =
        (cipher(keys).encrypt(&XNonce::from(nonce), payload)).map_err(|_| AddrError::Malformed)?;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    if out.len() > MAX_RECORD_LEN {
        return Err(AddrError::TooLong);
    }
    Ok(out)
}

/// Opens a mail record that `sender` left for the pair `keys`, and checks
/// it as an address record is checked.
pub fn open_mail_record(
    keys: &PairKeys,
    sender: &MeshId,
    bytes: &[u8],
    now: u64,
) -> Result<MailRecord, AddrError> {
    let (lookup, slot, expires_at) = addr_outer(bytes).ok_or(AddrError::Malformed)?;
    let (outer, rest) = bytes.split_at(OUTER_LEN);
    let (nonce, sealed) = rest.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("24 bytes");
    let payload = Payload {
        msg: sealed,
        aad: outer,
    };
    let plain =
        (cipher(keys).decrypt(&XNonce::from(nonce), payload)).map_err(|_| AddrError::WrongPair)?;
    let (body, signature) = plain.split_last_chunk::<64>().ok_or(AddrError::Malformed)?;

    let mut r = Reader(body);
    let malformed = AddrError::Malformed;
    if r.take(1)?[0] != FORMAT || r.take(16)? != lookup || r.take(8)? != slot {
        return Err(malformed);
    }
    let device = VerifyingKey::from_bytes(r.take(32)?.try_into().map_err(|_| malformed)?)
        .map_err(|_| malformed)?;
    let created_at = r.u64()?;
    if r.u64()? != expires_at {
        return Err(malformed);
    }
    let list_len = r.u16()?;
    let devices = DeviceList::from_bytes(r.take(list_len)?).map_err(|_| malformed)?;
    let e2ee_len = r.u16()?;
    if e2ee_len > MAX_E2EE_FIELD {
        return Err(malformed);
    }
    let e2ee = r.take(e2ee_len)?.to_vec();
    let count = r.take(1)?[0] as usize;
    if count > MAX_HOLDERS {
        return Err(malformed);
    }
    let mut holders = Vec::with_capacity(count);
    for _ in 0..count {
        let len = r.u16()?;
        let ticket = String::from_utf8(r.take(len)?.to_vec()).map_err(|_| malformed)?;
        holders.push(Holder {
            ticket,
            since: r.u64()?,
        });
    }
    if !r.0.is_empty() {
        return Err(malformed);
    }

    if devices.root() != *sender {
        return Err(AddrError::WrongIdentity);
    }
    if !devices.is_current(&device) || keys.slot(&device) != slot {
        return Err(AddrError::NotCurrent);
    }
    if !verify_device(&device, DOMAIN, body, &Signature::from_bytes(signature)) {
        return Err(AddrError::BadSignature);
    }
    if expires_at <= now {
        return Err(AddrError::Expired);
    }
    Ok(MailRecord {
        device,
        created_at,
        expires_at,
        devices,
        e2ee,
        holders,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::open_addr;
    use crate::device::DeviceCert;
    use crate::id::RootKey;

    const NOW: u64 = 1_800_000_000;

    struct Person {
        root: RootKey,
        device: DeviceKey,
        devices: DeviceList,
    }

    fn person() -> Person {
        let root = RootKey::generate().unwrap();
        let device = DeviceKey::generate().unwrap();
        let cert = DeviceCert::issue(&root, &device.public(), "pc", NOW).unwrap();
        let devices = DeviceList::first(&root, cert).unwrap();
        Person {
            root,
            device,
            devices,
        }
    }

    fn holders() -> Vec<Holder> {
        let holder = |n: u64| Holder {
            ticket: format!("mesh://node/seed{n}?relay=https://relay.example/"),
            since: NOW - n,
        };
        vec![holder(1), holder(2)]
    }

    fn sealed(from: &Person, to: &Person) -> Vec<u8> {
        let keys = PairKeys::new(&from.root, &to.root.id()).unwrap();
        seal_mail_record(
            &keys,
            &from.device,
            &from.devices,
            b"e2ee",
            &holders(),
            NOW,
            MAIL_RECORD_LIFE,
        )
        .unwrap()
    }

    #[test]
    fn round_trip() {
        let (alice, bob) = (person(), person());
        let bytes = sealed(&alice, &bob);
        let keys = PairKeys::new(&bob.root, &alice.root.id()).unwrap();
        let record = open_mail_record(&keys, &alice.root.id(), &bytes, NOW + 60).unwrap();
        assert_eq!(record.device, alice.device.public());
        assert_eq!(
            (record.created_at, record.expires_at),
            (NOW, NOW + MAIL_RECORD_LIFE)
        );
        assert_eq!(record.e2ee, b"e2ee");
        assert_eq!(record.holders, holders());
        let (lookup, slot, expires) = addr_outer(&bytes).unwrap();
        assert_eq!(lookup, keys.mail_lookup(&alice.root.id(), week_of(NOW)));
        assert_ne!(
            lookup,
            keys.lookup(&alice.root.id(), crate::pair::day_of(NOW))
        );
        assert_eq!(slot, keys.slot(&alice.device.public()));
        assert_eq!(expires, NOW + MAIL_RECORD_LIFE);
    }

    #[test]
    fn refusals() {
        let (alice, bob, eve) = (person(), person(), person());
        let bytes = sealed(&alice, &bob);
        let keys = PairKeys::new(&bob.root, &alice.root.id()).unwrap();
        let alice_id = alice.root.id();
        for i in [0, 20, 30, 40, bytes.len() - 1] {
            let mut tampered = bytes.clone();
            tampered[i] ^= 1;
            assert!(
                open_mail_record(&keys, &alice_id, &tampered, NOW).is_err(),
                "byte {i}"
            );
        }
        let eves = PairKeys::new(&eve.root, &alice_id).unwrap();
        assert_eq!(
            open_mail_record(&eves, &alice_id, &bytes, NOW).unwrap_err(),
            AddrError::WrongPair
        );
        let lapsed = open_mail_record(&keys, &alice_id, &bytes, NOW + MAIL_RECORD_LIFE);
        assert_eq!(lapsed.unwrap_err(), AddrError::Expired);
        assert_eq!(
            open_mail_record(&keys, &eve.root.id(), &bytes, NOW).unwrap_err(),
            AddrError::WrongIdentity
        );
        // Not an address record, nor the other way round: their domains differ.
        assert!(open_addr(&keys, &alice_id, &bytes, NOW).is_err());
        let four = vec![holders()[0].clone(); MAX_HOLDERS + 1];
        let alice_keys = PairKeys::new(&alice.root, &bob.root.id()).unwrap();
        let too_many = seal_mail_record(
            &alice_keys,
            &alice.device,
            &alice.devices,
            b"",
            &four,
            NOW,
            60,
        );
        assert_eq!(too_many.unwrap_err(), AddrError::TooLong);
    }
}
