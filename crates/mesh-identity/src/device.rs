//! A person's devices. Each install has its own device key; the root key
//! certifies it (`DeviceCert`) and lists the current ones (`DeviceList`, the
//! highest `seq` wins). Removing a device puts its key on the list's revoked
//! side, so honest peers stop talking to it.
//!
//! Signed bytes are a fixed layout (big-endian integers, length-prefixed
//! strings), never serde, so encoding can't make a signature ambiguous. Values
//! of these types only come from issuing or from parsing, and parsing always
//! verifies: holding one means its signatures check out.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::id::{MeshId, RootKey};

const CERT_DOMAIN: &str = "mesh/v1/device-cert";
const LIST_DOMAIN: &str = "mesh/v1/device-list";
const FORMAT_V1: u8 = 1;
/// A device name's limit, in UTF-8 bytes.
pub const MAX_DEVICE_NAME: usize = 64;
/// Devices one identity can have at once.
pub const MAX_DEVICES: usize = 16;
/// Revoked keys a list keeps; the oldest drop off past this.
const MAX_REVOKED: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeviceError {
    #[error("a device name can be at most {MAX_DEVICE_NAME} bytes")]
    NameTooLong,
    #[error("an identity can have at most {MAX_DEVICES} devices")]
    TooManyDevices,
    #[error("that device is already linked")]
    AlreadyLinked,
    #[error("that device was removed and can't come back; link it again as a new device")]
    Revoked,
    #[error("that device isn't linked")]
    NotLinked,
    #[error("the record isn't signed by this identity")]
    BadSignature,
    #[error("the record belongs to another identity")]
    WrongIdentity,
    #[error("an older device list can't replace a newer one")]
    Stale,
    #[error("the record is damaged or in an unknown format")]
    Malformed,
}

/// The root key's statement that `device` belongs to `root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCert {
    root: MeshId,
    device: VerifyingKey,
    name: String,
    /// Unix seconds.
    created_at: u64,
    signature: Signature,
}

impl DeviceCert {
    /// Certifies `device` as one of `root`'s devices.
    pub fn issue(
        root: &RootKey,
        device: &VerifyingKey,
        name: &str,
        created_at: u64,
    ) -> Result<Self, DeviceError> {
        if name.len() > MAX_DEVICE_NAME {
            return Err(DeviceError::NameTooLong);
        }
        let body = cert_body(&root.id(), device, name, created_at);
        Ok(Self {
            root: root.id(),
            device: *device,
            name: name.to_owned(),
            created_at,
            signature: root.sign(CERT_DOMAIN, &body),
        })
    }

    pub fn root(&self) -> MeshId {
        self.root
    }

    pub fn device(&self) -> &VerifyingKey {
        &self.device
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// The signed body followed by the 64-byte signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = cert_body(&self.root, &self.device, &self.name, self.created_at);
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes
    }

    /// Parses and verifies a certificate.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeviceError> {
        let mut r = Reader(bytes);
        if r.u8()? != FORMAT_V1 {
            return Err(DeviceError::Malformed);
        }
        let root = MeshId::from_bytes(&r.array()?).map_err(|_| DeviceError::Malformed)?;
        let device = VerifyingKey::from_bytes(&r.array()?).map_err(|_| DeviceError::Malformed)?;
        let created_at = r.u64()?;
        let name_len = r.u16()? as usize;
        if name_len > MAX_DEVICE_NAME {
            return Err(DeviceError::NameTooLong);
        }
        let name =
            String::from_utf8(r.take(name_len)?.to_vec()).map_err(|_| DeviceError::Malformed)?;
        let signature = Signature::from_bytes(&r.array()?);
        r.end()?;
        let body_len = bytes.len() - 64;
        if !root.verify(CERT_DOMAIN, &bytes[..body_len], &signature) {
            return Err(DeviceError::BadSignature);
        }
        Ok(Self {
            root,
            device,
            name,
            created_at,
            signature,
        })
    }
}

fn cert_body(root: &MeshId, device: &VerifyingKey, name: &str, created_at: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + 32 + 32 + 8 + 2 + name.len());
    body.push(FORMAT_V1);
    body.extend_from_slice(&root.to_bytes());
    body.extend_from_slice(device.as_bytes());
    body.extend_from_slice(&created_at.to_be_bytes());
    // Fits: names are checked against MAX_DEVICE_NAME first.
    body.extend_from_slice(&(name.len() as u16).to_be_bytes());
    body.extend_from_slice(name.as_bytes());
    body
}

/// The current devices of one identity, signed by its root key. A newer
/// list (higher `seq`) replaces an older one; see [`DeviceList::replaces`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceList {
    root: MeshId,
    seq: u64,
    devices: Vec<DeviceCert>,
    revoked: Vec<VerifyingKey>,
    signature: Signature,
}

impl DeviceList {
    /// The list a new identity starts with: its first device, `seq` 1.
    pub fn first(root: &RootKey, cert: DeviceCert) -> Result<Self, DeviceError> {
        Self::sign(root, 1, vec![cert], Vec::new())
    }

    /// This list plus a newly linked device, one `seq` later.
    pub fn with_device(&self, root: &RootKey, cert: DeviceCert) -> Result<Self, DeviceError> {
        if cert.root != self.root {
            return Err(DeviceError::WrongIdentity);
        }
        if self.revoked.contains(&cert.device) {
            return Err(DeviceError::Revoked);
        }
        if self.devices.iter().any(|d| d.device == cert.device) {
            return Err(DeviceError::AlreadyLinked);
        }
        let mut devices = self.devices.clone();
        devices.push(cert);
        Self::sign(root, self.seq + 1, devices, self.revoked.clone())
    }

    /// This list with `device` removed and revoked, one `seq` later.
    pub fn without_device(
        &self,
        root: &RootKey,
        device: &VerifyingKey,
    ) -> Result<Self, DeviceError> {
        if !self.devices.iter().any(|d| &d.device == device) {
            return Err(DeviceError::NotLinked);
        }
        let devices = self
            .devices
            .iter()
            .filter(|d| &d.device != device)
            .cloned()
            .collect();
        let mut revoked = self.revoked.clone();
        revoked.push(*device);
        if revoked.len() > MAX_REVOKED {
            revoked.remove(0);
        }
        Self::sign(root, self.seq + 1, devices, revoked)
    }

    fn sign(
        root: &RootKey,
        seq: u64,
        devices: Vec<DeviceCert>,
        revoked: Vec<VerifyingKey>,
    ) -> Result<Self, DeviceError> {
        if devices.iter().any(|d| d.root != root.id()) {
            return Err(DeviceError::WrongIdentity);
        }
        if devices.len() > MAX_DEVICES {
            return Err(DeviceError::TooManyDevices);
        }
        let body = list_body(&root.id(), seq, &devices, &revoked);
        Ok(Self {
            root: root.id(),
            seq,
            devices,
            revoked,
            signature: root.sign(LIST_DOMAIN, &body),
        })
    }

    pub fn root(&self) -> MeshId {
        self.root
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn devices(&self) -> &[DeviceCert] {
        &self.devices
    }

    /// Whether `device` is one of this identity's devices right now.
    pub fn is_current(&self, device: &VerifyingKey) -> bool {
        self.devices.iter().any(|d| &d.device == device) && !self.revoked.contains(device)
    }

    /// Ok when this list may replace `older`: same identity, higher `seq`.
    pub fn replaces(&self, older: &DeviceList) -> Result<(), DeviceError> {
        if self.root != older.root {
            return Err(DeviceError::WrongIdentity);
        }
        if self.seq <= older.seq {
            return Err(DeviceError::Stale);
        }
        Ok(())
    }

    /// The signed body followed by the 64-byte signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = list_body(&self.root, self.seq, &self.devices, &self.revoked);
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes
    }

    /// Parses and verifies a list and every certificate in it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeviceError> {
        let mut r = Reader(bytes);
        if r.u8()? != FORMAT_V1 {
            return Err(DeviceError::Malformed);
        }
        let root = MeshId::from_bytes(&r.array()?).map_err(|_| DeviceError::Malformed)?;
        let seq = r.u64()?;
        let device_count = r.u16()? as usize;
        if device_count > MAX_DEVICES {
            return Err(DeviceError::TooManyDevices);
        }
        let mut devices = Vec::with_capacity(device_count);
        for _ in 0..device_count {
            let len = r.u16()? as usize;
            let cert = DeviceCert::from_bytes(r.take(len)?)?;
            if cert.root != root {
                return Err(DeviceError::WrongIdentity);
            }
            devices.push(cert);
        }
        let revoked_count = r.u16()? as usize;
        if revoked_count > MAX_REVOKED {
            return Err(DeviceError::Malformed);
        }
        let revoked = (0..revoked_count)
            .map(|_| VerifyingKey::from_bytes(&r.array()?).map_err(|_| DeviceError::Malformed))
            .collect::<Result<Vec<_>, _>>()?;
        let signature = Signature::from_bytes(&r.array()?);
        r.end()?;
        if !root.verify(LIST_DOMAIN, &bytes[..bytes.len() - 64], &signature) {
            return Err(DeviceError::BadSignature);
        }
        Ok(Self {
            root,
            seq,
            devices,
            revoked,
            signature,
        })
    }
}

fn list_body(root: &MeshId, seq: u64, devices: &[DeviceCert], revoked: &[VerifyingKey]) -> Vec<u8> {
    let mut body = vec![FORMAT_V1];
    body.extend_from_slice(&root.to_bytes());
    body.extend_from_slice(&seq.to_be_bytes());
    // Counts and lengths fit u16: devices, names and revocations are all capped.
    body.extend_from_slice(&(devices.len() as u16).to_be_bytes());
    for cert in devices {
        let bytes = cert.to_bytes();
        body.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&bytes);
    }
    body.extend_from_slice(&(revoked.len() as u16).to_be_bytes());
    for key in revoked {
        body.extend_from_slice(key.as_bytes());
    }
    body
}

/// Reads a fixed layout front to back; running short is `Malformed`.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DeviceError> {
        if self.0.len() < n {
            return Err(DeviceError::Malformed);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DeviceError> {
        self.take(N).map(|b| b.try_into().expect("took N bytes"))
    }

    fn u8(&mut self) -> Result<u8, DeviceError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, DeviceError> {
        self.array().map(u16::from_be_bytes)
    }

    fn u64(&mut self) -> Result<u64, DeviceError> {
        self.array().map(u64::from_be_bytes)
    }

    /// Trailing bytes mean a different record than the one we parsed.
    fn end(&self) -> Result<(), DeviceError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DeviceError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::DeviceKey;

    fn new_device(root: &RootKey, name: &str) -> (DeviceKey, DeviceCert) {
        let key = DeviceKey::generate().unwrap();
        let cert = DeviceCert::issue(root, &key.public(), name, 1_792_627_200).unwrap();
        (key, cert)
    }

    #[test]
    fn certs_round_trip_and_reject_tampering() {
        let root = RootKey::generate().unwrap();
        let (_, cert) = new_device(&root, "Desktop");
        let bytes = cert.to_bytes();
        assert_eq!(DeviceCert::from_bytes(&bytes), Ok(cert.clone()));
        // Any flipped byte in the body breaks the signature (or the layout).
        for i in [0, 5, 40, 70, 75, 80] {
            let mut bad = bytes.clone();
            bad[i] ^= 1;
            assert!(DeviceCert::from_bytes(&bad).is_err(), "byte {i}");
        }
        assert_eq!(
            DeviceCert::from_bytes(&bytes[..bytes.len() - 1]),
            Err(DeviceError::Malformed)
        );
        assert_eq!(
            DeviceCert::from_bytes(&[bytes.clone(), vec![0]].concat()),
            Err(DeviceError::Malformed)
        );
        assert_eq!(
            DeviceCert::issue(&root, cert.device(), &"x".repeat(65), 0),
            Err(DeviceError::NameTooLong)
        );
    }

    #[test]
    fn a_cert_signed_by_another_root_is_rejected() {
        let (root, other) = (RootKey::generate().unwrap(), RootKey::generate().unwrap());
        let (_, cert) = new_device(&root, "Desktop");
        // Swap in another root's ID: the signature no longer matches the claimed root.
        let mut forged = cert.to_bytes();
        forged[1..33].copy_from_slice(&other.id().to_bytes());
        assert_eq!(
            DeviceCert::from_bytes(&forged),
            Err(DeviceError::BadSignature)
        );
        let (_, foreign) = new_device(&other, "Theirs");
        let list = DeviceList::first(&root, cert).unwrap();
        assert_eq!(
            list.with_device(&root, foreign),
            Err(DeviceError::WrongIdentity)
        );
    }

    #[test]
    fn lists_grow_shrink_and_only_move_forward() {
        let root = RootKey::generate().unwrap();
        let (desktop, desktop_cert) = new_device(&root, "Desktop");
        let (laptop, laptop_cert) = new_device(&root, "Laptop");
        let first = DeviceList::first(&root, desktop_cert).unwrap();
        let two = first.with_device(&root, laptop_cert.clone()).unwrap();
        assert_eq!((first.seq(), two.seq()), (1, 2));
        assert!(two.is_current(&laptop.public()) && two.is_current(&desktop.public()));
        assert_eq!(two.replaces(&first), Ok(()));
        assert_eq!(first.replaces(&two), Err(DeviceError::Stale));
        assert_eq!(two.replaces(&two), Err(DeviceError::Stale));
        assert_eq!(
            two.with_device(&root, laptop_cert.clone()),
            Err(DeviceError::AlreadyLinked)
        );

        let removed = two.without_device(&root, &laptop.public()).unwrap();
        assert!(!removed.is_current(&laptop.public()) && removed.is_current(&desktop.public()));
        assert_eq!(
            removed.with_device(&root, laptop_cert),
            Err(DeviceError::Revoked)
        );
        assert_eq!(
            removed.without_device(&root, &laptop.public()),
            Err(DeviceError::NotLinked)
        );

        let parsed = DeviceList::from_bytes(&removed.to_bytes()).unwrap();
        assert_eq!(parsed, removed);
        assert!(!parsed.is_current(&laptop.public()));
    }

    #[test]
    fn lists_reject_tampering_and_foreign_certs() {
        let root = RootKey::generate().unwrap();
        let (_, cert) = new_device(&root, "Desktop");
        let list = DeviceList::first(&root, cert).unwrap();
        let bytes = list.to_bytes();
        // Bumping seq without the root key: the signature fails.
        let mut bumped = bytes.clone();
        bumped[40] ^= 1;
        assert_eq!(
            DeviceList::from_bytes(&bumped),
            Err(DeviceError::BadSignature)
        );
        assert_eq!(
            DeviceList::from_bytes(&bytes[..bytes.len() - 3]),
            Err(DeviceError::Malformed)
        );

        let other = RootKey::generate().unwrap();
        let (_, theirs) = new_device(&other, "Theirs");
        assert_eq!(
            DeviceList::first(&root, theirs),
            Err(DeviceError::WrongIdentity)
        );
    }

    #[test]
    fn device_count_is_capped() {
        let root = RootKey::generate().unwrap();
        let mut list = DeviceList::first(&root, new_device(&root, "0").1).unwrap();
        for i in 1..MAX_DEVICES {
            list = list
                .with_device(&root, new_device(&root, &i.to_string()).1)
                .unwrap();
        }
        assert_eq!(
            list.with_device(&root, new_device(&root, "one too many").1),
            Err(DeviceError::TooManyDevices)
        );
    }
}
