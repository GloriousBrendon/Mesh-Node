//! The hello exchange every connection starts with (SPEC-transport D5). iroh
//! has already proved which device key the other side holds; the certificate
//! proves which person that device belongs to.

use crate::Peer;
use crate::frame::{self, FrameError};
use iroh::endpoint::{Connection, ConnectionError, VarInt};
use mesh_identity::DeviceCert;

/// Mesh's QUIC protocol, version 1.
pub const ALPN: &[u8] = b"mesh/1";
const HELLO: &str = "hello";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    #[error("the other side's certificate is damaged or not signed by its identity")]
    BadCert,
    #[error("the other side's certificate is for a different device")]
    KeyMismatch,
    #[error("the other side didn't finish the handshake in time")]
    Timeout,
    #[error("the connection dropped during the handshake")]
    Dropped,
    /// The listener only takes connections from people it chose (`Config::allow`).
    #[error("that device doesn't take connections from this identity")]
    NotAllowed,
}

impl HandshakeError {
    /// The close code that tells the other side why.
    pub(crate) fn code(self) -> u32 {
        match self {
            HandshakeError::BadCert => 1,
            HandshakeError::KeyMismatch => 2,
            HandshakeError::Timeout => 3,
            HandshakeError::Dropped => 4,
            // 5 is the endpoint's "locked".
            HandshakeError::NotAllowed => 6,
        }
    }

    fn from_code(code: VarInt) -> Option<Self> {
        Some(match code.into_inner() {
            1 => HandshakeError::BadCert,
            2 => HandshakeError::KeyMismatch,
            3 => HandshakeError::Timeout,
            4 => HandshakeError::Dropped,
            6 => HandshakeError::NotAllowed,
            _ => return None,
        })
    }

    /// Ends the connection, saying why.
    pub(crate) fn close(self, conn: &Connection) {
        conn.close(self.code().into(), self.to_string().as_bytes());
    }
}

/// Checks a peer's hello: its certificate must be signed by its root and name
/// the same device key iroh authenticated, or someone holding one device's key
/// is presenting another identity's certificate.
pub(crate) fn check_hello(cert: &[u8], remote: &iroh::PublicKey) -> Result<Peer, HandshakeError> {
    let cert = DeviceCert::from_bytes(cert).map_err(|_| HandshakeError::BadCert)?;
    if cert.device().as_bytes() != remote.as_bytes() {
        return Err(HandshakeError::KeyMismatch);
    }
    Ok(Peer {
        id: cert.root(),
        device: *remote,
        name: cert.name().to_owned(),
    })
}

/// The dialling side: send our certificate, then check theirs.
pub(crate) async fn dial(conn: &Connection, ours: &[u8]) -> Result<Peer, HandshakeError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| closed(&e))?;
    frame::write_tag(&mut send, HELLO)
        .await
        .map_err(|e| io(conn, e))?;
    frame::write_frame(&mut send, ours)
        .await
        .map_err(|e| io(conn, e))?;
    send.finish().map_err(|_| HandshakeError::Dropped)?;
    let theirs = match frame::read_frame(&mut recv).await {
        Ok(Some(cert)) => cert,
        // They closed the connection instead of answering: their close code says why.
        Ok(None) | Err(_) => {
            return Err(conn
                .close_reason()
                .map_or(HandshakeError::Dropped, |e| closed(&e)));
        }
    };
    check_hello(&theirs, &conn.remote_id())
}

/// The accepting side: check theirs before showing ours, so a peer that
/// fails the check, or isn't allowed, learns nothing about whose device this is.
pub(crate) async fn accept(
    conn: &Connection,
    ours: &[u8],
    allow: &crate::Allow,
) -> Result<Peer, HandshakeError> {
    let (mut send, mut recv) = conn.accept_bi().await.map_err(|e| closed(&e))?;
    if frame::read_tag(&mut recv).await.ok().as_deref() != Some(HELLO) {
        return Err(HandshakeError::BadCert);
    }
    let theirs = frame::read_frame(&mut recv)
        .await
        .ok()
        .flatten()
        .ok_or(HandshakeError::BadCert)?;
    let peer = check_hello(&theirs, &conn.remote_id())?;
    if !allow.allows(&peer.id, &peer.device) {
        return Err(HandshakeError::NotAllowed);
    }
    frame::write_frame(&mut send, ours)
        .await
        .map_err(|e| io(conn, e))?;
    send.finish().map_err(|_| HandshakeError::Dropped)?;
    Ok(peer)
}

/// Why a connection ended: our own close codes, or just "dropped".
fn closed(e: &ConnectionError) -> HandshakeError {
    match e {
        ConnectionError::ApplicationClosed(close) => {
            HandshakeError::from_code(close.error_code).unwrap_or(HandshakeError::Dropped)
        }
        _ => HandshakeError::Dropped,
    }
}

fn io(conn: &Connection, _: FrameError) -> HandshakeError {
    conn.close_reason()
        .map_or(HandshakeError::Dropped, |e| closed(&e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_identity::{DeviceKey, RootKey};

    fn cert(root: &RootKey, device: &DeviceKey) -> Vec<u8> {
        DeviceCert::issue(root, &device.public(), "box", 1)
            .unwrap()
            .to_bytes()
    }

    #[test]
    fn checks_the_certificate() {
        let (root, device) = (RootKey::generate().unwrap(), DeviceKey::generate().unwrap());
        let key = crate::secret_key(&device).public();
        let peer = check_hello(&cert(&root, &device), &key).expect("valid");
        assert_eq!((peer.id, peer.name.as_str()), (root.id(), "box"));

        // Someone else's device key presenting this certificate.
        let other = crate::secret_key(&DeviceKey::generate().unwrap()).public();
        assert_eq!(
            check_hello(&cert(&root, &device), &other),
            Err(HandshakeError::KeyMismatch)
        );

        // A flipped bit breaks the root's signature.
        let mut forged = cert(&root, &device);
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert_eq!(check_hello(&forged, &key), Err(HandshakeError::BadCert));
        assert_eq!(check_hello(b"garbage", &key), Err(HandshakeError::BadCert));
    }

    #[test]
    fn close_codes_round_trip() {
        for e in [
            HandshakeError::BadCert,
            HandshakeError::KeyMismatch,
            HandshakeError::Timeout,
            HandshakeError::Dropped,
        ] {
            assert_eq!(HandshakeError::from_code(e.code().into()), Some(e));
        }
        assert_eq!(HandshakeError::from_code(0u32.into()), None);
    }
}
