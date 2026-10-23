//! The safety number: 60 digits two people compare (aloud or by QR) to check
//! that each holds the other's real ID. It comes from both root IDs, so it's
//! the same on both sides and doesn't change when either adds a device.

use std::fmt;

use crate::id::MeshId;

const DOMAIN: &[u8] = b"mesh/v1/safety";
/// Five-digit groups per person; two people make 12 groups, 60 digits.
const GROUPS_PER_ID: usize = 6;
const QR_PREFIX: &str = "MESHSAFETY1:";

/// Two people's safety number, the lower ID's half first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetyNumber([u32; 2 * GROUPS_PER_ID]);

impl SafetyNumber {
    /// The same number whichever of the two computes it.
    pub fn new(a: &MeshId, b: &MeshId) -> Self {
        let (low, high) = if a.to_bytes() <= b.to_bytes() {
            (a, b)
        } else {
            (b, a)
        };
        let mut groups = [0; 2 * GROUPS_PER_ID];
        groups[..GROUPS_PER_ID].copy_from_slice(&half(low));
        groups[GROUPS_PER_ID..].copy_from_slice(&half(high));
        Self(groups)
    }

    /// Twelve groups of five digits, each 0..=99999.
    pub fn groups(&self) -> &[u32; 2 * GROUPS_PER_ID] {
        &self.0
    }

    /// What the QR code carries: capitals, digits and `:` only, so it fits
    /// a QR code's compact alphanumeric mode.
    pub fn qr_payload(&self) -> String {
        format!("{QR_PREFIX}{}", self.digits())
    }

    /// Whether `text` (a scanned QR payload, or the 60 digits typed with any
    /// spacing) is this number.
    pub fn matches(&self, text: &str) -> bool {
        let text = text.trim();
        let digits = text.strip_prefix(QR_PREFIX).unwrap_or(text);
        digits
            .chars()
            .filter(|c| !c.is_whitespace())
            .eq(self.digits().chars())
    }

    fn digits(&self) -> String {
        self.0.iter().map(|g| format!("{g:05}")).collect()
    }
}

impl fmt::Display for SafetyNumber {
    /// `12345 67890 …`, the way it's read aloud.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, group) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{group:05}")?;
        }
        Ok(())
    }
}

/// One person's 30 digits: six 5-byte chunks of `BLAKE3-XOF(domain || id)`,
/// each taken mod 100000 (a 40-bit chunk makes the bias negligible).
fn half(id: &MeshId) -> [u32; GROUPS_PER_ID] {
    let mut out = [0u8; 5 * GROUPS_PER_ID];
    blake3::Hasher::new()
        .update(DOMAIN)
        .update(&id.to_bytes())
        .finalize_xof()
        .fill(&mut out);
    let mut groups = [0; GROUPS_PER_ID];
    for (group, chunk) in groups.iter_mut().zip(out.as_chunks::<5>().0) {
        let n = chunk.iter().fold(0u64, |n, &b| n << 8 | u64::from(b));
        *group = (n % 100_000) as u32;
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::RootKey;
    use proptest::prelude::*;

    fn id(secret: [u8; 32]) -> MeshId {
        RootKey::from_secret_bytes(secret).id()
    }

    #[test]
    fn shape_and_comparing() {
        let (a, b) = (id([1; 32]), id([2; 32]));
        let n = SafetyNumber::new(&a, &b);
        let text = n.to_string();
        assert_eq!(text.split(' ').count(), 12);
        assert!(text.split(' ').all(|g| g.len() == 5));
        assert!(n.matches(&n.qr_payload()));
        assert!(n.matches(&text));
        assert!(n.matches(&text.replace(' ', "")));
        let mut wrong = text.into_bytes();
        wrong[0] = if wrong[0] == b'9' { b'8' } else { b'9' };
        assert!(!n.matches(std::str::from_utf8(&wrong).unwrap()));
        assert!(!n.matches(&SafetyNumber::new(&a, &id([3; 32])).qr_payload()));
        assert!(!n.matches(""));
    }

    #[test]
    fn each_half_belongs_to_one_id() {
        let (a, b, c) = (id([1; 32]), id([2; 32]), id([3; 32]));
        let ab = SafetyNumber::new(&a, &b);
        let ac = SafetyNumber::new(&a, &c);
        // a's half appears in both; the other half differs.
        let a_half = half(&a);
        for n in [ab, ac] {
            assert!(n.groups()[..6] == a_half || n.groups()[6..] == a_half);
        }
        assert_ne!(ab, ac);
    }

    proptest! {
        #[test]
        fn both_sides_see_the_same_number(x in any::<[u8; 32]>(), y in any::<[u8; 32]>()) {
            let (a, b) = (id(x), id(y));
            prop_assert_eq!(SafetyNumber::new(&a, &b), SafetyNumber::new(&b, &a));
        }
    }
}
