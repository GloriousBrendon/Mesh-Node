//! Profiles (SPEC-profile): the signed, versioned manifest a person sends
//! their friends. It carries their `profile.toml` (a rice for their profile:
//! a theme, blocks, a font name) and the list of files it shows, each sealed
//! with its own key as message files are (`blob`, D12). Pure: no networking
//! and no decoding; the caps here are on what's declared, and the decoder
//! checks what's actually in the files (PR8).

use mesh_identity::{DeviceCert, DeviceKey, DeviceList, verify_device_bytes};
use serde::{Deserialize, Serialize};

use crate::Sender;

/// The domain a profile manifest is signed under (PR2).
pub const PROFILE_SIGNATURE: &str = "mesh/v1/profile";
/// The manifest's format.
pub const PROFILE_FORMAT: u8 = 1;

/// A whole manifest, in bytes: it goes in one e2ee message (64 KiB) with
/// room for the envelope.
pub const MAX_MANIFEST_LEN: usize = 60 * 1024;
/// `profile.toml` itself.
pub const MAX_TOML_LEN: usize = 32 * 1024;
/// Every file of a profile together (PR7): 25 MB.
pub const MAX_BUNDLE: u64 = 25 * 1000 * 1000;
pub const MAX_AVATAR: u64 = 8 * 1000 * 1000;
pub const MAX_BANNER: u64 = 12 * 1000 * 1000;
/// The theme's own background picture: as big as a banner.
pub const MAX_BACKGROUND: u64 = 12 * 1000 * 1000;
pub const MAX_GALLERY_PICTURE: u64 = 4 * 1000 * 1000;
pub const MAX_GALLERY: usize = 12;
pub const MAX_SONG: u64 = 10 * 1000 * 1000;
/// The song's length, in seconds (PR7): 6 minutes.
pub const MAX_SONG_SECONDS: u32 = 6 * 60;
/// Characters (PR5).
pub const MAX_BIO: usize = 4000;
pub const MAX_STATUS: usize = 128;
pub const MAX_LINKS: usize = 16;
pub const MAX_LINK_LEN: usize = 512;
pub const MAX_LINK_LABEL: usize = 64;
pub const MAX_BLOCKS: usize = 32;
pub const MAX_FONT_NAME: usize = 64;

/// The kinds of picture a profile may hold (PR7).
pub const PICTURE_TYPES: [&str; 5] = [
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
    "image/apng",
];
/// The kinds of song (Q4): Opus and Vorbis in Ogg, MP3, FLAC.
pub const SONG_TYPES: [&str; 3] = ["audio/ogg", "audio/mpeg", "audio/flac"];

/// What a file is for. Avatar, banner, song and background are one each;
/// the gallery up to `MAX_GALLERY`, shown in the order listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Slot {
    Avatar,
    Banner,
    Gallery,
    Song,
    /// `[theme]`'s background picture.
    Background,
}

impl Slot {
    fn cap(self) -> u64 {
        match self {
            Slot::Avatar => MAX_AVATAR,
            Slot::Banner => MAX_BANNER,
            Slot::Background => MAX_BACKGROUND,
            Slot::Gallery => MAX_GALLERY_PICTURE,
            Slot::Song => MAX_SONG,
        }
    }

    fn types(self) -> &'static [&'static str] {
        match self {
            Slot::Song => &SONG_TYPES,
            _ => &PICTURE_TYPES,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Slot::Avatar => "avatar",
            Slot::Banner => "banner",
            Slot::Background => "background",
            Slot::Gallery => "gallery picture",
            Slot::Song => "song",
        }
    }
}

/// One file of a profile: sealed as message files are, fetched by `hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub slot: Slot,
    pub key: [u8; 32],
    /// The encrypted file's blake3 hash.
    pub hash: [u8; 32],
    /// The plain file's size.
    pub size: u64,
    pub mime: String,
    /// The song's length as the sender measured it; the player checks it.
    pub seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    #[error("profile.toml isn't valid: {0}")]
    Toml(String),
    #[error("profile.toml is longer than 32 KB")]
    TomlTooLong,
    #[error("the {0} is too long")]
    TooLong(&'static str),
    #[error("there are too many {0}")]
    TooMany(&'static str),
    #[error("the {0} is too big")]
    TooBig(&'static str),
    #[error("a {0} can't be that kind of file")]
    WrongType(&'static str),
    #[error("a profile has one {0} at most")]
    Duplicate(&'static str),
    #[error("the song is longer than 6 minutes")]
    SongTooLong,
    #[error("all the files together are bigger than 25 MB")]
    BundleTooBig,
    #[error("a link must start with https://, http:// or mailto:")]
    BadLink,
    #[error("the profile's signature doesn't check out")]
    BadSignature,
    #[error("the profile isn't from one of their current devices")]
    NotCurrentDevice,
    #[error("the profile is damaged")]
    Malformed,
}

/// The signed manifest (PR2): `profile.toml`, the files, a version that
/// only goes up, and the device that signed it with its certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u8,
    pub version: u64,
    pub toml: String,
    pub assets: Vec<Asset>,
    pub cert: Vec<u8>,
    pub signature: Vec<u8>,
}

/// The fields a device signs: everything but the signature.
fn signed_bytes(m: &Manifest) -> Vec<u8> {
    let fields = (m.format, m.version, &m.toml, &m.assets, &m.cert);
    postcard::to_stdvec(&fields).expect("to memory")
}

impl Manifest {
    /// A new manifest, checked against every cap, then signed by `device`
    /// under its certificate.
    pub fn signed(
        version: u64,
        toml: String,
        assets: Vec<Asset>,
        device: &DeviceKey,
        cert: &DeviceCert,
    ) -> Result<Self, ProfileError> {
        let mut m = Self {
            format: PROFILE_FORMAT,
            version,
            toml,
            assets,
            cert: cert.to_bytes(),
            signature: Vec::new(),
        };
        m.check()?;
        m.signature = device
            .sign(PROFILE_SIGNATURE, &signed_bytes(&m))
            .to_bytes()
            .to_vec();
        Ok(m)
    }

    /// Who signed it, if the certificate is its author's ID's and the
    /// signature is that device's.
    pub fn author(&self) -> Option<Sender> {
        let cert = DeviceCert::from_bytes(&self.cert).ok()?;
        verify_device_bytes(
            cert.device(),
            PROFILE_SIGNATURE,
            &signed_bytes(self),
            &self.signature,
        )
        .then(|| Sender {
            person: cert.root().to_bytes(),
            device: cert.device().to_bytes(),
        })
    }

    /// The author, if they signed it from a device on their current
    /// `list`: what a friend checks before showing or caching it.
    pub fn check_from(&self, list: &DeviceList) -> Result<Sender, ProfileError> {
        let author = self.author().ok_or(ProfileError::BadSignature)?;
        let cert = DeviceCert::from_bytes(&self.cert).map_err(|_| ProfileError::BadSignature)?;
        if list.root().to_bytes() != author.person || !list.is_current(cert.device()) {
            return Err(ProfileError::NotCurrentDevice);
        }
        Ok(author)
    }

    /// Whether this manifest replaces `other`, the one held now: a higher
    /// version, or the same version from a higher device key (PR14), so
    /// every device settles on the same one.
    pub fn replaces(&self, other: &Manifest) -> bool {
        let device = |m: &Manifest| {
            DeviceCert::from_bytes(&m.cert)
                .map(|c| c.device().to_bytes())
                .unwrap_or_default()
        };
        (self.version, device(self)) > (other.version, device(other))
    }

    /// Every cap (PR4, PR5, PR7): `profile.toml` parses and its blocks fit,
    /// one avatar, banner, song and background at most, each file within
    /// its size and of a kind it may be, and the whole bundle under 25 MB.
    pub fn check(&self) -> Result<Profile, ProfileError> {
        if self.format != PROFILE_FORMAT {
            return Err(ProfileError::Malformed);
        }
        let profile = Profile::parse(&self.toml)?;
        let mut total: u64 = 0;
        let mut gallery = 0;
        let mut seen = Vec::new();
        for asset in &self.assets {
            let slot = asset.slot;
            if slot == Slot::Gallery {
                gallery += 1;
                if gallery > MAX_GALLERY {
                    return Err(ProfileError::TooMany("gallery pictures"));
                }
            } else if seen.contains(&slot) {
                return Err(ProfileError::Duplicate(slot.name()));
            } else {
                seen.push(slot);
            }
            if asset.size > slot.cap() {
                return Err(ProfileError::TooBig(slot.name()));
            }
            if !slot.types().contains(&asset.mime.as_str()) {
                return Err(ProfileError::WrongType(slot.name()));
            }
            if slot == Slot::Song && asset.seconds.is_some_and(|s| s > MAX_SONG_SECONDS) {
                return Err(ProfileError::SongTooLong);
            }
            if slot != Slot::Song && asset.seconds.is_some() {
                return Err(ProfileError::Malformed);
            }
            total = total.saturating_add(asset.size);
        }
        if total > MAX_BUNDLE {
            return Err(ProfileError::BundleTooBig);
        }
        Ok(profile)
    }

    /// The manifest's bytes, once it's checked.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProfileError> {
        self.check()?;
        let bytes = postcard::to_stdvec(self).map_err(|_| ProfileError::Malformed)?;
        if bytes.len() > MAX_MANIFEST_LEN {
            return Err(ProfileError::TooLong("profile"));
        }
        Ok(bytes)
    }

    /// A manifest from its bytes, checked against the caps (not its
    /// author: that's `check_from`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProfileError> {
        if bytes.len() > MAX_MANIFEST_LEN {
            return Err(ProfileError::TooLong("profile"));
        }
        let m: Manifest = postcard::from_bytes(bytes).map_err(|_| ProfileError::Malformed)?;
        m.check()?;
        Ok(m)
    }

    /// The files of one slot, in the order listed.
    pub fn assets(&self, slot: Slot) -> impl Iterator<Item = &Asset> {
        self.assets.iter().filter(move |a| a.slot == slot)
    }
}

/// `profile.toml`, as far as Mesh-Node reads it. `[theme]` is the Rice
/// token table (theme.toml's keys), left for Aflos to draw (PR4); keys
/// nobody knows are dropped, not errors, and so are block kinds a newer
/// Aflos added (PR5), so an older one still shows the rest.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Profile {
    /// Wear the sender's desktop rice: `[theme]` is a snapshot of it.
    pub follow_rice: bool,
    /// A font from Aflos's bundled set (PR9), by name.
    pub font: Option<String>,
    pub theme: toml::Table,
    pub blocks: Vec<Block>,
}

/// A block, in the order the profile sets (PR5).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Block {
    /// A markdown subset: bold, italic, links, lists.
    Bio {
        text: String,
    },
    Links {
        #[serde(default)]
        links: Vec<Link>,
    },
    /// The gallery pictures, in the manifest's order.
    Gallery,
    /// The song's play button; never autoplays by default (PR10).
    Song,
    /// Friends who agreed to be shown (PR11, Task 5).
    Top8,
    Status {
        text: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Link {
    pub label: String,
    pub url: String,
}

#[derive(Deserialize)]
struct Raw {
    #[serde(default)]
    follow_rice: bool,
    font: Option<String>,
    #[serde(default)]
    theme: toml::Table,
    #[serde(default, rename = "block")]
    blocks: Vec<toml::Value>,
}

/// The block kinds this version knows; others are skipped.
const KNOWN_BLOCKS: [&str; 6] = ["bio", "links", "gallery", "song", "top8", "status"];

impl Profile {
    /// Parses and checks `profile.toml` (PR4, PR5).
    pub fn parse(text: &str) -> Result<Self, ProfileError> {
        if text.len() > MAX_TOML_LEN {
            return Err(ProfileError::TomlTooLong);
        }
        let raw: Raw =
            toml::from_str(text).map_err(|e| ProfileError::Toml(e.message().to_string()))?;
        if raw.blocks.len() > MAX_BLOCKS {
            return Err(ProfileError::TooMany("blocks"));
        }
        let mut blocks = Vec::new();
        for value in raw.blocks {
            let known = value
                .get("kind")
                .and_then(toml::Value::as_str)
                .is_some_and(|k| KNOWN_BLOCKS.contains(&k));
            if !known {
                continue;
            }
            let block: Block = value
                .try_into()
                .map_err(|e: toml::de::Error| ProfileError::Toml(e.message().to_string()))?;
            check_block(&block)?;
            blocks.push(block);
        }
        if raw
            .font
            .as_ref()
            .is_some_and(|f| f.chars().count() > MAX_FONT_NAME)
        {
            return Err(ProfileError::TooLong("font name"));
        }
        Ok(Self {
            follow_rice: raw.follow_rice,
            font: raw.font,
            theme: raw.theme,
            blocks,
        })
    }
}

fn check_block(block: &Block) -> Result<(), ProfileError> {
    match block {
        Block::Bio { text } if text.chars().count() > MAX_BIO => Err(ProfileError::TooLong("bio")),
        Block::Status { text } if text.chars().count() > MAX_STATUS => {
            Err(ProfileError::TooLong("status"))
        }
        Block::Links { links } => {
            if links.len() > MAX_LINKS {
                return Err(ProfileError::TooMany("links"));
            }
            for link in links {
                if link.url.chars().count() > MAX_LINK_LEN {
                    return Err(ProfileError::TooLong("link"));
                }
                if link.label.chars().count() > MAX_LINK_LABEL {
                    return Err(ProfileError::TooLong("link's label"));
                }
                // PR6: shown in full and opened on click; never a file,
                // a script or an app's own scheme.
                let url = link.url.to_ascii_lowercase();
                if !["https://", "http://", "mailto:"]
                    .iter()
                    .any(|s| url.starts_with(s))
                {
                    return Err(ProfileError::BadLink);
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_identity::RootKey;

    const SAMPLE: &str = r##"
follow_rice = true
font = "Michroma"
sparkles = "an unknown key, dropped"

[theme]
accent = "#d88f92"
animation = "rain"

[[block]]
kind = "bio"
text = "Frontman of **Nagbreek**."

[[block]]
kind = "links"
links = [{ label = "Bandcamp", url = "https://example.com" }]

[[block]]
kind = "marquee"
text = "a kind from a newer Aflos, skipped"

[[block]]
kind = "song"

[[block]]
kind = "status"
text = "mixing"
"##;

    struct Someone {
        root: RootKey,
        device: DeviceKey,
        cert: DeviceCert,
    }

    impl Someone {
        fn new() -> Self {
            let root = RootKey::generate().unwrap();
            let device = DeviceKey::generate().unwrap();
            let cert = DeviceCert::issue(&root, &device.public(), "laptop", 1).unwrap();
            Self { root, device, cert }
        }

        fn sign(&self, version: u64, assets: Vec<Asset>) -> Result<Manifest, ProfileError> {
            Manifest::signed(
                version,
                SAMPLE.to_string(),
                assets,
                &self.device,
                &self.cert,
            )
        }
    }

    fn asset(slot: Slot, size: u64, mime: &str) -> Asset {
        Asset {
            slot,
            key: [1; 32],
            hash: [2; 32],
            size,
            mime: mime.to_string(),
            seconds: None,
        }
    }

    fn toml_with(block: &str) -> Result<Profile, ProfileError> {
        Profile::parse(&format!("[[block]]\n{block}\n"))
    }

    #[test]
    fn parses_the_sample_dropping_what_it_doesnt_know() {
        let p = Profile::parse(SAMPLE).unwrap();
        assert!(p.follow_rice);
        assert_eq!(p.font.as_deref(), Some("Michroma"));
        assert_eq!(
            p.theme.get("accent").and_then(|v| v.as_str()),
            Some("#d88f92")
        );
        assert_eq!(p.blocks.len(), 4, "the unknown block kind is skipped");
        assert_eq!(
            p.blocks[0],
            Block::Bio {
                text: "Frontman of **Nagbreek**.".into()
            }
        );
        assert_eq!(p.blocks[2], Block::Song);
    }

    #[test]
    fn an_empty_profile_is_fine() {
        assert_eq!(Profile::parse("").unwrap(), Profile::default());
    }

    #[test]
    fn broken_toml_is_refused() {
        assert!(matches!(
            Profile::parse("[[block]\nkind ="),
            Err(ProfileError::Toml(_))
        ));
        assert!(
            matches!(toml_with("kind = \"bio\""), Err(ProfileError::Toml(_))),
            "a bio needs text"
        );
    }

    #[test]
    fn text_caps_at_and_over() {
        let bio = |n| toml_with(&format!("kind = \"bio\"\ntext = \"{}\"", "é".repeat(n)));
        assert!(bio(MAX_BIO).is_ok(), "counted in characters, not bytes");
        assert_eq!(bio(MAX_BIO + 1), Err(ProfileError::TooLong("bio")));
        let status = |n| toml_with(&format!("kind = \"status\"\ntext = \"{}\"", "x".repeat(n)));
        assert!(status(MAX_STATUS).is_ok());
        assert_eq!(status(MAX_STATUS + 1), Err(ProfileError::TooLong("status")));
        assert_eq!(
            Profile::parse(&format!("font = \"{}\"", "f".repeat(MAX_FONT_NAME + 1))),
            Err(ProfileError::TooLong("font name"))
        );
        assert_eq!(
            Profile::parse(&format!("# {}", "x".repeat(MAX_TOML_LEN))),
            Err(ProfileError::TomlTooLong)
        );
    }

    #[test]
    fn block_and_link_counts() {
        let blocks = "[[block]]\nkind = \"top8\"\n".repeat(MAX_BLOCKS);
        assert!(Profile::parse(&blocks).is_ok());
        let more = format!("{blocks}[[block]]\nkind = \"top8\"\n");
        assert_eq!(Profile::parse(&more), Err(ProfileError::TooMany("blocks")));
        let links = |n: usize| {
            let items = vec!["{ label = \"a\", url = \"https://a.example\" }"; n].join(", ");
            toml_with(&format!("kind = \"links\"\nlinks = [{items}]"))
        };
        assert!(links(MAX_LINKS).is_ok());
        assert_eq!(links(MAX_LINKS + 1), Err(ProfileError::TooMany("links")));
    }

    #[test]
    fn only_web_and_mail_links() {
        let link = |url: &str| {
            toml_with(&format!(
                "kind = \"links\"\nlinks = [{{ label = \"a\", url = \"{url}\" }}]"
            ))
        };
        assert!(link("HTTPS://example.com").is_ok());
        assert!(link("mailto:me@example.com").is_ok());
        for bad in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "steam://run/1",
            "example.com",
        ] {
            assert_eq!(link(bad), Err(ProfileError::BadLink), "{bad}");
        }
    }

    #[test]
    fn signed_by_its_device_and_checked_against_the_list() {
        let me = Someone::new();
        let m = me
            .sign(1, vec![asset(Slot::Avatar, 1000, "image/gif")])
            .unwrap();
        let author = m.author().unwrap();
        assert_eq!(author.person, me.root.id().to_bytes());
        assert_eq!(author.device, me.device.public().to_bytes());
        let list = DeviceList::first(&me.root, me.cert.clone()).unwrap();
        assert_eq!(m.check_from(&list), Ok(author));

        let stranger = Someone::new();
        let theirs = DeviceList::first(&stranger.root, stranger.cert.clone()).unwrap();
        assert_eq!(m.check_from(&theirs), Err(ProfileError::NotCurrentDevice));
    }

    #[test]
    fn any_change_breaks_the_signature() {
        let me = Someone::new();
        let m = me
            .sign(1, vec![asset(Slot::Avatar, 1000, "image/png")])
            .unwrap();
        let mut bumped = m.clone();
        bumped.version = 2;
        assert!(bumped.author().is_none());
        let mut swapped = m.clone();
        swapped.assets[0].hash = [9; 32];
        assert!(swapped.author().is_none());
        let mut edited = m;
        edited.toml.push_str("\n# changed");
        assert!(edited.author().is_none());
    }

    #[test]
    fn bytes_round_trip() {
        let me = Someone::new();
        let m = me
            .sign(7, vec![asset(Slot::Banner, 5000, "image/webp")])
            .unwrap();
        let back = Manifest::from_bytes(&m.to_bytes().unwrap()).unwrap();
        assert_eq!(back, m);
        assert!(back.author().is_some());
        assert_eq!(
            Manifest::from_bytes(&[1, 2, 3]),
            Err(ProfileError::Malformed)
        );
    }

    #[test]
    fn file_caps_at_and_over() {
        let me = Someone::new();
        let one = |slot, size, mime| me.sign(1, vec![asset(slot, size, mime)]);
        for (slot, cap, mime) in [
            (Slot::Avatar, MAX_AVATAR, "image/gif"),
            (Slot::Banner, MAX_BANNER, "image/apng"),
            (Slot::Background, MAX_BACKGROUND, "image/jpeg"),
            (Slot::Gallery, MAX_GALLERY_PICTURE, "image/png"),
            (Slot::Song, MAX_SONG, "audio/ogg"),
        ] {
            assert!(one(slot, cap, mime).is_ok(), "{slot:?} at its cap");
            assert_eq!(
                one(slot, cap + 1, mime),
                Err(ProfileError::TooBig(slot.name()))
            );
        }
    }

    #[test]
    fn file_kinds() {
        let me = Someone::new();
        assert_eq!(
            me.sign(1, vec![asset(Slot::Avatar, 10, "image/svg+xml")]),
            Err(ProfileError::WrongType("avatar")),
            "no SVG: it's a document, not a picture"
        );
        assert_eq!(
            me.sign(1, vec![asset(Slot::Song, 10, "image/png")]),
            Err(ProfileError::WrongType("song"))
        );
        assert!(
            me.sign(1, vec![asset(Slot::Song, 10, "audio/flac")])
                .is_ok()
        );
    }

    #[test]
    fn one_of_each_slot_and_twelve_pictures() {
        let me = Someone::new();
        assert_eq!(
            me.sign(
                1,
                vec![
                    asset(Slot::Avatar, 10, "image/png"),
                    asset(Slot::Avatar, 10, "image/png")
                ]
            ),
            Err(ProfileError::Duplicate("avatar"))
        );
        let pictures = |n| vec![asset(Slot::Gallery, 10, "image/png"); n];
        assert!(me.sign(1, pictures(MAX_GALLERY)).is_ok());
        assert_eq!(
            me.sign(1, pictures(MAX_GALLERY + 1)),
            Err(ProfileError::TooMany("gallery pictures"))
        );
    }

    #[test]
    fn the_whole_bundle_is_capped() {
        let me = Someone::new();
        // 8 + 12 + 4 = 24 MB fits; another 1 MB of song tips it over 25.
        let mut assets = vec![
            asset(Slot::Avatar, MAX_AVATAR, "image/gif"),
            asset(Slot::Banner, MAX_BANNER, "image/gif"),
            asset(Slot::Gallery, MAX_GALLERY_PICTURE, "image/png"),
        ];
        assert!(me.sign(1, assets.clone()).is_ok());
        assets.push(asset(Slot::Song, 1_000_001, "audio/mpeg"));
        assert_eq!(me.sign(1, assets), Err(ProfileError::BundleTooBig));
    }

    #[test]
    fn song_length() {
        let me = Someone::new();
        let song = |seconds| {
            let mut a = asset(Slot::Song, 10, "audio/ogg");
            a.seconds = Some(seconds);
            me.sign(1, vec![a])
        };
        assert!(song(MAX_SONG_SECONDS).is_ok());
        assert_eq!(song(MAX_SONG_SECONDS + 1), Err(ProfileError::SongTooLong));
        let mut picture = asset(Slot::Avatar, 10, "image/png");
        picture.seconds = Some(3);
        assert_eq!(me.sign(1, vec![picture]), Err(ProfileError::Malformed));
    }

    #[test]
    fn newer_versions_replace_older_and_ties_settle_the_same_way() {
        let me = Someone::new();
        let laptop = me.sign(3, vec![]).unwrap();
        let newer = me.sign(4, vec![]).unwrap();
        assert!(newer.replaces(&laptop));
        assert!(!laptop.replaces(&newer));
        assert!(!laptop.replaces(&laptop), "the same one isn't a change");

        // Two devices both publish version 4: every device picks the same.
        let device = DeviceKey::generate().unwrap();
        let cert = DeviceCert::issue(&me.root, &device.public(), "desktop", 1).unwrap();
        let desktop = Manifest::signed(4, SAMPLE.to_string(), vec![], &device, &cert).unwrap();
        assert_ne!(newer.replaces(&desktop), desktop.replaces(&newer));
    }

    #[test]
    fn the_order_of_gallery_pictures_is_kept() {
        let me = Someone::new();
        let mut first = asset(Slot::Gallery, 10, "image/png");
        first.hash = [3; 32];
        let second = asset(Slot::Gallery, 10, "image/png");
        let m = me
            .sign(
                1,
                vec![
                    first.clone(),
                    asset(Slot::Avatar, 10, "image/png"),
                    second.clone(),
                ],
            )
            .unwrap();
        let gallery: Vec<_> = m.assets(Slot::Gallery).collect();
        assert_eq!(gallery, vec![&first, &second]);
    }
}
