//! Reports to a Space's owner (SPEC-connection-privacy P11): a member tells
//! the owner about another member, with a reason and, if they choose, the
//! messages in question. It goes to the owner's devices only, end-to-end
//! encrypted like a Space event but in its own layout (`REPORT_LAYOUT`), and
//! never to anyone else: no other member, no seed, nobody at Aflos.
//!
//! The reporter's device keeps it until one of the owner's devices takes it,
//! sending again whenever the owner connects, for up to `OUT_LIFE`. The owner
//! keeps what came in a sealed file, per device.

use super::*;
use mesh_dm::space::SpaceId;
use mesh_identity::{read_sealed, write_sealed};
use serde::Serialize;

/// The first byte of a report's body; Space events use 2 and 3, chat
/// events 1. An engine without reports fails to read it, and the reporter
/// keeps it until it lapses.
pub(super) const REPORT_LAYOUT: u8 = 4;
/// What a reason may hold, in bytes.
const MAX_REASON: usize = 1000;
/// Quoted messages, and each one's length in bytes.
const MAX_QUOTED: usize = 10;
const MAX_QUOTE: usize = 2000;
/// How long a report waits for the owner, in seconds.
const OUT_LIFE: u64 = 30 * 86_400;
/// Reports an owner's device keeps, oldest dropped first.
const MAX_KEPT: usize = 500;
const CONTEXT: &str = "mesh/v1 space reports";
const FORMAT: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Report {
    pub space: SpaceId,
    /// The member reported.
    pub about: [u8; 32],
    pub reason: String,
    /// Their messages the reporter chose to include, as text.
    pub quoted: Vec<String>,
    /// When it was made, Unix seconds.
    pub at: u64,
}

impl Report {
    fn valid(&self) -> bool {
        self.reason.len() <= MAX_REASON
            && self.quoted.len() <= MAX_QUOTED
            && self.quoted.iter().all(|q| q.len() <= MAX_QUOTE)
    }

    fn to_body(&self) -> Vec<u8> {
        let mut body = vec![REPORT_LAYOUT];
        body.extend(postcard::to_stdvec(self).expect("to memory"));
        body
    }

    pub(super) fn from_body(body: &[u8]) -> Option<Self> {
        let (&layout, rest) = body.split_first()?;
        let report: Self = postcard::from_bytes(rest).ok()?;
        (layout == REPORT_LAYOUT && report.valid()).then_some(report)
    }
}

/// A report an owner's device holds: who sent it, and what.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Kept {
    pub from: [u8; 32],
    pub report: Report,
}

/// The reports waiting for an owner, and those that came to us as one.
#[derive(Default)]
pub(super) struct Reports {
    /// The owner each is for, and the report.
    pub out: Vec<(MeshId, Report)>,
    pub kept: Vec<Kept>,
}

fn path(root: &Path) -> PathBuf {
    root.join("reports")
}

impl Helper {
    /// The reports this device keeps as an owner, at unlock. Unreadable
    /// ones start empty (they were only ever on this device).
    pub(super) fn reports_load(&mut self) {
        let Some(store) = &self.store else { return };
        let root = self.path.parent().unwrap_or(Path::new(".")).to_owned();
        let read = read_sealed(&path(&root), store.data_key(), CONTEXT, FORMAT);
        self.reports.kept = match read {
            Ok(Some((_, bytes))) => postcard::from_bytes(&bytes).unwrap_or_default(),
            Ok(None) => Vec::new(),
            Err(e) => {
                eprintln!("mesh-node: the Space reports couldn't be read ({e}); they start empty");
                Vec::new()
            }
        };
    }

    fn reports_save(&self) {
        let Some(store) = &self.store else { return };
        let root = self.path.parent().unwrap_or(Path::new("."));
        let bytes = postcard::to_stdvec(&self.reports.kept).expect("to memory");
        if let Err(e) = write_sealed(&path(root), store.data_key(), CONTEXT, FORMAT, &bytes) {
            eprintln!("mesh-node: couldn't save the Space reports: {e}");
        }
    }

    /// `spaceReport <space> <member> <reason> [quoted…]`: a member reports
    /// another to the Space's owner.
    pub(super) fn space_report(&mut self, args: &[String]) -> Result<(), Fail> {
        let bad = |why: &str| Fail("bad-args", why.to_owned());
        let space = spaces::parse16(args.first().ok_or_else(|| bad("a Space"))?, "Space")?;
        let about = parse_id(args.get(1).ok_or_else(|| bad("who"))?)?;
        let reason = args.get(2).map(|r| r.trim().to_owned()).unwrap_or_default();
        let quoted: Vec<String> = args.iter().skip(3).cloned().collect();
        let me = self.unlocked()?.id();
        let v = self
            .space_version(&space)
            .ok_or_else(|| Fail("not-found", "no such Space".into()))?;
        let owner =
            MeshId::from_bytes(&v.state.owner).map_err(|_| Fail("not-found", "no owner".into()))?;
        if !v.state.members.contains_key(&me.to_bytes()) {
            return Err(Fail("not-allowed", "you're not in that Space".into()));
        }
        if about == me || owner == me {
            return Err(Fail(
                "not-allowed",
                "you can't report yourself or to yourself".into(),
            ));
        }
        if !v.ever_members.contains(&about.to_bytes()) {
            return Err(Fail("not-found", "they've never been in that Space".into()));
        }
        let report = Report {
            space,
            about: about.to_bytes(),
            reason,
            quoted,
            at: unix_now(),
        };
        if !report.valid() {
            return Err(bad("the reason or the quoted messages are too long"));
        }
        self.reports.out.push((owner, report));
        self.report_deliver(&owner);
        emit("meshDone", json!({ "fn": "spaceReport" }));
        Ok(())
    }

    /// Sends what's waiting for `owner` to each of their connected devices;
    /// a report goes once one of them has it (`Back::ReportTaken`).
    pub(super) fn report_deliver(&mut self, owner: &MeshId) {
        let now = unix_now();
        self.reports.out.retain(|(_, r)| r.at + OUT_LIFE > now);
        let waiting: Vec<Report> = (self.reports.out.iter())
            .filter(|(o, _)| o == owner)
            .map(|(_, r)| r.clone())
            .collect();
        let (Some(net), Some(e2ee)) = (&self.net, self.e2ee.as_mut()) else {
            return;
        };
        if waiting.is_empty() {
            return;
        }
        // A report is Space traffic: relayed (P14), whoever the owner is.
        let node = net.node.relayed();
        let mut missing_keys = false;
        for addr in node.connected(owner) {
            let bodies: Vec<Vec<u8>> = waiting.iter().map(Report::to_body).collect();
            let device = *addr.device.as_bytes();
            let Ok(envelopes) =
                e2ee.encrypt_device_batch(owner, &device, NoteKind::Message, &bodies)
            else {
                missing_keys = true;
                continue;
            };
            let frames: Vec<Vec<u8>> = envelopes.iter().map(|e| [&[0][..], e].concat()).collect();
            let (node, back, owner, sent) =
                (node.clone(), self.back.clone(), *owner, waiting.clone());
            tokio::spawn(async move {
                if e2ee::send(&node, &addr, &frames).await {
                    let _ = back.send(Back::ReportTaken(Box::new((owner, sent))));
                }
            });
        }
        if missing_keys {
            self.keys_for(owner);
        }
    }

    /// Tries every owner something waits for (the refresh): a connection we
    /// made ourselves doesn't say so the way one made to us does.
    pub(super) fn report_retry(&mut self) {
        let mut owners: Vec<MeshId> = self.reports.out.iter().map(|(o, _)| *o).collect();
        owners.dedup();
        for owner in owners {
            self.report_deliver(&owner);
        }
    }

    /// One of the owner's devices took these: they don't wait any more.
    pub(super) fn report_taken(&mut self, owner: &MeshId, sent: &[Report]) {
        self.reports
            .out
            .retain(|(o, r)| o != owner || !sent.contains(r));
    }

    /// A report came: kept if it's about a Space we own, from someone in it.
    pub(super) fn report_heard(&mut self, from: &MeshId, body: &[u8]) {
        let Some(report) = Report::from_body(body) else {
            return eprintln!("mesh-node: a Space report didn't read");
        };
        let Some(me) = self.store.as_ref().map(Keystore::id) else {
            return;
        };
        let ours = self.space_version(&report.space).is_some_and(|v| {
            v.state.owner == me.to_bytes() && v.ever_members.contains(&from.to_bytes())
        });
        if !ours {
            return;
        }
        let kept = Kept {
            from: from.to_bytes(),
            report,
        };
        if self.reports.kept.contains(&kept) {
            return;
        }
        let space = kept.report.space;
        self.reports.kept.push(kept);
        if self.reports.kept.len() > MAX_KEPT {
            self.reports.kept.remove(0);
        }
        self.reports_save();
        self.emit_reports(&space);
    }

    /// `spaceReportDismiss <space> <from> <at>`: the owner is done with one.
    pub(super) fn report_dismiss(&mut self, args: &[String]) -> Result<(), Fail> {
        let bad = || Fail("bad-args", "a Space, who sent it and when".to_owned());
        let space = spaces::parse16(args.first().ok_or_else(bad)?, "Space")?;
        let from = parse_id(args.get(1).ok_or_else(bad)?)?.to_bytes();
        let at: u64 = args.get(2).and_then(|a| a.parse().ok()).ok_or_else(bad)?;
        self.reports
            .kept
            .retain(|k| !(k.report.space == space && k.from == from && k.report.at == at));
        self.reports_save();
        self.emit_reports(&space);
        Ok(())
    }

    /// `meshSpaceReports`: the reports this device keeps for a Space we own.
    pub(super) fn emit_reports(&self, space: &SpaceId) {
        let reports: Vec<Value> = (self.reports.kept.iter())
            .filter(|k| k.report.space == *space)
            .map(|k| {
                let id = |b: &[u8; 32]| {
                    MeshId::from_bytes(b)
                        .map(|i| i.to_string())
                        .unwrap_or_default()
                };
                json!({
                    "from": id(&k.from),
                    "about": id(&k.report.about),
                    "reason": k.report.reason,
                    "quoted": k.report.quoted,
                    "at": k.report.at,
                })
            })
            .collect();
        emit(
            "meshSpaceReports",
            json!({ "space": spaces::hex16(space), "reports": reports }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Report {
        Report {
            space: [1; 16],
            about: [2; 32],
            reason: "spam".into(),
            quoted: vec!["buy now".into()],
            at: 5,
        }
    }

    #[test]
    fn a_report_round_trips_and_is_bounded() {
        assert_eq!(Report::from_body(&report().to_body()), Some(report()));
        // Another layout (a Space event's) isn't a report.
        let mut other = report().to_body();
        other[0] = mesh_dm::space_store::SPACE_LAYOUT;
        assert_eq!(Report::from_body(&other), None);
        let long = Report {
            reason: "x".repeat(MAX_REASON + 1),
            ..report()
        };
        assert_eq!(
            Report::from_body(&long.to_body()),
            None,
            "too long a reason"
        );
        let many = Report {
            quoted: vec![String::new(); MAX_QUOTED + 1],
            ..report()
        };
        assert_eq!(Report::from_body(&many.to_body()), None, "too many quotes");
    }
}
