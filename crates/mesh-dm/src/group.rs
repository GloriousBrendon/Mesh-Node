//! A group's members and name (SPEC-dm D7), from its change events. Each
//! change names the change it follows (`after`), so they form a tree rooted
//! at the creation. A change counts only if its sender is a member of the
//! version it follows and may make it. Where two changes follow the same
//! one, the branch with a change by the creator wins; if both have one, the
//! earlier creator change; if neither, the lower first event ID. The result
//! depends only on which changes are held, never on their arrival order.

use std::collections::{BTreeSet, HashMap};

use crate::chat::Position;
use crate::event::{Change, EventId, GroupChange, MAX_MEMBERS};
use crate::{Person, group_id};

/// Who's in the group and what it's called.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Version {
    pub creator: Person,
    pub members: BTreeSet<Person>,
    pub name: String,
    /// The newest change on the winning line: what a new one follows.
    pub head: EventId,
}

struct Node {
    by: Person,
    after: Option<EventId>,
    change: Change,
    at: Position,
}

#[derive(Default)]
pub struct Group {
    changes: HashMap<EventId, Node>,
}

impl Group {
    /// A change by `by`, sitting at `at` in the chat.
    pub fn add(&mut self, id: EventId, by: Person, change: GroupChange, at: Position) {
        self.changes.entry(id).or_insert(Node {
            by,
            after: change.after,
            change: change.change,
            at,
        });
    }

    /// Every change held, to save with the chat (they're few): ID, sender,
    /// the change, and where it sits.
    pub fn changes(&self) -> Vec<(EventId, Person, GroupChange, Position)> {
        let changes = self.changes.iter().map(|(id, n)| {
            let change = GroupChange {
                after: n.after,
                change: n.change.clone(),
            };
            (*id, n.by, change, n.at)
        });
        changes.collect()
    }

    /// The group `id` as its winning line of changes leaves it; `None`
    /// before its creation has arrived. A creation counts only if its
    /// sender and nonce hash to `id`: nobody else can replace the creator.
    pub fn version(&self, id: &[u8; 16]) -> Option<Version> {
        let creates = self.changes.iter().filter(|(_, n)| {
            n.after.is_none()
                && matches!(&n.change, Change::Create { nonce, .. } if group_id(&n.by, nonce) == *id)
        });
        // The creator's two creations under one ID: the first in the chat's order.
        let (root, node) = creates.min_by_key(|(_, n)| n.at)?;
        let Change::Create { name, members, .. } = &node.change else {
            unreachable!("filtered above")
        };
        let mut start = Version {
            creator: node.by,
            members: BTreeSet::from([node.by]),
            name: name.clone(),
            head: *root,
        };
        start.members.extend(members.iter().take(MAX_MEMBERS - 1));
        let mut children: HashMap<EventId, Vec<EventId>> = HashMap::new();
        for (id, n) in &self.changes {
            if let Some(after) = n.after {
                children.entry(after).or_default().push(*id);
            }
        }
        // Top down: each change's version follows from its one line of
        // ancestors, so whether it counts is known before any fork is settled.
        let mut versions = HashMap::from([(*root, start)]);
        let mut order = vec![*root];
        let mut i = 0;
        while let Some(&id) = order.get(i) {
            i += 1;
            for child in children.get(&id).into_iter().flatten() {
                let node = &self.changes[child];
                if let Some(next) = apply(&versions[&id], node) {
                    versions.insert(*child, next);
                    order.push(*child);
                }
            }
        }
        // Bottom up: each change's best continuation, and the first creator
        // change on the line it leads.
        let mut best: HashMap<EventId, (Option<EventId>, Option<Position>)> = HashMap::new();
        for id in order.iter().rev() {
            let node = &self.changes[id];
            let valid = children.get(id).into_iter().flatten();
            let next = valid.filter(|c| versions.contains_key(*c)).min_by(|a, b| {
                let (fa, fb) = (best[*a].1, best[*b].1);
                match (fa, fb) {
                    (Some(x), Some(y)) => x.cmp(&y),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => a.cmp(b),
                }
            });
            let creator = versions[id].creator;
            let first = if node.by == creator {
                Some(node.at)
            } else {
                next.and_then(|n| best[n].1)
            };
            best.insert(*id, (next.copied(), first));
        }
        let mut at = *root;
        while let Some(next) = best[&at].0 {
            at = next;
        }
        let mut version = versions.remove(&at)?;
        version.head = at;
        Some(version)
    }
}

/// The version after `node`, if its sender may make that change in `v`.
fn apply(v: &Version, node: &Node) -> Option<Version> {
    let member = v.members.contains(&node.by);
    let mut next = v.clone();
    match &node.change {
        Change::Create { .. } => return None,
        Change::Add(who) if member && !v.members.contains(who) && v.members.len() < MAX_MEMBERS => {
            next.members.insert(*who);
        }
        Change::Remove(who) if node.by == v.creator && member && *who != v.creator => {
            if !next.members.remove(who) {
                return None;
            }
        }
        Change::Leave if member => {
            next.members.remove(&node.by);
        }
        Change::Rename(name) if member => next.name = name.clone(),
        _ => return None,
    }
    Some(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: Person = [1; 32];
    const A: Person = [2; 32];
    const B: Person = [3; 32];
    const D: Person = [4; 32];
    const E: Person = [5; 32];

    /// (id, by, after, change, seq)
    type Step = (u8, Person, Option<u8>, Change, u64);

    fn group(steps: &[Step]) -> Option<Version> {
        let mut g = Group::default();
        for (id, by, after, change, seq) in steps.iter().cloned() {
            let change = GroupChange {
                after: after.map(|a| [a; 16]),
                change,
            };
            g.add([id; 16], by, change, (seq, [id; 16]));
        }
        g.version(&id())
    }

    const NONCE: [u8; 16] = [7; 16];

    /// The test group's ID: C made it.
    fn id() -> [u8; 16] {
        group_id(&C, &NONCE)
    }

    fn create() -> Step {
        let members = vec![A, B];
        (
            1,
            C,
            None,
            Change::Create {
                name: "hike".into(),
                members,
                nonce: NONCE,
            },
            1,
        )
    }

    fn members(v: &Version) -> Vec<Person> {
        v.members.iter().copied().collect()
    }

    /// Every order of `steps` gives the same group.
    fn in_any_order(steps: &[Step]) -> Version {
        let first = group(steps).unwrap();
        let mut order: Vec<usize> = (0..steps.len()).collect();
        for _ in 0..24 {
            order.rotate_left(1);
            let middle = order.len() / 2;
            order.swap(0, middle);
            let shuffled: Vec<Step> = order.iter().map(|&i| steps[i].clone()).collect();
            assert_eq!(group(&shuffled).unwrap(), first, "order {order:?}");
        }
        first
    }

    #[test]
    fn the_creation_and_simple_changes() {
        assert_eq!(group(&[]), None);
        let v = in_any_order(&[
            create(),
            (2, A, Some(1), Change::Add(D), 2),
            (3, B, Some(2), Change::Rename("trip".into()), 3),
            (4, D, Some(3), Change::Leave, 4),
        ]);
        assert_eq!(
            (members(&v), v.name.as_str(), v.creator),
            (vec![C, A, B], "trip", C)
        );
    }

    #[test]
    fn a_change_waits_for_the_one_it_follows() {
        let waiting = group(&[create(), (3, A, Some(2), Change::Rename("late".into()), 3)]);
        assert_eq!(waiting.unwrap().name, "hike");
        let v = group(&[
            create(),
            (3, A, Some(2), Change::Rename("late".into()), 3),
            (2, B, Some(1), Change::Add(D), 2),
        ]);
        assert_eq!(v.unwrap().name, "late");
    }

    #[test]
    fn only_the_creator_removes_and_only_members_change() {
        let v = group(&[create(), (2, A, Some(1), Change::Remove(B), 2)]);
        assert_eq!(members(&v.unwrap()), [C, A, B], "a non-creator's removal");
        let v = group(&[create(), (2, E, Some(1), Change::Add(D), 2)]);
        assert_eq!(members(&v.unwrap()), [C, A, B], "a stranger's add");
        let v = group(&[create(), (2, C, Some(1), Change::Remove(C), 2)]);
        assert_eq!(
            members(&v.unwrap()),
            [C, A, B],
            "the creator can't be removed"
        );
    }

    #[test]
    fn concurrent_add_and_remove_go_to_the_creator() {
        let v = in_any_order(&[
            create(),
            (2, A, Some(1), Change::Add(D), 2),
            (3, C, Some(1), Change::Remove(B), 2),
        ]);
        assert_eq!(members(&v), [C, A]);
    }

    /// A removed member forks from before their removal to add someone. The
    /// removal's branch has the creator's change, even when it isn't first.
    #[test]
    fn a_back_dated_add_loses_to_the_creators_branch() {
        let v = in_any_order(&[
            create(),
            (2, C, Some(1), Change::Remove(B), 5),
            (3, B, Some(1), Change::Add(E), 2),
        ]);
        assert_eq!(members(&v), [C, A]);
        let v = in_any_order(&[
            create(),
            (2, A, Some(1), Change::Rename("x".into()), 3),
            (4, C, Some(2), Change::Remove(B), 4),
            // B's id is lower, so without the creator rule B's branch would win.
            (0, B, Some(1), Change::Add(E), 2),
        ]);
        assert_eq!((members(&v), v.name.as_str()), (vec![C, A], "x"));
    }

    #[test]
    fn two_creator_branches_go_to_the_earlier_change() {
        let v = in_any_order(&[
            create(),
            (2, C, Some(1), Change::Rename("later".into()), 10),
            (3, C, Some(1), Change::Rename("earlier".into()), 5),
        ]);
        assert_eq!(v.name, "earlier");
        // Neither branch has the creator: the lower first event ID.
        let v = in_any_order(&[
            create(),
            (7, A, Some(1), Change::Rename("seven".into()), 2),
            (6, B, Some(1), Change::Rename("six".into()), 3),
        ]);
        assert_eq!(v.name, "six");
    }

    /// A member with a new device sends a second creation that sorts
    /// first (a lower seq, which is the sender's choice). The creator stays.
    #[test]
    fn a_second_creation_cant_replace_the_creator() {
        let takeover = Change::Create {
            name: "mine".into(),
            members: vec![B],
            nonce: NONCE,
        };
        let v = group(&[create(), (0, A, None, takeover, 0)]).unwrap();
        assert_eq!((v.creator, v.name.as_str()), (C, "hike"));
        // Even with a nonce that would make A the creator of some other group.
        let theirs = Change::Create {
            name: "mine".into(),
            members: vec![B],
            nonce: [9; 16],
        };
        let takeover = (0, A, None, theirs, 0);
        let v = group(&[create(), takeover]).unwrap();
        assert_eq!((v.creator, v.name.as_str()), (C, "hike"));
    }

    /// The head is the newest change on the winning line: what the next
    /// change names as `after`. And the changes can be saved and loaded.
    #[test]
    fn the_head_and_saving_the_changes() {
        let steps = [create(), (2, A, Some(1), Change::Rename("x".into()), 2)];
        assert_eq!(group(&steps).unwrap().head, [2; 16]);
        assert_eq!(group(&steps[..1]).unwrap().head, [1; 16]);
        let mut g = Group::default();
        for (i, by, after, change, seq) in steps.iter().cloned() {
            let change = GroupChange {
                after: after.map(|a| [a; 16]),
                change,
            };
            g.add([i; 16], by, change, (seq, [i; 16]));
        }
        let mut back = Group::default();
        for (id, by, change, at) in g.changes() {
            back.add(id, by, change, at);
        }
        assert_eq!(back.version(&id()), g.version(&id()));
    }

    #[test]
    fn at_most_ten_members() {
        let mut steps = vec![create()];
        for i in 0..10u8 {
            steps.push((
                10 + i,
                C,
                Some(if i == 0 { 1 } else { 9 + i }),
                Change::Add([100 + i; 32]),
                2 + u64::from(i),
            ));
        }
        assert_eq!(group(&steps).unwrap().members.len(), MAX_MEMBERS);
    }
}
