//! Which member a `select` client group is on, shared by every chain built
//! from it.
//!
//! A named group does not survive validation as one object: every rule of
//! every listener builds its own chains from the group's members, each with
//! its own pool. So the choice cannot live in a chain. It lives here, keyed by
//! group name, and each chain built from the group holds the same
//! [`GroupSelection`] and reads it once per connection.
//!
//! The registry is replaced on every launch, keeping a group's choice when the
//! group and the chosen member both survive, so a reload does not undo what a
//! controller selected.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use log::warn;
use parking_lot::RwLock;

/// A `select` group as validation describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionSpec {
    pub name: String,
    /// Outbound names (`ClientConfig::stats_key`), in pool order. Unique.
    pub members: Vec<String>,
    pub default_index: usize,
}

/// The live choice of one `select` group.
#[derive(Debug)]
pub struct GroupSelection {
    name: Arc<str>,
    members: Box<[Arc<str>]>,
    default_index: usize,
    selected: AtomicUsize,
}

impl GroupSelection {
    fn new(spec: &SelectionSpec, selected: usize) -> Self {
        Self {
            name: spec.name.as_str().into(),
            members: spec.members.iter().map(|m| m.as_str().into()).collect(),
            default_index: spec.default_index,
            selected: AtomicUsize::new(selected),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn members(&self) -> &[Arc<str>] {
        &self.members
    }

    /// The pool index a new connection takes.
    pub fn selected_index(&self) -> usize {
        self.selected.load(Ordering::Relaxed)
    }

    pub fn selected_member(&self) -> &str {
        &self.members[self.selected_index()]
    }

    pub fn default_member(&self) -> &str {
        &self.members[self.default_index]
    }

    /// Choose `member` by outbound name. False if the group has no such
    /// member, in which case nothing changes.
    ///
    /// Only the controller changes a selection, so a build without it never
    /// calls this or `reset`.
    #[cfg_attr(not(feature = "clash-api"), allow(dead_code))]
    pub fn select(&self, member: &str) -> bool {
        match self.members.iter().position(|m| &**m == member) {
            Some(index) => {
                self.selected.store(index, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// Back to the configured default.
    #[cfg_attr(not(feature = "clash-api"), allow(dead_code))]
    pub fn reset(&self) {
        self.selected.store(self.default_index, Ordering::Relaxed);
    }

    fn matches(&self, spec: &SelectionSpec) -> bool {
        self.default_index == spec.default_index
            && self.members.len() == spec.members.len()
            && self
                .members
                .iter()
                .zip(&spec.members)
                .all(|(a, b)| &**a == b)
    }
}

fn registry() -> &'static RwLock<Registry> {
    static REGISTRY: OnceLock<RwLock<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

type Registry = HashMap<Arc<str>, Arc<GroupSelection>>;

/// Held for writing by every [`install`] in a test build, and for reading by
/// any test that looks a group up by name between two steps. Without it, a
/// test elsewhere that prepares a config -- `control`'s, for one -- installs
/// an empty registry in the middle of that test, since the registry is
/// process-wide and tests run in parallel. Taking it inside `install` is what
/// makes it complete: every replacement passes through here.
#[cfg(test)]
pub(crate) static TEST_REGISTRY_GUARD: RwLock<()> = RwLock::new(());

/// Replace the registry with the groups of a newly validated config.
///
/// Called before any chain of that config is built. A group whose name and
/// chosen member both survive keeps its choice; any other falls back to its
/// default, with a warning when a choice is lost.
pub fn install(specs: &[SelectionSpec]) {
    #[cfg(test)]
    let _exclusive = TEST_REGISTRY_GUARD.write();
    let mut registry = registry().write();
    *registry = carried_over(&registry, specs);
}

/// The registry for `specs`, keeping what `old` had chosen where it still
/// applies. Separate from [`install`] so it can be tested without replacing
/// the process-wide registry under every other test.
fn carried_over(old: &Registry, specs: &[SelectionSpec]) -> Registry {
    let mut next = HashMap::with_capacity(specs.len());
    for spec in specs {
        let selected = old
            .get(spec.name.as_str())
            .and_then(|old| {
                let chosen = old.selected_member();
                let kept = spec.members.iter().position(|m| m == chosen);
                if kept.is_none() && chosen != old.default_member() {
                    warn!(
                        "client group '{}': the selected member '{chosen}' is no longer in \
                         the group; back to the default",
                        spec.name
                    );
                }
                kept
            })
            .unwrap_or(spec.default_index);
        let selection = Arc::new(GroupSelection::new(spec, selected));
        next.insert(selection.name.clone(), selection);
    }
    next
}

/// The selection a chain built from `spec` reads.
///
/// Normally the one [`install`] put there. A chain built without a launch --
/// a test, or a host that builds selectors itself -- gets a fresh one at the
/// default, registered so a later lookup by name finds the same object.
pub fn for_chain(spec: &SelectionSpec) -> Arc<GroupSelection> {
    if let Some(existing) = registry().read().get(spec.name.as_str())
        && existing.matches(spec)
    {
        return existing.clone();
    }
    let mut registry = registry().write();
    if let Some(existing) = registry.get(spec.name.as_str())
        && existing.matches(spec)
    {
        return existing.clone();
    }
    let selection = Arc::new(GroupSelection::new(spec, spec.default_index));
    registry.insert(selection.name.clone(), selection.clone());
    selection
}

/// Every installed selection, sorted by group name.
#[cfg_attr(not(feature = "clash-api"), allow(dead_code))] // the controller's
pub fn all() -> Vec<Arc<GroupSelection>> {
    let mut all: Vec<_> = registry().read().values().cloned().collect();
    all.sort_by(|a, b| a.name.cmp(&b.name));
    all
}

/// The live selection of the group called `name`.
#[cfg_attr(not(feature = "clash-api"), allow(dead_code))] // the controller's
pub fn get(name: &str) -> Option<Arc<GroupSelection>> {
    registry().read().get(name).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // `install` replaces the process-wide registry, and tests run in
    // parallel, so these go through `carried_over` on a registry of their
    // own. `for_chain` only adds, so its tests use names no other test does.
    fn spec(name: &str, members: &[&str], default_index: usize) -> SelectionSpec {
        SelectionSpec {
            name: name.to_string(),
            members: members.iter().map(|m| m.to_string()).collect(),
            default_index,
        }
    }

    #[test]
    fn a_group_starts_on_its_default() {
        let registry = carried_over(&Registry::new(), &[spec("g", &["a", "b", "c"], 1)]);
        assert_eq!(registry["g"].selected_member(), "b");
    }

    #[test]
    fn select_changes_what_every_holder_reads() {
        let _stable = TEST_REGISTRY_GUARD.read();
        let s = spec("gs-shared", &["a", "b"], 0);
        let one = for_chain(&s);
        let two = for_chain(&s);
        assert!(Arc::ptr_eq(&one, &two));
        assert!(one.select("b"));
        assert_eq!(two.selected_index(), 1);
        assert!(!one.select("nope"));
        assert_eq!(two.selected_member(), "b");
        two.reset();
        assert_eq!(one.selected_member(), "a");
    }

    #[test]
    fn a_reload_keeps_a_choice_whose_member_survives() {
        let first = carried_over(&Registry::new(), &[spec("g", &["a", "b", "c"], 0)]);
        first["g"].select("c");
        // Reordered, with a member added: the choice follows the name.
        let second = carried_over(&first, &[spec("g", &["c", "d", "a"], 2)]);
        assert_eq!(second["g"].selected_member(), "c");
    }

    #[test]
    fn a_reload_drops_a_choice_whose_member_is_gone() {
        let first = carried_over(&Registry::new(), &[spec("g", &["a", "b"], 0)]);
        first["g"].select("b");
        let second = carried_over(&first, &[spec("g", &["a", "c"], 1)]);
        assert_eq!(second["g"].selected_member(), "c");
    }

    #[test]
    fn a_reload_drops_groups_that_are_gone() {
        let first = carried_over(&Registry::new(), &[spec("g", &["a"], 0)]);
        let second = carried_over(&first, &[spec("h", &["a"], 0)]);
        assert!(!second.contains_key("g"));
    }

    #[test]
    fn a_chain_built_against_a_changed_group_gets_a_fresh_selection() {
        let old = for_chain(&spec("gs-fresh", &["a", "b"], 0));
        let fresh = for_chain(&spec("gs-fresh", &["a", "b", "c"], 2));
        assert!(!Arc::ptr_eq(&old, &fresh));
        assert_eq!(fresh.selected_member(), "c");
    }
}
