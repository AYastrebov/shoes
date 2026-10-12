//! `state_file`: what a controller chose, kept across restarts.
//!
//! sing-box keeps a selector's choice in its `cache_file`, and awg-manager
//! relies on that: a router that reboots comes back on the server the user
//! picked, not on the first member. This is the same promise, in a small
//! JSON file the config names, because a router's config directory is often
//! read-only.
//!
//! The file mirrors the live choice: written after every change, read at
//! every launch. A failure to write is logged and the selection still
//! applies; a file that cannot be read is logged and ignored.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use log::warn;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
struct State {
    /// Group name to the chosen member's outbound name.
    #[serde(default)]
    selections: BTreeMap<String, String>,
    /// Always `rule` until modes exist; written so the file's shape does
    /// not change when they do.
    #[serde(default = "rule")]
    mode: String,
}

fn rule() -> String {
    "rule".to_string()
}

/// Apply a saved file's choices to the groups now installed.
///
/// A choice naming a group or member the config no longer has is dropped
/// with a warning. A missing file is the normal first start.
pub fn restore(path: &Path) {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!("clash_api state_file {}: {e}; ignored", path.display());
            return;
        }
    };
    let state: State = match serde_json::from_slice(&bytes) {
        Ok(state) => state,
        Err(e) => {
            warn!(
                "clash_api state_file {} does not parse ({e}); ignored",
                path.display()
            );
            return;
        }
    };
    for (group, member) in &state.selections {
        match crate::group_selection::get(group) {
            Some(selection) => {
                if !selection.select(member) {
                    warn!(
                        "clash_api state_file: group '{group}' has no member '{member}' any \
                         more; it stays on '{}'",
                        selection.selected_member()
                    );
                }
            }
            None => warn!("clash_api state_file: no select group '{group}' any more; dropped"),
        }
    }
}

/// Write every select group's current choice.
pub fn save(path: &Path) {
    let state = State {
        selections: crate::group_selection::all()
            .iter()
            .map(|s| (s.name().to_string(), s.selected_member().to_string()))
            .collect(),
        mode: rule(),
    };
    if let Err(e) = write_atomically(path, &serde_json::to_vec_pretty(&state).expect("plain map")) {
        warn!(
            "clash_api state_file {}: {e}; the selection applies but will not survive a restart",
            path.display()
        );
    }
}

/// Temporary file, flush to disk, rename: a crash leaves the old file or the
/// new one, never half of either.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_selection::{SelectionSpec, for_chain};

    fn spec(name: &str, members: &[&str]) -> SelectionSpec {
        SelectionSpec {
            name: name.to_string(),
            members: members.iter().map(|m| m.to_string()).collect(),
            default_index: 0,
        }
    }

    #[test]
    fn a_saved_choice_is_restored() {
        let _stable = crate::group_selection::TEST_REGISTRY_GUARD.read();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let selection = for_chain(&spec("st-restore", &["a", "b"]));
        selection.select("b");
        save(&path);
        selection.reset();
        restore(&path);
        assert_eq!(selection.selected_member(), "b");
        assert!(!dir.path().join("state.json.tmp").exists());
    }

    #[test]
    fn a_vanished_member_leaves_the_group_where_it_is() {
        let _stable = crate::group_selection::TEST_REGISTRY_GUARD.read();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(
            &path,
            r#"{"selections":{"st-vanished":"gone","st-no-such-group":"x"},"mode":"rule"}"#,
        )
        .unwrap();
        let selection = for_chain(&spec("st-vanished", &["a", "b"]));
        restore(&path);
        assert_eq!(selection.selected_member(), "a");
    }

    #[test]
    fn a_missing_or_broken_file_changes_nothing() {
        let _stable = crate::group_selection::TEST_REGISTRY_GUARD.read();
        let dir = tempfile::tempdir().unwrap();
        let selection = for_chain(&spec("st-broken", &["a", "b"]));
        selection.select("b");
        restore(&dir.path().join("absent.json"));
        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, "{not json").unwrap();
        restore(&broken);
        assert_eq!(selection.selected_member(), "b");
    }

    #[test]
    fn an_unwritable_path_does_not_undo_the_selection() {
        let selection = for_chain(&spec("st-unwritable", &["a", "b"]));
        selection.select("b");
        save(Path::new("/nonexistent-dir-for-shoes-test/state.json"));
        assert_eq!(selection.selected_member(), "b");
    }
}
