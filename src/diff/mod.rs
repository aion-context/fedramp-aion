//! Semantic diffs. A byte-level diff is useless here: upstream rewrites the
//! marketplace file every day and reformats the rules file at will.

pub mod kev;
pub mod marketplace;
pub mod oscal;
pub mod rules;
pub mod schemas;

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

use crate::severity::Severity;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FieldChange {
    pub field: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Modified {
    pub id: String,
    pub fields: Vec<FieldChange>,
}

/// A change worth putting in the PR title rather than the appendix.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Highlight {
    pub kind: String,
    pub id: String,
    pub field: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Delta {
    pub source: String,
    pub changed: bool,
    pub severity: Severity,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<Modified>,
    pub highlights: Vec<Highlight>,
    /// Upstream structural surprises: a new top-level section, a collection
    /// that stopped being keyed. Surfaced rather than silently absorbed.
    pub drift: Vec<String>,
    pub counts: BTreeMap<String, usize>,
}

impl Delta {
    pub fn new(source: &str) -> Self {
        Self {
            source: source.to_string(),
            ..Self::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.modified.is_empty()
            && self.counts.values().all(|c| *c == 0)
    }

    pub fn total(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }
}

/// Compare two flattened maps and record adds, removes, and field-level edits.
pub fn compare_maps(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    delta: &mut Delta,
    highlight_fields: &[&str],
    highlight_kind: &str,
) {
    for id in after.keys() {
        if !before.contains_key(id) {
            delta.added.push(id.clone());
        }
    }
    for id in before.keys() {
        if !after.contains_key(id) {
            delta.removed.push(id.clone());
        }
    }
    for (id, old) in before {
        let Some(new) = after.get(id) else { continue };
        if old == new {
            continue;
        }
        let fields = field_changes(old, new);
        for change in &fields {
            if highlight_fields.contains(&change.field.as_str()) {
                delta.highlights.push(Highlight {
                    kind: highlight_kind.to_string(),
                    id: id.clone(),
                    field: change.field.clone(),
                    from: change.from.clone(),
                    to: change.to.clone(),
                });
            }
        }
        delta.modified.push(Modified {
            id: id.clone(),
            fields,
        });
    }
}

/// Field-level changes between two values. Non-objects are reported as a
/// single synthetic `value` field so scalars still diff cleanly.
pub fn field_changes(old: &Value, new: &Value) -> Vec<FieldChange> {
    match (old.as_object(), new.as_object()) {
        (Some(old_map), Some(new_map)) => {
            let mut keys: Vec<&String> = old_map.keys().chain(new_map.keys()).collect();
            keys.sort_unstable();
            keys.dedup();
            keys.into_iter()
                .filter(|key| old_map.get(*key) != new_map.get(*key))
                .map(|key| FieldChange {
                    field: key.clone(),
                    from: render(old_map.get(key)),
                    to: render(new_map.get(key)),
                })
                .collect()
        }
        _ => vec![FieldChange {
            field: "value".to_string(),
            from: render(Some(old)),
            to: render(Some(new)),
        }],
    }
}

const RENDER_LIMIT: usize = 160;

/// Compact one-line rendering, truncated so a report stays readable.
pub fn render(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return "(absent)".to_string();
    };
    let text = match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let flattened = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flattened.chars().count() <= RENDER_LIMIT {
        return flattened;
    }
    let head: String = flattened.chars().take(RENDER_LIMIT).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn field_changes_names_only_moved_fields() {
        let old = json!({"force": "SHOULD", "statement": "same", "note": "a"});
        let new = json!({"force": "MUST", "statement": "same", "note": "a"});
        let changes = field_changes(&old, &new);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "force");
        assert_eq!(changes[0].from, "SHOULD");
        assert_eq!(changes[0].to, "MUST");
    }

    #[test]
    fn field_changes_report_added_and_removed_fields() {
        let changes = field_changes(&json!({"a": 1}), &json!({"b": 2}));
        let fields: Vec<&str> = changes.iter().map(|c| c.field.as_str()).collect();
        assert_eq!(fields, vec!["a", "b"]);
        assert_eq!(changes[0].to, "(absent)");
        assert_eq!(changes[1].from, "(absent)");
    }

    #[test]
    fn compare_maps_promotes_configured_fields_to_highlights() {
        let before = BTreeMap::from([("R-1".to_string(), json!({"force": "SHOULD"}))]);
        let after = BTreeMap::from([("R-1".to_string(), json!({"force": "MUST"}))]);
        let mut delta = Delta::new("rules");
        compare_maps(&before, &after, &mut delta, &["force"], "force");
        assert_eq!(delta.highlights.len(), 1);
        assert_eq!(delta.highlights[0].id, "R-1");
    }

    #[test]
    fn render_truncates_long_text_and_collapses_whitespace() {
        let long = json!("x ".repeat(400));
        let rendered = render(Some(&long));
        assert!(rendered.ends_with('…'));
        assert!(rendered.chars().count() <= RENDER_LIMIT + 1);
    }
}
