//! Schema diff: keyed by filename, with JSON-pointer level detail.
//!
//! The CR26 package schemas are versioned by filename
//! (`…-2026-06-24.json`), so a new revision shows up as an add plus a remove.

use serde_json::Value;
use std::collections::BTreeSet;

use super::{render, Delta, FieldChange, Modified};
use crate::severity::Severity;

/// Pointer segments that change what a submitted package must contain.
const HIGHLIGHT_SEGMENTS: &[&str] = &["required", "properties", "enum", "type"];

const MAX_POINTERS_PER_FILE: usize = 40;

pub fn diff(before: &Value, after: &Value) -> Delta {
    let mut delta = Delta::new(crate::sources::SCHEMAS);
    let empty = serde_json::Map::new();
    let old_files = before.as_object().unwrap_or(&empty);
    let new_files = after.as_object().unwrap_or(&empty);

    for name in new_files.keys() {
        if !old_files.contains_key(name) {
            delta.added.push(name.clone());
        }
    }
    for name in old_files.keys() {
        if !new_files.contains_key(name) {
            delta.removed.push(name.clone());
        }
    }
    for (name, old) in old_files {
        let Some(new) = new_files.get(name) else {
            continue;
        };
        if old == new {
            continue;
        }
        let mut pointers = Vec::new();
        walk("", old, new, &mut pointers);
        let truncated = pointers.len() > MAX_POINTERS_PER_FILE;
        if truncated {
            delta.drift.push(format!(
                "{name}: {} pointer changes, reporting the first {MAX_POINTERS_PER_FILE}",
                pointers.len()
            ));
            pointers.truncate(MAX_POINTERS_PER_FILE);
        }
        for change in &pointers {
            if HIGHLIGHT_SEGMENTS
                .iter()
                .any(|segment| change.field.contains(segment))
            {
                delta.highlights.push(super::Highlight {
                    kind: "schema".to_string(),
                    id: name.clone(),
                    field: change.field.clone(),
                    from: change.from.clone(),
                    to: change.to.clone(),
                });
            }
        }
        delta.modified.push(Modified {
            id: name.clone(),
            fields: pointers,
        });
    }

    delta.changed = !delta.is_empty();
    delta.severity = if delta.changed {
        Severity::Major
    } else {
        Severity::None
    };
    delta
}

/// Emit one entry per differing JSON pointer, descending only while both
/// sides remain objects.
fn walk(pointer: &str, old: &Value, new: &Value, out: &mut Vec<FieldChange>) {
    if old == new {
        return;
    }
    match (old.as_object(), new.as_object()) {
        (Some(old_map), Some(new_map)) => {
            let keys: BTreeSet<&String> = old_map.keys().chain(new_map.keys()).collect();
            for key in keys {
                let child = format!("{pointer}/{key}");
                match (old_map.get(key), new_map.get(key)) {
                    (Some(a), Some(b)) => walk(&child, a, b, out),
                    (a, b) => out.push(FieldChange {
                        field: child,
                        from: render(a),
                        to: render(b),
                    }),
                }
            }
        }
        _ => out.push(FieldChange {
            field: if pointer.is_empty() {
                "/".into()
            } else {
                pointer.to_string()
            },
            from: render(Some(old)),
            to: render(Some(new)),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn files() -> Value {
        json!({
            "fedramp-incident-report-schema-2026-06-24.json": {
                "type": "object",
                "required": ["incident_id"],
                "properties": {"incident_id": {"type": "string"}}
            }
        })
    }

    #[test]
    fn unchanged_schemas_produce_nothing() {
        let delta = diff(&files(), &files());
        assert!(!delta.changed);
        assert_eq!(delta.severity, Severity::None);
    }

    #[test]
    fn a_new_dated_revision_is_an_add_and_a_remove() {
        let after = json!({"fedramp-incident-report-schema-2026-09-01.json": {"type": "object"}});
        let delta = diff(&files(), &after);
        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.removed.len(), 1);
        assert_eq!(delta.severity, Severity::Major);
    }

    #[test]
    fn required_field_addition_is_highlighted_by_pointer() {
        let mut after = files();
        after["fedramp-incident-report-schema-2026-06-24.json"]["required"] =
            json!(["incident_id", "reported_at"]);
        let delta = diff(&files(), &after);
        assert_eq!(delta.modified.len(), 1);
        assert_eq!(delta.modified[0].fields[0].field, "/required");
        assert_eq!(delta.highlights.len(), 1);
    }

    #[test]
    fn nested_property_change_reports_full_pointer() {
        let mut after = files();
        after["fedramp-incident-report-schema-2026-06-24.json"]["properties"]["incident_id"]
            ["type"] = json!("integer");
        let delta = diff(&files(), &after);
        assert_eq!(
            delta.modified[0].fields[0].field,
            "/properties/incident_id/type"
        );
    }
}
