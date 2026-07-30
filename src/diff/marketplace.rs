//! Marketplace diff.
//!
//! Two upstream facts shape this: the file is rewritten daily whether or not
//! anything moved, and `ReuseMapping` has no usable key (316 distinct ids
//! across 2813 rows), so it is compared as a multiset.

use serde_json::Value;
use std::collections::BTreeMap;

use super::{compare_maps, render, Delta};
use crate::severity::Severity;

/// Field changes that reflect a real authorization event.
const MATERIAL_FIELDS: &[&str] = &[
    "status",
    "auth_type",
    "auth_date",
    "impact_level",
    "impact_level_number",
    "fedramp_ready",
    "fedramp_auth",
    "ready_status",
    "ready_date",
    "ip_jab_status",
    "ip_prog_status",
    "ip_agency_status",
    "ip_pmo_status",
    "annual_assessment",
    "independent_assessor",
];

/// Collections with no stable key; compared as multisets of row digests.
const UNKEYED: &[&str] = &["ReuseMapping"];

pub fn diff(before: &Value, after: &Value) -> Delta {
    let mut delta = Delta::new(crate::sources::MARKETPLACE);
    let old_data = before.get("data").unwrap_or(before);
    let new_data = after.get("data").unwrap_or(after);

    let mut collections: Vec<&String> = old_data
        .as_object()
        .into_iter()
        .chain(new_data.as_object())
        .flat_map(serde_json::Map::keys)
        .collect();
    collections.sort_unstable();
    collections.dedup();

    for name in collections {
        let old = old_data.get(name);
        let new = new_data.get(name);
        match (old, new) {
            (Some(Value::Array(_)) | None, Some(Value::Array(_)))
            | (Some(Value::Array(_)), None) => {
                diff_collection(name, old, new, &mut delta);
            }
            _ => diff_opaque(name, old, new, &mut delta),
        }
    }

    delta.changed = !delta.is_empty();
    delta.severity = classify(&delta);
    delta
}

fn diff_collection(name: &str, old: Option<&Value>, new: Option<&Value>, delta: &mut Delta) {
    let old_rows = rows(old);
    let new_rows = rows(new);

    if UNKEYED.contains(&name) || !uniquely_keyed(&new_rows) {
        if !UNKEYED.contains(&name) && !new_rows.is_empty() {
            delta.drift.push(format!(
                "`{name}` rows are not uniquely keyed by id — compared as a multiset"
            ));
        }
        return diff_multiset(name, &old_rows, &new_rows, delta);
    }

    let keyed = |rows: &[Value]| -> BTreeMap<String, Value> {
        rows.iter()
            .map(|row| (format!("{name}/{}", render(row.get("id"))), row.clone()))
            .collect()
    };
    let mut scoped = Delta::new(&delta.source);
    compare_maps(
        &keyed(&old_rows),
        &keyed(&new_rows),
        &mut scoped,
        MATERIAL_FIELDS,
        "marketplace",
    );
    delta.added.extend(scoped.added);
    delta.removed.extend(scoped.removed);
    delta.modified.extend(scoped.modified);
    delta.highlights.extend(scoped.highlights);
}

/// Rows are indistinguishable, so only the net add/remove counts are truthful.
fn diff_multiset(name: &str, old_rows: &[Value], new_rows: &[Value], delta: &mut Delta) {
    let tally = |rows: &[Value]| -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for row in rows {
            let digest = crate::canon::digest_value(row).unwrap_or_else(|_| row.to_string());
            *counts.entry(digest).or_insert(0) += 1;
        }
        counts
    };
    let old_counts = tally(old_rows);
    let new_counts = tally(new_rows);

    let added: usize = new_counts
        .iter()
        .map(|(k, n)| n.saturating_sub(old_counts.get(k).copied().unwrap_or(0)))
        .sum();
    let removed: usize = old_counts
        .iter()
        .map(|(k, n)| n.saturating_sub(new_counts.get(k).copied().unwrap_or(0)))
        .sum();

    if added > 0 {
        delta.counts.insert(format!("{name}.rows_added"), added);
    }
    if removed > 0 {
        delta.counts.insert(format!("{name}.rows_removed"), removed);
    }
}

/// `Metrics` and `Filters` are objects, not collections; report field moves.
fn diff_opaque(name: &str, old: Option<&Value>, new: Option<&Value>, delta: &mut Delta) {
    if old == new {
        return;
    }
    match (old, new) {
        (None, Some(_)) => delta.added.push(name.to_string()),
        (Some(_), None) => delta.removed.push(name.to_string()),
        (Some(old), Some(new)) => delta.modified.push(super::Modified {
            id: name.to_string(),
            fields: super::field_changes(old, new),
        }),
        (None, None) => {}
    }
}

fn rows(value: Option<&Value>) -> Vec<Value> {
    value.and_then(Value::as_array).cloned().unwrap_or_default()
}

fn uniquely_keyed(rows: &[Value]) -> bool {
    if rows.is_empty() {
        return true;
    }
    let mut ids: Vec<String> = rows.iter().map(|r| render(r.get("id"))).collect();
    if ids.iter().any(|id| id == "(absent)") {
        return false;
    }
    ids.sort_unstable();
    let total = ids.len();
    ids.dedup();
    ids.len() == total
}

/// Product churn is mostly counters ticking; only authorization events are
/// worth interrupting a human for.
fn classify(delta: &Delta) -> Severity {
    if delta.is_empty() {
        return Severity::None;
    }
    let product_membership = delta
        .added
        .iter()
        .chain(&delta.removed)
        .any(|id| id.starts_with("Products/"));
    if product_membership || !delta.highlights.is_empty() {
        Severity::Minor
    } else {
        Severity::Routine
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snapshot(products: &Value, reuse: &Value) -> Value {
        json!({
            "meta": {"last_change": "2026-07-30T02:27:34.555Z"},
            "data": {
                "Metrics": {"ready": 69, "total": 530},
                "Products": products.clone(),
                "ReuseMapping": reuse.clone()
            }
        })
    }

    fn base() -> Value {
        snapshot(
            &json!([{"id": "F1", "name": "Salesforce", "status": "Authorized", "reuse": 313}]),
            &json!([{"id": "AG", "agency_id": 1}, {"id": "AG", "agency_id": 1}]),
        )
    }

    #[test]
    fn daily_rewrite_with_no_content_move_is_not_a_change() {
        let mut after = base();
        after["meta"]["last_change"] = json!("2026-07-31T06:27:00.000Z");
        let delta = diff(&base(), &after);
        assert!(!delta.changed);
        assert_eq!(delta.severity, Severity::None);
    }

    #[test]
    fn counter_movement_is_routine() {
        let mut after = base();
        after["data"]["Products"][0]["reuse"] = json!(314);
        let delta = diff(&base(), &after);
        assert_eq!(delta.severity, Severity::Routine);
        assert_eq!(delta.modified.len(), 1);
        assert!(delta.highlights.is_empty());
    }

    #[test]
    fn status_change_is_minor_and_highlighted() {
        let mut after = base();
        after["data"]["Products"][0]["status"] = json!("Ready");
        let delta = diff(&base(), &after);
        assert_eq!(delta.severity, Severity::Minor);
        assert_eq!(delta.highlights[0].field, "status");
    }

    #[test]
    fn new_product_is_minor() {
        let mut after = base();
        after["data"]["Products"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id": "F2", "name": "Bidscale", "status": "In Process"}));
        let delta = diff(&base(), &after);
        assert_eq!(delta.severity, Severity::Minor);
        assert_eq!(delta.added, vec!["Products/F2"]);
    }

    #[test]
    fn duplicate_ids_are_counted_not_keyed() {
        let mut after = base();
        after["data"]["ReuseMapping"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id": "AG", "agency_id": 2}));
        let delta = diff(&base(), &after);
        assert_eq!(delta.counts.get("ReuseMapping.rows_added"), Some(&1));
        assert!(delta.added.is_empty());
        assert_eq!(delta.severity, Severity::Routine);
    }

    #[test]
    fn repeated_identical_rows_do_not_register_as_changes() {
        let delta = diff(&base(), &base());
        assert!(delta.counts.is_empty());
        assert!(!delta.changed);
    }

    #[test]
    fn metrics_object_moves_are_reported() {
        let mut after = base();
        after["data"]["Metrics"]["ready"] = json!(70);
        let delta = diff(&base(), &after);
        assert_eq!(delta.modified[0].id, "Metrics");
        assert_eq!(delta.severity, Severity::Routine);
    }
}
