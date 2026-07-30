//! Rules diff: flatten the four sections to leaf ids, then compare.
//!
//! Leaf ids are the FedRAMP identifiers themselves (`VDR-FRP-XYZ`,
//! `KSI-CED-RAT`, `AC-06-01`), so a report names rules rather than JSON paths.

use serde_json::{Map, Value};
use std::collections::BTreeMap;

use super::{compare_maps, Delta};
use crate::severity::Severity;

/// Fields whose movement changes what a provider must do.
const HIGHLIGHT_FIELDS: &[&str] = &["force", "status", "effective"];

const KNOWN_SECTIONS: &[&str] = &["FRD", "FRR", "KSI", "CTL"];

pub fn diff(before: &Value, after: &Value) -> Delta {
    let mut delta = Delta::new(crate::sources::RULES);

    let (old_leaves, _) = flatten(before);
    let (new_leaves, drift) = flatten(after);
    delta.drift = drift;

    compare_maps(
        &old_leaves,
        &new_leaves,
        &mut delta,
        HIGHLIGHT_FIELDS,
        "rule",
    );
    highlight_per_class_force(&old_leaves, &new_leaves, &mut delta);

    let info_moved = before.get("info") != after.get("info");
    delta.changed = !delta.is_empty() || info_moved;
    delta.severity = if delta.is_empty() {
        if info_moved {
            Severity::Metadata
        } else {
            Severity::None
        }
    } else {
        Severity::Major
    };
    if info_moved {
        delta.counts.insert("info_fields_moved".to_string(), 1);
    }
    delta
}

/// Some rules carry a different obligation per certification class under
/// `varies_by_class`. A `SHOULD → MUST` in there is as binding as one at the
/// top level, so it is promoted the same way.
fn highlight_per_class_force(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    delta: &mut Delta,
) {
    for entry in &delta.modified {
        if !entry.fields.iter().any(|f| f.field == "varies_by_class") {
            continue;
        }
        let (Some(old), Some(new)) = (before.get(&entry.id), after.get(&entry.id)) else {
            continue;
        };
        let mut classes: Vec<&String> = class_map(old).chain(class_map(new)).collect();
        classes.sort_unstable();
        classes.dedup();
        for class in classes {
            let force_of = |leaf: &Value| -> Option<String> {
                leaf.get("varies_by_class")?
                    .get(class)?
                    .get("force")?
                    .as_str()
                    .map(str::to_string)
            };
            let (from, to) = (force_of(old), force_of(new));
            if from == to {
                continue;
            }
            delta.highlights.push(super::Highlight {
                kind: "force".to_string(),
                id: format!("{} (class {class})", entry.id),
                field: "varies_by_class.force".to_string(),
                from: from.unwrap_or_else(|| "(absent)".to_string()),
                to: to.unwrap_or_else(|| "(absent)".to_string()),
            });
        }
    }
}

fn class_map(leaf: &Value) -> impl Iterator<Item = &String> {
    object(leaf.get("varies_by_class")).map(|(class, _)| class)
}

/// Flatten to `id -> leaf`, plus notes for any section shaped unexpectedly.
pub fn flatten(doc: &Value) -> (BTreeMap<String, Value>, Vec<String>) {
    let mut leaves = BTreeMap::new();
    let mut drift = Vec::new();
    let Some(root) = doc.as_object() else {
        return (leaves, vec!["rules document is not an object".to_string()]);
    };

    for (section, body) in root {
        match section.as_str() {
            "info" => {}
            "FRD" => flatten_frd(body, &mut leaves),
            "FRR" => flatten_frr(body, &mut leaves),
            "KSI" => flatten_ksi(body, &mut leaves),
            "CTL" => flatten_ctl(body, &mut leaves),
            other => {
                drift.push(format!(
                    "unknown top-level section `{other}` — diffed as an opaque subtree"
                ));
                leaves.insert(other.to_string(), body.clone());
            }
        }
    }
    for known in KNOWN_SECTIONS {
        if !root.contains_key(*known) {
            drift.push(format!("section `{known}` disappeared from upstream"));
        }
    }
    (leaves, drift)
}

/// `FRD.data.{group}.{FRD-XXX}`
fn flatten_frd(body: &Value, leaves: &mut BTreeMap<String, Value>) {
    insert_info("FRD", body, leaves);
    for (group, entries) in object(body.get("data")) {
        for (id, leaf) in object(Some(entries)) {
            leaves.insert(format!("FRD/{group}/{id}"), leaf.clone());
        }
    }
}

/// `FRR.{family}.data.{applicability}.{class}.{RULE-ID}`
///
/// Applicability (`all` / `20x` / `rev5`) is part of leaf identity: the same
/// rule id under a different applicability is a different obligation.
fn flatten_frr(body: &Value, leaves: &mut BTreeMap<String, Value>) {
    for (family, family_body) in object(Some(body)) {
        insert_info(&format!("FRR/{family}"), family_body, leaves);
        for (applicability, classes) in object(family_body.get("data")) {
            for (class, rules) in object(Some(classes)) {
                for (id, leaf) in object(Some(rules)) {
                    leaves.insert(
                        format!("FRR/{family}/{applicability}/{class}/{id}"),
                        leaf.clone(),
                    );
                }
            }
        }
    }
}

/// `KSI.{family}.indicators.{KSI-XXX-YYY}`
fn flatten_ksi(body: &Value, leaves: &mut BTreeMap<String, Value>) {
    for (family, family_body) in object(Some(body)) {
        let mut header = family_body.clone();
        if let Some(map) = header.as_object_mut() {
            map.remove("indicators");
        }
        leaves.insert(format!("KSI/{family}/info"), header);
        for (id, leaf) in object(family_body.get("indicators")) {
            leaves.insert(format!("KSI/{family}/{id}"), leaf.clone());
        }
    }
}

/// `CTL.{family}.{CONTROL-ID}`
fn flatten_ctl(body: &Value, leaves: &mut BTreeMap<String, Value>) {
    for (family, controls) in object(Some(body)) {
        for (control, leaf) in object(Some(controls)) {
            leaves.insert(format!("CTL/{family}/{control}"), leaf.clone());
        }
    }
}

/// Family headers carry `status` and `effective`, which gate whether a rule is
/// live. They are leaves in their own right.
fn insert_info(prefix: &str, body: &Value, leaves: &mut BTreeMap<String, Value>) {
    if let Some(info) = body.get("info") {
        leaves.insert(format!("{prefix}/info"), info.clone());
    }
}

fn object(value: Option<&Value>) -> impl Iterator<Item = (&String, &Value)> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    value
        .and_then(Value::as_object)
        .unwrap_or_else(|| EMPTY.get_or_init(Map::new))
        .iter()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc() -> Value {
        json!({
            "info": {"version": "2026.07.14.01", "last_updated": "2026-07-14"},
            "FRD": {"info": {"name": "definitions"}, "data": {"all": {
                "FRD-ACV": {"term": "Accepted Vulnerability", "definition": "d"}}}},
            "FRR": {"VDR": {"info": {"name": "Vuln Detection", "status": "stable"},
                "data": {"all": {"FRP": {"VDR-FRP-ONE": {"statement": "s", "force": "SHOULD"}}},
                         "rev5": {"TFR": {"VDR-TFR-ONE": {"statement": "t", "force": "MUST"}}}}}},
            "KSI": {"CED": {"name": "Cybersecurity Education", "status": "stable",
                "indicators": {"KSI-CED-RAT": {"statement": "x", "controls": ["cp-3"]}}}},
            "CTL": {"AC": {"AC-20": {"guidance": ["g"]}}}
        })
    }

    #[test]
    fn flatten_produces_fedramp_ids_including_applicability() {
        let (leaves, drift) = flatten(&doc());
        assert!(drift.is_empty());
        assert!(leaves.contains_key("FRD/all/FRD-ACV"));
        assert!(leaves.contains_key("FRR/VDR/all/FRP/VDR-FRP-ONE"));
        assert!(leaves.contains_key("FRR/VDR/rev5/TFR/VDR-TFR-ONE"));
        assert!(leaves.contains_key("KSI/CED/KSI-CED-RAT"));
        assert!(leaves.contains_key("CTL/AC/AC-20"));
        assert!(leaves.contains_key("FRR/VDR/info"));
    }

    #[test]
    fn identical_documents_produce_no_change() {
        let delta = diff(&doc(), &doc());
        assert!(!delta.changed);
        assert_eq!(delta.severity, Severity::None);
    }

    #[test]
    fn version_bump_alone_is_metadata_not_major() {
        let mut after = doc();
        after["info"]["version"] = json!("2026.08.01.01");
        let delta = diff(&doc(), &after);
        assert!(delta.changed);
        assert_eq!(delta.severity, Severity::Metadata);
        assert_eq!(delta.total(), 0);
    }

    #[test]
    fn force_transition_is_highlighted_as_major() {
        let mut after = doc();
        after["FRR"]["VDR"]["data"]["all"]["FRP"]["VDR-FRP-ONE"]["force"] = json!("MUST");
        let delta = diff(&doc(), &after);
        assert_eq!(delta.severity, Severity::Major);
        assert_eq!(delta.highlights.len(), 1);
        assert_eq!(delta.highlights[0].id, "FRR/VDR/all/FRP/VDR-FRP-ONE");
        assert_eq!(delta.highlights[0].to, "MUST");
    }

    #[test]
    fn added_and_removed_rules_are_named() {
        let mut after = doc();
        after["FRR"]["VDR"]["data"]["all"]["FRP"]["VDR-FRP-TWO"] = json!({"statement": "new"});
        after["CTL"]["AC"].as_object_mut().unwrap().remove("AC-20");
        let delta = diff(&doc(), &after);
        assert_eq!(delta.added, vec!["FRR/VDR/all/FRP/VDR-FRP-TWO"]);
        assert_eq!(delta.removed, vec!["CTL/AC/AC-20"]);
    }

    #[test]
    fn per_class_force_transition_is_highlighted() {
        let mut before = doc();
        before["FRR"]["VDR"]["data"]["all"]["FRP"]["VDR-FRP-ONE"]["varies_by_class"] =
            json!({"a": {"force": "SHOULD"}, "b": {"force": "MUST"}});
        let mut after = before.clone();
        after["FRR"]["VDR"]["data"]["all"]["FRP"]["VDR-FRP-ONE"]["varies_by_class"] =
            json!({"a": {"force": "MUST"}, "b": {"force": "MUST"}});

        let delta = diff(&before, &after);
        assert_eq!(delta.severity, Severity::Major);
        let highlight = delta
            .highlights
            .iter()
            .find(|h| h.kind == "force")
            .expect("per-class force transition should be highlighted");
        assert!(highlight.id.contains("(class a)"));
        assert_eq!(
            (highlight.from.as_str(), highlight.to.as_str()),
            ("SHOULD", "MUST")
        );
    }

    #[test]
    fn a_dropped_class_is_highlighted_too() {
        let mut before = doc();
        before["FRR"]["VDR"]["data"]["all"]["FRP"]["VDR-FRP-ONE"]["varies_by_class"] =
            json!({"a": {"force": "SHOULD"}, "b": {"force": "MUST"}});
        let mut after = before.clone();
        after["FRR"]["VDR"]["data"]["all"]["FRP"]["VDR-FRP-ONE"]["varies_by_class"] =
            json!({"b": {"force": "MUST"}});

        let delta = diff(&before, &after);
        let highlight = delta
            .highlights
            .iter()
            .find(|h| h.id.contains("class a"))
            .unwrap();
        assert_eq!(highlight.to, "(absent)");
    }

    #[test]
    fn unknown_section_is_reported_as_drift_not_dropped() {
        let mut after = doc();
        after["FRA"] = json!({"anything": 1});
        let delta = diff(&doc(), &after);
        assert_eq!(delta.added, vec!["FRA"]);
        assert!(delta.drift.iter().any(|d| d.contains("FRA")));
    }

    #[test]
    fn removed_section_is_reported_as_drift() {
        let mut after = doc();
        after.as_object_mut().unwrap().remove("KSI");
        let delta = diff(&doc(), &after);
        assert!(delta.drift.iter().any(|d| d.contains("KSI")));
        assert_eq!(delta.severity, Severity::Major);
    }
}
