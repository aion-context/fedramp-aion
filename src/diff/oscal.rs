//! NIST 800-53 catalog diff.
//!
//! Severity here is **relative to FedRAMP**: 800-53 carries 1,196 controls and
//! FedRAMP references 284 of them. A change to `pm-31` matters to us only if
//! FedRAMP points at it, so a control the ruleset references is `major` and
//! everything else is `routine`. Without that, one NIST revision would drown a
//! rules change in noise — the same failure the marketplace projection avoids.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use super::{compare_maps, Delta};
use crate::severity::Severity;

/// Fields whose movement changes what an implementer must do.
const HIGHLIGHT_FIELDS: &[&str] = &["title", "class"];

pub fn diff(before: &Value, after: &Value, referenced: &BTreeSet<String>) -> Delta {
    let mut delta = Delta::new(crate::sources::OSCAL);

    let old = flatten(before);
    let new = flatten(after);
    compare_maps(&old, &new, &mut delta, HIGHLIGHT_FIELDS, "control");

    // Metadata that survived the volatility projection — `version` moving from
    // 5.2.0 to 5.3.0 is a real event even if no control text moved.
    let version = |doc: &Value| {
        doc.pointer("/catalog/metadata/version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let (old_version, new_version) = (version(before), version(after));
    if old_version != new_version && !old_version.is_empty() {
        delta.highlights.push(super::Highlight {
            kind: "catalog".to_string(),
            id: "800-53 revision".to_string(),
            field: "version".to_string(),
            from: old_version,
            to: new_version,
        });
    }

    let touched: BTreeSet<&String> = delta
        .added
        .iter()
        .chain(&delta.removed)
        .chain(delta.modified.iter().map(|m| &m.id))
        .collect();
    let fedramp_relevant: Vec<String> = touched
        .iter()
        .filter(|id| referenced.contains(**id))
        .map(|id| (*id).clone())
        .collect();

    delta.counts.insert(
        "controls_referenced_by_fedramp".to_string(),
        fedramp_relevant.len(),
    );
    for id in &fedramp_relevant {
        delta.highlights.push(super::Highlight {
            kind: "referenced".to_string(),
            id: id.clone(),
            field: "control".to_string(),
            from: "FedRAMP references this control".to_string(),
            to: "changed upstream".to_string(),
        });
    }

    delta.changed = !delta.is_empty() || !delta.highlights.is_empty();
    delta.severity = if !fedramp_relevant.is_empty() {
        Severity::Major
    } else if delta.changed {
        Severity::Routine
    } else {
        Severity::None
    };
    delta
}

/// Flatten the catalog to `control id -> control`, enhancements included.
/// Ids are OSCAL's own lowercase dotted form (`ac-6.1`).
pub fn flatten(doc: &Value) -> BTreeMap<String, Value> {
    let mut controls = BTreeMap::new();
    let Some(catalog) = doc.get("catalog") else {
        return controls;
    };
    collect(catalog, &mut controls);
    controls
}

fn collect(node: &Value, out: &mut BTreeMap<String, Value>) {
    if let Some(groups) = node.get("groups").and_then(Value::as_array) {
        for group in groups {
            collect(group, out);
        }
    }
    if let Some(list) = node.get("controls").and_then(Value::as_array) {
        for control in list {
            if let Some(id) = control.get("id").and_then(Value::as_str) {
                out.insert(id.to_string(), control.clone());
            }
            collect(control, out);
        }
    }
}

/// FedRAMP writes control ids two ways: `CTL` uses `AC-06-01`, KSI references
/// use OSCAL's own `ac-6.1`. Both normalise to the OSCAL form so the catalog
/// can be joined.
pub fn normalise_id(id: &str) -> String {
    let lower = id.to_ascii_lowercase();
    let mut parts = lower.split('-');
    let (Some(family), Some(number)) = (parts.next(), parts.next()) else {
        return lower;
    };
    let base = format!("{family}-{}", number.trim_start_matches('0'));
    match parts.next() {
        Some(enhancement) => format!("{base}.{}", enhancement.trim_start_matches('0')),
        None => base,
    }
}

/// Every 800-53 control the ruleset points at, in OSCAL form.
pub fn referenced_controls(rules: &Value) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    if let Some(families) = rules.get("CTL").and_then(Value::as_object) {
        for controls in families.values() {
            if let Some(map) = controls.as_object() {
                ids.extend(map.keys().map(|id| normalise_id(id)));
            }
        }
    }
    if let Some(families) = rules.get("KSI").and_then(Value::as_object) {
        for family in families.values() {
            let Some(indicators) = family.get("indicators").and_then(Value::as_object) else {
                continue;
            };
            for indicator in indicators.values() {
                if let Some(controls) = indicator.get("controls").and_then(Value::as_array) {
                    ids.extend(controls.iter().filter_map(Value::as_str).map(normalise_id));
                }
            }
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn catalog(version: &str, ac20_title: &str) -> Value {
        json!({"catalog": {
        "uuid": "doc-uuid",
        "metadata": {"version": version, "last-modified": "2026-05-11T16:01:09.00000-00:00"},
        "groups": [{
            "id": "ac", "title": "Access Control",
            "controls": [
                {"id": "ac-20", "title": ac20_title,
                 "controls": [{"id": "ac-20.1", "title": "Limits on Authorized Use"}]},
                {"id": "pm-31", "title": "Continuous Monitoring Strategy"}
            ]}]}})
    }

    fn fedramp_rules() -> Value {
        json!({
            "CTL": {"AC": {"AC-20": {"guidance": ["g"]}, "AC-06-01": {"parameters": []}}},
            "KSI": {"CED": {"indicators": {"KSI-CED-RAT": {"controls": ["cp-3", "ac-20.1"]}}}}
        })
    }

    #[test]
    fn ids_normalise_from_both_fedramp_forms() {
        assert_eq!(normalise_id("AC-06-01"), "ac-6.1");
        assert_eq!(normalise_id("AC-20"), "ac-20");
        assert_eq!(normalise_id("ac-20.1"), "ac-20.1");
        assert_eq!(normalise_id("AU-10"), "au-10");
    }

    #[test]
    fn referenced_controls_span_ctl_and_ksi() {
        let referenced = referenced_controls(&fedramp_rules());
        assert!(referenced.contains("ac-20"));
        assert!(referenced.contains("ac-6.1"));
        assert!(referenced.contains("ac-20.1"), "KSI references must count");
        assert!(referenced.contains("cp-3"));
    }

    #[test]
    fn flatten_includes_enhancements() {
        let controls = flatten(&catalog("5.2.0", "Use of External Systems"));
        assert!(controls.contains_key("ac-20"));
        assert!(controls.contains_key("ac-20.1"), "enhancement was dropped");
        assert_eq!(controls.len(), 3);
    }

    #[test]
    fn an_unchanged_republish_is_not_a_change() {
        let referenced = referenced_controls(&fedramp_rules());
        let delta = diff(
            &catalog("5.2.0", "Use of External Systems"),
            &catalog("5.2.0", "Use of External Systems"),
            &referenced,
        );
        assert!(!delta.changed);
        assert_eq!(delta.severity, Severity::None);
    }

    /// A control FedRAMP points at is major; one it ignores is routine.
    #[test]
    fn severity_depends_on_whether_fedramp_references_the_control() {
        let referenced = referenced_controls(&fedramp_rules());
        let before = catalog("5.2.0", "Use of External Systems");

        let mut after = before.clone();
        after["catalog"]["groups"][0]["controls"][0]["title"] = json!("Use of External Systems v2");
        let delta = diff(&before, &after, &referenced);
        assert_eq!(delta.severity, Severity::Major);
        assert_eq!(delta.counts["controls_referenced_by_fedramp"], 1);

        let mut after = before.clone();
        after["catalog"]["groups"][0]["controls"][1]["title"] = json!("Renamed, unreferenced");
        let delta = diff(&before, &after, &referenced);
        assert_eq!(delta.severity, Severity::Routine);
        assert_eq!(delta.counts["controls_referenced_by_fedramp"], 0);
    }

    #[test]
    fn a_catalog_revision_bump_is_reported_even_without_control_edits() {
        let referenced = referenced_controls(&fedramp_rules());
        let delta = diff(
            &catalog("5.2.0", "Use of External Systems"),
            &catalog("5.3.0", "Use of External Systems"),
            &referenced,
        );
        assert!(delta.changed);
        let highlight = delta
            .highlights
            .iter()
            .find(|h| h.kind == "catalog")
            .expect("revision bump should be highlighted");
        assert_eq!(
            (highlight.from.as_str(), highlight.to.as_str()),
            ("5.2.0", "5.3.0")
        );
    }
}
