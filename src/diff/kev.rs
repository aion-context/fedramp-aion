//! CISA Known Exploited Vulnerabilities diff.
//!
//! FedRAMP defines KEV as a term (`FRD-KEV`) and hangs remediation duties off
//! it, so the catalog turns "respond to known exploited vulnerabilities" from
//! prose into a list with due dates.
//!
//! CISA publishes two to three times a week and the catalog only grows, so an
//! added CVE is `minor` — a real event a provider must act on — while edits to
//! an existing entry are `routine`.

use serde_json::Value;
use std::collections::BTreeMap;

use super::{compare_maps, Delta};
use crate::severity::Severity;

/// Fields that change what a provider must do, and by when.
const HIGHLIGHT_FIELDS: &[&str] = &["dueDate", "requiredAction", "knownRansomwareCampaignUse"];

pub fn diff(before: &Value, after: &Value) -> Delta {
    let mut delta = Delta::new(crate::sources::KEV);
    compare_maps(
        &flatten(before),
        &flatten(after),
        &mut delta,
        HIGHLIGHT_FIELDS,
        "kev",
    );

    delta.changed = !delta.is_empty();
    delta.severity = if !delta.added.is_empty() || !delta.removed.is_empty() {
        Severity::Minor
    } else if delta.changed {
        Severity::Routine
    } else {
        Severity::None
    };
    delta
}

/// Keyed by CVE id, which is unique in the catalog.
pub fn flatten(doc: &Value) -> BTreeMap<String, Value> {
    doc.get("vulnerabilities")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    entry
                        .get("cveID")
                        .and_then(Value::as_str)
                        .map(|id| (id.to_string(), entry.clone()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The FedRAMP rules that govern known-exploited vulnerabilities, found via the
/// aliases FedRAMP itself defines in `FRD-KEV`.
pub fn governing_rules(rules: &Value) -> Vec<String> {
    let aliases: Vec<String> = rules
        .pointer("/FRD/data/all/FRD-KEV/alts")
        .and_then(Value::as_array)
        .map_or_else(
            || vec!["known exploited vulnerabilit".to_string()],
            |alts| {
                alts.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_lowercase)
                    .collect()
            },
        );

    let (leaves, _) = crate::diff::rules::flatten(rules);
    let mut ids: Vec<String> = leaves
        .iter()
        .filter(|(path, _)| path.starts_with("FRR/"))
        .filter(|(_, leaf)| {
            let text = leaf
                .get("statement")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_lowercase();
            aliases.iter().any(|alias| text.contains(alias))
        })
        .filter_map(|(path, _)| path.rsplit('/').next().map(str::to_string))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn catalog(entries: &Value) -> Value {
        json!({
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": "2026.07.27",
            "dateReleased": "2026-07-27T19:00:15.8632Z",
            "count": entries.as_array().map_or(0, Vec::len),
            "vulnerabilities": entries.clone()
        })
    }

    fn entry(cve: &str, due: &str) -> Value {
        json!({"cveID": cve, "vendorProject": "Cisco", "product": "FMC",
               "dueDate": due, "knownRansomwareCampaignUse": "Unknown",
               "requiredAction": "Apply mitigations per vendor instructions."})
    }

    #[test]
    fn a_new_cve_is_minor() {
        let before = catalog(&json!([entry("CVE-2026-1", "2026-08-01")]));
        let after = catalog(&json!([
            entry("CVE-2026-1", "2026-08-01"),
            entry("CVE-2026-2", "2026-08-15")
        ]));
        let delta = diff(&before, &after);
        assert_eq!(delta.severity, Severity::Minor);
        assert_eq!(delta.added, vec!["CVE-2026-2"]);
    }

    #[test]
    fn a_due_date_change_is_routine_but_highlighted() {
        let before = catalog(&json!([entry("CVE-2026-1", "2026-08-01")]));
        let after = catalog(&json!([entry("CVE-2026-1", "2026-08-20")]));
        let delta = diff(&before, &after);
        assert_eq!(delta.severity, Severity::Routine);
        assert_eq!(delta.highlights.len(), 1);
        assert_eq!(delta.highlights[0].field, "dueDate");
    }

    /// The same catalogVersion can carry different content, so only the
    /// vulnerability list may drive the verdict.
    #[test]
    fn identical_entries_are_no_change_whatever_the_header_says() {
        let before = catalog(&json!([entry("CVE-2026-1", "2026-08-01")]));
        let mut after = before.clone();
        after["dateReleased"] = json!("2026-07-29T18:45:59.5809Z");
        assert!(!diff(&before, &after).changed);
    }

    #[test]
    fn governing_rules_are_found_through_fedramps_own_aliases() {
        let rules = json!({
            "FRD": {"data": {"all": {"FRD-KEV": {"alts": ["known exploited vulnerability", "KEV"]}}}},
            "FRR": {"VDR": {"data": {"all": {"CSO": {
                "VDR-CSO-KEV": {"statement": "Providers MUST remediate each known exploited vulnerability."},
                "VDR-CSO-OTH": {"statement": "Providers MUST patch quarterly."}}}}}}
        });
        assert_eq!(governing_rules(&rules), vec!["VDR-CSO-KEV"]);
    }
}
