//! Fetch, compare against the previous chain payload, and decide.

use anyhow::Result;
use serde::Serialize;

use crate::bundle::Bundle;
use crate::diff::{self, Delta};
use crate::severity::Severity;
use crate::sources::{self, Fetcher, Snapshot, MARKETPLACE, RULES, SCHEMAS};

#[derive(Debug, Serialize)]
pub struct Plan {
    pub genesis: bool,
    pub changed: bool,
    pub severity: Severity,
    pub upstream_version: String,
    pub previous_upstream_version: Option<String>,
    pub bundle_sha256: String,
    pub deltas: Vec<Delta>,
    #[serde(skip)]
    pub bundle: Bundle,
    /// The previous ruleset, kept so the report can answer "who does this
    /// change affect" rather than only "what changed".
    #[serde(skip)]
    pub previous_rules: Option<serde_json::Value>,
}

impl Plan {
    pub fn delta(&self, source: &str) -> Option<&Delta> {
        self.deltas.iter().find(|d| d.source == source)
    }

    pub fn headline(&self) -> String {
        if self.genesis {
            return format!("FedRAMP rules {} — genesis", self.upstream_version);
        }
        if !self.changed {
            return "FedRAMP sources unchanged".to_string();
        }
        let moved: Vec<&str> = self
            .deltas
            .iter()
            .filter(|d| d.changed)
            .map(|d| d.source.as_str())
            .collect();
        format!(
            "{}: {} ({})",
            self.severity.headline(),
            self.upstream_version,
            moved.join(", ")
        )
    }
}

pub fn build(fetcher: &Fetcher, previous: Option<&Bundle>) -> Result<Plan> {
    let mut snapshots = Vec::new();
    for spec in sources::SOURCES {
        snapshots.push(fetcher.snapshot(spec)?);
    }
    Ok(compare(&snapshots, previous))
}

/// Gate on the substance digest; run the semantic diff only where it moved.
pub fn compare(snapshots: &[Snapshot], previous: Option<&Bundle>) -> Plan {
    let bundle = Bundle::from_snapshots(snapshots);
    let genesis = previous.is_none();

    let deltas: Vec<Delta> = snapshots
        .iter()
        .map(|snapshot| delta_for(snapshot, previous))
        .collect();

    let severity = deltas
        .iter()
        .map(|d| d.severity)
        .max()
        .unwrap_or(Severity::None);

    let previous_rules = previous.and_then(|b| b.section(RULES).cloned());
    Plan {
        genesis,
        previous_rules,
        changed: genesis || deltas.iter().any(|d| d.changed),
        severity: if genesis { Severity::Major } else { severity },
        upstream_version: bundle.upstream_version.clone(),
        previous_upstream_version: previous.map(|b| b.upstream_version.clone()),
        bundle_sha256: bundle.digest().unwrap_or_default(),
        deltas,
        bundle,
    }
}

fn delta_for(snapshot: &Snapshot, previous: Option<&Bundle>) -> Delta {
    let Some(previous) = previous else {
        let mut delta = Delta::new(&snapshot.id);
        delta.changed = true;
        delta.severity = Severity::Major;
        delta.counts = genesis_counts(snapshot);
        return delta;
    };

    let unchanged = previous.substance(&snapshot.id) == Some(snapshot.substance_sha256.as_str());
    if unchanged {
        return Delta::new(&snapshot.id);
    }

    let empty = serde_json::Value::Null;
    let before = previous.section(&snapshot.id).unwrap_or(&empty);
    let after = &snapshot.content;
    let mut delta = match snapshot.id.as_str() {
        RULES => diff::rules::diff(before, after),
        SCHEMAS => diff::schemas::diff(before, after),
        MARKETPLACE => diff::marketplace::diff(before, after),
        _ => {
            let mut delta = Delta::new(&snapshot.id);
            delta.changed = true;
            delta.severity = Severity::Minor;
            delta
                .drift
                .push(format!("no diff strategy for source `{}`", snapshot.id));
            delta
        }
    };

    // The digest gate is authoritative: a source whose substance moved is
    // changed even when the semantic diff cannot name what moved.
    if !delta.changed {
        delta.changed = true;
        delta.severity = delta.severity.max(Severity::Metadata);
        delta.drift.push(format!(
            "substance digest moved but the semantic diff found nothing in `{}`",
            snapshot.id
        ));
    }
    delta
}

/// Genesis has nothing to diff against, so report what is being signed.
fn genesis_counts(snapshot: &Snapshot) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::new();
    match snapshot.id.as_str() {
        RULES => {
            let (leaves, _) = diff::rules::flatten(&snapshot.content);
            counts.insert("rules".to_string(), leaves.len());
        }
        SCHEMAS => {
            counts.insert(
                "files".to_string(),
                snapshot.content.as_object().map_or(0, serde_json::Map::len),
            );
        }
        MARKETPLACE => {
            let data = snapshot.content.get("data").unwrap_or(&snapshot.content);
            if let Some(map) = data.as_object() {
                for (name, value) in map {
                    if let Some(rows) = value.as_array() {
                        counts.insert(name.clone(), rows.len());
                    }
                }
            }
        }
        _ => {}
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::Provenance;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    fn snapshot(id: &str, content: Value) -> Snapshot {
        let volatile = sources::spec(id).volatile;
        let substance = if volatile.is_empty() {
            content.clone()
        } else {
            crate::canon::without(&content, volatile)
        };
        Snapshot {
            id: id.to_string(),
            provenance: Provenance {
                repo: "repo".into(),
                path: "path".into(),
                commit: "sha".into(),
                committed_at: "2026-07-14T21:11:00Z".into(),
                raw_sha256: "raw".into(),
                bytes: 1,
                files: BTreeMap::new(),
            },
            content_sha256: crate::canon::digest_value(&content).unwrap(),
            substance_sha256: crate::canon::digest_value(&substance).unwrap(),
            content,
        }
    }

    fn rules(version: &str, force: &str) -> Value {
        json!({
            "info": {"version": version, "last_updated": "2026-07-14"},
            "FRR": {"VDR": {"data": {"all": {"FRP": {"VDR-FRP-ONE": {"force": force}}}}}}
        })
    }

    fn market(reuse: i64) -> Value {
        json!({
            "meta": {"last_change": "2026-07-30T02:27:34.555Z"},
            "data": {"Products": [{"id": "F1", "name": "Salesforce", "reuse": reuse}]}
        })
    }

    fn schemas() -> Value {
        json!({"fedramp-incident-report-schema-2026-06-24.json": {"type": "object"}})
    }

    fn all(version: &str, force: &str, reuse: i64) -> Vec<Snapshot> {
        vec![
            snapshot(RULES, rules(version, force)),
            snapshot(SCHEMAS, schemas()),
            snapshot(MARKETPLACE, market(reuse)),
        ]
    }

    #[test]
    fn genesis_is_always_a_change() {
        let plan = compare(&all("v1", "SHOULD", 313), None);
        assert!(plan.genesis && plan.changed);
        assert_eq!(plan.severity, Severity::Major);
    }

    #[test]
    fn rerun_against_the_same_pins_is_a_no_op() {
        let first = compare(&all("v1", "SHOULD", 313), None);
        let second = compare(&all("v1", "SHOULD", 313), Some(&first.bundle));
        assert!(!second.changed);
        assert_eq!(second.severity, Severity::None);
        assert_eq!(first.bundle_sha256, second.bundle_sha256);
    }

    #[test]
    fn rules_change_outranks_concurrent_marketplace_churn() {
        let first = compare(&all("v1", "SHOULD", 313), None);
        let plan = compare(&all("v2", "MUST", 314), Some(&first.bundle));
        assert_eq!(plan.severity, Severity::Major);
        assert_eq!(plan.delta(RULES).unwrap().severity, Severity::Major);
        assert_eq!(plan.delta(MARKETPLACE).unwrap().severity, Severity::Routine);
        assert!(plan.headline().contains("RULES CHANGED"));
    }

    #[test]
    fn marketplace_only_churn_stays_routine() {
        let first = compare(&all("v1", "SHOULD", 313), None);
        let plan = compare(&all("v1", "SHOULD", 314), Some(&first.bundle));
        assert!(plan.changed);
        assert_eq!(plan.severity, Severity::Routine);
        assert!(!plan.delta(RULES).unwrap().changed);
    }

    #[test]
    fn volatile_timestamp_churn_alone_changes_nothing() {
        let first = compare(&all("v1", "SHOULD", 313), None);
        let mut later = all("v1", "SHOULD", 313);
        later[0].content["info"]["last_updated"] = json!("2026-08-30");
        later[0].content_sha256 = crate::canon::digest_value(&later[0].content).unwrap();
        let plan = compare(&later, Some(&first.bundle));
        assert!(!plan.changed);
    }
}
