//! The signed payload: provenance + digests + canonical content.
//!
//! Determinism invariant (DESIGN.md §6): nothing in here may depend on wall
//! clock time. The bundle is a pure function of the pinned upstream commits.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::canon;
use crate::sources::{Provenance, Snapshot, RULES};

pub const SCHEMA: &str = "fedramp-aion/1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceRecord {
    #[serde(flatten)]
    pub provenance: Provenance,
    pub content_sha256: String,
    pub substance_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub schema: String,
    /// `info.version` from the rules document, carried for humans. Never used
    /// for change detection — upstream bumps it in a later commit than the
    /// content edits it describes.
    pub upstream_version: String,
    pub sources: BTreeMap<String, SourceRecord>,
    pub content: BTreeMap<String, Value>,
}

impl Bundle {
    pub fn from_snapshots(snapshots: &[Snapshot]) -> Self {
        let mut sources = BTreeMap::new();
        let mut content = BTreeMap::new();
        for snapshot in snapshots {
            sources.insert(
                snapshot.id.clone(),
                SourceRecord {
                    provenance: snapshot.provenance.clone(),
                    content_sha256: snapshot.content_sha256.clone(),
                    substance_sha256: snapshot.substance_sha256.clone(),
                },
            );
            content.insert(snapshot.id.clone(), snapshot.content.clone());
        }
        let upstream_version = content
            .get(RULES)
            .and_then(|rules| rules["info"]["version"].as_str())
            .unwrap_or("unknown")
            .to_string();
        Self {
            schema: SCHEMA.to_string(),
            upstream_version,
            sources,
            content,
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let bundle: Self = serde_json::from_slice(bytes)
            .context("previous chain payload is not a fedramp-aion bundle")?;
        anyhow::ensure!(
            bundle.schema == SCHEMA,
            "previous chain payload uses schema {}, this build writes {SCHEMA}",
            bundle.schema
        );
        Ok(bundle)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        canon::canonical_bytes(&serde_json::to_value(self)?)
    }

    pub fn digest(&self) -> Result<String> {
        Ok(canon::sha256_hex(&self.to_bytes()?))
    }

    /// The newest upstream commit time across sources, as unix nanoseconds.
    /// Used as the `.aion` version timestamp so a replayed run is byte-stable.
    pub fn pinned_timestamp(&self) -> Option<u64> {
        self.sources
            .values()
            .filter_map(|s| rfc3339_nanos(&s.provenance.committed_at))
            .max()
    }

    pub fn substance(&self, source: &str) -> Option<&str> {
        self.sources
            .get(source)
            .map(|s| s.substance_sha256.as_str())
    }

    pub fn section(&self, source: &str) -> Option<&Value> {
        self.content.get(source)
    }
}

fn rfc3339_nanos(value: &str) -> Option<u64> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .and_then(|t| u64::try_from(t.unix_timestamp_nanos()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(committed_at: &str) -> SourceRecord {
        SourceRecord {
            provenance: Provenance {
                repo: "r".into(),
                path: "p".into(),
                commit: "c".into(),
                committed_at: committed_at.into(),
                raw_sha256: "d".into(),
                bytes: 1,
                files: BTreeMap::new(),
            },
            content_sha256: "x".into(),
            substance_sha256: "y".into(),
        }
    }

    fn bundle_with(times: &[&str]) -> Bundle {
        let sources = times
            .iter()
            .enumerate()
            .map(|(i, t)| (format!("s{i}"), record(t)))
            .collect();
        Bundle {
            schema: SCHEMA.into(),
            upstream_version: "v".into(),
            sources,
            content: BTreeMap::new(),
        }
    }

    #[test]
    fn timestamp_pins_to_newest_upstream_commit() {
        let bundle = bundle_with(&["2026-07-14T21:11:00Z", "2026-07-30T06:27:00Z"]);
        let expected = rfc3339_nanos("2026-07-30T06:27:00Z").unwrap();
        assert_eq!(bundle.pinned_timestamp(), Some(expected));
    }

    #[test]
    fn bundle_bytes_round_trip_and_are_stable() {
        let bundle = bundle_with(&["2026-07-14T21:11:00Z"]);
        let first = bundle.to_bytes().unwrap();
        let reparsed = Bundle::parse(&first).unwrap();
        assert_eq!(first, reparsed.to_bytes().unwrap());
    }

    #[test]
    fn parse_rejects_foreign_schema() {
        let mut bundle = bundle_with(&["2026-07-14T21:11:00Z"]);
        bundle.schema = "something-else/9".into();
        let bytes = bundle.to_bytes().unwrap();
        assert!(Bundle::parse(&bytes).is_err());
    }
}
