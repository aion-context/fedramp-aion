//! Canonicalization, substance projection, and digests.
//!
//! Every digest in this pipeline is taken over JCS (RFC 8785) bytes, so
//! upstream whitespace or key-order churn can never reach the gate.

use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Parse and re-serialize as canonical JSON.
pub fn canonicalize(raw: &[u8]) -> Result<Value> {
    let value: Value = serde_json::from_slice(raw).context("upstream payload is not valid JSON")?;
    let canonical = aion_context::jcs::canonicalize_json_bytes(&serde_json::to_vec(&value)?)
        .map_err(|e| anyhow::anyhow!("JCS canonicalization failed: {e}"))?;
    Ok(serde_json::from_slice(&canonical)?)
}

/// Canonical bytes for a value already parsed.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    aion_context::jcs::canonicalize_json_bytes(&serde_json::to_vec(value)?)
        .map_err(|e| anyhow::anyhow!("JCS canonicalization failed: {e}"))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// Digest of a value's canonical form.
pub fn digest_value(value: &Value) -> Result<String> {
    Ok(sha256_hex(&canonical_bytes(value)?))
}

pub fn from_hex(text: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(text.len() % 2 == 0, "hex string has an odd length");
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("invalid hex at byte {}: {e}", i / 2))
        })
        .collect()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Strip a `parent.child` field, returning the projection.
///
/// Used for the per-source substance projections in DESIGN.md §3.4:
/// `rules` strips `info.last_updated`, `marketplace` strips `meta`.
pub fn without(value: &Value, path: &[&str]) -> Value {
    let mut projected = value.clone();
    let Some((last, parents)) = path.split_last() else {
        return projected;
    };
    let mut cursor = &mut projected;
    for key in parents {
        match cursor.get_mut(*key) {
            Some(next) => cursor = next,
            None => return projected,
        }
    }
    if let Some(map) = cursor.as_object_mut() {
        map.remove(*last);
    }
    projected
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hex_round_trips_and_rejects_malformed_input() {
        let bytes = [0u8, 1, 15, 16, 254, 255];
        assert_eq!(from_hex(&hex(&bytes)).unwrap(), bytes);
        assert!(from_hex("abc").is_err());
        assert!(from_hex("zz").is_err());
    }

    #[test]
    fn canonicalization_absorbs_key_order_and_whitespace() {
        let a = canonicalize(br#"{"b":1,  "a":  2}"#).unwrap();
        let b = canonicalize(br#"{"a":2,"b":1}"#).unwrap();
        assert_eq!(digest_value(&a).unwrap(), digest_value(&b).unwrap());
    }

    #[test]
    fn without_strips_nested_field_only() {
        let value = json!({"info": {"version": "1", "last_updated": "x"}, "FRR": {}});
        let projected = without(&value, &["info", "last_updated"]);
        assert_eq!(projected["info"]["version"], json!("1"));
        assert!(projected["info"].get("last_updated").is_none());
        assert!(projected.get("FRR").is_some());
    }

    #[test]
    fn without_is_a_noop_when_path_is_absent() {
        let value = json!({"info": {"version": "1"}});
        assert_eq!(without(&value, &["meta", "last_change"]), value);
    }

    #[test]
    fn substance_ignores_timestamp_churn() {
        let day_one = json!({"info": {"version": "2026.07.14.01", "last_updated": "2026-07-14"}});
        let day_two = json!({"info": {"version": "2026.07.14.01", "last_updated": "2026-07-20"}});
        let strip = |v: &Value| digest_value(&without(v, &["info", "last_updated"])).unwrap();
        assert_eq!(strip(&day_one), strip(&day_two));
        assert_ne!(
            digest_value(&day_one).unwrap(),
            digest_value(&day_two).unwrap()
        );
    }
}
