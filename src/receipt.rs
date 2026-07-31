//! Receipts — binding an action to the obligations in force when it was taken.
//!
//! The chain answers "what did FedRAMP require on date X". A receipt answers
//! "and here is what we did about it, signed by us, against that exact
//! version".
//!
//! Carried as a DSSE envelope over an in-toto statement, because that is what
//! the surrounding ecosystem already verifies. The load-bearing property is
//! **author binding**: the operator signs with their own registry-tracked key,
//! distinct from the feed's, and verification resolves the signer from the
//! envelope keyid — so a receipt cannot be fabricated in someone else's name.
//!
//! Evidence never enters a receipt. Only its digest does, which keeps CUI out
//! of an artifact designed to be forwarded to an agency.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use aion_context::crypto::SigningKey;
use aion_context::dsse::{self, DsseEnvelope};
use aion_context::key_registry::KeyRegistry;
use aion_context::types::AuthorId;

use crate::bundle::Bundle;
use crate::obligations::{Obligation, Profile};

pub const SCHEMA: &str = "fedramp-aion/receipt/1";

/// Subject names committed in the envelope. Verification recomputes each from
/// the plaintext claim, so the claim cannot drift from the signature.
const SUBJECT_ACTION: &str = "action";
const SUBJECT_OBLIGATIONS: &str = "obligations";
const SUBJECT_RULES: &str = "rules";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRef {
    pub name: String,
    pub blake3: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileRef {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl From<&Profile> for ProfileRef {
    fn from(p: &Profile) -> Self {
        Self {
            role: p.role.clone(),
            class: p.class.clone(),
            cert_type: p.cert_type.clone(),
            path: p.path.clone(),
        }
    }
}

impl From<&ProfileRef> for Profile {
    fn from(p: &ProfileRef) -> Self {
        Self {
            role: p.role.clone(),
            class: p.class.clone(),
            cert_type: p.cert_type.clone(),
            path: p.path.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObligationRef {
    pub id: String,
    pub force: String,
}

/// What the ruleset was when the action was taken.
///
/// `file_id` is a string because JCS canonicalization serializes numbers with
/// ECMAScript semantics: a u64 above 2^53 would silently round.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulesRef {
    pub file_id: String,
    pub chain_version: u64,
    pub bundle_sha256: String,
    pub upstream_version: String,
    pub rules_commit: String,
}

/// The human-readable half. Every field here is digest-committed in the
/// envelope, so editing any of it invalidates the receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claim {
    pub action: String,
    pub decision: String,
    pub operator: u64,
    pub profile: ProfileRef,
    pub obligations: Vec<ObligationRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceRef>,
    pub rules: RulesRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub schema: String,
    pub claim: Claim,
    /// The DSSE envelope, as produced by `aion-context`.
    pub envelope: serde_json::Value,
}

/// What the operator is asserting about the obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// Performed, and the operator asserts conformance.
    Satisfied,
    /// Deliberately not performed — the reason belongs in `action`.
    NotSatisfied,
    /// Partially met, or met by a compensating control.
    Compensating,
    /// Not yet evaluated; recorded so the gap itself is on the record.
    Unevaluated,
}

pub fn parse_decision(text: &str) -> Result<Decision> {
    Ok(
        match text.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "satisfied" => Decision::Satisfied,
            "notsatisfied" => Decision::NotSatisfied,
            "compensating" => Decision::Compensating,
            "unevaluated" => Decision::Unevaluated,
            other => anyhow::bail!(
                "unknown decision `{other}` \
                 (satisfied, not-satisfied, compensating, unevaluated)"
            ),
        },
    )
}

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://aion-context.dev/fedramp-aion/receipt/v1";
pub const PAYLOAD_TYPE: &str = "application/vnd.fedramp-aion.receipt.v1+json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubjectEntry {
    name: String,
    digest: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyBlock {
    /// String for the same reason as `RulesRef::file_id`.
    file_id: String,
    chain_version: u64,
    feed_author: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Predicate {
    policy: PolicyBlock,
    decision: Decision,
    operator: u64,
    receipt_version: u64,
    nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Statement {
    #[serde(rename = "_type")]
    type_uri: String,
    subject: Vec<SubjectEntry>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: Predicate,
}

fn subject(name: &str, digest: [u8; 32]) -> SubjectEntry {
    let mut map = std::collections::BTreeMap::new();
    map.insert("blake3".to_string(), hex(&digest));
    SubjectEntry {
        name: name.to_string(),
        digest: map,
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn hex(bytes: &[u8; 32]) -> String {
    crate::canon::hex(bytes)
}

/// The digest of the obligation set, over ids and force only. Statement text
/// is excluded deliberately: an editorial rewording should not invalidate an
/// operator's receipt, but a change in what binds them must.
fn obligations_digest(obligations: &[ObligationRef]) -> Result<[u8; 32]> {
    Ok(digest(&serde_json::to_vec(obligations)?))
}

fn rules_digest(rules: &RulesRef) -> Result<[u8; 32]> {
    Ok(digest(&serde_json::to_vec(rules)?))
}

pub struct Inputs<'a> {
    pub action: &'a str,
    pub decision: Decision,
    pub operator: u64,
    pub receipt_version: u64,
    pub profile: &'a Profile,
    pub obligations: &'a [Obligation],
    pub evidence: &'a [EvidenceRef],
    pub bundle: &'a Bundle,
    pub file_id: u64,
    pub chain_version: u64,
}

/// Seal a receipt with the operator's own key.
pub fn create(inputs: &Inputs, operator_key: &SigningKey, feed_author: u64) -> Result<Receipt> {
    let rules = RulesRef {
        file_id: inputs.file_id.to_string(),
        chain_version: inputs.chain_version,
        bundle_sha256: inputs.bundle.digest()?,
        upstream_version: inputs.bundle.upstream_version.clone(),
        rules_commit: inputs
            .bundle
            .sources
            .get(crate::sources::RULES)
            .map(|s| s.provenance.commit.clone())
            .unwrap_or_default(),
    };
    let obligations: Vec<ObligationRef> = inputs
        .obligations
        .iter()
        .map(|o| ObligationRef {
            id: o.id.clone(),
            force: o.force.clone(),
        })
        .collect();

    let claim = Claim {
        action: inputs.action.to_string(),
        decision: serde_json::to_value(inputs.decision)?
            .as_str()
            .unwrap_or_default()
            .to_string(),
        operator: inputs.operator,
        profile: inputs.profile.into(),
        obligations,
        evidence: inputs.evidence.to_vec(),
        rules,
    };

    let mut subjects = vec![
        subject(SUBJECT_ACTION, digest(claim.action.as_bytes())),
        subject(SUBJECT_OBLIGATIONS, obligations_digest(&claim.obligations)?),
        subject(SUBJECT_RULES, rules_digest(&claim.rules)?),
    ];
    for evidence in &claim.evidence {
        subjects.push(SubjectEntry {
            name: format!("evidence/{}", evidence.name),
            digest: std::collections::BTreeMap::from([(
                "blake3".to_string(),
                evidence.blake3.clone(),
            )]),
        });
    }

    let statement = Statement {
        type_uri: STATEMENT_TYPE.to_string(),
        subject: subjects,
        predicate_type: PREDICATE_TYPE.to_string(),
        predicate: Predicate {
            policy: PolicyBlock {
                file_id: inputs.file_id.to_string(),
                chain_version: inputs.chain_version,
                feed_author,
            },
            decision: inputs.decision,
            operator: inputs.operator,
            receipt_version: inputs.receipt_version,
            nonce: crate::canon::hex(&nonce()),
        },
    };

    // Canonical payload bytes, so an independent implementation can rebuild
    // and re-verify the signature.
    let payload = crate::canon::canonical_bytes(&serde_json::to_value(&statement)?)?;
    let envelope = dsse::sign_envelope(
        &payload,
        PAYLOAD_TYPE,
        AuthorId::new(inputs.operator),
        operator_key,
    );

    Ok(Receipt {
        schema: SCHEMA.to_string(),
        claim,
        envelope: serde_json::from_str(
            &envelope
                .to_json()
                .map_err(|e| anyhow::anyhow!("serializing envelope: {e}"))?,
        )?,
    })
}

fn nonce() -> [u8; 16] {
    use std::hash::{BuildHasher, Hasher};
    // Uniqueness is what matters here; the signature provides authenticity.
    let mut nonce = [0u8; 16];
    let seed = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    nonce[..8].copy_from_slice(&seed.to_le_bytes());
    let second = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    nonce[8..].copy_from_slice(&second.to_le_bytes());
    nonce
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub signature_valid: bool,
    pub claim_bound: bool,
    pub matches_chain: Option<bool>,
    pub obligations_reproduced: Option<bool>,
    pub operator: u64,
    pub problems: Vec<String>,
}

impl Verdict {
    pub fn is_valid(&self) -> bool {
        self.problems.is_empty()
    }
}

pub fn evidence_ref(path: &Path) -> Result<EvidenceRef> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(EvidenceRef {
        name: path.file_name().map_or_else(
            || path.display().to_string(),
            |n| n.to_string_lossy().to_string(),
        ),
        blake3: hex(&digest(&bytes)),
        bytes: bytes.len() as u64,
    })
}

/// Verify signature, claim binding, and — when a chain is supplied — that the
/// operator's stated obligations are what the signed rules actually say.
pub fn verify(
    receipt: &Receipt,
    registry: &KeyRegistry,
    chain: Option<(&Bundle, u64, u64)>,
) -> Result<Verdict> {
    let mut verdict = Verdict {
        signature_valid: false,
        claim_bound: false,
        matches_chain: None,
        obligations_reproduced: None,
        operator: receipt.claim.operator,
        problems: Vec::new(),
    };

    anyhow::ensure!(
        receipt.schema == SCHEMA,
        "receipt schema is {}, expected {SCHEMA}",
        receipt.schema
    );

    let envelope = DsseEnvelope::from_json(&receipt.envelope.to_string())
        .map_err(|e| anyhow::anyhow!("receipt envelope is unreadable: {e}"))?;

    let statement: Statement = serde_json::from_slice(&envelope.payload)
        .context("receipt payload is not a fedramp-aion statement")?;
    anyhow::ensure!(
        statement.predicate_type == PREDICATE_TYPE,
        "receipt predicate type is {}, expected {PREDICATE_TYPE}",
        statement.predicate_type
    );

    // The epoch is resolved at the version the receipt cites, so a key valid
    // then still verifies after a later rotation.
    let at_version = statement.predicate.policy.chain_version.max(1);
    match dsse::verify_envelope(&envelope, registry, at_version) {
        Ok(keyids) => {
            verdict.signature_valid = true;
            let signed_by_operator = keyids.iter().any(|k| {
                dsse::author_from_keyid(k).is_ok_and(|a| a.as_u64() == statement.predicate.operator)
            });
            if !signed_by_operator {
                verdict.problems.push(format!(
                    "receipt claims operator {} but no signature from that author verified",
                    statement.predicate.operator
                ));
            }
        }
        Err(e) => verdict.problems.push(format!("signature: {e}")),
    }
    verdict.claim_bound = check_claim_binding(receipt, &statement, &mut verdict.problems)?;

    let predicate = &statement.predicate;
    if predicate.operator != receipt.claim.operator {
        verdict.problems.push(format!(
            "claim names operator {} but the signed statement names {}",
            receipt.claim.operator, predicate.operator
        ));
    }

    if let Some((bundle, file_id, chain_version)) = chain {
        check_chain(
            receipt,
            &statement.predicate,
            bundle,
            file_id,
            chain_version,
            &mut verdict,
        )?;
    }

    Ok(verdict)
}

/// Recompute every digest from the plaintext claim and compare it with what
/// was signed. This is what stops a claim from being edited after sealing.
fn check_claim_binding(
    receipt: &Receipt,
    statement: &Statement,
    problems: &mut Vec<String>,
) -> Result<bool> {
    let subject_digest = |name: &str| -> Option<String> {
        statement
            .subject
            .iter()
            .find(|s| s.name == name)
            .and_then(|s| s.digest.values().next().cloned())
    };

    let expected = [
        (
            SUBJECT_ACTION,
            hex(&digest(receipt.claim.action.as_bytes())),
        ),
        (
            SUBJECT_OBLIGATIONS,
            hex(&obligations_digest(&receipt.claim.obligations)?),
        ),
        (SUBJECT_RULES, hex(&rules_digest(&receipt.claim.rules)?)),
    ];
    let mut bound = true;
    for (name, want) in expected {
        match subject_digest(name) {
            Some(got) if got == want => {}
            Some(_) => {
                bound = false;
                problems.push(format!(
                    "claim field `{name}` does not match the signed digest"
                ));
            }
            None => {
                bound = false;
                problems.push(format!("receipt commits no digest for `{name}`"));
            }
        }
    }
    for evidence in &receipt.claim.evidence {
        let name = format!("evidence/{}", evidence.name);
        if subject_digest(&name).as_deref() != Some(evidence.blake3.as_str()) {
            bound = false;
            problems.push(format!(
                "evidence `{}` is not the signed digest",
                evidence.name
            ));
        }
    }
    Ok(bound)
}

/// Cross-check the receipt against a chain we hold: same policy, same bundle,
/// and — for the version the chain still carries — the same obligations the
/// signed rules actually produce for that profile.
fn check_chain(
    receipt: &Receipt,
    predicate: &Predicate,
    bundle: &Bundle,
    file_id: u64,
    chain_version: u64,
    verdict: &mut Verdict,
) -> Result<()> {
    let file_id = file_id.to_string();
    let same_policy = predicate.policy.file_id == file_id
        && receipt.claim.rules.file_id == file_id
        && receipt.claim.rules.chain_version == predicate.policy.chain_version;
    let digest_matches = bundle.digest()? == receipt.claim.rules.bundle_sha256;
    verdict.matches_chain = Some(same_policy && digest_matches);
    if !same_policy {
        verdict
            .problems
            .push("receipt was issued against a different chain".to_string());
    }

    // Only the version the chain currently holds can be re-derived; earlier
    // versions live in git, not in the .aion payload.
    if receipt.claim.rules.chain_version != chain_version {
        return Ok(());
    }
    if !digest_matches {
        verdict
            .problems
            .push("receipt cites this chain version but a different bundle digest".to_string());
    }
    let Some(rules) = bundle.section(crate::sources::RULES) else {
        return Ok(());
    };

    let profile: Profile = (&receipt.claim.profile).into();
    let derived = crate::obligations::select(rules, &profile);
    let consistent = receipt.claim.obligations.iter().all(|claimed| {
        derived
            .iter()
            .any(|d| d.id == claimed.id && d.force == claimed.force)
    });
    verdict.obligations_reproduced = Some(consistent);
    if !consistent {
        verdict.problems.push(
            "claimed obligations do not match what the signed rules say for this profile"
                .to_string(),
        );
    }
    Ok(())
}

/// A verdict a human can act on, listing what was checked and what failed.
pub fn verdict_markdown(receipt: &Receipt, verdict: &Verdict) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let mark = |ok: bool| if ok { "PASS" } else { "FAIL" };
    let _ = writeln!(out, "# Receipt — {}\n", receipt.claim.action);
    let _ = writeln!(out, "| check | result |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(
        out,
        "| signature by operator {} | {} |",
        verdict.operator,
        mark(verdict.signature_valid)
    );
    let _ = writeln!(
        out,
        "| claim bound to signature | {} |",
        mark(verdict.claim_bound)
    );
    if let Some(ok) = verdict.matches_chain {
        let _ = writeln!(out, "| cites this chain | {} |", mark(ok));
    }
    if let Some(ok) = verdict.obligations_reproduced {
        let _ = writeln!(out, "| obligations match the signed rules | {} |", mark(ok));
    }
    let _ = writeln!(
        out,
        "\n- decision: `{}`\n- profile: {} \n- rules: chain v{}, upstream `{}`, commit `{}`",
        receipt.claim.decision,
        receipt.claim.profile.role,
        receipt.claim.rules.chain_version,
        receipt.claim.rules.upstream_version,
        &receipt.claim.rules.rules_commit[..receipt.claim.rules.rules_commit.len().min(8)]
    );
    let _ = writeln!(out, "- obligations: {}", receipt.claim.obligations.len());
    for evidence in &receipt.claim.evidence {
        let _ = writeln!(
            out,
            "- evidence `{}` ({} bytes) blake3 `{}`",
            evidence.name,
            evidence.bytes,
            &evidence.blake3[..16]
        );
    }
    if verdict.problems.is_empty() {
        let _ = writeln!(out, "\n**VALID**");
    } else {
        let _ = writeln!(out, "\n**INVALID**");
        for problem in &verdict.problems {
            let _ = writeln!(out, "- {problem}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions_parse_in_the_forms_a_cli_sees() {
        assert_eq!(parse_decision("satisfied").unwrap(), Decision::Satisfied);
        assert_eq!(
            parse_decision("not-satisfied").unwrap(),
            Decision::NotSatisfied
        );
        assert_eq!(
            parse_decision("NOT_SATISFIED").unwrap(),
            Decision::NotSatisfied
        );
        assert!(parse_decision("maybe").is_err());
    }

    #[test]
    fn obligation_digest_ignores_order_of_nothing_but_tracks_force() {
        let a = vec![ObligationRef {
            id: "X".into(),
            force: "MUST".into(),
        }];
        let b = vec![ObligationRef {
            id: "X".into(),
            force: "SHOULD".into(),
        }];
        assert_ne!(
            obligations_digest(&a).unwrap(),
            obligations_digest(&b).unwrap(),
            "a force change must break the digest"
        );
    }

    /// JCS serializes numbers as ECMAScript doubles, so a u64 file id above
    /// 2^53 rounds. The chain's file id is a random u64 and hits this.
    #[test]
    fn a_large_file_id_survives_canonicalization() {
        let file_id: u64 = 6_675_964_335_526_256_880;
        let policy = PolicyBlock {
            file_id: file_id.to_string(),
            chain_version: 1,
            feed_author: 1,
        };
        let canonical =
            crate::canon::canonical_bytes(&serde_json::to_value(&policy).unwrap()).unwrap();
        let parsed: PolicyBlock = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(parsed.file_id, file_id.to_string());
        assert!(
            String::from_utf8_lossy(&canonical).contains("6675964335526256880"),
            "file id was rounded by canonicalization"
        );
    }

    #[test]
    fn nonces_differ_between_receipts() {
        assert_ne!(nonce(), nonce());
    }
}
