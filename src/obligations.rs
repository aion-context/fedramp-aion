//! Which rules apply to *you*, and what they oblige you to do.
//!
//! A rule's applicability comes from four places in the published data, and no
//! single one is complete:
//!
//! | dimension | source | fallback |
//! |---|---|---|
//! | certification type | the `data.<type>` path (`all` / `20x` / `rev5`) | none needed — always present |
//! | affected party | the rule's own `affects` | subset applicability |
//! | class | `varies_by_class` keys | subset `classes`, else unconstrained |
//! | path | subset `paths` | unconstrained |
//!
//! The subset fallback matters because 19 of 246 rules live in subsets
//! (`CSF`, `CSX`) that no family declares in `info.subsets`. Those are exactly
//! the type-specific ones, so the `data.<type>` path carries their scope.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// `Providers`, `Agencies`, `Assessors`, `Advisors`, or `FedRAMP`.
    pub role: String,
    /// `A`–`D`. `None` means "any class".
    pub class: Option<String>,
    /// `20x` or `Rev5`. `None` means "any type".
    pub cert_type: Option<String>,
    /// `Program` or `Agency`. `None` means "any path".
    pub path: Option<String>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            role: "Providers".to_string(),
            class: None,
            cert_type: None,
            path: None,
        }
    }
}

impl Profile {
    pub fn label(&self) -> String {
        let mut parts = vec![self.role.clone()];
        for (name, value) in [
            ("class", self.class.as_ref()),
            ("type", self.cert_type.as_ref()),
            ("path", self.path.as_ref()),
        ] {
            if let Some(value) = value {
                parts.push(format!("{name} {value}"));
            }
        }
        parts.join(", ")
    }
}

/// One rule as it applies to a specific profile, with the class-specific
/// variant already resolved.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Obligation {
    pub id: String,
    pub family: String,
    pub subset: String,
    pub cert_type: String,
    pub force: String,
    pub statement: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Set when the text came from a `varies_by_class` branch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeframe: Option<String>,
    /// The machine-readable artifact this rule binds, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
}

impl Obligation {
    /// `MUST` and `MUST NOT` are binding; the rest are not.
    pub fn is_binding(&self) -> bool {
        self.force.starts_with("MUST")
    }
}

/// Every obligation that applies to `profile`, sorted by rule id.
pub fn select(rules: &Value, profile: &Profile) -> Vec<Obligation> {
    let mut out = Vec::new();
    let Some(families) = rules.get("FRR").and_then(Value::as_object) else {
        return out;
    };

    for (family, body) in families {
        let subsets = body.pointer("/info/subsets").and_then(Value::as_object);
        let Some(data) = body.get("data").and_then(Value::as_object) else {
            continue;
        };
        for (cert_type, groups) in data {
            if !type_matches(cert_type, profile.cert_type.as_deref()) {
                continue;
            }
            let Some(groups) = groups.as_object() else {
                continue;
            };
            for (subset, entries) in groups {
                let applicability = subsets
                    .and_then(|s| s.get(subset))
                    .and_then(|s| s.get("applicability"));
                if !path_matches(applicability, profile.path.as_deref()) {
                    continue;
                }
                let Some(entries) = entries.as_object() else {
                    continue;
                };
                for (id, leaf) in entries {
                    if !role_matches(leaf, applicability, &profile.role) {
                        continue;
                    }
                    if let Some(obligation) =
                        resolve(id, family, subset, cert_type, leaf, applicability, profile)
                    {
                        out.push(obligation);
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// `all` applies to every certification type; otherwise it must match.
fn type_matches(cert_type: &str, wanted: Option<&str>) -> bool {
    let Some(wanted) = wanted else { return true };
    cert_type == "all" || cert_type.eq_ignore_ascii_case(wanted)
}

fn path_matches(applicability: Option<&Value>, wanted: Option<&str>) -> bool {
    let (Some(wanted), Some(paths)) = (
        wanted,
        applicability
            .and_then(|a| a.get("paths"))
            .and_then(Value::as_array),
    ) else {
        return true;
    };
    paths
        .iter()
        .filter_map(Value::as_str)
        .any(|p| p.eq_ignore_ascii_case(wanted))
}

/// The rule's own `affects` wins; every rule in the current data carries one.
fn role_matches(leaf: &Value, applicability: Option<&Value>, role: &str) -> bool {
    let affects = leaf
        .get("affects")
        .or_else(|| applicability.and_then(|a| a.get("affects")))
        .and_then(Value::as_array);
    match affects {
        Some(list) => list
            .iter()
            .filter_map(Value::as_str)
            .any(|a| a.eq_ignore_ascii_case(role)),
        None => true,
    }
}

fn resolve(
    id: &str,
    family: &str,
    subset: &str,
    cert_type: &str,
    leaf: &Value,
    applicability: Option<&Value>,
    profile: &Profile,
) -> Option<Obligation> {
    let base = Obligation {
        id: id.to_string(),
        family: family.to_string(),
        subset: subset.to_string(),
        cert_type: cert_type.to_string(),
        force: String::new(),
        statement: String::new(),
        name: leaf.get("name").and_then(Value::as_str).map(str::to_string),
        class: None,
        timeframe: None,
        schema: leaf
            .pointer("/schema/name")
            .and_then(Value::as_str)
            .map(str::to_string),
    };

    if let Some(variants) = leaf.get("varies_by_class").and_then(Value::as_object) {
        // Per-class variants are authoritative: a class absent here has no
        // obligation under this rule, whatever the subset declares.
        let Some(class) = &profile.class else {
            // No class given: report the strictest variant so nothing is missed.
            let (class, variant) = variants
                .iter()
                .max_by_key(|(_, v)| force_rank(v.get("force").and_then(Value::as_str)))?;
            return Some(fill(base, variant, Some(class)));
        };
        let key = class.to_ascii_lowercase();
        let variant = variants.get(&key)?;
        return Some(fill(base, variant, Some(&key)));
    }

    if !class_matches(applicability, profile.class.as_deref()) {
        return None;
    }
    Some(fill(base, leaf, None))
}

fn class_matches(applicability: Option<&Value>, wanted: Option<&str>) -> bool {
    let (Some(wanted), Some(classes)) = (
        wanted,
        applicability
            .and_then(|a| a.get("classes"))
            .and_then(Value::as_array),
    ) else {
        return true;
    };
    classes
        .iter()
        .filter_map(Value::as_str)
        .any(|c| c.eq_ignore_ascii_case(wanted))
}

fn fill(mut obligation: Obligation, source: &Value, class: Option<&str>) -> Obligation {
    obligation.force = source
        .get("force")
        .and_then(Value::as_str)
        .unwrap_or("UNSPECIFIED")
        .to_string();
    obligation.statement = source
        .get("statement")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    obligation.class = class.map(str::to_ascii_uppercase);
    obligation.timeframe = match (
        source.get("timeframe_num").and_then(Value::as_i64),
        source.get("timeframe_type").and_then(Value::as_str),
    ) {
        (Some(n), Some(unit)) => Some(format!("{n} {unit}")),
        _ => None,
    };
    obligation
}

fn force_rank(force: Option<&str>) -> u8 {
    match force {
        Some("MUST" | "MUST NOT") => 4,
        Some("SHOULD" | "SHOULD NOT") => 3,
        Some("MAY") => 2,
        Some(_) => 1,
        None => 0,
    }
}

/// What changed for one profile between two versions of the ruleset.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ObligationDelta {
    pub profile: String,
    pub added: Vec<Obligation>,
    pub removed: Vec<Obligation>,
    pub changed: Vec<ObligationChange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObligationChange {
    pub id: String,
    pub field: String,
    pub from: String,
    pub to: String,
}

impl ObligationDelta {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    /// Changes that alter what is binding — the ones worth waking someone for.
    pub fn binding_shifts(&self) -> Vec<&ObligationChange> {
        self.changed
            .iter()
            .filter(|c| c.field == "force")
            .filter(|c| c.from.starts_with("MUST") != c.to.starts_with("MUST"))
            .collect()
    }
}

pub fn delta(before: &Value, after: &Value, profile: &Profile) -> ObligationDelta {
    let index = |rules: &Value| -> BTreeMap<String, Obligation> {
        select(rules, profile)
            .into_iter()
            .map(|o| (o.id.clone(), o))
            .collect()
    };
    let old = index(before);
    let new = index(after);

    let mut delta = ObligationDelta {
        profile: profile.label(),
        ..ObligationDelta::default()
    };
    for (id, obligation) in &new {
        if !old.contains_key(id) {
            delta.added.push(obligation.clone());
        }
    }
    for (id, obligation) in &old {
        if !new.contains_key(id) {
            delta.removed.push(obligation.clone());
        }
    }
    for (id, old_obligation) in &old {
        let Some(new_obligation) = new.get(id) else {
            continue;
        };
        for (field, from, to) in [
            ("force", &old_obligation.force, &new_obligation.force),
            (
                "statement",
                &old_obligation.statement,
                &new_obligation.statement,
            ),
        ] {
            if from != to {
                delta.changed.push(ObligationChange {
                    id: id.clone(),
                    field: field.to_string(),
                    from: from.clone(),
                    to: to.clone(),
                });
            }
        }
    }
    delta
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rules() -> Value {
        json!({"FRR": {
            "CCM": {
                "info": {"subsets": {
                    "OCR": {"applicability": {"affects": ["Providers"], "classes": ["B","C","D"],
                                              "paths": ["Program","Agency"], "types": ["20x","Rev5"]}},
                    "AGM": {"applicability": {"affects": ["Agencies"], "classes": ["B","C","D"],
                                              "paths": ["Agency"], "types": ["Rev5"]}}}},
                "data": {"all": {
                    "OCR": {"CCM-OCR-AVL": {"affects": ["Providers"], "force": "MUST",
                                            "statement": "Report availability.",
                                            "schema": {"name": "Ongoing Certification Report"}}},
                    "AGM": {"CCM-AGM-ONE": {"affects": ["Agencies"], "force": "SHOULD",
                                            "statement": "Agencies should review."}}}}},
            "CPO": {
                "info": {"subsets": {}},
                "data": {"rev5": {"CSF": {"CPO-CSF-CPM": {
                    "affects": ["Providers"], "name": "Certification Package Maintenance",
                    "varies_by_class": {
                        "b": {"force": "MUST", "statement": "Class B maintains yearly.",
                              "timeframe_num": 1, "timeframe_type": "years"},
                        "c": {"force": "SHOULD", "statement": "Class C should maintain."}}}}}}}
        }})
    }

    fn provider(class: &str, cert_type: &str) -> Profile {
        Profile {
            role: "Providers".into(),
            class: Some(class.into()),
            cert_type: Some(cert_type.into()),
            path: None,
        }
    }

    #[test]
    fn selects_only_rules_affecting_the_role() {
        let ids: Vec<String> = select(&rules(), &provider("B", "Rev5"))
            .into_iter()
            .map(|o| o.id)
            .collect();
        assert!(ids.contains(&"CCM-OCR-AVL".to_string()));
        assert!(
            !ids.contains(&"CCM-AGM-ONE".to_string()),
            "agency rule leaked"
        );
    }

    #[test]
    fn type_specific_rules_are_scoped_by_their_data_path() {
        let rev5: Vec<String> = select(&rules(), &provider("B", "Rev5"))
            .into_iter()
            .map(|o| o.id)
            .collect();
        let twentyx: Vec<String> = select(&rules(), &provider("B", "20x"))
            .into_iter()
            .map(|o| o.id)
            .collect();
        assert!(rev5.contains(&"CPO-CSF-CPM".to_string()));
        assert!(
            !twentyx.contains(&"CPO-CSF-CPM".to_string()),
            "rev5-only rule applied to a 20x profile"
        );
        assert!(
            twentyx.contains(&"CCM-OCR-AVL".to_string()),
            "`all` rule dropped"
        );
    }

    #[test]
    fn per_class_variant_is_resolved() {
        let b = select(&rules(), &provider("B", "Rev5"));
        let cpm = b.iter().find(|o| o.id == "CPO-CSF-CPM").unwrap();
        assert_eq!(cpm.force, "MUST");
        assert_eq!(cpm.timeframe.as_deref(), Some("1 years"));
        assert!(cpm.is_binding());

        let c = select(&rules(), &provider("C", "Rev5"));
        let cpm = c.iter().find(|o| o.id == "CPO-CSF-CPM").unwrap();
        assert_eq!(cpm.force, "SHOULD");
        assert!(!cpm.is_binding());
    }

    #[test]
    fn a_class_absent_from_variants_has_no_obligation() {
        let d = select(&rules(), &provider("D", "Rev5"));
        assert!(
            !d.iter().any(|o| o.id == "CPO-CSF-CPM"),
            "class D has no variant and must not inherit one"
        );
    }

    #[test]
    fn omitting_class_reports_the_strictest_variant() {
        let profile = Profile {
            role: "Providers".into(),
            class: None,
            cert_type: Some("Rev5".into()),
            path: None,
        };
        let cpm = select(&rules(), &profile)
            .into_iter()
            .find(|o| o.id == "CPO-CSF-CPM")
            .unwrap();
        assert_eq!(cpm.force, "MUST");
        assert_eq!(cpm.class.as_deref(), Some("B"));
    }

    #[test]
    fn subset_path_constraint_is_honored() {
        let program = Profile {
            role: "Agencies".into(),
            class: Some("B".into()),
            cert_type: None,
            path: Some("Program".into()),
        };
        assert!(
            !select(&rules(), &program)
                .iter()
                .any(|o| o.id == "CCM-AGM-ONE"),
            "AGM is Agency-path only"
        );
        let agency = Profile {
            path: Some("Agency".into()),
            ..program
        };
        assert!(select(&rules(), &agency)
            .iter()
            .any(|o| o.id == "CCM-AGM-ONE"));
    }

    #[test]
    fn schema_bound_rules_carry_their_artifact() {
        let avl = select(&rules(), &provider("B", "Rev5"))
            .into_iter()
            .find(|o| o.id == "CCM-OCR-AVL")
            .unwrap();
        assert_eq!(avl.schema.as_deref(), Some("Ongoing Certification Report"));
    }

    #[test]
    fn delta_reports_a_binding_shift_for_the_affected_class_only() {
        let mut after = rules();
        after["FRR"]["CPO"]["data"]["rev5"]["CSF"]["CPO-CSF-CPM"]["varies_by_class"]["c"]
            ["force"] = json!("MUST");

        let class_c = delta(&rules(), &after, &provider("C", "Rev5"));
        assert_eq!(class_c.binding_shifts().len(), 1);
        assert_eq!(class_c.binding_shifts()[0].from, "SHOULD");

        let class_b = delta(&rules(), &after, &provider("B", "Rev5"));
        assert!(class_b.is_empty(), "class B was untouched");
    }

    #[test]
    fn delta_reports_added_and_removed_obligations() {
        let mut after = rules();
        after["FRR"]["CCM"]["data"]["all"]["OCR"]["CCM-OCR-NEW"] =
            json!({"affects": ["Providers"], "force": "MUST", "statement": "New duty."});
        after["FRR"]["CCM"]["data"]["all"]["OCR"]
            .as_object_mut()
            .unwrap()
            .remove("CCM-OCR-AVL");

        let d = delta(&rules(), &after, &provider("B", "Rev5"));
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].id, "CCM-OCR-NEW");
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].id, "CCM-OCR-AVL");
    }
}
