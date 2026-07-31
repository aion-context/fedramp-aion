//! Change severity. Its job is to keep a rules change from being buried under
//! a week of marketplace counter churn.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    None,
    /// Only `info.*` moved in the rules document.
    Metadata,
    /// Marketplace counters and mapping rows.
    Routine,
    /// A marketplace authorization event.
    Minor,
    /// A rule or a submission schema moved.
    Major,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Metadata => "metadata",
            Self::Routine => "routine",
            Self::Minor => "minor",
            Self::Major => "major",
        }
    }

    pub fn headline(self) -> &'static str {
        match self {
            Self::None => "no change",
            Self::Metadata => "metadata only",
            Self::Routine => "routine movement",
            Self::Minor => "marketplace authorization activity",
            Self::Major => "RULES CHANGED",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "metadata" => Ok(Self::Metadata),
            "routine" => Ok(Self::Routine),
            "minor" => Ok(Self::Minor),
            "major" => Ok(Self::Major),
            other => Err(format!("unknown severity `{other}`")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_lets_max_pick_the_loudest_source() {
        let observed = [Severity::Routine, Severity::Major, Severity::Metadata];
        assert_eq!(observed.into_iter().max(), Some(Severity::Major));
    }

    #[test]
    fn gate_threshold_comparisons_hold() {
        assert!(Severity::Routine > Severity::None);
        assert!(Severity::Minor < Severity::Major);
        assert!(Severity::Metadata > Severity::None);
    }

    #[test]
    fn parses_from_cli_text() {
        assert_eq!("Major".parse::<Severity>().unwrap(), Severity::Major);
        assert!("loud".parse::<Severity>().is_err());
    }
}
