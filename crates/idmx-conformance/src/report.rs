//! Check results and the report they add up to.

use std::fmt;

/// How binding the checked requirement is (BCP 14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// A MUST / MUST NOT: failing it means the receiver does not conform.
    Must,
    /// A SHOULD: failing it is reported as a warning.
    Should,
}

/// What a check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The receiver meets the requirement.
    Pass,
    /// The receiver violates the requirement; the text says how.
    Fail(String),
    /// The check could not run; the text says why.
    Skipped(String),
}

/// One requirement of the spec, checked against one receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Stable identifier, e.g. `CAP-02`.
    pub id: &'static str,
    /// Where the requirement is written, e.g. `capabilities.md §3`.
    pub spec: &'static str,
    /// MUST or SHOULD.
    pub level: Level,
    /// The requirement in one line.
    pub requirement: &'static str,
    /// The finding.
    pub outcome: Outcome,
}

impl Check {
    /// Whether this check is a violated MUST.
    #[must_use]
    pub fn is_violation(&self) -> bool {
        self.level == Level::Must && matches!(self.outcome, Outcome::Fail(_))
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verdict = match (&self.outcome, self.level) {
            (Outcome::Pass, _) => "PASS",
            (Outcome::Fail(_), Level::Must) => "FAIL",
            (Outcome::Fail(_), Level::Should) => "WARN",
            (Outcome::Skipped(_), _) => "SKIP",
        };
        write!(
            f,
            "{verdict} {} {} ({})",
            self.id, self.requirement, self.spec
        )?;
        match &self.outcome {
            Outcome::Pass => Ok(()),
            Outcome::Fail(detail) | Outcome::Skipped(detail) => write!(f, ": {detail}"),
        }
    }
}

/// All checks run against one receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The checks in execution order.
    pub checks: Vec<Check>,
}

impl Report {
    /// Whether no MUST is violated.
    #[must_use]
    pub fn conforms(&self) -> bool {
        !self.checks.iter().any(Check::is_violation)
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for check in &self.checks {
            writeln!(f, "{check}")?;
        }
        let violations = self.checks.iter().filter(|c| c.is_violation()).count();
        write!(f, "{} checks, {violations} violations", self.checks.len())
    }
}
