use crate::lockfile::LockfileModel;
use crate::signals::{RiskSignal, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectRisk {
    pub score: u8,
    pub level: RiskLevel,
    /// Highest single-package score, useful for `max_package_score` policy checks.
    pub max_package_score: u8,
    /// Per-package scores, sorted by package id for determinism.
    pub packages: Vec<PackageRisk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRisk {
    pub package: String,
    pub score: u8,
    pub level: RiskLevel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

/// Decay factor for repeated heuristic findings of the same class.
const HEURISTIC_DECAY: f64 = 0.5;

fn is_advisory(signal: &RiskSignal) -> bool {
    signal.id.starts_with("advisory_")
}

/// Compute the project risk score from collected signals (0–100).
///
/// The aggregation is deliberately *not* a flat sum, to avoid false-positive
/// inflation on large dependency trees:
///
/// - **Advisory findings** (real, matched vulnerabilities) are summed in full —
///   each additional known vulnerability genuinely adds risk. A `Critical`
///   advisory pins the project score to 100.
/// - **Heuristic findings** (FFI, build scripts, `unsafe`, duplicate versions,
///   license) get *diminishing returns per class*: the largest finding of a
///   class counts in full, the next at 50%, then 25%, … so a project with 30
///   `-sys` crates is not scored as 30× the risk of one.
///
/// Per-package scores use a plain saturating sum so that a single highly-risky
/// package can still trip `max_package_score`.
pub fn score_project(_lock: &LockfileModel, signals: &[RiskSignal]) -> ProjectRisk {
    let mut critical = false;
    let mut advisory_sum: f64 = 0.0;
    // Heuristic weights grouped by signal id, for diminishing aggregation.
    let mut heuristic_by_id: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
    let mut per_package: BTreeMap<&str, u16> = BTreeMap::new();
    let mut package_critical: BTreeMap<&str, bool> = BTreeMap::new();

    for signal in signals {
        let pkg = per_package.entry(&signal.package).or_insert(0);
        *pkg = pkg.saturating_add(signal.weight as u16);
        if signal.severity == Severity::Critical {
            critical = true;
            package_critical.insert(&signal.package, true);
        }
        if is_advisory(signal) {
            advisory_sum += signal.weight as f64;
        } else if signal.weight > 0 {
            heuristic_by_id
                .entry(&signal.id)
                .or_default()
                .push(signal.weight);
        }
    }

    let mut heuristic_sum = 0.0;
    for weights in heuristic_by_id.values_mut() {
        weights.sort_unstable_by(|a, b| b.cmp(a)); // largest first
        for (i, w) in weights.iter().enumerate() {
            heuristic_sum += (*w as f64) * HEURISTIC_DECAY.powi(i as i32);
        }
    }

    let raw = advisory_sum + heuristic_sum;
    let score = if critical {
        100
    } else {
        raw.round().min(100.0) as u8
    };

    let packages = per_package
        .into_iter()
        .map(|(name, raw)| {
            let s = if package_critical.get(name).copied().unwrap_or(false) {
                100
            } else {
                raw.min(100) as u8
            };
            PackageRisk {
                package: name.to_string(),
                score: s,
                level: level_for_score(s),
            }
        })
        .collect::<Vec<_>>();

    let max_package_score = packages.iter().map(|p| p.score).max().unwrap_or(0);

    ProjectRisk {
        score,
        level: level_for_score(score),
        max_package_score,
        packages,
    }
}

/// A transparent breakdown of how the project score was computed.
#[derive(Debug, Clone)]
pub struct ScoreExplanation {
    /// `(label, points)` contributions, largest first.
    pub contributions: Vec<(String, f64)>,
    pub total: u8,
    /// True when a critical advisory pinned the score to 100.
    pub critical_pin: bool,
}

/// Explain the score: per-advisory full weights plus per-class diminishing
/// heuristic contributions. The summed `total` is guaranteed to equal
/// [`score_project`]'s score for the same signals (asserted in tests).
pub fn explain(signals: &[RiskSignal]) -> ScoreExplanation {
    let mut critical = false;
    let mut contributions: Vec<(String, f64)> = Vec::new();
    let mut heuristic_by_id: BTreeMap<&str, Vec<u8>> = BTreeMap::new();

    for signal in signals {
        if signal.severity == Severity::Critical {
            critical = true;
        }
        if is_advisory(signal) {
            contributions.push((
                format!(
                    "{} on {}",
                    signal.id.trim_start_matches("advisory_"),
                    signal.package
                ),
                signal.weight as f64,
            ));
        } else if signal.weight > 0 {
            heuristic_by_id
                .entry(&signal.id)
                .or_default()
                .push(signal.weight);
        }
    }

    for (id, weights) in heuristic_by_id.iter_mut() {
        weights.sort_unstable_by(|a, b| b.cmp(a));
        let sum: f64 = weights
            .iter()
            .enumerate()
            .map(|(i, w)| (*w as f64) * HEURISTIC_DECAY.powi(i as i32))
            .sum();
        contributions.push((format!("{} (×{})", id, weights.len()), sum));
    }

    let raw: f64 = contributions.iter().map(|(_, p)| p).sum();
    let total = if critical {
        100
    } else {
        raw.round().min(100.0) as u8
    };

    contributions.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });

    ScoreExplanation {
        contributions,
        total,
        critical_pin: critical,
    }
}

pub fn level_for_score(score: u8) -> RiskLevel {
    match score {
        0..=19 => RiskLevel::Low,
        20..=49 => RiskLevel::Medium,
        50..=79 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::RiskSignal;

    fn sig(pkg: &str, sev: Severity, weight: u8) -> RiskSignal {
        sig_id("x", pkg, sev, weight)
    }

    fn sig_id(id: &str, pkg: &str, sev: Severity, weight: u8) -> RiskSignal {
        RiskSignal {
            id: id.into(),
            package: pkg.into(),
            severity: sev,
            weight,
            confidence: 1.0,
            evidence: vec![],
            recommendation: String::new(),
        }
    }

    fn empty_lock() -> LockfileModel {
        LockfileModel {
            path: "Cargo.lock".into(),
            version: None,
            packages: vec![],
        }
    }

    #[test]
    fn empty_is_low() {
        let r = score_project(&empty_lock(), &[]);
        assert_eq!(r.score, 0);
        assert_eq!(r.level, RiskLevel::Low);
    }

    #[test]
    fn diminishing_within_same_class() {
        // Two findings of the SAME id => diminishing: 20 + 12*0.5 = 26.
        let signals = vec![
            sig("a@1", Severity::High, 20),
            sig("a@1", Severity::Medium, 12),
        ];
        let r = score_project(&empty_lock(), &signals);
        assert_eq!(r.score, 26);
        // Per-package score still sums fully so a single bad crate can trip policy.
        assert_eq!(r.max_package_score, 32);
    }

    #[test]
    fn different_classes_sum_fully() {
        let signals = vec![
            sig_id("native_ffi_detected", "a@1", Severity::Medium, 14),
            sig_id("build_script_present", "a@1", Severity::Medium, 10),
        ];
        let r = score_project(&empty_lock(), &signals);
        assert_eq!(r.score, 24);
    }

    #[test]
    fn many_low_findings_do_not_saturate() {
        // 30 identical Low/8 FFI findings must NOT blow up to 100.
        let signals: Vec<RiskSignal> = (0..30)
            .map(|i| sig_id("native_ffi_detected", &format!("c{i}@1"), Severity::Low, 8))
            .collect();
        let r = score_project(&empty_lock(), &signals);
        // 8 * (1 + 0.5 + 0.25 + ...) -> converges to 16.
        assert!(r.score <= 16, "score was {}", r.score);
    }

    #[test]
    fn explain_total_matches_score() {
        let cases: Vec<Vec<RiskSignal>> = vec![
            vec![],
            vec![sig_id("native_ffi_detected", "a@1", Severity::Low, 8)],
            vec![
                sig_id("native_ffi_detected", "a@1", Severity::Low, 8),
                sig_id("native_ffi_detected", "b@1", Severity::Low, 8),
                sig_id("build_script_present", "a@1", Severity::Medium, 10),
                sig_id("advisory_RUSTSEC-1", "v@1", Severity::High, 30),
            ],
            vec![sig_id("advisory_RUSTSEC-X", "c@1", Severity::Critical, 60)],
        ];
        for signals in cases {
            let score = score_project(&empty_lock(), &signals).score;
            let ex = explain(&signals);
            assert_eq!(ex.total, score, "explain/score drift for {signals:?}");
        }
    }

    #[test]
    fn advisories_sum_fully() {
        let signals = vec![
            sig_id("advisory_RUSTSEC-1", "a@1", Severity::High, 30),
            sig_id("advisory_RUSTSEC-2", "b@1", Severity::High, 30),
        ];
        let r = score_project(&empty_lock(), &signals);
        assert_eq!(r.score, 60);
    }

    #[test]
    fn critical_pins_to_100() {
        let signals = vec![sig("a@1", Severity::Critical, 5)];
        let r = score_project(&empty_lock(), &signals);
        assert_eq!(r.score, 100);
        assert_eq!(r.level, RiskLevel::Critical);
    }

    #[test]
    fn level_boundaries() {
        assert_eq!(level_for_score(0), RiskLevel::Low);
        assert_eq!(level_for_score(19), RiskLevel::Low);
        assert_eq!(level_for_score(20), RiskLevel::Medium);
        assert_eq!(level_for_score(49), RiskLevel::Medium);
        assert_eq!(level_for_score(50), RiskLevel::High);
        assert_eq!(level_for_score(79), RiskLevel::High);
        assert_eq!(level_for_score(80), RiskLevel::Critical);
    }
}
