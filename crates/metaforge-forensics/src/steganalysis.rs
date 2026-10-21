pub use crate::chi_square::{
    approximate_chi_square_p_value, calculate_ascii_ratio, calculate_chi_square_uniformity,
    calculate_pov_chi_square, extract_entropy_continuum, CHI_SQUARE_CRITICAL_DF255_A01,
    CHI_SQUARE_CRITICAL_DF255_A05,
};
use serde::{Deserialize, Serialize};

/// Severity level of a steganalysis finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Category of the steganalysis finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StegFindingType {
    SuspiciousScanData,
    SuspiciousComment,
    SuspiciousAppSegment,
    EmbeddedAsciiText,
    AnomalousPoVDistribution,
    GenericAnomaly,
}

/// Individual anomaly or finding detected during steganalysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SteganalysisFinding {
    pub finding_type: StegFindingType,
    pub description: String,
    pub severity: FindingSeverity,
    pub metric_value: Option<f64>,
}

/// Comprehensive report of statistical steganalysis performed on JPEG scan data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SteganalysisReport {
    pub scan_data_bytes: usize,
    pub chi_square_stat: f64,
    pub degrees_of_freedom: usize,
    pub p_value_approx: f64,
    pub pov_chi_square_stat: Option<f64>,
    pub ascii_ratio: f64,
    pub findings: Vec<SteganalysisFinding>,
    pub is_suspicious: bool,
}

/// Analyzes JPEG comment (0xFFFE) payload for hidden text or anomalies.
pub fn analyze_comment_segment(comment_data: &[u8]) -> Vec<SteganalysisFinding> {
    let mut findings = Vec::new();
    if comment_data.is_empty() {
        return findings;
    }

    if comment_data.len() > 256 {
        findings.push(SteganalysisFinding {
            finding_type: StegFindingType::SuspiciousComment,
            description: format!(
                "Unusually large comment payload detected ({} bytes > 256 threshold)",
                comment_data.len()
            ),
            severity: FindingSeverity::Low,
            metric_value: Some(comment_data.len() as f64),
        });
    }

    let non_printable = comment_data
        .iter()
        .filter(|&&b| !(32..=126).contains(&b) && !(9..=13).contains(&b))
        .count();
    let ratio = non_printable as f64 / comment_data.len() as f64;
    if ratio > 0.15 {
        findings.push(SteganalysisFinding {
            finding_type: StegFindingType::SuspiciousComment,
            description: format!(
                "High proportion of non-printable bytes in COM segment ({:.1}% > 15.0% threshold)",
                ratio * 100.0
            ),
            severity: FindingSeverity::Medium,
            metric_value: Some(ratio),
        });
    }

    findings
}

/// Analyzes an APPn segment for anomalies and excessive binary footprints.
pub fn analyze_app_segment(app_data: &[u8], marker: u8) -> Vec<SteganalysisFinding> {
    let mut findings = Vec::new();
    if app_data.is_empty() {
        return findings;
    }

    let app_n = marker.saturating_sub(0xE0);

    if app_data.len() > 32_768 {
        findings.push(SteganalysisFinding {
            finding_type: StegFindingType::SuspiciousAppSegment,
            description: format!(
                "Unusually large APP{} segment detected ({} bytes > 32768 threshold)",
                app_n,
                app_data.len()
            ),
            severity: FindingSeverity::Low,
            metric_value: Some(app_data.len() as f64),
        });
    }

    findings
}

/// Analyzes extracted entropy-coded scan data for statistical steganography anomalies.
pub fn analyze_scan_data(scan_data: &[u8]) -> SteganalysisReport {
    let mut findings = Vec::new();

    if scan_data.len() < 256 {
        return SteganalysisReport {
            scan_data_bytes: scan_data.len(),
            chi_square_stat: 0.0,
            degrees_of_freedom: 255,
            p_value_approx: 1.0,
            pov_chi_square_stat: None,
            ascii_ratio: calculate_ascii_ratio(scan_data),
            findings,
            is_suspicious: false,
        };
    }

    let (chi_stat, df, p_val) = calculate_chi_square_uniformity(scan_data);

    if chi_stat > CHI_SQUARE_CRITICAL_DF255_A01 || p_val < 0.01 {
        findings.push(SteganalysisFinding {
            finding_type: StegFindingType::SuspiciousScanData,
            description: format!(
                "Chi-Square test indicates significant statistical deviation from expected distribution (Stat={:.2}, p={:.4} < alpha=0.01)",
                chi_stat, p_val
            ),
            severity: FindingSeverity::Medium,
            metric_value: Some(chi_stat),
        });
    }

    let (pov_stat, pov_df) = calculate_pov_chi_square(scan_data);
    if pov_df > 64 && pov_stat < (pov_df as f64 * 0.2) {
        findings.push(SteganalysisFinding {
            finding_type: StegFindingType::AnomalousPoVDistribution,
            description: format!(
                "Pairs-of-Values distribution is artificially equalized (PoV Stat={:.2} vs df={}), indicative of LSB steganography",
                pov_stat, pov_df
            ),
            severity: FindingSeverity::High,
            metric_value: Some(pov_stat),
        });
    }

    let ascii_ratio = calculate_ascii_ratio(scan_data);
    if ascii_ratio > 0.12 {
        findings.push(SteganalysisFinding {
            finding_type: StegFindingType::EmbeddedAsciiText,
            description: format!(
                "Suspicious ASCII concentration detected in compressed scan stream ({:.1}% > 12.0% threshold)",
                ascii_ratio * 100.0
            ),
            severity: FindingSeverity::High,
            metric_value: Some(ascii_ratio),
        });
    }

    let is_suspicious = findings.iter().any(|f| {
        f.severity == FindingSeverity::Medium
            || f.severity == FindingSeverity::High
            || f.severity == FindingSeverity::Critical
    });

    SteganalysisReport {
        scan_data_bytes: scan_data.len(),
        chi_square_stat: chi_stat,
        degrees_of_freedom: df,
        p_value_approx: p_val,
        pov_chi_square_stat: Some(pov_stat),
        ascii_ratio,
        findings,
        is_suspicious,
    }
}

/// End-to-end steganalysis on raw JPEG file bytes.
pub fn analyze_jpeg_steganography(bytes: &[u8]) -> SteganalysisReport {
    let scan_data = extract_entropy_continuum(bytes);
    let mut report = analyze_scan_data(&scan_data);

    let mut pos = 2;
    while pos + 4 <= bytes.len() {
        if bytes[pos] == 0xFF {
            let marker = bytes[pos + 1];
            if marker == 0xFE {
                let len = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
                if pos + 2 + len <= bytes.len() && len >= 2 {
                    let com_data = &bytes[pos + 4..pos + 2 + len];
                    report.findings.extend(analyze_comment_segment(com_data));
                }
            } else if (0xE0..=0xEF).contains(&marker) {
                let len = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
                if pos + 2 + len <= bytes.len() && len >= 2 {
                    let app_data = &bytes[pos + 4..pos + 2 + len];
                    report.findings.extend(analyze_app_segment(app_data, marker));
                }
            }
        }
        pos += 1;
    }

    report.is_suspicious = report.findings.iter().any(|f| {
        f.severity == FindingSeverity::Medium
            || f.severity == FindingSeverity::High
            || f.severity == FindingSeverity::Critical
    });

    report
}
