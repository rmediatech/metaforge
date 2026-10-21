pub mod chi_square;
pub mod entropy;
pub mod overlay;
pub mod signatures;
pub mod steganalysis;

pub use chi_square::{
    approximate_chi_square_p_value, calculate_ascii_ratio, calculate_chi_square_uniformity,
    calculate_pov_chi_square, extract_entropy_continuum, CHI_SQUARE_CRITICAL_DF255_A01,
    CHI_SQUARE_CRITICAL_DF255_A05,
};
pub use entropy::{calculate_shannon_entropy, is_suspicious_entropy};
pub use overlay::{detect_overlay, OverlayInfo};
pub use signatures::{scan_embedded_payloads, EmbeddedPayload};
pub use steganalysis::{
    analyze_app_segment, analyze_comment_segment, analyze_jpeg_steganography, analyze_scan_data,
    FindingSeverity, StegFindingType, SteganalysisFinding, SteganalysisReport,
};
