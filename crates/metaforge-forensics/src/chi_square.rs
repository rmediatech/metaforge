/// Critical value for Chi-Square distribution with df=255 at alpha=0.01 (99% confidence).
pub const CHI_SQUARE_CRITICAL_DF255_A01: f64 = 310.457;

/// Critical value for Chi-Square distribution with df=255 at alpha=0.05 (95% confidence).
pub const CHI_SQUARE_CRITICAL_DF255_A05: f64 = 293.248;

/// Extracts the raw entropy-coded scan data stream following the Start of Scan (SOS, 0xFFDA) marker.
///
/// Un-stuffs `0xFF00` sequences (converting them back to a single `0xFF` byte) and consumes
/// restart markers (`0xFFD0` - `0xFFD7`) without adding them to the scan payload.
/// Parsing stops upon encountering the next legitimate structural marker (such as `0xFFD9` EOI).
pub fn extract_entropy_continuum(bytes: &[u8]) -> Vec<u8> {
    let mut scan_data = Vec::new();
    let mut pos = 0;

    while pos + 1 < bytes.len() {
        if bytes[pos] == 0xFF && bytes[pos + 1] == 0xDA {
            pos += 2;
            break;
        }
        pos += 1;
    }

    if pos >= bytes.len() || pos + 2 > bytes.len() {
        return scan_data;
    }

    let header_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += header_len;

    while pos < bytes.len() {
        let b1 = bytes[pos];
        pos += 1;

        if b1 == 0xFF {
            if pos >= bytes.len() {
                scan_data.push(0xFF);
                break;
            }
            let b2 = bytes[pos];
            pos += 1;

            if b2 == 0x00 {
                scan_data.push(0xFF);
            } else if (0xD0..=0xD7).contains(&b2) {
                continue;
            } else {
                break;
            }
        } else {
            scan_data.push(b1);
        }
    }

    scan_data
}

/// Calculates the Chi-Square statistic and approximated p-value against a uniform distribution.
///
/// Degree of freedom = 255 (256 byte values - 1).
/// Uses the Wilson-Hilferty normal approximation of the Chi-Square distribution for high df.
pub fn calculate_chi_square_uniformity(data: &[u8]) -> (f64, usize, f64) {
    if data.is_empty() {
        return (0.0, 255, 1.0);
    }

    let mut observed = [0u64; 256];
    for &b in data {
        observed[b as usize] += 1;
    }

    let total = data.len() as f64;
    let expected = (total / 256.0).max(1.0);

    let mut chi_square = 0.0;
    for &count in &observed {
        let diff = count as f64 - expected;
        chi_square += (diff * diff) / expected;
    }

    let df = 255;
    let p_val = approximate_chi_square_p_value(chi_square, df);
    (chi_square, df, p_val)
}

/// Westfeld-Pfitzmann Pairs-of-Values (PoVs) Chi-Square test for LSB embedding.
///
/// Under natural image compression, frequencies within adjacent pairs (2k, 2k+1) differ.
/// Steganographic LSB replacement equalizes their frequencies, making chi-square drop towards 0.
pub fn calculate_pov_chi_square(data: &[u8]) -> (f64, usize) {
    if data.is_empty() {
        return (0.0, 0);
    }

    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let mut chi_square = 0.0;
    let mut active_pairs: usize = 0;

    for k in 0..128 {
        let n0 = counts[2 * k] as f64;
        let n1 = counts[2 * k + 1] as f64;
        let sum = n0 + n1;
        if sum > 0.0 {
            active_pairs += 1;
            let diff = n0 - n1;
            chi_square += (diff * diff) / (2.0 * sum);
        }
    }

    let df = active_pairs.saturating_sub(1);
    (chi_square, df)
}

/// Computes the ratio of printable graphic/whitespace ASCII characters.
pub fn calculate_ascii_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    printable as f64 / data.len() as f64
}

/// Approximate p-value for large degrees of freedom using the Wilson-Hilferty transformation.
pub fn approximate_chi_square_p_value(chi_sq: f64, df: usize) -> f64 {
    if df == 0 || chi_sq <= 0.0 {
        return 1.0;
    }

    let k = df as f64;
    let term1 = (chi_sq / k).powf(1.0 / 3.0);
    let term2 = 1.0 - (2.0 / (9.0 * k));
    let denominator = (2.0 / (9.0 * k)).sqrt();
    let z = (term1 - term2) / denominator;

    normal_ccdf(z)
}

fn normal_ccdf(z: f64) -> f64 {
    if z < -8.0 {
        return 1.0;
    }
    if z > 8.0 {
        return 0.0;
    }
    let x = z / std::f64::consts::SQRT_2;
    0.5 * erfc_approx(x)
}

fn erfc_approx(x: f64) -> f64 {
    let t = 1.0 / (1.0 + 0.3275911 * x.abs());
    let poly = t
        * (0.254829592
            + t * (-0.284496736
                + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
    let ans = poly * (-x * x).exp();
    if x >= 0.0 {
        ans
    } else {
        2.0 - ans
    }
}
