use pyo3::prelude::*;
use pyo3::types::PyDict;
use rayon::prelude::*;
use std::cmp::Ordering;

/// Normalize a string for fuzzy matching: lowercase and trim
fn normalize(s: &str) -> String {
    s.to_lowercase().trim().to_string()
}

/// Compute a weighted ratio similarity score (0-100)
/// Using Jaro-Winkler as a fast approximation to RapidFuzz's WRatio
fn weighted_ratio(s1: &str, s2: &str) -> f32 {
    if s1.is_empty() && s2.is_empty() {
        return 100.0;
    }
    if s1.is_empty() || s2.is_empty() {
        return 0.0;
    }

    let norm1 = normalize(s1);
    let norm2 = normalize(s2);

    // Jaro-Winkler similarity (0.0-1.0) scaled to 0-100
    (strsim::jaro_winkler(&norm1, &norm2) * 100.0) as f32
}

/// Score a single candidate against query tokens
fn score_candidate(
    tokens: &[String],
    vendor: &str,
    product: &str,
    version: &str,
    frmt: &str,
) -> f32 {
    match frmt {
        "Vpv" => {
            let v_token = tokens.get(0).map(|s| s.as_str()).unwrap_or("");
            let p_token = tokens.get(1).map(|s| s.as_str()).unwrap_or("");
            let ver_token = tokens.get(2).map(|s| s.as_str()).unwrap_or("");

            let v_score = weighted_ratio(v_token, vendor);
            let p_score = weighted_ratio(p_token, product);
            let ver_score = weighted_ratio(ver_token, version);

            // Weights: vendor=0.4, product=0.4, version=0.2
            v_score * 0.4 + p_score * 0.4 + ver_score * 0.2
        }
        "pv" => {
            let p_token = tokens.get(0).map(|s| s.as_str()).unwrap_or("");
            let ver_token = tokens.get(1).map(|s| s.as_str()).unwrap_or("");

            let p_score = weighted_ratio(p_token, product);
            let ver_score = weighted_ratio(ver_token, version);

            // Weights: product=0.4, version=0.6 (adjusted from 0.4+0.2)
            p_score * 0.4 + ver_score * 0.6
        }
        _ => 0.0,
    }
}

#[pyfunction]
fn hi() -> PyResult<&'static str> {
    Ok("hello from rustyVault (PyO3)!")
}

#[pyfunction]
fn add(a: i64, b: i64) -> PyResult<i64> {
    Ok(a + b)
}

/// Intermediate structure for parallel processing
#[derive(Clone)]
struct CandidateData {
    id: String,
    vendor: String,
    product: String,
    version: String,
    cpe_name: String,
}

/// Score a list of CPE candidates against a query string
///
/// Args:
///     query: Search string (will be tokenized by spaces)
///     candidates: List of dicts with keys: _id, vendor, product, version, cpe_name
///     frmt: Format string - either "Vpv" or "pv"
///     threshold: Minimum score to include (0-100)
///     limit: Maximum number of results to return (-1 for unlimited)
///
/// Returns:
///     List of tuples (score, candidate_dict) sorted by score descending
#[pyfunction]
fn score_candidates<'py>(
    py: Python<'py>,
    query: &str,
    candidates: Vec<Bound<'py, PyDict>>,
    frmt: &str,
    threshold: f32,
    limit: isize,
) -> PyResult<Vec<(f32, PyObject)>> {
    // Tokenize query by whitespace
    let tokens: Vec<String> = query
        .split_whitespace()
        .map(|s| normalize(s))
        .collect();

    // Extract data from Python dicts into Rust structs for parallel processing
    let candidate_data: Vec<CandidateData> = candidates
        .iter()
        .filter_map(|cand| {
            let id = cand.get_item("_id").ok()??.extract::<String>().ok()?;
            let vendor = cand.get_item("vendor").ok()??.extract::<String>().ok()?;
            let product = cand.get_item("product").ok()??.extract::<String>().ok()?;
            let version = cand.get_item("version").ok()??.extract::<String>().ok()?;
            let cpe_name = cand.get_item("cpe_name").ok()??.extract::<String>().ok()?;

            Some(CandidateData { id, vendor, product, version, cpe_name })
        })
        .collect();

    // Parallel scoring with rayon
    let mut scored: Vec<(f32, CandidateData)> = candidate_data
        .par_iter()
        .filter_map(|cand| {
            // Score this candidate
            let score = score_candidate(&tokens, &cand.vendor, &cand.product, &cand.version, frmt);

            if score >= threshold {
                Some((score, cand.clone()))
            } else {
                None
            }
        })
        .collect();

    // Sort by score descending, then by cpe_name for stable ordering
    scored.par_sort_by(|a, b| {
        match b.0.partial_cmp(&a.0) {
            Some(Ordering::Equal) | None => {
                // Tie-break by cpe_name
                a.1.cpe_name.cmp(&b.1.cpe_name)
            }
            Some(ord) => ord,
        }
    });

    // Apply limit
    if limit > 0 {
        scored.truncate(limit as usize);
    }

    // Convert back to Python objects
    let results: Vec<(f32, PyObject)> = scored
        .into_iter()
        .map(|(score, cand)| {
            let dict = PyDict::new_bound(py);
            dict.set_item("_id", cand.id).unwrap();
            dict.set_item("vendor", cand.vendor).unwrap();
            dict.set_item("product", cand.product).unwrap();
            dict.set_item("version", cand.version).unwrap();
            dict.set_item("cpe_name", cand.cpe_name).unwrap();
            (score, dict.into_py(py))
        })
        .collect();

    Ok(results)
}

/// Split CPE name by unescaped colons
///
/// Manually iterate through the string and split on colons that aren't escaped
fn split_cpe_name(cpe_name: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = cpe_name.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() && chars[i + 1] == ':' {
            // Escaped colon - add the colon and skip the backslash
            current.push(':');
            i += 2;
        } else if chars[i] == ':' {
            // Unescaped colon - split here
            parts.push(current.clone());
            current.clear();
            i += 1;
        } else {
            // Regular character
            current.push(chars[i]);
            i += 1;
        }
    }

    // Don't forget the last part
    if !current.is_empty() || !parts.is_empty() {
        parts.push(current);
    }

    parts
}

/// Parse a CPE name string into its components
///
/// Handles escaped colons (\\:) correctly
/// Returns a dict with all CPE components
///
/// Example:
///     "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
///     -> {"cpe": "cpe", "cpe_version": "2.3", "part": "a", "vendor": "vendor", ...}
#[pyfunction]
fn parse_cpe_name<'py>(py: Python<'py>, cpe_name: &str) -> PyResult<Bound<'py, PyDict>> {
    let result = PyDict::new_bound(py);

    // Split by unescaped colons
    let parts = split_cpe_name(cpe_name);

    // CPE 2.3 format has 13 parts total
    // cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    let fields = [
        "cpe", "cpe_version", "part", "vendor", "product", "version",
        "update", "edition", "language", "sw_edition", "target_sw",
        "target_hw", "other"
    ];

    for (i, field) in fields.iter().enumerate() {
        let value = parts.get(i).map(|s| s.as_str()).unwrap_or("*");
        result.set_item(field, value)?;
    }

    Ok(result)
}

/// Batch parse multiple CPE names in parallel
///
/// Args:
///     cpe_names: List of CPE name strings
///
/// Returns:
///     List of dicts, each containing parsed CPE components
#[pyfunction]
fn batch_parse_cpe_names<'py>(
    py: Python<'py>,
    cpe_names: Vec<String>,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let fields = [
        "cpe", "cpe_version", "part", "vendor", "product", "version",
        "update", "edition", "language", "sw_edition", "target_sw",
        "target_hw", "other"
    ];

    // Parse in parallel (only Rust strings, no Python objects)
    let parsed: Vec<Vec<String>> = cpe_names
        .par_iter()
        .map(|cpe_name| split_cpe_name(cpe_name))
        .collect();

    // Convert to Python dicts (must be done in main Python thread)
    let results: Vec<Bound<PyDict>> = parsed
        .into_iter()
        .map(|parts| {
            let dict = PyDict::new_bound(py);
            for (i, field) in fields.iter().enumerate() {
                let value = parts.get(i).map(|s| s.as_str()).unwrap_or("*");
                dict.set_item(field, value).unwrap();
            }
            dict
        })
        .collect();

    Ok(results)
}

/// Build a CPE name string from components
///
/// Args:
///     components: Dict with CPE fields (cpe, cpe_version, part, vendor, etc.)
///
/// Returns:
///     CPE name string with properly escaped colons
#[pyfunction]
fn build_cpe_name(components: &Bound<PyDict>) -> PyResult<String> {
    let fields = [
        "cpe", "cpe_version", "part", "vendor", "product", "version",
        "update", "edition", "language", "sw_edition", "target_sw",
        "target_hw", "other"
    ];

    let parts: Vec<String> = fields
        .iter()
        .map(|field| {
            components
                .get_item(field)
                .ok()
                .flatten()
                .and_then(|v| v.extract::<String>().ok())
                .unwrap_or_else(|| "*".to_string())
                .replace(":", "\\:")  // Escape colons
        })
        .collect();

    Ok(parts.join(":"))
}

#[pymodule]
fn rustyVault(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hi, m)?)?;
    m.add_function(wrap_pyfunction!(add, m)?)?;
    m.add_function(wrap_pyfunction!(score_candidates, m)?)?;
    m.add_function(wrap_pyfunction!(parse_cpe_name, m)?)?;
    m.add_function(wrap_pyfunction!(batch_parse_cpe_names, m)?)?;
    m.add_function(wrap_pyfunction!(build_cpe_name, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize() {
        assert_eq!(normalize("  CISCO  "), "cisco");
        assert_eq!(normalize("IoS"), "ios");
    }

    #[test]
    fn test_weighted_ratio() {
        assert!(weighted_ratio("cisco", "cisco") > 99.0);
        assert!(weighted_ratio("cisco", "Cisco") > 99.0);
        assert!(weighted_ratio("cisco", "cisca") > 80.0);
        assert!(weighted_ratio("", "") == 100.0);
        assert!(weighted_ratio("abc", "") == 0.0);
    }

    #[test]
    fn test_score_candidate_vpv() {
        let tokens = vec!["cisco".to_string(), "ios".to_string(), "15.0".to_string()];
        let score = score_candidate(&tokens, "cisco", "ios", "15.0", "Vpv");
        assert!(score > 99.0);
    }

    #[test]
    fn test_score_candidate_pv() {
        let tokens = vec!["windows".to_string(), "10".to_string()];
        let score = score_candidate(&tokens, "microsoft", "windows", "10", "pv");
        assert!(score > 90.0);
    }
}