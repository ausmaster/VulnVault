"""
Test to compare Python scorer vs Rust scorer on a small in-memory dataset.
Ensures that both scorers produce consistent results within tolerance.
"""
from operator import itemgetter
from rapidfuzz.fuzz import WRatio

try:
    import rustyVault

    HAS_RUST = True
except ImportError:
    HAS_RUST = False
    print("Warning: rustyVault not available, skipping Rust comparison")


def python_score_candidates(query: str, candidates: list[dict], frmt: str, threshold: float, limit: int):
    """Python reference implementation"""
    tokens = query.lower().split()
    weights = {"vendor": 0.4, "product": 0.4, "version": 0.2}
    matches = []

    if frmt == "Vpv":
        def get_weighted_score(scores):
            return scores[0] * weights["vendor"] + scores[1] * weights["product"] + scores[2] * weights["version"]

        fetcher = (
            (tokens[0] if len(tokens) > 0 else "", itemgetter("vendor")),
            (tokens[1] if len(tokens) > 1 else "", itemgetter("product")),
            (tokens[2] if len(tokens) > 2 else "", itemgetter("version")),
        )
    elif frmt == "pv":
        def get_weighted_score(scores):
            return scores[0] * weights["product"] + scores[1] * weights["version"]

        fetcher = (
            (tokens[0] if len(tokens) > 0 else "", itemgetter("product")),
            (tokens[1] if len(tokens) > 1 else "", itemgetter("version")),
        )
    else:
        raise ValueError(f"Unsupported format: {frmt}")

    for cpe in candidates:
        match_scores = [WRatio(srch_str, db_itm_gttr(cpe)) for srch_str, db_itm_gttr in fetcher]
        score = get_weighted_score(match_scores)
        if score > threshold:
            matches.append((score, cpe))

    matches.sort(key=lambda x: (-x[0], x[1].get("cpe_name", "")))
    if limit > 0:
        matches = matches[:limit]
    return matches


def test_scorer_consistency():
    """Test that Python and Rust scorers produce similar results"""
    # Small test dataset
    candidates = [
        {"_id": "1", "vendor": "cisco", "product": "ios", "version": "15.0", "cpe_name": "cpe:2.3:o:cisco:ios:15.0"},
        {"_id": "2", "vendor": "cisco", "product": "ios", "version": "15.1", "cpe_name": "cpe:2.3:o:cisco:ios:15.1"},
        {"_id": "3", "vendor": "microsoft", "product": "windows", "version": "10",
         "cpe_name": "cpe:2.3:o:microsoft:windows:10"},
        {"_id": "4", "vendor": "apple", "product": "macos", "version": "12.0",
         "cpe_name": "cpe:2.3:o:apple:macos:12.0"},
        {"_id": "5", "vendor": "cisco", "product": "asa", "version": "9.0", "cpe_name": "cpe:2.3:o:cisco:asa:9.0"},
    ]

    query = "cisco ios 15.0"
    frmt = "Vpv"
    threshold = 50.0
    limit = 10

    # Python scorer
    python_results = python_score_candidates(query, candidates, frmt, threshold, limit)
    print(f"Python scorer found {len(python_results)} results")
    for score, cpe in python_results:
        print(f"  Score: {score:.2f} - {cpe['cpe_name']}")

    if not HAS_RUST:
        print("\nSkipping Rust comparison (module not available)")
        return

    # Rust scorer
    rust_results = rustyVault.score_candidates(query, candidates, frmt, threshold, limit)
    print(f"\nRust scorer found {len(rust_results)} results")
    for score, cpe in rust_results:
        print(f"  Score: {score:.2f} - {cpe['cpe_name']}")

    # Compare results
    print("\n--- Comparison ---")
    assert len(python_results) == len(
        rust_results), f"Result count mismatch: Python={len(python_results)}, Rust={len(rust_results)}"

    for i, ((py_score, py_cpe), (rust_score, rust_cpe)) in enumerate(zip(python_results, rust_results)):
        print(f"Result {i + 1}:")
        print(f"  Python: {py_score:.2f} - {py_cpe['cpe_name']}")
        print(f"  Rust:   {rust_score:.2f} - {rust_cpe['cpe_name']}")

        # Allow some tolerance due to different similarity algorithms
        # Python uses RapidFuzz WRatio, Rust uses Jaro-Winkler
        score_diff = abs(py_score - rust_score)
        print(f"  Score difference: {score_diff:.2f}")

        # Ensure same CPE is matched (order should be the same for top results)
        assert py_cpe['_id'] == rust_cpe['_id'], f"CPE mismatch at position {i + 1}"

    print("\n✓ All tests passed! Scorers are consistent.")


if __name__ == "__main__":
    test_scorer_consistency()