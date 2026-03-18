"""Shared fixtures for VulnVault test suite."""
import pytest
from unittest.mock import MagicMock

from pymongo.cursor import Cursor

from vulnvault.lib.config import VaultConfig
from vulnvault.lib.api import NVDFetch


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@pytest.fixture
def vault_config():
    """VaultConfig with all defaults and a dummy API key."""
    cfg = VaultConfig(config_path="/nonexistent/path/config.json")
    cfg.api_key = "test-api-key"
    return cfg


@pytest.fixture
def vault_config_no_api_key():
    """VaultConfig with empty API key to test non-API rate limits."""
    cfg = VaultConfig(config_path="/nonexistent/path/config.json")
    cfg.api_key = ""
    return cfg


@pytest.fixture
def nvd_fetch(vault_config):
    """NVDFetch instance from default config."""
    return NVDFetch(vault_config)


# ---------------------------------------------------------------------------
# Raw NVD API responses — CPE
# ---------------------------------------------------------------------------

@pytest.fixture
def raw_nvd_cpe_response():
    """Single-page NVD CPE API response with 2 products."""
    return {
        "resultsPerPage": 2,
        "startIndex": 0,
        "totalResults": 2,
        "products": [
            {
                "cpe": {
                    "cpeNameId": "abc-123-def",
                    "cpeName": "cpe:2.3:a:cisco:ios:15.0:*:*:*:*:*:*:*",
                    "titles": [
                        {"title": "Cisco IOS 15.0", "lang": "en"},
                        {"title": "Cisco IOS 15.0 JP", "lang": "ja"},
                    ],
                    "created": "2020-01-01T00:00:00.000",
                    "lastModified": "2023-06-15T12:30:00.000",
                    "deprecated": False,
                }
            },
            {
                "cpe": {
                    "cpeNameId": "xyz-789-uvw",
                    "cpeName": "cpe:2.3:o:microsoft:windows_10:1903:*:*:*:*:*:*:*",
                    "titles": [
                        {"title": "Microsoft Windows 10 1903", "lang": "en"},
                    ],
                    "created": "2019-05-21T00:00:00.000",
                    "lastModified": "2024-01-10T08:00:00.000",
                    "deprecated": False,
                }
            },
        ],
    }


@pytest.fixture
def raw_nvd_cpe_escaped_colon():
    """CPE whose cpeName contains escaped colons in the version field."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "products": [
            {
                "cpe": {
                    "cpeNameId": "esc-colon-001",
                    "cpeName": "cpe:2.3:a:vendor:product:1.0\\:special:*:*:*:*:*:*:*",
                    "titles": [{"title": "Escaped Colon Product", "lang": "en"}],
                    "created": "2021-03-01T00:00:00.000",
                    "lastModified": "2021-03-01T00:00:00.000",
                    "deprecated": False,
                }
            }
        ],
    }


@pytest.fixture
def raw_nvd_cpe_non_english_only():
    """CPE with only non-English titles."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "products": [
            {
                "cpe": {
                    "cpeNameId": "non-en-001",
                    "cpeName": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                    "titles": [
                        {"title": "Produit Exemple", "lang": "fr"},
                    ],
                    "created": "2022-01-01T00:00:00.000",
                    "lastModified": "2022-01-01T00:00:00.000",
                    "deprecated": False,
                }
            }
        ],
    }


# ---------------------------------------------------------------------------
# Raw NVD API responses — CVE
# ---------------------------------------------------------------------------

@pytest.fixture
def raw_nvd_cve_response():
    """Single-page NVD CVE API response with full metrics."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-12345",
                    "vulnStatus": "Analyzed",
                    "published": "2024-01-15T10:00:00.000",
                    "lastModified": "2024-02-20T14:30:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "A critical buffer overflow vulnerability."},
                        {"lang": "es", "value": "Una vulnerabilidad critica de desbordamiento."},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "exploitabilityScore": 3.9,
                                "impactScore": 5.9,
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "description": [
                                {"lang": "en", "value": "CWE-120"},
                            ],
                        }
                    ],
                    "references": [
                        {"source": "vendor@example.com", "url": "https://example.com/advisory/1"},
                        {"source": "vendor@example.com", "url": "https://example.com/advisory/2"},
                        {"source": "cve@mitre.org", "url": "https://cve.mitre.org/CVE-2024-12345"},
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "negate": False,
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "match-001",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            }
        ],
    }


@pytest.fixture
def raw_nvd_cve_minimal():
    """CVE with no optional fields (no metrics, weaknesses, references, configurations)."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-00001",
                    "vulnStatus": "Awaiting Analysis",
                    "published": "2024-06-01T00:00:00.000",
                    "lastModified": "2024-06-01T00:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Minimal CVE for testing."},
                    ],
                }
            }
        ],
    }


@pytest.fixture
def raw_nvd_cve_all_metrics():
    """CVE with all four CVSS metric versions present."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-99999",
                    "vulnStatus": "Analyzed",
                    "published": "2024-01-01T00:00:00.000",
                    "lastModified": "2024-01-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Test CVE with all metrics."}],
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "exploitabilityScore": 10.0,
                                "impactScore": 6.4,
                                "cvssData": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                    "baseScore": 7.5,
                                },
                            }
                        ],
                        "cvssMetricV30": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "exploitabilityScore": 3.9,
                                "impactScore": 5.9,
                                "cvssData": {
                                    "version": "3.0",
                                    "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ],
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "exploitabilityScore": 3.9,
                                "impactScore": 5.9,
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ],
                        "cvssMetricV40": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "exploitabilityScore": 3.9,
                                "impactScore": 5.9,
                                "cvssData": {
                                    "version": "4.0",
                                    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                                    "baseScore": 9.3,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ],
                    },
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "description": [{"lang": "en", "value": "CWE-79"}],
                        },
                        {
                            "source": "other@nist.gov",
                            "description": [{"lang": "en", "value": "CWE-89"}],
                        },
                    ],
                    "references": [
                        {"source": "vendor@example.com", "url": "https://example.com/1"},
                    ],
                    "configurations": [],
                }
            }
        ],
    }


# ---------------------------------------------------------------------------
# Raw NVD API responses — CPE Match
# ---------------------------------------------------------------------------

@pytest.fixture
def raw_nvd_cpe_match_response():
    """Single-page NVD CPE Match API response."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "matchStrings": [
            {
                "matchString": {
                    "matchCriteriaId": "match-criteria-001",
                    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                    "status": "Active",
                    "lastModified": "2024-01-01T00:00:00.000",
                    "cpeLastModified": "2024-01-01T00:00:00.000",
                    "matches": [
                        {"cpeNameId": "abc-123-def"},
                        {"cpeNameId": "xyz-789-uvw"},
                    ],
                }
            }
        ],
    }


# ---------------------------------------------------------------------------
# Pre-serialized MongoDB documents (for cve_str / cpe_str tests)
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_cve_doc():
    """CVESchema-conformant dict as stored in MongoDB."""
    return {
        "_id": "CVE-2024-12345",
        "description": "A critical buffer overflow vulnerability in the example product.",
        "published": "2024-01-15T10:00:00.000",
        "last_modified": "2024-02-20T14:30:00.000",
        "status": "Analyzed",
        "metrics_v20": None,
        "metrics_v30": None,
        "metrics_v31": {"primary": {"base_score": 9.8, "base_severity": "CRITICAL"}},
        "metrics_v40": None,
        "configurations": [],
        "references": [
            {"source": "vendor@example.com", "url": "https://example.com/advisory/1"},
            {"source": "cve@mitre.org", "url": "https://cve.mitre.org/CVE-2024-12345"},
        ],
        "cwes": {"primary": "CWE-120"},
    }


@pytest.fixture
def sample_cpe_doc():
    """CPESchema-conformant dict as stored in MongoDB."""
    return {
        "_id": "abc-123-def",
        "cpe_name": "cpe:2.3:a:cisco:ios:15.0:*:*:*:*:*:*:*",
        "title": "Cisco IOS 15.0",
        "created": "2020-01-01T00:00:00.000",
        "last_modified": "2023-06-15T12:30:00.000",
        "deprecated": False,
        "part": "a",
        "vendor": "cisco",
        "product": "ios",
        "version": "15.0",
        "update": "*",
        "edition": "*",
        "language": "*",
        "sw_edition": "*",
        "target_sw": "*",
        "target_hw": "*",
        "other": "*",
    }


# ---------------------------------------------------------------------------
# Mock pymongo cursors for stringify_results
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_cve_cursor(sample_cve_doc):
    """Mock Cursor over CVE documents."""
    cursor = MagicMock(spec=Cursor)
    cursor.collection.name = "cves"
    cursor.__iter__ = MagicMock(return_value=iter([sample_cve_doc]))
    return cursor


@pytest.fixture
def mock_cpe_cursor(sample_cpe_doc):
    """Mock Cursor over CPE documents."""
    cursor = MagicMock(spec=Cursor)
    cursor.collection.name = "cpes"
    cursor.__iter__ = MagicMock(return_value=iter([sample_cpe_doc]))
    return cursor


# ---------------------------------------------------------------------------
# Pagination factory
# ---------------------------------------------------------------------------

@pytest.fixture
def make_paginated_response():
    """Factory to create paginated NVD API responses."""
    def _make(data_key, items_per_page, total_items, page_index=0):
        count = min(items_per_page, max(0, total_items - page_index))
        return {
            "resultsPerPage": items_per_page,
            "startIndex": page_index,
            "totalResults": total_items,
            data_key: [{"id": f"item-{page_index + i}"} for i in range(count)],
        }
    return _make
