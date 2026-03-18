"""
Comprehensive non-regression tests for vulnvault/lib/api.py.

Private methods on NVDFetch use Python name mangling:
    __method_name  →  _NVDFetch__method_name
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import responses
from requests import HTTPError, Response, PreparedRequest

from vulnvault.lib.api import (
    NVDFetch,
    NVDParallelAPICaller,
    CPEComponents,
    cve_str,
    cpe_str,
    stringify_results,
    DATETIME_FORMAT,
)
from vulnvault.lib.config import VaultConfig


# ===================================================================
# cve_str
# ===================================================================

class TestCveStr:
    def test_full_doc_output(self, sample_cve_doc):
        result = cve_str(sample_cve_doc)
        assert "[CVE-2024-12345]" in result
        assert "Analyzed" in result
        assert "CWE-120" in result
        assert "vendor@example.com" in result
        assert "https://example.com/advisory/1" in result

    def test_empty_input_returns_empty(self):
        assert cve_str(None) == ""
        assert cve_str({}) == ""

    def test_datetime_formatting(self, sample_cve_doc):
        result = cve_str(sample_cve_doc)
        # 2024-01-15T10:00:00.000 → 01/15/2024 10:00:00
        assert "01/15/2024 10:00:00" in result
        # 2024-02-20T14:30:00.000 → 02/20/2024 14:30:00
        assert "02/20/2024 14:30:00" in result

    def test_description_wrapping(self, sample_cve_doc):
        long_desc = "A " * 80 + "vulnerability."
        doc = {**sample_cve_doc, "description": long_desc}
        result = cve_str(doc)
        # textwrap.wrap defaults to 70-char lines; output should have multiple lines
        desc_section = result.split("Description: ")[1].split("\nCWEs:")[0]
        lines = desc_section.strip().split("\n")
        assert len(lines) > 1

    def test_multiple_references(self, sample_cve_doc):
        result = cve_str(sample_cve_doc)
        assert "vendor@example.com - https://example.com/advisory/1" in result
        assert "cve@mitre.org - https://cve.mitre.org/CVE-2024-12345" in result

    def test_multiple_cwes(self, sample_cve_doc):
        doc = {**sample_cve_doc, "cwes": {"primary": "CWE-120", "secondary": "CWE-79"}}
        result = cve_str(doc)
        assert "CWE-120" in result
        assert "CWE-79" in result


# ===================================================================
# cpe_str
# ===================================================================

class TestCpeStr:
    def test_full_doc_output(self, sample_cpe_doc):
        result = cpe_str(sample_cpe_doc)
        assert "[cpe:2.3:a:cisco:ios:15.0:*:*:*:*:*:*:*]" in result
        assert "ID: abc-123-def" in result
        assert "Title: Cisco IOS 15.0" in result
        assert "Vendor: cisco" in result
        assert "Product: ios" in result
        assert "Version: 15.0" in result

    def test_all_wildcard_fields(self, sample_cpe_doc):
        result = cpe_str(sample_cpe_doc)
        assert "Update: *" in result
        assert "Edition: *" in result
        assert "Language: *" in result
        assert "SW Edition: *" in result
        assert "Target SW: *" in result
        assert "Target HW: *" in result
        assert "Other: *" in result

    def test_datetime_formatting(self, sample_cpe_doc):
        result = cpe_str(sample_cpe_doc)
        assert "01/01/2020 00:00:00" in result
        assert "06/15/2023 12:30:00" in result


# ===================================================================
# stringify_results
# ===================================================================

class TestStringifyResults:
    def test_cve_cursor_dispatch(self, mock_cve_cursor, sample_cve_doc):
        results = list(stringify_results(mock_cve_cursor))
        assert len(results) == 1
        assert "[CVE-2024-12345]" in results[0]

    def test_cpe_cursor_dispatch(self, mock_cpe_cursor, sample_cpe_doc):
        results = list(stringify_results(mock_cpe_cursor))
        assert len(results) == 1
        assert "[cpe:2.3:a:cisco:ios:15.0" in results[0]

    def test_empty_cursor(self):
        cursor = MagicMock()
        cursor.collection.name = "cves"
        cursor.__iter__ = MagicMock(return_value=iter([]))
        assert list(stringify_results(cursor)) == []

    def test_multiple_documents(self, sample_cve_doc):
        doc2 = {**sample_cve_doc, "_id": "CVE-2024-99999"}
        cursor = MagicMock()
        cursor.collection.name = "cves"
        cursor.__iter__ = MagicMock(return_value=iter([sample_cve_doc, doc2]))
        results = list(stringify_results(cursor))
        assert len(results) == 2
        assert "[CVE-2024-12345]" in results[0]
        assert "[CVE-2024-99999]" in results[1]


# ===================================================================
# CPEComponents namedtuple
# ===================================================================

class TestCPEComponents:
    def test_all_13_fields(self):
        parts = ["cpe", "2.3", "a", "cisco", "ios", "15.0",
                 "update1", "ed1", "en", "sw_ed", "tgt_sw", "tgt_hw", "oth"]
        comp = CPEComponents(*parts)
        d = comp._asdict()
        assert len(d) == 13
        assert d["vendor"] == "cisco"
        assert d["product"] == "ios"
        assert d["version"] == "15.0"
        assert d["other"] == "oth"

    def test_defaults_for_last_7_fields(self):
        comp = CPEComponents("cpe", "2.3", "a", "cisco", "ios", "15.0")
        assert comp.update == "*"
        assert comp.edition == "*"
        assert comp.language == "*"
        assert comp.sw_edition == "*"
        assert comp.target_sw == "*"
        assert comp.target_hw == "*"
        assert comp.other == "*"


# ===================================================================
# NVDFetch.__prep_params
# ===================================================================

class TestPrepParams:
    def test_snake_to_camel_conversion(self):
        result = NVDFetch._NVDFetch__prep_params(10000, {"cpe_name": "foo"})
        assert "cpeName" in result
        assert result["cpeName"] == "foo"

    def test_default_start_index(self):
        result = NVDFetch._NVDFetch__prep_params(10000, {})
        assert result["startIndex"] == "0"

    def test_default_results_per_page(self):
        result = NVDFetch._NVDFetch__prep_params(10000, {})
        assert result["resultsPerPage"] == "10000"

    def test_explicit_start_index_preserved(self):
        result = NVDFetch._NVDFetch__prep_params(10000, {"start_index": 500})
        assert result["startIndex"] == "500"

    def test_explicit_results_per_page_preserved(self):
        result = NVDFetch._NVDFetch__prep_params(10000, {"results_per_page": 100})
        assert result["resultsPerPage"] == "100"

    def test_values_are_stringified(self):
        result = NVDFetch._NVDFetch__prep_params(10000, {"some_int": 42})
        assert result["someInt"] == "42"

    def test_empty_kwargs(self):
        result = NVDFetch._NVDFetch__prep_params(500, {})
        assert result == {"startIndex": "0", "resultsPerPage": "500"}


# ===================================================================
# NVDFetch.__serialize_cpes
# ===================================================================

class TestSerializeCpes:
    def test_basic_serialization(self, raw_nvd_cpe_response):
        result = NVDFetch._NVDFetch__serialize_cpes(raw_nvd_cpe_response["products"])
        assert len(result) == 2

        cpe0 = result[0]
        assert cpe0["_id"] == "abc-123-def"
        assert cpe0["title"] == "Cisco IOS 15.0"
        assert cpe0["vendor"] == "cisco"
        assert cpe0["product"] == "ios"
        assert cpe0["version"] == "15.0"
        assert cpe0["part"] == "a"
        # snake_case keys
        assert "last_modified" in cpe0
        assert "lastModified" not in cpe0

    def test_second_cpe(self, raw_nvd_cpe_response):
        result = NVDFetch._NVDFetch__serialize_cpes(raw_nvd_cpe_response["products"])
        cpe1 = result[1]
        assert cpe1["_id"] == "xyz-789-uvw"
        assert cpe1["vendor"] == "microsoft"
        assert cpe1["product"] == "windows_10"
        assert cpe1["version"] == "1903"
        assert cpe1["part"] == "o"

    def test_cpe_name_id_and_titles_excluded(self, raw_nvd_cpe_response):
        result = NVDFetch._NVDFetch__serialize_cpes(raw_nvd_cpe_response["products"])
        for cpe in result:
            assert "cpe_name_id" not in cpe
            assert "cpeNameId" not in cpe
            assert "titles" not in cpe

    def test_escaped_colons_in_version(self, raw_nvd_cpe_escaped_colon):
        result = NVDFetch._NVDFetch__serialize_cpes(
            raw_nvd_cpe_escaped_colon["products"]
        )
        cpe = result[0]
        assert cpe["_id"] == "esc-colon-001"
        # The version field should have unescaped colons
        assert cpe["version"] == "1.0:special"

    def test_non_english_title_fallback(self, raw_nvd_cpe_non_english_only):
        result = NVDFetch._NVDFetch__serialize_cpes(
            raw_nvd_cpe_non_english_only["products"]
        )
        assert result[0]["title"] == ""

    def test_wildcard_defaults(self, raw_nvd_cpe_response):
        result = NVDFetch._NVDFetch__serialize_cpes(raw_nvd_cpe_response["products"])
        cpe0 = result[0]
        for field in ("update", "edition", "language", "sw_edition",
                      "target_sw", "target_hw", "other"):
            assert cpe0[field] == "*"

    def test_cpe_and_cpe_version_excluded(self, raw_nvd_cpe_response):
        result = NVDFetch._NVDFetch__serialize_cpes(raw_nvd_cpe_response["products"])
        for cpe in result:
            # "cpe" and "cpe_version" from CPEComponents should be filtered out
            assert "cpe_version" not in cpe


# ===================================================================
# NVDFetch.__serialize_cves
# ===================================================================

class TestSerializeCves:
    def test_basic_serialization(self, raw_nvd_cve_response):
        result = NVDFetch._NVDFetch__serialize_cves(
            raw_nvd_cve_response["vulnerabilities"]
        )
        assert len(result) == 1
        cve = result[0]
        assert cve["_id"] == "CVE-2024-12345"
        assert cve["status"] == "Analyzed"
        assert cve["published"] == "2024-01-15T10:00:00.000"
        assert cve["last_modified"] == "2024-02-20T14:30:00.000"

    def test_english_description_selected(self, raw_nvd_cve_response):
        result = NVDFetch._NVDFetch__serialize_cves(
            raw_nvd_cve_response["vulnerabilities"]
        )
        assert result[0]["description"] == "A critical buffer overflow vulnerability."

    def test_no_english_description(self):
        vuln = [{
            "cve": {
                "id": "CVE-2024-00002",
                "vulnStatus": "New",
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-01T00:00:00.000",
                "descriptions": [{"lang": "ja", "value": "Japanese only"}],
            }
        }]
        result = NVDFetch._NVDFetch__serialize_cves(vuln)
        assert result[0]["description"] == ""

    def test_metrics_v31_flattened(self, raw_nvd_cve_response):
        result = NVDFetch._NVDFetch__serialize_cves(
            raw_nvd_cve_response["vulnerabilities"]
        )
        cve = result[0]
        assert cve["metrics_v31"] is not None
        primary = cve["metrics_v31"]["primary"]
        assert primary["base_score"] == 9.8
        assert primary["base_severity"] == "CRITICAL"
        assert primary["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        # "version" from cvssData should be excluded
        assert "version" not in primary

    def test_all_metrics_versions(self, raw_nvd_cve_all_metrics):
        result = NVDFetch._NVDFetch__serialize_cves(
            raw_nvd_cve_all_metrics["vulnerabilities"]
        )
        cve = result[0]
        assert cve["metrics_v20"] is not None
        assert cve["metrics_v30"] is not None
        assert cve["metrics_v31"] is not None
        assert cve["metrics_v40"] is not None

    def test_multiple_metrics_ordinal_keys(self, raw_nvd_cve_all_metrics):
        result = NVDFetch._NVDFetch__serialize_cves(
            raw_nvd_cve_all_metrics["vulnerabilities"]
        )
        cve = result[0]
        # Each metrics version has 1 entry → "primary"
        assert "primary" in cve["metrics_v31"]

    def test_multiple_cwes_ordinal_keys(self, raw_nvd_cve_all_metrics):
        result = NVDFetch._NVDFetch__serialize_cves(
            raw_nvd_cve_all_metrics["vulnerabilities"]
        )
        cwes = result[0]["cwes"]
        assert cwes["primary"] == "CWE-79"
        assert cwes["secondary"] == "CWE-89"

    def test_minimal_cve_no_optional_fields(self, raw_nvd_cve_minimal):
        result = NVDFetch._NVDFetch__serialize_cves(
            raw_nvd_cve_minimal["vulnerabilities"]
        )
        cve = result[0]
        assert cve["_id"] == "CVE-2024-00001"
        assert cve["description"] == "Minimal CVE for testing."
        assert cve["metrics_v20"] is None
        assert cve["metrics_v30"] is None
        assert cve["metrics_v31"] is None
        assert cve["metrics_v40"] is None
        assert cve["cwes"] is None
        assert cve["configurations"] is None

    def test_cvss_flatten_excludes_type(self, raw_nvd_cve_response):
        result = NVDFetch._NVDFetch__serialize_cves(
            raw_nvd_cve_response["vulnerabilities"]
        )
        primary = result[0]["metrics_v31"]["primary"]
        assert "type" not in primary

    def test_cvss_keys_are_snake_case(self, raw_nvd_cve_response):
        result = NVDFetch._NVDFetch__serialize_cves(
            raw_nvd_cve_response["vulnerabilities"]
        )
        primary = result[0]["metrics_v31"]["primary"]
        assert "exploitability_score" in primary
        assert "impact_score" in primary
        assert "exploitabilityScore" not in primary


# ===================================================================
# NVDFetch.__serialize_cpe_matches
# ===================================================================

class TestSerializeCpeMatches:
    def test_basic_serialization(self, raw_nvd_cpe_match_response):
        result = NVDFetch._NVDFetch__serialize_cpe_matches(
            raw_nvd_cpe_match_response["matchStrings"]
        )
        assert len(result) == 1
        match = result[0]
        assert match["_id"] == "match-criteria-001"
        assert match["matches"] == ["abc-123-def", "xyz-789-uvw"]

    def test_keys_are_snake_case(self, raw_nvd_cpe_match_response):
        result = NVDFetch._NVDFetch__serialize_cpe_matches(
            raw_nvd_cpe_match_response["matchStrings"]
        )
        match = result[0]
        assert "last_modified" in match
        assert "cpe_last_modified" in match
        assert "lastModified" not in match

    def test_no_matches_key(self):
        data = [{
            "matchString": {
                "matchCriteriaId": "no-match-001",
                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
            }
        }]
        result = NVDFetch._NVDFetch__serialize_cpe_matches(data)
        assert result[0]["_id"] == "no-match-001"
        assert "matches" not in result[0]

    def test_empty_matches_list(self):
        data = [{
            "matchString": {
                "matchCriteriaId": "empty-match-001",
                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                "matches": [],
            }
        }]
        result = NVDFetch._NVDFetch__serialize_cpe_matches(data)
        # empty list is falsy, so matches key stays as []
        assert result[0]["matches"] == []


# ===================================================================
# NVDFetch.__ensure_connection
# ===================================================================

class TestEnsureConnection:
    def test_success_no_retry(self, nvd_fetch):
        mock_resp = MagicMock(spec=Response)
        mock_resp.request = MagicMock(spec=PreparedRequest)
        mock_resp.raise_for_status = MagicMock()  # no exception
        result = nvd_fetch._NVDFetch__ensure_connection(mock_resp)
        assert result is mock_resp

    @patch("vulnvault.lib.api.sleep")
    @patch("vulnvault.lib.api.Session")
    def test_retry_then_success(self, mock_session_cls, mock_sleep, nvd_fetch):
        # First response fails, second succeeds
        failing_resp = MagicMock(spec=Response)
        failing_resp.raise_for_status.side_effect = HTTPError()
        failing_resp.headers = {}
        failing_resp.request = MagicMock(spec=PreparedRequest)

        success_resp = MagicMock(spec=Response)
        success_resp.raise_for_status = MagicMock()

        mock_session = MagicMock()
        mock_session.send.return_value = success_resp
        mock_session_cls.return_value = mock_session

        result = nvd_fetch._NVDFetch__ensure_connection(failing_resp)
        assert result is success_resp
        mock_session.close.assert_called_once()

    @patch("vulnvault.lib.api.sleep")
    @patch("vulnvault.lib.api.Session")
    def test_exhausted_retries_raises(self, mock_session_cls, mock_sleep, nvd_fetch):
        failing_resp = MagicMock(spec=Response)
        failing_resp.raise_for_status.side_effect = HTTPError()
        failing_resp.headers = {}
        failing_resp.request = MagicMock(spec=PreparedRequest)

        retry_resp = MagicMock(spec=Response)
        retry_resp.raise_for_status.side_effect = HTTPError()
        retry_resp.headers = {}

        mock_session = MagicMock()
        mock_session.send.return_value = retry_resp
        mock_session_cls.return_value = mock_session

        with pytest.raises(HTTPError):
            nvd_fetch._NVDFetch__ensure_connection(failing_resp)

    @patch("vulnvault.lib.api.sleep")
    @patch("vulnvault.lib.api.Session")
    def test_exponential_backoff_delays(self, mock_session_cls, mock_sleep, nvd_fetch):
        # Default: retry_delay=10, retry_mult=3, retries=3
        failing_resp = MagicMock(spec=Response)
        failing_resp.raise_for_status.side_effect = HTTPError()
        failing_resp.headers = {}
        failing_resp.request = MagicMock(spec=PreparedRequest)

        # Each retry response also fails
        retry_resp = MagicMock(spec=Response)
        retry_resp.raise_for_status.side_effect = HTTPError()
        retry_resp.headers = {}

        mock_session = MagicMock()
        mock_session.send.return_value = retry_resp
        mock_session_cls.return_value = mock_session

        with pytest.raises(HTTPError):
            nvd_fetch._NVDFetch__ensure_connection(failing_resp)

        # delay starts at 10, first multiply: 10*3=30, second multiply: 30*3=90
        sleep_calls = [call.args[0] for call in mock_sleep.call_args_list]
        assert sleep_calls == [30, 90]


# ===================================================================
# NVDFetch.__init__
# ===================================================================

class TestNVDFetchInit:
    def test_fetch_limits(self, nvd_fetch):
        assert nvd_fetch.cves_fetch_limit == 2000
        assert nvd_fetch.cpes_fetch_limit == 10000
        assert nvd_fetch.cpe_mc_fetch_limit == 500
        assert nvd_fetch.cve_ch_fetch_limit == 5000

    def test_delay_with_api_key(self, vault_config):
        # Default config has an api_key set
        fetch = NVDFetch(vault_config)
        assert fetch.fetch_delay == pytest.approx(30 / 50)

    def test_delay_without_api_key(self, vault_config_no_api_key):
        fetch = NVDFetch(vault_config_no_api_key)
        assert fetch.fetch_delay == pytest.approx(30 / 5)

    def test_retry_config(self, nvd_fetch):
        assert nvd_fetch.retries == 3
        assert nvd_fetch.retry_delay == 10
        assert nvd_fetch.retry_mult == 3

    def test_fetch_threads(self, nvd_fetch):
        assert nvd_fetch.fetch_threads == 3

    def test_partials_have_correct_urls(self, nvd_fetch):
        cves_partial = nvd_fetch._NVDFetch__cves
        cpes_partial = nvd_fetch._NVDFetch__cpes
        cpe_mc_partial = nvd_fetch._NVDFetch__cpe_mc

        assert "cves/2.0" in cves_partial.args[0]
        assert "cpes/2.0" in cpes_partial.args[0]
        assert "cpematch/2.0" in cpe_mc_partial.args[0]


# ===================================================================
# NVDParallelAPICaller
# ===================================================================

class TestNVDParallelAPICaller:
    def test_single_page_no_extra_calls(self, make_paginated_response):
        resp = make_paginated_response("items", 50, 30)
        mock_api = MagicMock(return_value=resp)
        mock_progress = MagicMock()

        caller = NVDParallelAPICaller(
            delay=0.0,
            progress_callback=mock_progress,
            api_call=mock_api,
            params={"startIndex": "0", "resultsPerPage": "50"},
            data_key="items",
            max_workers=2,
        )
        assert len(caller.calls) == 0
        assert len(caller.results) == 30

    def test_multi_page_pagination(self, make_paginated_response):
        resp = make_paginated_response("items", 50, 150)
        mock_api = MagicMock(return_value=resp)
        mock_progress = MagicMock()

        caller = NVDParallelAPICaller(
            delay=0.0,
            progress_callback=mock_progress,
            api_call=mock_api,
            params={"startIndex": "0", "resultsPerPage": "50"},
            data_key="items",
            max_workers=2,
        )
        # 150 total, 50 per page → additional calls at index 50 and 100
        assert len(caller.calls) == 2
        assert caller.total_calls == 2

    def test_initial_results_stored(self, make_paginated_response):
        resp = make_paginated_response("items", 50, 150)
        mock_api = MagicMock(return_value=resp)
        mock_progress = MagicMock()

        caller = NVDParallelAPICaller(
            delay=0.0,
            progress_callback=mock_progress,
            api_call=mock_api,
            params={"startIndex": "0", "resultsPerPage": "50"},
            data_key="items",
            max_workers=2,
        )
        # First page (50 items) should already be in results
        assert len(caller.results) == 50

    def test_exact_page_boundary(self, make_paginated_response):
        resp = make_paginated_response("items", 50, 100)
        mock_api = MagicMock(return_value=resp)
        mock_progress = MagicMock()

        caller = NVDParallelAPICaller(
            delay=0.0,
            progress_callback=mock_progress,
            api_call=mock_api,
            params={"startIndex": "0", "resultsPerPage": "50"},
            data_key="items",
            max_workers=2,
        )
        # 100 total, 50 per page → one additional call at index 50
        assert len(caller.calls) == 1

    def test_run_aggregates_all_results(self):
        page1 = {
            "resultsPerPage": 2,
            "startIndex": 0,
            "totalResults": 4,
            "items": [{"id": "a"}, {"id": "b"}],
        }
        page2 = {
            "resultsPerPage": 2,
            "startIndex": 2,
            "totalResults": 4,
            "items": [{"id": "c"}, {"id": "d"}],
        }

        call_count = [0]

        def mock_api(params):
            call_count[0] += 1
            if call_count[0] == 1:
                return page1
            return page2

        caller = NVDParallelAPICaller(
            delay=0.0,
            progress_callback=MagicMock(),
            api_call=mock_api,
            params={"startIndex": "0", "resultsPerPage": "2"},
            data_key="items",
            max_workers=1,
        )
        results = caller.run()
        ids = {r["id"] for r in results}
        assert ids == {"a", "b", "c", "d"}

    def test_run_single_page_returns_initial(self):
        resp = {
            "resultsPerPage": 10,
            "startIndex": 0,
            "totalResults": 3,
            "items": [{"id": "x"}, {"id": "y"}, {"id": "z"}],
        }
        caller = NVDParallelAPICaller(
            delay=0.0,
            progress_callback=MagicMock(),
            api_call=MagicMock(return_value=resp),
            params={"startIndex": "0", "resultsPerPage": "10"},
            data_key="items",
            max_workers=1,
        )
        results = caller.run()
        assert len(results) == 3

    def test_progress_callback_invoked(self):
        page1 = {
            "resultsPerPage": 2,
            "startIndex": 0,
            "totalResults": 4,
            "items": [{"id": "a"}, {"id": "b"}],
        }
        page2 = {
            "resultsPerPage": 2,
            "startIndex": 2,
            "totalResults": 4,
            "items": [{"id": "c"}, {"id": "d"}],
        }

        call_count = [0]

        def mock_api(params):
            call_count[0] += 1
            if call_count[0] == 1:
                return page1
            return page2

        mock_progress = MagicMock()
        caller = NVDParallelAPICaller(
            delay=0.0,
            progress_callback=mock_progress,
            api_call=mock_api,
            params={"startIndex": "0", "resultsPerPage": "2"},
            data_key="items",
            max_workers=1,
        )
        caller.run()
        mock_progress.assert_called_with(1, 1)

class TestFetchIntegration:
    @responses.activate
    def test_fetch_cpes_end_to_end(self, nvd_fetch, raw_nvd_cpe_response):
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cpes/2.0",
            json=raw_nvd_cpe_response,
            status=200,
        )
        result = nvd_fetch.fetch_cpes()
        assert len(result) == 2
        assert result[0]["_id"] == "abc-123-def"
        assert result[0]["vendor"] == "cisco"
        assert result[1]["_id"] == "xyz-789-uvw"

    @responses.activate
    def test_fetch_cves_end_to_end(self, nvd_fetch, raw_nvd_cve_response):
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json=raw_nvd_cve_response,
            status=200,
        )
        result = nvd_fetch.fetch_cves()
        assert len(result) == 1
        assert result[0]["_id"] == "CVE-2024-12345"
        assert result[0]["status"] == "Analyzed"

    @responses.activate
    def test_fetch_cpe_matches_end_to_end(self, nvd_fetch, raw_nvd_cpe_match_response):
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cpematch/2.0",
            json=raw_nvd_cpe_match_response,
            status=200,
        )
        result = nvd_fetch.fetch_cpe_matches()
        assert len(result) == 1
        assert result[0]["_id"] == "match-criteria-001"
        assert result[0]["matches"] == ["abc-123-def", "xyz-789-uvw"]

    @responses.activate
    def test_fetch_cves_passes_kwargs(self, nvd_fetch, raw_nvd_cve_response):
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json=raw_nvd_cve_response,
            status=200,
        )
        nvd_fetch.fetch_cves(keyword_search="buffer overflow")
        # Verify the request was made with camelCase params
        assert "keywordSearch=buffer+overflow" in responses.calls[0].request.url

    @responses.activate
    def test_fetch_cpes_pagination(self, nvd_fetch):
        page1 = {
            "resultsPerPage": 2,
            "startIndex": 0,
            "totalResults": 4,
            "products": [
                {
                    "cpe": {
                        "cpeNameId": "id-1",
                        "cpeName": "cpe:2.3:a:v1:p1:1.0:*:*:*:*:*:*:*",
                        "titles": [{"title": "Product 1", "lang": "en"}],
                        "created": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-01T00:00:00.000",
                        "deprecated": False,
                    }
                },
                {
                    "cpe": {
                        "cpeNameId": "id-2",
                        "cpeName": "cpe:2.3:a:v2:p2:2.0:*:*:*:*:*:*:*",
                        "titles": [{"title": "Product 2", "lang": "en"}],
                        "created": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-01T00:00:00.000",
                        "deprecated": False,
                    }
                },
            ],
        }
        page2 = {
            "resultsPerPage": 2,
            "startIndex": 2,
            "totalResults": 4,
            "products": [
                {
                    "cpe": {
                        "cpeNameId": "id-3",
                        "cpeName": "cpe:2.3:a:v3:p3:3.0:*:*:*:*:*:*:*",
                        "titles": [{"title": "Product 3", "lang": "en"}],
                        "created": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-01T00:00:00.000",
                        "deprecated": False,
                    }
                },
                {
                    "cpe": {
                        "cpeNameId": "id-4",
                        "cpeName": "cpe:2.3:a:v4:p4:4.0:*:*:*:*:*:*:*",
                        "titles": [{"title": "Product 4", "lang": "en"}],
                        "created": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-01T00:00:00.000",
                        "deprecated": False,
                    }
                },
            ],
        }
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cpes/2.0",
            json=page1,
            status=200,
        )
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cpes/2.0",
            json=page2,
            status=200,
        )
        result = nvd_fetch.fetch_cpes()
        ids = {cpe["_id"] for cpe in result}
        assert ids == {"id-1", "id-2", "id-3", "id-4"}
