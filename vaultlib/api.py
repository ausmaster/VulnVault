from __future__ import annotations

from functools import partial
from time import sleep
from typing import Any

from requests import get, HTTPError, PreparedRequest, Response, Session

from .config import VaultConfig
from .utils import camel_to_snake, snake_to_camel, int_to_ordinal


class NVDFetch:
    def __init__(self, config: VaultConfig) -> None:
        api_key_hdr = {"apiKey": config.api_key}
        self.__cves: partial = partial(get, config.nvd_cve_api, headers=api_key_hdr)
        self.cves_fetch_limit: int = 2_000  # Default and maximum by NVD
        self.__cve_ch: partial = partial(get, config.nvd_cve_ch_api, headers=api_key_hdr)
        self.cve_ch_fetch_limit: int = 5_000  # Default and maximum by NVD
        self.__cpes: partial = partial(get, config.nvd_cpe_api, headers=api_key_hdr)
        self.cpes_fetch_limit: int = 10_000  # Default and maximum by NVD
        self.__cpe_mc: partial = partial(get, config.nvd_cpe_mc_api, headers=api_key_hdr)
        self.cpe_mc_fetch_limit: int = 500  # Default and maximum by NVD
        self.retries: int = config.conn_retries
        self.retry_delay: int = config.conn_retry_delay  # seconds
        self.retry_mult: int = config.conn_retry_delay_mult
        # Non-API limited to 5 req / 30 secs, API get 50 reqs
        self.fetch_delay: float = 30 / 50 if config.api_key else 30 / 5

    @staticmethod
    def prep_params(fetch_limit: int, kwargs: dict[str, Any]) -> dict[str, str]:
        """
        Utility to prepoare the query parameters used in the API fetch.
        Main duty is to convert all kwargs into camelCase for NVD API.

        :param fetch_limit: The specific fetch limit corresponding to the API
        :param kwargs: All query parameters via kwargs
        :return: Dict of each parameter in proper camelCase form for key and string for value
        """
        params = {snake_to_camel(k): str(v) for k, v in kwargs.items()}
        if not params.get("startIndex"):
            params["startIndex"] = "0"
        if not params.get("resultsPerPage"):
            params["resultsPerPage"] = str(fetch_limit)
        return params

    def ensure_connection(self, response: Response) -> Response:
        """
        Ensures that a successful API fetch was made to the NVD API.
        This is needed due to the NVD API throwing 403 Forbiddens occassionally if the limit is reached.

        :param response: Response object returned by the NVD API.
        :return: New Response object if connection successful, else re-raise HttpError
        """
        req: PreparedRequest = response.request
        session: Session | None = None
        delay = self.retry_delay
        for retry in range(1, self.retries + 1):
            try:
                response.raise_for_status()
                break
            except HTTPError:
                if retry == self.retries:
                    raise
                if not session:
                    session = Session()

                # Retry connection
                print(f"Warning, retry #{retry}: NVD returned HTTPError. Retrying in {self.fetch_delay} seconds.")
                sleep(delay)
                response = session.send(req)
                delay *= self.retry_mult
                continue
        if session:
            session.close()
        return response

    def fetch_cves(self, **kwargs) -> list[dict[str, Any]]:
        """
        Fetch CVEs from NVD API.

        :param kwargs: Optional query parameters to pass to NVD API.
        Each parameter on https://nvd.nist.gov/developers/vulnerabilities is supported with caviot being that each
        parameter needs to be in snake_case instead of camelCase (ex: cpe_name instead of cpeName).
        :return: List of CVEs in a dictionary form.
        """

        def serialize_cves(res_cves: list[dict[str, dict[str, Any]]]) -> list[dict[str, Any]]:
            def flatten_cvss(metric: dict[str, Any]) -> dict[str, Any] | None:
                if not metric:
                    return None

                cvss = {camel_to_snake(k): v for k, v in metric.items() if k not in ("cvssData", "type")}
                cvss.update({camel_to_snake(k): v for k, v in metric["cvssData"].items() if k != "version"})
                return cvss

            def find_en_desc(list_search):
                return next((desc["value"] for desc in list_search if desc["lang"] == "en"), "")

            def metrics_flatten(metric):
                return {int_to_ordinal(index): flatten_cvss(metric) for index, metric in enumerate(metric, start=1)}

            cves: list[dict[str, Any]] = []

            for cve in res_cves:
                cve = cve["cve"]

                metrics_v2: dict[str, Any] | None = None
                metrics_v3: dict[str, Any] | None = None
                metrics_v31: dict[str, Any] | None = None
                metrics_v4: dict[str, Any] | None = None
                metrics: dict[str, Any] | None
                if metrics := cve.get("metrics"):
                    if v2 := metrics.get("cvssMetricV2"):
                        metrics_v2 = metrics_flatten(v2)
                    if v3 := metrics.get("cvssMetricV30"):
                        metrics_v3 = metrics_flatten(v3)
                    if v31 := metrics.get("cvssMetricV31"):
                        metrics_v31 = metrics_flatten(v31)
                    if v40 := metrics.get("cvssMetricV40"):
                        metrics_v4 = metrics_flatten(v40)

                cwes: dict[str, Any] | None = None
                if weaknesses := cve.get("weaknesses"):
                    cwes = {int_to_ordinal(index): find_en_desc(cwe["description"]) for index, cwe in
                            enumerate(weaknesses, start=1)}

                references: dict[str, list[str]] | None = None
                if refs := cve.get("references"):
                    references = {}
                    for ref in refs:
                        if ref["source"] not in references:
                            references[ref["source"]] = [ref["url"]]
                        else:
                            references[ref["source"]].append(ref["url"])

                cves.append({
                    "_id": cve["id"],
                    "status": cve["vulnStatus"],
                    "published": cve["published"],
                    "last_modified": cve["lastModified"],
                    "description": find_en_desc(cve["descriptions"]),
                    "metrics_v20": metrics_v2,
                    "metrics_v30": metrics_v3,
                    "metrics_v31": metrics_v31,
                    "metrics_v40": metrics_v4,
                    "configurations": cve.get("configurations"),
                    "cwes": cwes,
                    "references": references
                })
            return cves

        def fetch() -> list[dict[str, Any]]:
            return self.ensure_connection(self.__cves(params=params)).json()

        def curr_index() -> int:
            nonlocal curr_res
            return int(curr_res["startIndex"]) + int(curr_res["resultsPerPage"])

        def print_progress_bar():
            nonlocal total_results
            current = curr_index()
            if total_results == 0:
                print("No progress to show (total results is 0)")
                return

            percentage = (current / total_results) * 100
            filled_length = int(40 * current // total_results)
            bar = "█" * filled_length + '-' * (40 - filled_length)
            print(f"\rProgress: |{bar}| {percentage:.2f}% Complete", end="\r")
            if current == total_results:
                print()  # Move to the next line when complete

        params = self.prep_params(self.cves_fetch_limit, kwargs)
        results = serialize_cves((curr_res := fetch())["vulnerabilities"])
        try:
            total_results = int(curr_res["totalResults"])
            print_progress_bar()
            while curr_res["totalResults"] > (curr_res["startIndex"] + curr_res["resultsPerPage"]):
                sleep(self.fetch_delay)
                params.update({"startIndex": curr_res["startIndex"] + curr_res["resultsPerPage"]})
                results.extend(serialize_cves((curr_res := fetch())["vulnerabilities"]))
                print_progress_bar()
        except KeyboardInterrupt:
            print()
            print("Ctrl+C detected. Early returning accumulated CVEs. Use Ctrl+C to completely quit.")
            return results
        return results