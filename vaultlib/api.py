"""
Performs the NVD API fetches and returns digestable results.
"""
from __future__ import annotations

from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from functools import partial
from re import split
from threading import Lock
from time import time, sleep
from typing import Any, Callable, TypedDict

from requests import get, HTTPError, PreparedRequest, Response, Session

from .config import VaultConfig
from .utils import BColors as C
from .utils import camel_to_snake, snake_to_camel, int_to_ordinal, s_print


class CVESchema(TypedDict):
    """
    Schema for CVE records in the cves MongoDB collection.
    """
    description: str
    published: str
    last_modified: str
    status: str
    metrics_v20: dict[str, dict[str, Any]]
    metrics_v30: dict[str, dict[str, Any]]
    metrics_v31: dict[str, dict[str, Any]]
    metrics_v40: dict[str, dict[str, Any]]
    configurations: list[dict[str, Any]]
    references: list[dict[str, Any]]
    cwes: list[dict[str, Any]]


class CPESchema(TypedDict, total=False):
    """
    Schema for CPE records in the cpes MongoDB collection.
    """
    cpe_name: str
    created: str
    last_modified: str
    title: str
    deprecated: bool
    # The part type (e.g., 'a' for applications, 'o' for operating systems, 'h' for hardware)
    part: str
    vendor: str  # The vendor of the product
    product: str  # The product name
    version: str  # The version of the product
    update: str  # The update level of the product
    edition: str  # The edition of the product
    language: str  # The language of the product
    sw_edition: str  # The software edition
    target_sw: str  # The software environment targeted by the product
    target_hw: str  # The hardware environment targeted by the product
    other: str  # Any other information


CPEComponents = namedtuple(
    "CPEComponents",
    (
        "cpe",
        "cpe_version",
        "part",
        "vendor",
        "product",
        "version",
        "update",
        "edition",
        "language",
        "sw_edition",
        "target_sw",
        "target_hw",
        "other"
    ),
    defaults=(
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*"
    )
)


class NVDFetch:  # pylint: disable=R0902
    """
    Provides the NVD fetching functionality to return results from NVD database.
    """
    def __init__(self, config: VaultConfig) -> None:
        api_key_hdr = {"apiKey": config.api_key}
        self.__cves: partial = partial(get, config.nvd_cve_api, headers=api_key_hdr)
        self.cves_fetch_limit: int = 2_000  # Default and maximum by NVD
        # self.__cve_ch: partial = partial(get, config.nvd_cve_ch_api, headers=api_key_hdr)
        self.cve_ch_fetch_limit: int = 5_000  # Default and maximum by NVD
        self.__cpes: partial = partial(get, config.nvd_cpe_api, headers=api_key_hdr)
        self.cpes_fetch_limit: int = 10_000  # Default and maximum by NVD
        # self.__cpe_mc: partial = partial(get, config.nvd_cpe_mc_api, headers=api_key_hdr)
        self.cpe_mc_fetch_limit: int = 500  # Default and maximum by NVD
        self.retries: int = config.conn_retries
        self.retry_delay: int = config.conn_retry_delay  # seconds
        self.retry_mult: int = config.conn_retry_delay_mult
        # Non-API limited to 5 req / 30 secs, API get 50 reqs
        self.fetch_delay: float = 30 / 50 if config.api_key else 30 / 5
        self.fetch_threads: int = config.fetch_threads

    def __ensure_connection(self, response: Response) -> Response:
        """
        Ensures that a successful API fetch was made to the NVD API.
        This is needed due to the NVD API throwing 403 Forbiddens
        occassionally if the limit is reached.

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

                delay *= self.retry_mult
                # Retry connection
                print(f"Warning, retry #{retry}: NVD returned HTTPError. "
                      f"{f'{err_msg} ' if (err_msg := response.headers.get('message')) else ''}"
                      f"Retrying in {self.fetch_delay} seconds.")
                sleep(delay)
                response = session.send(req)
                continue
        if session:
            session.close()
        return response

    @staticmethod
    def __prep_params(fetch_limit: int, kwargs: dict[str, Any]) -> dict[str, str]:
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

    @staticmethod
    def __print_progress_bar(current_index: int, total_results: int) -> None:
        """
        Prints a progress bar based on current index.

        :param current_index: Current index out of the total results.
        :param total_results: Total number of results.
        :return: None. Progress is printed.
        """
        if total_results == 0:
            print("No progress to show (total results is 0)")
            return

        percentage = (current_index / total_results) * 100
        filled_length = int(40 * current_index // total_results)
        p_bar = "█" * filled_length + '-' * (40 - filled_length)
        print(f"\rProgress: |{p_bar}| {percentage:.2f}% Complete", end="\r", flush=True)
        if current_index == total_results:
            print()  # Move to the next line when complete

    def __fetch_collection(
            self,
            fetch_func: Callable,
            fetch_lim: int,
            data_key: str,
            serialize_func: Callable,
            **kwargs
    ) -> list[dict[str, Any]]:
        """
        Generic algorithm to accumulate data from NVD API.

        :param fetch_func: Function used to fetch data from NVD API and return Response.
        :param fetch_lim: The specific fetch limit for the operation.
        :param data_key: Key that points to where the data resides in the JSON Response.
        :param serialize_func: Function used to serialize data from NVD API.
        :return: List of data, each data is a dictionary
        """
        def fetch(f_params: dict[str, str]) -> dict[str, Any]:
            return self.__ensure_connection(fetch_func(params=f_params)).json()

        params = self.__prep_params(fetch_lim, kwargs)
        parallel = NVDParallelAPICaller(
            self.fetch_delay,
            self.__print_progress_bar,
            fetch,
            params,
            data_key,
            self.fetch_threads
        )
        C.print_bold("Collecting from NVD API", flush=True)
        results = parallel.run()
        C.print_success("Collection complete.")
        s_print("Serializing results...")
        results = serialize_func(results)
        C.print_success("Serialization complete.")
        return results

    @staticmethod
    def __serialize_cpes(res_cpes: list[dict[str, dict[str, Any]]]) -> list[dict[str, Any]]:  # pylint: disable=R0914
        """
        Serializes CPEs to MongoDB digestable form.

        :param res_cpes: List of CPEs returned from API.
        :return: Serialized list of CPEs.
        """
        def cpe_to_snake_case(_cpe: dict[str, Any]) -> dict[str, Any]:
            cpe_rtrn = {camel_to_snake(k): v for k, v in _cpe.items()
                        if k not in ("cpeNameId", "titles")}
            cpe_rtrn["_id"] = _cpe["cpeNameId"]
            cpe_rtrn["title"] = next((title["title"] for title in _cpe["titles"]
                                      if title["lang"] == "en"), "")
            return cpe_rtrn

        def split_cpe_name(cpe_name: str) -> list[str]:
            return [
                part.replace("\\:", ":")
                for part in split(r"(?<!\\):", cpe_name)
            ]

        cpes: list[dict[str, Any]] = []
        for cpe in res_cpes:
            cpe = cpe_to_snake_case(cpe["cpe"])
            cpe.update({
                k: v for k, v in
                CPEComponents(*split_cpe_name(cpe["cpe_name"]))._asdict().items()
                if k not in ("cpe", "cpe_version")
            })
            cpes.append(cpe)

        return cpes

    @staticmethod
    def __serialize_cves(res_cves: list[dict[str, dict[str, Any]]]) -> list[dict[str, Any]]:
        """
        Serializes CVEs to MongoDB digestable form.

        :param res_cves: List of CVEs returned from API.
        :return: Serialized list of CVEs.
        """
        def flatten_cvss(metric: dict[str, Any]) -> dict[str, Any] | None:
            if not metric:
                return None

            cvss = {camel_to_snake(k): v for k, v in metric.items()
                    if k not in ("cvssData", "type")}
            cvss.update({camel_to_snake(k): v for k, v in metric["cvssData"].items()
                         if k != "version"})
            return cvss

        def find_en_desc(list_search):
            return next((desc["value"] for desc in list_search
                         if desc["lang"] == "en"), "")

        def metrics_flatten(metric):
            return {int_to_ordinal(index): flatten_cvss(metric)
                    for index, metric in enumerate(metric, start=1)}

        cves: list[dict[str, Any]] = []

        for cve in res_cves:
            cve = cve["cve"]

            metrics_v2: dict[str, Any] | None = None
            metrics_v3: dict[str, Any] | None = None
            metrics_v31: dict[str, Any] | None = None
            metrics_v4: dict[str, Any] | None = None
            metrics: dict[str, Any] | None
            if metrics := cve.get("metrics"):
                if metrics_v2 := metrics.get("cvssMetricV2"):
                    metrics_v2 = metrics_flatten(metrics_v2)
                if metrics_v3 := metrics.get("cvssMetricV30"):
                    metrics_v3 = metrics_flatten(metrics_v3)
                if metrics_v31 := metrics.get("cvssMetricV31"):
                    metrics_v31 = metrics_flatten(metrics_v31)
                if metrics_v4 := metrics.get("cvssMetricV40"):
                    metrics_v4 = metrics_flatten(metrics_v4)

            cwes: dict[str, Any] | None
            if cwes := cve.get("weaknesses"):
                cwes = {int_to_ordinal(index): find_en_desc(_cwe["description"]) for index, _cwe in
                        enumerate(cwes, start=1)}

            references: dict[str, list[str]] | None
            if references := cve.get("references"):
                refs = {}
                for ref in references:
                    if ref["source"] not in refs:
                        refs[ref["source"]] = [ref["url"]]
                    else:
                        refs[ref["source"]].append(ref["url"])

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

    def fetch_cpes(self, **kwargs) -> list[dict[str, Any]]:
        """
        Fetch CPEs from NVD API.

        :param kwargs: Optional query parameters to pass to NVD API.
        Each parameter on https://nvd.nist.gov/developers/products
        is supported with caviot being that each parameter needs to be in
        snake_case instead of camelCase (ex: cpe_name instead of cpeName).
        :return: List of CPEs in a dictionary form.
        """
        return self.__fetch_collection(
            self.__cpes,
            self.cpes_fetch_limit,
            "products",
            self.__serialize_cpes,
            **kwargs
        )

    def fetch_cves(self, **kwargs) -> list[dict[str, Any]]:
        """
        Fetch CVEs from NVD API.

        :param kwargs: Optional query parameters to pass to NVD API.
        Each parameter on https://nvd.nist.gov/developers/vulnerabilities
        is supported with caviot being that each parameter needs to be in
        snake_case instead of camelCase (ex: cpe_name instead of cpeName).
        :return: List of CVEs in a dictionary form.
        """
        return self.__fetch_collection(
            self.__cves,
            self.cves_fetch_limit,
            "vulnerabilities",
            self.__serialize_cves,
            **kwargs
        )


class NVDParallelAPICaller:  # pylint: disable=R0902
    """
    Introduces parallelism for API calls to NVD.
    """
    def __init__(  # pylint: disable=R0913
            self,
            delay: float,
            progress_callback: Callable[[int, int], None],
            api_call: Callable[[dict[str, str]], dict[str, Any]],
            params: dict[str, Any],
            data_key: str,
            max_workers: int
    ) -> None:
        self.lock = Lock()
        self.delay = delay
        self.data_key = data_key
        self.results: list[dict[str, Any]] = []
        self.max_workers = max_workers
        self.progress_callback = progress_callback
        self.last_call_time = 0
        self.total_calls = 0
        self.completed_calls = 0

        api_resp = api_call(params)
        self.calls: list[partial] = []
        for curr_index in range(
                api_resp["startIndex"] + api_resp["resultsPerPage"],
                api_resp["totalResults"],
                api_resp["resultsPerPage"]
        ):
            curr_params = deepcopy(params)
            curr_params["startIndex"] = curr_index
            self.calls.append(partial(api_call, curr_params))
        self.total_calls = len(self.calls)
        self.results.extend(api_resp[data_key])

    def fetch_api(self, api_call: partial) -> list[dict[str, Any]]:
        """
        Used by executor to fetch one API call per worker.
        Capped by the delay to stay within NVD API limit.

        :param api_call: The API call to execute for this worker.
        :return: Results of API call, specified by self.data_key.
        """
        with self.lock:
            current_time = time()
            while current_time - self.last_call_time < self.delay:
                sleep(self.delay - (current_time - self.last_call_time))
                current_time = time()
            self.last_call_time = current_time
        return api_call()[self.data_key]

    def worker(self, api_call: partial) -> None:
        """
        Actual worker task. Calls self.fetch_api -> Results -> self.results -> print progress bar

        :param api_call: The API call to execute for this worker.
        :return: None
        """
        result = self.fetch_api(api_call)
        with self.lock:
            self.results.extend(result)
            self.completed_calls += 1
            self.progress_callback(self.completed_calls, self.total_calls)

    def run(self) -> list[dict[str, Any]]:
        """
        Runs the Parallel API fetching process.

        :return: All results of API fetch.
        """
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_call = {executor.submit(self.worker, call): call for call in self.calls}
            for future in as_completed(future_to_call):
                future.result()  # Ensure that all futures are processed
        return self.results
