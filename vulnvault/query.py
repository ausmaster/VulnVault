"""
This is the script with functions to query certain items from the MongoDB
"""
from __future__ import annotations

from operator import itemgetter
from sys import stdout
from typing import Callable, Literal, Generator

import nltk
from nltk.tokenize import word_tokenize
from pymongo.cursor import Cursor

# Try to import RapidFuzz, fall back to None if unavailable
try:
    from rapidfuzz.fuzz import WRatio
except ImportError:
    WRatio = None

# pylint: disable=E0401,E0611
from lib import VaultArgumentParser, VaultConfig, VaultMongoClient, s_print
from lib import BColors as C
from lib.api import CPESchema, CVESchema, stringify_results, cpe_str, cve_str

# Try to import Rust module, fall back to None if unavailable
try:
    import rustyVault
except Exception:
    rustyVault = None


class VaultQuery:
    """
    Main class to query items from the Vault MongoDB
    """
    client: VaultMongoClient

    def __init__(self, mongo_client: VaultMongoClient) -> None:
        self.client = mongo_client

    def cve_id(self, cve_id: str, prnt: bool = False) -> CVESchema | None:
        """Query/Print CVE by its real NVD ID (stored as _id)."""
        if cve := self.client.cves.find_one({"_id": cve_id}):
            if prnt:
                print(cve_str(cve))
                return None
            return cve
        if prnt:
            print(f"{cve_id} not found.")
        return None

    def cpe_ref(self, cpe_id: str, prnt: bool = False) -> CPESchema | None:
        """Query/Print CPE by Mongo reference _id."""
        if cpe := self.client.cpes.find_one({"_id": cpe_id}):
            if prnt:
                print(cpe_str(cpe))
                return None
            return cpe
        if prnt:
            print(f"{cpe_id} not found.")
        return None

    def cpe_name(self, cpe_name: str, prnt: bool = False) -> CPESchema | None:
        """Query/Print CPE by CPE string (cpe_name)."""
        if cpe := self.client.cpes.find_one({"cpe_name": cpe_name}):
            if prnt:
                print(cpe_str(cpe))
                return None
            return cpe
        if prnt:
            print(f"{cpe_name} not found.")
        return None

    def cpe_matches(self, cpe_id: str, prnt: bool = False) -> list[CPESchema] | None:
        """
        Query/Print CPE matches for a given CPE reference _id.
        Returns a list (materialized) so callers can safely iterate multiple times.
        """
        cursor = self.client.cpematches.find({"matches": cpe_id})
        matches = list(cursor)
        if not matches:
            if prnt:
                print(f"{cpe_id} not found.")
            return None
        if prnt:
            for match in matches:
                print(cpe_str(match))
            return None
        return matches

    def cpe_ref_to_cves(self, cpe_id: str, prnt: bool = False) -> Cursor[CVESchema] | None:
        """
        Find CVEs whose configurations reference any matchCriteriaId linked to this CPE ref.
        """
        matches = self.cpe_matches(cpe_id) or []
        match_ids = [m["_id"] for m in matches]
        if not match_ids:
            if prnt:
                print(f"No matches found for {cpe_id}.")
            return None

        cves = self.client.cves.find({
            "configurations.nodes.cpeMatch": {
                "$elemMatch": {"matchCriteriaId": {"$in": match_ids}}
            }
        })
        if prnt:
            for cve in stringify_results(cves):
                print(cve)
            return None
        return cves

    def cpe_name_to_cves(self, cpe_name: str, prnt: bool = False) -> Cursor[CVESchema] | None:
        """Resolve a CPE name to its ref id, then return/print its CVEs."""
        cpe = self.client.cpes.find_one({"cpe_name": cpe_name})
        if not cpe:
            if prnt:
                print(f"{cpe_name} not found.")
            return None
        return self.cpe_ref_to_cves(cpe["_id"], prnt=prnt)

    def ml_find_cpe(
        self,
        cpe_search_str: str,
        frmt: Literal["Vpv", "pv"] = "Vpv",
        threshold: float = 80.0,
        limit: int = 10,
        fast: bool = False
    ) -> Generator[tuple[float, CPESchema], None, None]:
        """
        Fuzzy find CPEs using weighted WRatio across vendor/product/version.

        Args:
            cpe_search_str: Search string to match
            frmt: Format - "Vpv" (vendor product version) or "pv" (product version)
            threshold: Minimum score (0-100) to include
            limit: Max results to return (-1 for unlimited)
            fast: Use Rust acceleration if available
        """
        # Determine which implementation to use
        if fast and rustyVault is not None:
            yield from self._ml_find_cpe_rust(cpe_search_str, frmt, threshold, limit)
        elif WRatio is not None:
            if fast:
                C.print_fail("Warning: --fast requested but rustyVault not available. Using Python with RapidFuzz.")
            yield from self._ml_find_cpe_python(cpe_search_str, frmt, threshold, limit)
        else:
            raise RuntimeError(
                "No fuzzy matching implementation available. "
                "Install 'rapidfuzz' (pip install rapidfuzz) or compile the Rust extension."
            )

    def _ml_find_cpe_rust(
        self,
        cpe_search_str: str,
        frmt: Literal["Vpv", "pv"] = "Vpv",
        threshold: float = 80.0,
        limit: int = 10
    ) -> Generator[tuple[float, CPESchema], None, None]:
        """
        Rust-accelerated fuzzy CPE search.
        """
        # Fetch candidates with projection to reduce I/O
        projection = {"_id": 1, "vendor": 1, "product": 1, "version": 1, "cpe_name": 1}
        candidates = list(self.client.cpes.find({}, projection))

        if not candidates:
            return

        # Call Rust scorer
        results = rustyVault.score_candidates(
            cpe_search_str,
            candidates,
            frmt,
            threshold,
            limit
        )

        # Fetch complete CPE documents for the results
        for score, cpe_dict in results:
            # Get full CPE document from MongoDB using the _id
            full_cpe = self.client.cpes.find_one({"_id": cpe_dict["_id"]})
            if full_cpe:
                yield (score, full_cpe)

    def _ml_find_cpe_python(
        self,
        cpe_search_str: str,
        frmt: Literal["Vpv", "pv"] = "Vpv",
        threshold: float = 80.0,
        limit: int = 10
    ) -> Generator[tuple[float, CPESchema], None, None]:
        """
        Python fallback fuzzy CPE search using RapidFuzz.
        """
        tokens = word_tokenize(cpe_search_str.lower())
        weights = {"vendor": 0.4, "product": 0.4, "version": 0.2}
        matches: list[tuple[float, CPESchema]] = []

        if frmt == "Vpv":
            def get_weighted_score(scores: list[float]) -> float:
                return (scores[0] * weights["vendor"]) + (scores[1] * weights["product"]) + (scores[2] * weights["version"])
            fetcher = (
                (tokens[0] if len(tokens) > 0 else "", itemgetter("vendor")),
                (tokens[1] if len(tokens) > 1 else "", itemgetter("product")),
                (tokens[2] if len(tokens) > 2 else "", itemgetter("version")),
            )
        elif frmt == "pv":
            def get_weighted_score(scores: list[float]) -> float:
                return (scores[0] * weights["product"]) + (scores[1] * weights["version"])
            fetcher = (
                (tokens[0] if len(tokens) > 0 else "", itemgetter("product")),
                (tokens[1] if len(tokens) > 1 else "", itemgetter("version")),
            )
        else:
            raise ValueError(f'frmt "{frmt}" is not supported')

        projection = {"vendor": 1, "product": 1, "version": 1, "cpe_name": 1, "_id": 1}
        for cpe in self.client.cpes.find({}, projection):
            match_scores = [WRatio(srch_str, db_itm_gttr(cpe)) for srch_str, db_itm_gttr in fetcher]
            score = get_weighted_score(match_scores)
            if score > threshold:
                matches.append((score, cpe))

        matches.sort(key=lambda x: (-x[0], x[1].get("cpe_name", "")))
        for entry_num, match in enumerate(matches, 1):
            if limit != -1 and entry_num > limit:
                return
            yield match

    def p_ml_find_cpe(
        self,
        cpe_search_str: str,
        frmt: Literal["Vpv", "pv"] = "Vpv",
        threshold: float = 80.0,
        limit: int = 10,
        fast: bool = False
    ) -> None:
        """Pretty-print fuzzy CPE matches."""
        for match_score, cpe in self.ml_find_cpe(cpe_search_str, frmt, threshold, limit, fast):
            print(f"[[Match Score {match_score}%]]\n{cpe_str(cpe)}")


if __name__ == '__main__':
    arg_parse = VaultArgumentParser(prog="VulnVault Query")
    op_group = arg_parse.add_argument_group("Operations", "Main Operations, must choose one.")
    op_select = op_group.add_mutually_exclusive_group(required=True)

    op_select.add_argument("--cpe", help="print CPE information about a specific CPE by CPE name")
    op_select.add_argument("--cpeid", help="print CPE information about a specific CPE by CPE reference _id")
    op_select.add_argument("--cve", help="print CVE information about a specfic CVE by CVE ID")
    op_select.add_argument("--cpe2cves", help="print all CVEs given a CPE name")
    op_select.add_argument("--str2cpes", help="prints closest matching CPE(s) given string in the form '<VENDOR> <PRODUCT> <VERSION>'.")

    # Rust sanity check (does not require Mongo or NLTK)
    op_select.add_argument("--rust-test", action="store_true",
                           help="call into the rustyVault extension to verify build/link")

    # Additional options for str2cpes
    op_augments = arg_parse.add_argument_group("Search Options")
    op_augments.add_argument("--fast", action="store_true", default=False,
                            help="use Rust acceleration for fuzzy search (requires rustyVault module)")
    op_augments.add_argument("--threshold", type=float, default=80.0,
                            help="minimum similarity score (0-100) to include results (default: 80.0)")
    op_augments.add_argument("--limit", type=int, default=10,
                            help="maximum number of results to return (default: 10, -1 for unlimited)")
    op_augments.add_argument("--format", choices=["Vpv", "pv"], default="Vpv",
                            help="search format: Vpv (vendor product version) or pv (product version)")

    args = arg_parse.parse_args()

    if args.rust_test:
        try:
            import rustyVault  # compiled PyO3 module
            print(rustyVault.hi())
            print("2 + 3 =", rustyVault.add(2, 3))
            C.print_success("Rust module test completed successfully!")
        except Exception as e:
            C.print_fail(f"rustyVault import/call failed: {e}")
            print("Make sure the Rust PyO3 module is compiled and in the Python path.")
        raise SystemExit(0)

    # Normal path - setup MongoDB and NLTK
    # Handle config path - argparser returns list if nargs=1
    config_path = args.config[0] if isinstance(args.config, list) else args.config
    config = VaultConfig(config_path)
    s_print("Connecting to MongoDB...")
    mngo_client = VaultMongoClient(config).raise_if_not_connected()
    C.print_success("Connected.")

    s_print("Ensuring NLTK Model downloaded...")
    nltk.download(config.punkt_url, print_error_to=stdout)
    C.print_success("Complete.")

    query = VaultQuery(mngo_client)

    if args.cve:
        query.cve_id(args.cve, prnt=True)
    elif args.cpe:
        query.cpe_name(args.cpe, prnt=True)
    elif args.cpeid:
        query.cpe_ref(args.cpeid, prnt=True)
    elif args.cpe2cves:
        query.cpe_name_to_cves(args.cpe2cves, prnt=True)
    elif args.str2cpes:
        # Check what's available and inform user
        if args.fast and rustyVault is None:
            C.print_fail("Warning: --fast requested but rustyVault module not available.")
            if WRatio is None:
                C.print_fail("ERROR: RapidFuzz also not available. Cannot perform search.")
                raise SystemExit(1)
            C.print_fail("Falling back to Python scorer with RapidFuzz.")
        elif args.fast:
            C.print_success("Using Rust-accelerated scorer.")
        else:
            if WRatio is None:
                C.print_fail("Warning: RapidFuzz not available. Trying Rust scorer...")
                if rustyVault is None:
                    C.print_fail("ERROR: Neither RapidFuzz nor rustyVault available. Cannot perform search.")
                    raise SystemExit(1)
                args.fast = True  # Force Rust usage
                C.print_success("Using Rust-accelerated scorer.")

        query.p_ml_find_cpe(
            args.str2cpes,
            frmt=args.format,
            threshold=args.threshold,
            limit=args.limit,
            fast=args.fast
        )