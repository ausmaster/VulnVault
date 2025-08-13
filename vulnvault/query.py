"""
This is the script with functions to query certain items from the MongoDB
"""
from __future__ import annotations

from operator import itemgetter
from sys import stdout
from typing import Callable, Literal, Generator, Any, cast

import nltk
from nltk.tokenize import word_tokenize
from pymongo.asynchronous.cursor import AsyncCursor
from pymongo.cursor import Cursor
from rapidfuzz.fuzz import WRatio

# pylint: disable=E0401,E0611
from vulnvault.lib import (
    VaultArgumentParser,
    VaultConfig,
    VaultMongoClient,
    AsyncVaultMongoClient,
    s_print
)
from vulnvault.lib import BColors as C
from vulnvault.lib.api import (
    CPESchema,
    CVESchema,
    stringify_results,
    cpe_str,
    cve_str,
    a_stringify_results,
)

class BaseVaultQuery:
    _connected: bool


class AsyncVaultQuery(BaseVaultQuery):
    _mongo: AsyncVaultMongoClient

    def __init__(
        self,
        mongo_client: AsyncVaultMongoClient | None = None,
        config_path: str = "config.json",
        suppress_prnt: bool = False,
    ) -> None:
        super().__init__()

        if mongo_client and not isinstance(mongo_client, AsyncVaultMongoClient):
            raise TypeError("mongo_client must be an instance of AsyncVaultMongoClient")
        else:
            if not suppress_prnt:
                print(
                    "Cannot connect to MongoDB ahead of time in async mode. "
                    "Run query first to establish connection."
                )
            self._mongo = mongo_client if mongo_client else AsyncVaultMongoClient(VaultConfig(config_path))
        self._connected = False

    async def connect(self) -> None:
        if not self._connected:
            await self._mongo.aconnect()
            self._connected = True


    async def cve_id(
            self,
            cve_id: str,
            prnt: bool = False,
            cve_proj: dict[str, Any] | list[str] | None = None
    ) -> CVESchema | None:
        """
        Queries/Prints CVE information given actual CVE ID (_id aligns to the actual NVD CVE ID)

        :param cve_id: The CVE ID
        :param prnt: If True, prints out the CVE information instead of returning CVE. Always returns None, Defaults to False.
        :return CVE Record in CVESchema, None if not found. None if prnt.
        """
        if cve_proj is None:
            cve_proj = {}

        if cve := await self._mongo.cves.find_one({"_id": cve_id}, projection=cve_proj):
            if prnt:
                print(cve_str(cve))
                return None
            else:
                return cve
        else:
            if prnt:
                print(f"{cve_id} not found.")
            return None


    async def cpe_matches(
            self, cpe_id: str,
            prnt: bool = False,
            cpematches_proj: dict[str, Any] | list[str] | None = None
    ) -> list[CPESchema] | None:
        """
        Queries/Prints CPE matches information given CPE reference _id.
        """
        if cpematches_proj is None:
            cpematches_proj = {}

        # Convert cursor to list immediately
        cursor = self._mongo.cpematches.find({"matches": cpe_id}, projection=cpematches_proj)
        matches = await cursor.to_list(None)

        if matches:
            if prnt:
                for match in matches:
                    print(match)
                return None
            return matches
        else:
            if prnt:
                print(f"{cpe_id} not found.")
            return None

    async def cpe_ref_to_cves(
            self,
            cpe_id: str,
            prnt: bool = False,
            cve_proj: dict[str, Any] | list[str] | None = None
    ) -> list[CVESchema] | None:
        """
        Queries CPE matches information given CPE reference _id.
        """
        if cve_proj is None:
            cve_proj = {}

        # Get matches as a list first
        matches = await self.cpe_matches(cpe_id)
        if not matches:
            if prnt:
                print(f"{cpe_id} not found.")
            return None

        # Create match_ids list from matches
        match_ids = [match["_id"] for match in matches]

        # Run query and convert cursor to list
        cursor = self._mongo.cves.find(
            {
                "configurations.nodes.cpeMatch": {
                    "$elemMatch": {"matchCriteriaId": {"$in": match_ids}}
                }
            },
            projection=cve_proj
        )
        cves = await cursor.to_list(None)

        if cves:
            if prnt:
                for cve in cves:
                    print(cve_str(cve))
                return None
            return cves
        else:
            if prnt:
                print(f"CVEs for {cpe_id} not found.")
            return None

    async def cpe_name_to_cves(
            self,
            cpe_name: str,
            prnt: bool = False,
            cve_proj: dict[str, Any] | list[str] | None = None
    ) -> list[CVESchema] | None:
        """
        Queries/Prints CPE matches information given CPE Name (CPE String).
        """
        if cve_proj is None:
            cve_proj = {}

        cpe = await self._mongo.cpes.find_one({"cpe_name": cpe_name})
        if not cpe:
            if prnt:
                print(f"{cpe_name} not found.")
            return None

        # Now this will return a list, not a cursor
        cves = await self.cpe_ref_to_cves(cpe["_id"], cve_proj=cve_proj)
        if cves:
            if prnt:
                for cve in cves:
                    print(cve_str(cve))
                return None
            return cves
        else:
            if prnt:
                print(f"CVEs for {cpe_name} not found.")
            return None



class VaultQuery:
    """
    Main class to query items from the Vault MongoDB
    """
    _mongo: VaultMongoClient | AsyncVaultMongoClient
    _async: bool
    _connected: bool

    def __init__(
            self,
            mongo_client: VaultMongoClient | AsyncVaultMongoClient | None = None,
            config_path: str = "config.json",
            create_async: bool = False,
            suppress_prnt: bool = False
    ) -> None:
        if mongo_client:
            self._async = isinstance(mongo_client, AsyncVaultMongoClient)

            if self._async:
                # We cannot call raise_if_not_connected() here
                if not suppress_prnt:
                    print("Cannot connect to MongoDB ahead of time in async mode. "
                          "Run query first to establish connection.")
                self._mongo = mongo_client
                self._connected = False
            else:
                if not suppress_prnt:
                    s_print("Connecting to MongoDB...")
                self._mongo = mongo_client.raise_if_not_connected()
                if not suppress_prnt:
                    C.print_success("Connected.")
                self._connected = True
        else:
            if create_async:
                # We cannot call raise_if_not_connected() here
                if not suppress_prnt:
                    print(
                        "Cannot connect to MongoDB ahead of time in async mode. "
                        "Run query first to establish connection."
                    )
                self._mongo = AsyncVaultMongoClient(VaultConfig(config_path))
                self._async = True
                self._connected = False
            else:
                if not suppress_prnt:
                    s_print("Connecting to MongoDB...")
                self._mongo = VaultMongoClient(VaultConfig(config_path), connect=True)
                if not suppress_prnt:
                    C.print_success("Connected.")
                self._async = False
                self._connected = True


    async def connect(self) -> None:
        if self._async:
            if not self._connected:
                await self._mongo.aconnect()
                self._connected = True
        else:
            if not self._connected:
                self._mongo._connect()
                self._connected = True



    def cve_id(self, cve_id: str, prnt: bool = False) -> CVESchema | None:
        """
        Queries/Prints CVE information given actual CVE ID (_id aligns to the actual NVD CVE ID)

        :param cve_id: The CVE ID
        :param prnt: If True, prints out the CVE information instead of returning CVE. Always returns None, Defaults to False.
        :return CVE Record in CVESchema, None if not found. None if prnt.
        """
        if self._async:
            raise RuntimeError("Cannot use cve_id in async mode, use a_cve_id instead.")

        if cve := self._mongo.cves.find_one({"_id": cve_id}):
            if prnt:
                print(cve_str(cve))
                return None
            else:
                return cve
        else:
            if prnt:
                print(f"{cve_id} not found.")
            return None


    def cpe_ref(self, cpe_id: str, prnt: bool = False) -> CPESchema | None:
        """
        Queries/Prints CPE information given CPE reference _id in Mongo.

        :param cpe_id: The CPE reference _id
        :param prnt: If True, prints out the CPE information instead of returning CPE. Always returns None, Defaults to False.
        :returns CPE Record in CPESchema, None if not found. None if prnt.
        """
        if self._async:
            raise RuntimeError("Cannot use cpe_ref in async mode, use a_cpe_ref instead.")

        if cpe := self._mongo.cpes.find_one({"_id": cpe_id}):
            if prnt:
                print(cpe_str(cpe))
                return None
            else:
                return cpe
        else:
            if prnt:
                print(f"{cpe_id} not found.")
            return None


    def cpe_name(self, cpe_name: str, prnt: bool = False) -> CPESchema | None:
        """
        Queries/Prints CPE information given CPE Name (CPE String).

        :param cpe_name: The NVD CPE Name
        :param prnt: If True, prints out the CVE information instead of returning CVE. Always returns None, Defaults to False.
        :returns CVE Record in CVESchema, None if not found. None if prnt.
        """
        if self._async:
            raise RuntimeError("Cannot use cpe_name in async mode, use a_cpe_name instead.")

        if cpe := self._mongo.cpes.find_one({"cpe_name": cpe_name}):
            if prnt:
                print(cpe_str(cpe))
                return None
            else:
                return cpe
        else:
            if prnt:
                print(f"{cpe_name} not found.")
            return None


    def cpe_matches(self, cpe_id: str, prnt: bool = False) -> Cursor[CPESchema] | None:
        """
        Queries/Prints CPE matches information given CPE reference _id.

        :param cpe_id: The CPE _id
        :param prnt: If True, prints out the CPE matches information instead of returning CPE matches. Always returns None, Defaults to False.
        :return: List of matches in CPESchema, None if not found. None if prnt.
        """
        if self._async:
            raise RuntimeError("Cannot use cpe_matches in async mode, use a_cpe_matches instead.")

        if matches := self._mongo.cpematches.find({"matches": cpe_id}):
            if prnt:
                for match in matches:
                    print(cpe_str(match))
                return None
            else:
                return matches
        else:
            if prnt:
                print(f"{cpe_id} not found.")
            return None


    def cpe_ref_to_cves(self, cpe_id: str, prnt: bool = False) -> Cursor[CVESchema] | None:
        """
        Queries CPE matches information given CPE reference _id.

        :param cpe_id: The CPE reference _id
        :param prnt: If True, prints out the CVEs instead of returning Cursor for CVEs. Always returns None, Defaults to False.
        :return: Cursor for all CVEs, None if not found. None if prnt.
        """
        if self._async:
            raise RuntimeError("Cannot use cpe_ref_to_cves in async mode, use a_cpe_ref_to_cves instead.")

        if cves := self._mongo.cves.find({
            "configurations.nodes.cpeMatch": {
                "$elemMatch": {
                    "matchCriteriaId": {
                        "$in": [match["_id"] for match in self.cpe_matches(cpe_id)]
                    }
                }
            }
        }):
            if prnt:
                for cve in stringify_results(cves):
                    print(cve)
                return None
            else:
                return cves
        else:
            if prnt:
                print(f"{cpe_id} not found.")
            return None


    def cpe_name_to_cves(
            self,
            cpe_name: str,
            prnt: bool = False
    ) -> Cursor[CVESchema] | None:
        """
        Queries/Prints CPE matches information given CPE Name (CPE String).

        :param cpe_name: The CPE name
        :param prnt: If True, prints out the CVEs instead of returning Cursor for CVEs. Always returns None, Defaults to False.
        :return: Cursor for all CVEs, None if not found. None if prnt.
        """
        if self._async:
            raise RuntimeError("Cannot use cpe_name_to_cves in async mode, use a_cpe_name_to_cves instead.")

        cpe = self._mongo.cpes.find_one({"cpe_name": cpe_name})
        if not cpe:
            if prnt:
                print(f"{cpe_name} not found.")
            return None

        if cves := self.cpe_ref_to_cves(cpe["_id"]):
            if prnt:
                for cve in stringify_results(cves):
                    print(cve)
                return None
            else:
                return cves
        else:
            if prnt:
                print(f"CVEs for {cpe_name} not found.")
            return None


    def ml_find_cpe(
            self,
            cpe_search_str: str,
            frmt: Literal["Vpv", "pv"] = "Vpv",
            threshold: float = 80.0,
            limit: int = 10
    ) -> Generator[tuple[float, CPESchema], None, None]:
        """
        Using Levenshtein Distance, find the most similar CPE(s)
        given a string containing the Vendor, Product, and/or Version.
        Takes a weighted score across vendor (40%), product (40%),
        and version (20%) for overall similarity.

        :param cpe_search_str: String to search for
        :param frmt: The specific ordering of token elements in the string.
        V = Vendor, p = Product, v = Version. Defaults to "Vpv",
        choices are "Vpv" and "pv".
        :param threshold: Minimum WRatio score to be included in results.
        :param limit: Maximum number of results to return. Defaults to 10, set to -1 to return all.
        :return: Generator that yields a sorted list of CPEs from highest WRatio score to lowest.
        """
        if self._async:
            raise RuntimeError("Cannot use ml_find_cpe in async mode, use a_ml_find_cpe instead.")

        tokens = word_tokenize(cpe_search_str.lower())
        weights = {"vendor": 0.4, "product": 0.4, "version": 0.2}
        matches = []
        get_weighted_score: Callable[[list[float]], float]
        fetcher: tuple
        if frmt == "Vpv":
            def get_weighted_score(scores: list[float]) -> float:
                return (
                        (scores[0] * weights["vendor"]) +
                        (scores[1] * weights["product"]) +
                        (scores[2] * weights["version"])
                )

            fetcher = (
                (tokens[0], itemgetter("vendor")),
                (tokens[1], itemgetter("product")),
                (tokens[2], itemgetter("version")),
            )
        elif frmt == "pv":
            def get_weighted_score(scores: list[float]) -> float:
                return (
                        (scores[0] * weights["product"]) +
                        (scores[1] * weights["version"])
                )

            fetcher = (
                (tokens[0], itemgetter("product")),
                (tokens[1], itemgetter("version")),
            )
        else:
            raise ValueError(f"frmt \"{frmt}\" is not supported")

        for cpe in self._mongo.cpes.find({}):
            match_scores = [WRatio(srch_str, db_itm_gttr(cpe)) for srch_str, db_itm_gttr in fetcher]
            if (score := get_weighted_score(match_scores)) > threshold:
                matches.append((score, cpe))
        matches.sort(key=itemgetter(0), reverse=True)
        for entry_num, match in enumerate(matches, 1):
            if limit != -1 and entry_num > limit:
                return
            yield match

    def p_ml_find_cpe(
            self,
            cpe_search_str: str,
            frmt: Literal["Vpv", "pv"] = "Vpv",
            threshold: float = 80.0,
            limit: int = 10
    ) -> None:
        """
        Prints results gathered from ml_find_cpe.

        :param cpe_search_str: String to search for
        :param frmt: The specific ordering of token elements in the string.
        V = Vendor, p = Product, v = Version. Defaults to "Vpv",
        choices are "Vpv" and "pv".
        :param threshold: Minimum WRatio score to be included in results.
        :param limit: Maximum number of results to return. Defaults to 10, set to -1 to return all.
        :return: Sorted list of CPEs from highest WRatio score to lowest.
        """
        for match_score, cpe in self.ml_find_cpe(cpe_search_str, frmt, threshold, limit):
            print(f"[[Match Score {match_score}%]]\n{cpe_str(cpe)}")


if __name__ == '__main__':
    arg_parse = VaultArgumentParser(prog="VulnVault Query")
    op_group = arg_parse.add_argument_group("Operations", "Main Operations, must choose one.")
    op_select = op_group.add_mutually_exclusive_group(required=True)
    op_select.add_argument("--cpe",
                           help="print CPE information about a specific CPE by CPE name")
    op_select.add_argument("--cpeid",
                           help="print CPE information about a specific CPE by CPE reference _id")
    op_select.add_argument("--cve",
                           help="print CVE information about a specfic CVE by CVE ID")
    op_select.add_argument("--cpe2cves",
                           help="print all CVEs given a CPE name")
    op_select.add_argument("--str2cpes",
                           help="prints closest matching CPE(s) given "
                                "string in the form '<VENDOR> <PRODUCT> <VERSION>'.")
    args = arg_parse.parse_args()

    config = VaultConfig(args.config)
    mngo_client = VaultMongoClient(config).raise_if_not_connected()

    print("Ensuring NLTK Model downloaded...")
    nltk.download(config.punkt_url, print_error_to=stdout)
    C.print_success("Complete.")

    query = VaultQuery(mongo_client=mngo_client)

    if args.cve:
        query.cve_id(args.cve, prnt=True)
    elif args.cpe:
        query.cpe_name(args.cpe, prnt=True)
    elif args.cpeid:
        query.cpe_ref(args.cpeid, prnt=True)
    elif args.cpe2cves:
        query.cpe_name_to_cves(args.cpe2cves, prnt=True)
    elif args.str2cpes:
        query.p_ml_find_cpe(args.str2cpes)
