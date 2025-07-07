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
from rapidfuzz.fuzz import WRatio

# pylint: disable=E0401,E0611
from .lib import VaultArgumentParser, VaultConfig, VaultMongoClient, s_print
from .lib import BColors as C
from .lib.api import CPESchema, CVESchema, stringify_results, cpe_str, cve_str


class VaultQuery:
    """
    Main class to query items from the Vault MongoDB
    """
    client: VaultMongoClient

    def __init__(self, mongo_client: VaultMongoClient) -> None:
        self.client = mongo_client

    def cve_id(self, cve_id: str, prnt: bool = False) -> CVESchema | None:
        """
        Queries/Prints CVE information given actual CVE ID (_id aligns to the actual NVD CVE ID)

        :param cve_id: The CVE ID
        :param prnt: If True, prints out the CVE information instead of returning CVE. Always returns None, Defaults to False.
        :return CVE Record in CVESchema, None if not found. None if prnt.
        """
        if cve := self.client.cves.find_one({"_id": cve_id}):
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
        if cpe := self.client.cpes.find_one({"_id": cpe_id}):
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
        if cpe := self.client.cpes.find_one({"cpe_name": cpe_name}):
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
        if matches := self.client.cpematches.find({"matches": cpe_id}):
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
        if cves := self.client.cves.find({
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

    def cpe_name_to_cves(self, cpe_name: str, prnt: bool = False) -> Cursor[CVESchema] | None:
        """
        Queries/Prints CPE matches information given CPE Name (CPE String).

        :param cpe_name: The CPE name
        :param prnt: If True, prints out the CVEs instead of returning Cursor for CVEs. Always returns None, Defaults to False.
        :return: Cursor for all CVEs, None if not found. None if prnt.
        """
        cpe = self.client.cpes.find_one({"cpe_name": cpe_name})
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

        for cpe in self.client.cpes.find({}):
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
        query.p_ml_find_cpe(args.str2cpes)
