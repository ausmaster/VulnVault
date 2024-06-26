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
from vaultlib import VaultArgumentParser, VaultConfig, VaultMongoClient, s_print
from vaultlib import BColors as C
from vaultlib.api import CPESchema, CVESchema, stringify_results, cpe_str, cve_str


class VaultQuery:
    """
    Main class to query items from the Vault MongoDB
    """
    def __init__(self, mongo_client: VaultMongoClient) -> None:
        self.client = mongo_client

    def p_cve_id(self, cve_id: str) -> None:
        """
        Prints CVE information given CVE ID.

        :param cve_id: The CVE ID
        :return: None
        """
        if cve := self.client.cves.find_one({"_id": cve_id}):
            print(cve_str(cve))
        else:
            print(f"{cve_id} not found.")

    def p_cpe_id(self, cpe_id: str) -> None:
        """
        Prints CPE information given CPE ID.

        :param cpe_id: The CPE ID
        :return: Dict of CPE.
        """
        if cpe := self.client.cpes.find_one({"_id": cpe_id}):
            print(cpe_str(cpe))
        else:
            print(f"{cpe_id} not found.")

    def p_cpe_name(self, cpe_name: str) -> None:
        """
        Prints CPE information given CPE Name.

        :param cpe_name: The CPE Name
        :return: Dict of CPE.
        """
        if cpe := self.client.cpes.find_one({"cpe_name": cpe_name}):
            print(cpe_str(cpe))
        else:
            print(f"{cpe_name} not found.")

    def q_cpe_matches(self, cpe_id: str) -> Cursor:
        """
        Queries CPE matches information given CPE ID.

        :param cpe_id: The CPE ID
        :return: Dict of CPE.
        """
        return self.client.cpematches.find({"matches": cpe_id})

    def q_cpe_to_cves(self, cpe_id: str) -> Cursor[CVESchema]:
        """
        Queries CPE matches information given CPE ID.

        :param cpe_id: The CPE ID
        :return: Cursor for all CVEs
        """
        return self.client.cves.find({
            "configurations.nodes.cpeMatch": {
                "$elemMatch": {
                    "matchCriteriaId": {
                        "$in": [match["_id"] for match in self.q_cpe_matches(cpe_id)]
                    }
                }
            }
        })

    def p_cpe_to_cves(self, cpe_id: str) -> None:
        """
        Prints all CVEs given a CPE ID.

        :param cpe_id: The CPE ID
        :return: List of all CVEs
        """
        for str_cve in stringify_results(self.q_cpe_to_cves(cpe_id)):
            print(str_cve)

    def p_cpename_to_cves(self, cpe_name: str) -> None:
        """
        Prints all CVEs given a CPE Name.

        :param cpe_name: The CPE Name
        :return: List of all CVEs
        """
        cpe = self.client.cpes.find_one({"cpe_name": cpe_name})
        if not cpe:
            return
        self.p_cpe_to_cves(cpe["_id"])

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
                           help="print CPE information about a specific CPE by CPE ID")
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
        query.p_cve_id(args.cve)
    elif args.cpe:
        query.p_cpe_name(args.cpe)
    elif args.cpeid:
        query.p_cpe_id(args.cpeid)
    elif args.cpe2cves:
        query.p_cpename_to_cves(args.cpe2cves)
    elif args.str2cpes:
        query.p_ml_find_cpe(args.str2cpes)
