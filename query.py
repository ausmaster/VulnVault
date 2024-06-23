"""
This is the script with functions to query certain items from the MongoDB
"""
from __future__ import annotations

from operator import itemgetter
from typing import Callable

import nltk
from nltk.tokenize import word_tokenize
from rapidfuzz.fuzz import WRatio

# pylint: disable=E0401,E0611
from vaultlib import VaultArgumentParser, VaultConfig, VaultMongoClient, s_print
from vaultlib import BColors as C
from vaultlib.api import CPESchema, CVESchema


class VaultQuery:
    """
    Main class to query items from the Vault MongoDB
    """
    def __init__(self, mongo_client: VaultMongoClient) -> None:
        self.client = mongo_client

    def find_cve_id(self, cve_id: str) -> CVESchema | None:
        """
        Returns CVE information given CVE ID.

        :param cve_id: The CVE ID
        :return: Dict of CVE.
        """
        return self.client.cves.find_one({"_id": cve_id})

    def find_cpe_id(self, cpe_id: str) -> CPESchema | None:
        """
        Returns CPE information given CPE ID.

        :param cpe_id: The CPE ID
        :return: Dict of CPE.
        """
        return self.client.cpes.find_one({"_id": cpe_id})

    def ml_find_cpe(
            self,
            cpe_search_str: str,
            frmt: str = "Vpv",
            threshold: float = 80.0,
            limit: int = 10
    ) -> list[tuple[float, CPESchema]]:
        """
        Using fuzzy matching, find the most similar CPEs
        given a string containing the Vendor, Product, and/or Version

        :param cpe_search_str: String to search for
        :param frmt: The specific ordering of token elements in the string.
        V = Vendor, p = Product, v = Version.
        :param threshold: Minimum WRatio score to be included in results.
        :param limit: Maximum number of results to return.
        :return: Sorted list of CPEs from highest WRatio score to lowest.
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
        return matches[:limit]


if __name__ == '__main__':
    arg_parse = VaultArgumentParser(prog="VulnVault Query")
    op_group = arg_parse.add_argument_group("Operations", "Main Operations, must choose one.")
    op_select = op_group.add_mutually_exclusive_group(required=True)
    op_select.add_argument("--cve", help="print CVE information about a specfic CVE by CVE ID")
    op_select.add_argument("--cpesearch", help="find closest matching CPE given string")
    args = arg_parse.parse_args()

    config = VaultConfig(args.config)
    s_print("Connecting to MongoDB...")
    mngo_client = VaultMongoClient(config).raise_if_not_connected()
    C.print_success("Connected.")

    s_print("Ensuring NLTK Model downloaded...")
    nltk.download(config.punkt_url)
    C.print_success("Complete.")

    query = VaultQuery(mngo_client)

    if args.cve:
        print(query.find_cve_id(args.cve))
    elif args.cpesearch:
        print(query.ml_find_cpe(args.cpesearch))
