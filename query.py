"""
This is the script with functions to query certain items from the MongoDB
"""
from __future__ import annotations

from operator import itemgetter

import nltk
from nltk.tokenize import word_tokenize
from rapidfuzz.fuzz import WRatio

# pylint: disable=E0401,E0611
from vaultlib import VaultArgumentParser, VaultConfig, VaultMongoClient, s_print, VAULT_MONGO
from vaultlib import BColors as C
from vaultlib.api import CPESchema, CVESchema


def find_cve_id(cve_id: str) -> CVESchema | None:
    """
    Returns CVE information given CVE ID.

    :param cve_id: The CVE ID
    :return: Dict of CVE.
    """
    return VAULT_MONGO.cves.find_one({"_id": cve_id})


def find_cpe_id(cpe_id: str) -> CPESchema | None:
    """
    Returns CPE information given CPE ID.

    :param cpe_id: The CPE ID
    :return: Dict of CPE.
    """
    return VAULT_MONGO.cpes.find_one({"_id": cpe_id})


def ml_find_cpe(
        cpe_search_str: str,
        frmt: str = "Vpv",
        threshold: float = 80.0
) -> list[tuple[float, CPESchema]]:
    """
    Using fuzzy matching, find the most similar CPEs
    given a string containing the Vendor, Product, and/or Version

    :param cpe_search_str: String to search for
    :param frmt: The specific ordering of token elements in the string.
    V = Vendor, p = Product, v = Version.
    :param threshold: WRatio score on
    :return:
    """
    tokens = word_tokenize(cpe_search_str.lower())
    matches = []
    fetcher: tuple
    match frmt:
        case "Vpv":
            fetcher = (
                (tokens[0], itemgetter("vendor")),
                (tokens[1], itemgetter("product")),
                (tokens[2], itemgetter("version")),
            )
        case "pv":
            fetcher = (
                (tokens[0], itemgetter("product")),
                (tokens[1], itemgetter("version")),
            )
        case _:
            raise ValueError(f"frmt \"{frmt}\" is not supported")
    for cpe in VAULT_MONGO.cpes.find({}):
        match_scores = [WRatio(srch_str, db_itm_gttr(cpe)) for srch_str, db_itm_gttr in fetcher]
        match_score = sum(match_scores) / len(match_scores)
        if sum(match_scores) / len(match_scores) > threshold:
            matches.append((match_score, cpe))
    return matches


if __name__ == '__main__':
    arg_parse = VaultArgumentParser(prog="VulnVault Query")
    op_group = arg_parse.add_argument_group("Operations", "Main Operations, must choose one.")
    op_select = op_group.add_mutually_exclusive_group(required=True)
    op_select.add_argument("--cve", help="print CVE information about a specfic CVE by CVE ID")
    op_select.add_argument("--cpesearch", help="find closest matching CPE given string")
    args = arg_parse.parse_args()

    config = VaultConfig(args.config)
    s_print("Connecting to MongoDB...")
    VAULT_MONGO = VaultMongoClient(config).raise_if_not_connected()
    C.print_success("Connected.")

    s_print("Ensuring NLTK Model downloaded...")
    nltk.download(config.punkt_url)
    C.print_success("Complete.")

    if args.cve:
        find_cve_id(args.cve)
    elif args.cpesearch:
        print(ml_find_cpe(args.cpesearch))
