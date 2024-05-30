"""
This is the main module used for running the main functions.
"""
from __future__ import annotations

from vaultlib.api import NVDFetch  # pylint: disable=E0401
from vaultlib.argparser import VaultArgumentParser  # pylint: disable=E0401
from vaultlib.config import VaultConfig  # pylint: disable=E0401
from vaultlib.mongo import VaultMongoClient  # pylint: disable=E0401
from vaultlib.utils import BColors as Colors  # pylint: disable=E0401

NVD_API: NVDFetch | None = None
VAULT_MONGO: VaultMongoClient | None = None
C: Colors = Colors()


def initial_load() -> None:
    """
    Provides the initial procedure of loading all CVEs and CPEs from NVD.

    :return: None
    """
    print("Dropping CVEs/CPEs collection... ", end="")
    db = VAULT_MONGO.get_default_database()
    # db.drop_collection("cves")
    db.drop_collection("cpes")
    print(C.success_msg("Dropped."))
    insert_cpes()
    # insert_cves()


def insert_cpes() -> None:
    """
    Insert procudure for inserting CPEs.

    :return: None
    """
    print(C.underline_msg("Starting Collection and Insertion Procedure for CPEs"))
    VAULT_MONGO.cpes.insert_many(NVD_API.fetch_cpes())
    print(C.success_msg("Complete."))


def insert_cves() -> None:
    """
    Insert procudure for inserting CVEs.

    :return: None
    """
    print(C.underline_msg("Starting Collection and Insertion Procedure for CVEs"))
    VAULT_MONGO.cves.insert_many(NVD_API.fetch_cves())
    print(C.success_msg("Complete."))


if __name__ == "__main__":
    arg_parse = VaultArgumentParser()
    arg_parse.add_argument("-f", "--initialfetch", action="store_true",
                           help="purge all CVEs and fetch all CVEs from NVD")
    args = arg_parse.parse_args()

    config = VaultConfig(args.config)
    print("Connecting to MongoDB... ", end="")
    VAULT_MONGO = VaultMongoClient(config).raise_if_not_connected()
    print(C.success_msg("Connected."))  # pylint: disable=E1120
    NVD_API = NVDFetch(config)

    if args.initialfetch:
        initial_load()
