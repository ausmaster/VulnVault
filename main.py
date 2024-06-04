"""
This is the main module used for running the main functions.
"""
from __future__ import annotations

from vaultlib.api import NVDFetch  # pylint: disable=E0401
from vaultlib.argparser import VaultArgumentParser  # pylint: disable=E0401
from vaultlib.config import VaultConfig  # pylint: disable=E0401
from vaultlib.mongo import VaultMongoClient  # pylint: disable=E0401
from vaultlib.utils import BColors as C  # pylint: disable=E0401
from vaultlib.utils import s_print

NVD_API: NVDFetch | None = None
VAULT_MONGO: VaultMongoClient | None = None


def initial_load(drop: bool = False, **kwargs) -> None:
    """
    Provides the initial procedure of loading all CVEs and CPEs from NVD.

    :param drop: Drop collections before inserting CPEs.
    :return: None
    """
    insert_cpes(drop=drop, **kwargs)
    insert_cves(drop=drop, **kwargs)


def insert_cpes(drop: bool = False, **kwargs) -> None:
    """
    Insert procudure for inserting CPEs.

    :param drop: Drop collection before inserting CPEs.
    :return: None
    """
    if drop:
        s_print("Dropping CPEs collection...")
        VAULT_MONGO.get_default_database().drop_collection("cpes")
        C.print_success("Dropped.")
    C.print_underline("Starting Collection and Insertion Procedure for CPEs")
    VAULT_MONGO.cpes.insert_many(NVD_API.fetch_cpes(**kwargs))
    C.print_success("Complete.")


def insert_cves(drop: bool = False, **kwargs) -> None:
    """
    Insert procudure for inserting CVEs.

    :param drop: Drop collection before inserting CVEs.
    :return: None
    """
    if drop:
        s_print("Dropping CVEs collection...")
        VAULT_MONGO.get_default_database().drop_collection("cves")
        C.print_success("Dropped.")
    C.print_underline("Starting Collection and Insertion Procedure for CVEs")
    VAULT_MONGO.cves.insert_many(NVD_API.fetch_cves(**kwargs))
    C.print_success("Complete.")


if __name__ == "__main__":
    arg_parse = VaultArgumentParser(prog="VulnVault",
                                    epilog="Specific NVD API arguments can be passed via a "
                                           "-- suffix and can be in snake_case or camelCase. "
                                           "Example: --cvss_v3_severity=HIGH or "
                                           "--cvssV3Severity=HIGH")
    op_group = arg_parse.add_argument_group("Operations", "Main Operations, must choose one.")
    op_select = op_group.add_mutually_exclusive_group(required=True)
    op_select.add_argument("--initialfetch", action="store_true",
                           help="fetch CPEs and CVEs from NVD")
    op_select.add_argument("--cpefetch", action="store_true",
                           help="fetch CPEs from NVD")
    op_select.add_argument("--cvefetch", action="store_true",
                           help="fetch CVEs from NVD")
    op_augments = arg_parse.add_argument_group("Operation Augments")
    op_augments.add_argument("-p", "--purge", action="store_true", default=False,
                             help="purges selected collection before performing operation")
    args, api_options = arg_parse.parse_known_args()
    api_options = {api_options[i][2:]: api_options[i + 1] for i in range(0, len(api_options), 2)}

    config = VaultConfig(args.config)

    s_print("Connecting to MongoDB...")
    VAULT_MONGO = VaultMongoClient(config).raise_if_not_connected()
    C.print_success("Connected.")
    NVD_API = NVDFetch(config)

    if args.initialfetch:
        initial_load(drop=args.purge, **api_options)
    elif args.cpefetch:
        insert_cpes(drop=args.purge, **api_options)
    elif args.cvefetch:
        insert_cves(drop=args.purge, **api_options)
