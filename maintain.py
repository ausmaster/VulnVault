"""
This is the script to run all maintainance functions to insert, delete, and update the MongoDB data.
"""
from __future__ import annotations
from datetime import datetime as Datetime

from pymongo import ReplaceOne

# pylint: disable=E0401,E0611
from vaultlib import NVDFetch, VaultArgumentParser, VaultConfig, VaultMongoClient, s_print
from vaultlib import BColors as C

NVD_API: NVDFetch | None = None
VAULT_MONGO: VaultMongoClient | None = None


def update_metadata(collection: str, datetime: Datetime) -> None:
    """
    Updates the metadata for the selected collection.

    :return: None
    """
    VAULT_MONGO.meta.update_one({"collection": collection}, {"$set": {"updated": datetime}})


def drop_metadata() -> None:
    """
    Drops the metadata collection.

    :return: None
    """
    VAULT_MONGO.db.drop_collection("metadata")


def initial_load() -> None:
    """
    Provides the initial procedure of loading all CVEs and CPEs from NVD.

    :return: None
    """
    now = Datetime.now()
    drop_metadata()
    insert_cpes(drop=True)
    update_metadata("cpes", now)
    insert_cves(drop=True)
    update_metadata("cves", now)


def insert_cpes(drop: bool = False, **kwargs) -> None:
    """
    Insert procudure for inserting CPEs.

    :param drop: Drop collection before inserting CPEs.
    :return: None
    """
    if drop:
        drop_cpes()
    C.print_underline("Starting Collection and Insertion Procedure for CPEs")
    VAULT_MONGO.cpes.insert_many(NVD_API.fetch_cpes(**kwargs))
    C.print_success("Complete.")


def drop_cpes() -> None:
    """
    Procedure for dropping all CPEs from CPE collection.

    :return: None
    """
    s_print("Dropping CPEs collection...")
    VAULT_MONGO.db.drop_collection("cpes")
    C.print_success("Dropped.")


def update_cpes(**kwargs) -> None:
    """
    Procedure for updating CPEs in CPE collection.

    :return: None
    """
    C.print_underline("Updating CPEs collection")
    counts = VAULT_MONGO.cpes.bulk_write(
        [ReplaceOne({"_id": cpe["_id"]}, cpe, upsert=True) for cpe in NVD_API.fetch_cpes(**kwargs)]
    )
    C.print_success(f"{f'{counts.inserted_count} CPEs Inserted. ' if counts.inserted_count else ''}"
                    f"{counts.modified_count} CPEs Updated.")


def insert_cves(drop: bool = False, **kwargs) -> None:
    """
    Insert procudure for inserting CVEs.

    :param drop: Drop collection before inserting CVEs.
    :return: None
    """
    if drop:
        drop_cves()
    C.print_underline("Starting Collection and Insertion Procedure for CVEs")
    VAULT_MONGO.cves.insert_many(NVD_API.fetch_cves(**kwargs))
    C.print_success("Complete.")


def drop_cves() -> None:
    """
    Procedure for dropping all CVEs from CVE collection.

    :return: None
    """
    s_print("Dropping CVEs collection...")
    VAULT_MONGO.db.drop_collection("cves")
    C.print_success("Dropped.")


def update_cves(**kwargs) -> None:
    """
    Procedure for updating CPEs in CPE collection.

    :return: None
    """
    C.print_underline("Updating CVEs collection")
    counts = VAULT_MONGO.cves.bulk_write(
        [ReplaceOne({"_id": cve["_id"]}, cve, upsert=True) for cve in NVD_API.fetch_cves(**kwargs)]
    )
    C.print_success(f"{f'{counts.inserted_count} CVEs Inserted. ' if counts.inserted_count else ''}"
                    f"{counts.modified_count} CVEs Updated.")


if __name__ == "__main__":
    arg_parse = VaultArgumentParser(prog="VulnVault",
                                    epilog="Specific NVD API arguments can be passed via a "
                                           "-- suffix and can be in snake_case or camelCase. "
                                           "Example: --cvss_v3_severity HIGH or "
                                           "--cvssV3Severity HIGH")
    op_group = arg_parse.add_argument_group("Operations", "Main Operations, must choose one.")
    op_select = op_group.add_mutually_exclusive_group(required=True)
    op_select.add_argument("--init", action="store_true",
                           help="fetch CPEs and CVEs from NVD")
    op_select.add_argument("--cpefetch", action="store_true",
                           help="fetch CPEs from NVD")
    op_select.add_argument("--cvefetch", action="store_true",
                           help="fetch CVEs from NVD")
    op_select.add_argument("--dropcpe", action="store_true",
                           help="purges all CPEs from CPE collection")
    op_select.add_argument("--dropcve", action="store_true",
                           help="purges all CVEs from CVE collection")
    op_select.add_argument("--updatecpe", action="store_true",
                           help="updates the CPE collection")
    op_select.add_argument("--updatecve", action="store_true",
                           help="updates the CVE collection")
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

    if args.init:
        initial_load()
    elif args.cpefetch:
        insert_cpes(drop=args.purge, **api_options)
    elif args.cvefetch:
        insert_cves(drop=args.purge, **api_options)
    elif args.dropcpe:
        drop_cpes()
    elif args.dropcve:
        drop_cves()
    elif args.updatecpe:
        update_cpes(**api_options)
    # elif args.updatecve:
    #     update_cves()
