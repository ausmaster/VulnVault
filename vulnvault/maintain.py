"""
This is the script to run all maintainance functions to insert, delete, and update the MongoDB data.
"""
from __future__ import annotations
from datetime import datetime as Datetime
from typing import Callable

from pymongo import ReplaceOne

# pylint: disable=E0401,E0611
from lib import (
    NVDFetch,
    VaultArgumentParser,
    VaultConfig,
    VaultMongoClient,
    s_print
)
from lib import BColors as C

vault_mongo: VaultMongoClient
nvd_api: NVDFetch
arg_to_print_and_func: dict[str, tuple[str, Callable]]


class MetadataNotFoundException(Exception):
    """
    Exception raised when a metadata entry cannot be found.
    """


def setup(config_path: str) -> tuple[VaultMongoClient, NVDFetch, dict[str, tuple[str, Callable]]]:
    """
    Returns values for maintain.py global variables.

    :param config_path: Configuration file path
    :return: (VAULT_MONGO, NVDFetch, ARGS_TO_PRINT_AND_FUNC)
    """
    config = VaultConfig(config_path)
    s_print("Connecting to MongoDB...")
    client = VaultMongoClient(config).raise_if_not_connected()
    C.print_success("Connected.")
    api = NVDFetch(config)
    return client, api, {
        "cpes": ("CPEs", api.fetch_cpes),
        "cves": ("CVEs", api.fetch_cves),
        "cpematches": ("CPE matches", api.fetch_cpe_matches),
    }


def initial_load(now: Datetime) -> None:
    """
    Provides the initial procedure of fetching and insering data into
    all available collections from NVD.

    :param now: DateTime now
    :return: None
    """
    vault_mongo.db.drop_collection("metadata")
    insert_collection("cpes", now, drop=True)
    update_metadata("cpes", now)
    insert_collection("cves", now, drop=True)
    update_metadata("cves", now)
    insert_collection("cpematches", now, drop=True)
    update_metadata("cpematches", now)


def insert_collection(coll: str, now: Datetime, drop: bool = False, **kwargs) -> None:
    """
    Procedure for inserting API entries.

    :param coll: Collection name
    :param now: DateTime now
    :param drop: Drop collection before inserting entries
    :param kwargs: API keyward arguments
    :return: None
    """
    print_coll_str, api_call = arg_to_print_and_func[coll]
    if drop:
        drop_collection(coll)
    C.print_underline(f"Starting Collection and Insertion Procedure for {print_coll_str}")
    results = api_call(**kwargs)
    C.print_success("Collection complete.")
    s_print(f"Inserting {print_coll_str}...")
    getattr(vault_mongo, coll).insert_many(results)
    C.print_success("Collection and Insertion Complete.")
    update_metadata(coll, now)


def drop_collection(coll: str) -> None:
    """
    Procedure for dropping a selected collection.

    :param coll: Collection name
    :return: None
    """
    print_coll_str, _ = arg_to_print_and_func[coll]
    s_print(f"Dropping {print_coll_str} collection...")
    vault_mongo.db.drop_collection(coll)
    C.print_success("Dropped.")


def update_collection(coll: str, now: Datetime, **kwargs) -> None:
    """
    Procedure for updating collections.

    :param coll: Collection name
    :param now: DateTime now
    :param kwargs: API keyward arguments
    :return: None
    """
    print_coll_str, api_call = arg_to_print_and_func[coll]
    C.print_underline(f"Updating {print_coll_str} collection")
    metadata = vault_mongo.meta.find_one({"collection": coll})
    if not metadata or not (last_updated := metadata.get("updated")):
        raise MetadataNotFoundException(f"No {coll} metadata found")
    results: list[ReplaceOne] = [
        ReplaceOne({"_id": x["_id"]}, x, upsert=True)
        for x in api_call(
            last_mod_start_date=last_updated.isoformat(),
            last_mod_end_date=now.isoformat(),
            **kwargs
        )
    ]
    if results:
        counts = vault_mongo.cves.bulk_write(results)
        C.print_success("\n".join((
            f"{counts.upserted_count} {print_coll_str} Upserted."
            if counts.upserted_count else "",
            f"{counts.modified_count} {print_coll_str} Modified."
            if counts.modified_count else "",
            f"{counts.inserted_count} {print_coll_str} Inserted."
            if counts.inserted_count else ""
        )))
    else:
        C.print_fail(f"No {print_coll_str} to update.")
    update_metadata(coll, now)


def update_metadata(collection: str, datetime: Datetime) -> None:
    """
    Updates the metadata for the selected collection.

    :return: None
    """
    vault_mongo.meta.update_one(
        {"collection": collection},
        {"$set": {"updated": datetime}},
        upsert=True
    )


if __name__ == "__main__":
    arg_parse = VaultArgumentParser(prog="VulnVault Maintenance",
                                    epilog="Specific NVD API arguments can be passed via a "
                                           "-- suffix and can be in snake_case or camelCase. "
                                           "Example: --cvss_v3_severity HIGH or "
                                           "--cvssV3Severity HIGH")
    op_group = arg_parse.add_argument_group("Operations", "Main Operations, must choose one.")
    op_select = op_group.add_mutually_exclusive_group(required=True)
    op_select.add_argument("--init", action="store_true",
                           help="load all collections from NVD")
    op_select.add_argument("--fetchcpes", action="store_true",
                           help="fetch CPEs from NVD")
    op_select.add_argument("--fetchcves", action="store_true",
                           help="fetch CVEs from NVD")
    op_select.add_argument("--fetchcpematches", action="store_true",
                           help="fetch CPE matches from NVD")
    op_select.add_argument("--dropcpes", action="store_true",
                           help="purges all CPEs from CPE collection")
    op_select.add_argument("--dropcves", action="store_true",
                           help="purges all CVEs from CVE collection")
    op_select.add_argument("--dropcpematches", action="store_true",
                           help="purges all CPE matches from CPE match collection")
    op_select.add_argument("--updatecpes", action="store_true",
                           help="updates the CPE collection")
    op_select.add_argument("--updatecves", action="store_true",
                           help="updates the CVE collection")
    op_select.add_argument("--updatecpematches", action="store_true",
                           help="updates the CPE match collection")
    op_augments = arg_parse.add_argument_group("Operation Augments")
    op_augments.add_argument("-p", "--purge", action="store_true", default=False,
                             help="purges selected collection before performing operation. "
                                  "Only functional for fetch operations.")
    args, api_options = arg_parse.parse_known_args()
    api_options: dict[str, str] = {
        api_options[i][2:]: api_options[i + 1]
        for i in range(0, len(api_options), 2)
    }

    vault_mongo, nvd_api, arg_to_print_and_func = setup(args.config)

    d_now = Datetime.now()
    if args.init:
        initial_load(d_now)
    elif args.fetchcpes:
        insert_collection("cpes", d_now, drop=args.purge, **api_options)
    elif args.fetchcves:
        insert_collection("cves", d_now, drop=args.purge, **api_options)
    elif args.fetchcpematches:
        insert_collection("cpematches", d_now, drop=args.purge, **api_options)
    elif args.dropcpes:
        drop_collection("cpes")
    elif args.dropcves:
        drop_collection("cves")
    elif args.dropcpematches:
        drop_collection("cpematches")
    elif args.updatecpes:
        update_collection("cpes", d_now, **api_options)
    elif args.updatecves:
        update_collection("cves", d_now, **api_options)
    elif args.updatecpematches:
        update_collection("cpematches", d_now, **api_options)
