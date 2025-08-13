"""
This is the script to run all maintainance functions to insert, delete, and update the MongoDB data.
"""
from __future__ import annotations
from datetime import datetime as Datetime
from typing import Callable

from time import sleep

from pymongo import ReplaceOne
from pymongo.errors import AutoReconnect, BulkWriteError, OperationFailure

# pylint: disable=E0401,E0611
from vulnvault.lib import (
    NVDFetch,
    VaultArgumentParser,
    VaultConfig,
    VaultMongoClient,
    s_print,
    AsyncVaultMongoClient,
)
from vulnvault.lib import BColors as C


class MetadataNotFoundException(Exception):
    """
    Exception raised when a metadata entry cannot be found.
    """

class VaultMaintenance:
    _mongo: VaultMongoClient | AsyncVaultMongoClient
    _async: bool
    _connected: bool

    _arg_to_print_and_func: dict[str, tuple[str, Callable]]

    def __init__(
            self,
            mongo_client: VaultMongoClient | AsyncVaultMongoClient | None = None,
            config_path: str = "config.json",
            create_async: bool = False,
            suppress_prnt: bool = False,
    ) -> None:
        config: VaultConfig

        if mongo_client:
            self._async = isinstance(mongo_client, AsyncVaultMongoClient)

            if self._async:
                # We cannot call raise_if_not_connected() here
                if not suppress_prnt:
                    print(
                        "Cannot connect to MongoDB ahead of time in async mode. "
                        "Run query first to establish connection."
                    )
                self._mongo = mongo_client
                self._connected = False
            else:
                if not suppress_prnt:
                    s_print("Connecting to MongoDB...")
                self._mongo = mongo_client.raise_if_not_connected()
                if not suppress_prnt:
                    C.print_success("Connected.")
                self._connected = True

            config = self._mongo.vv_config
        else:
            if create_async:
                # We cannot call raise_if_not_connected() here
                if not suppress_prnt:
                    print(
                        "Cannot connect to MongoDB ahead of time in async mode. "
                        "Run query first to establish connection."
                    )
                config = VaultConfig(config_path)
                self._mongo = AsyncVaultMongoClient(config)
                self._async = True
                self._connected = False
            else:
                if not suppress_prnt:
                    s_print("Connecting to MongoDB...")
                config = VaultConfig(config_path)
                self._mongo = VaultMongoClient(config).raise_if_not_connected()
                if not suppress_prnt:
                    C.print_success("Connected.")
                self._async = False
                self._connected = True

        api = NVDFetch(config)
        self._arg_to_print_and_func = {
            "cpes": ("CPEs", api.fetch_cpes),
            "cves": ("CVEs", api.fetch_cves),
            "cpematches": ("CPE matches", api.fetch_cpe_matches),
        }
        self._suppress_prnt = suppress_prnt
        self._config = config

    def initial_load(self, now: Datetime) -> None:
        """
        Provides the initial procedure of fetching and insering data into
        all available collections from NVD.

        :param now: DateTime now
        :return: None
        """
        self._mongo.db.drop_collection("metadata")
        self.insert_collection("cpes", now, drop=True)
        self.update_metadata("cpes", now)
        self.insert_collection("cves", now, drop=True)
        self.update_metadata("cves", now)
        self.insert_collection("cpematches", now, drop=True)
        self.update_metadata("cpematches", now)


    def insert_collection(self, coll: str, now: Datetime, drop: bool = False, **kwargs) -> None:
        """
        Procedure for inserting API entries.

        :param coll: Collection name
        :param now: DateTime now
        :param drop: Drop collection before inserting entries
        :param kwargs: API keyward arguments
        :return: None
        """
        print_coll_str, api_call = self._arg_to_print_and_func[coll]
        if drop:
            self.drop_collection(coll)
        if not self._suppress_prnt:
            C.print_underline(f"Starting Collection and Insertion Procedure for {print_coll_str}")
        results = api_call(**kwargs)
        if not self._suppress_prnt:
            C.print_success("Collection complete.")
            s_print(f"Inserting {print_coll_str}...")
        self._insert_many_with_retry(coll, results)
        if not self._suppress_prnt:
            C.print_success("Collection and Insertion Complete.")
        self.update_metadata(coll, now)

    def _insert_many_with_retry(self, coll: str, docs: list[dict]) -> None:
        batch_size = self._config.insert_batch_size
        total_batches = (len(docs) + batch_size - 1) // batch_size
        inserted = 0
        for i in range(0, len(docs), batch_size):
            batch = docs[i:i + batch_size]
            delay = self._config.conn_retry_delay
            for attempt in range(1, self._config.conn_retries + 1):
                try:
                    try:
                        getattr(self._mongo, coll).insert_many(batch, ordered=False, bypass_document_validation=True)
                    except OperationFailure as ofe:
                        if "bypassDocumentValidation" in str(ofe):
                            getattr(self._mongo, coll).insert_many(batch, ordered=False)
                        else:
                            raise
                    inserted += len(batch)
                    if not self._suppress_prnt:
                        print(f"Inserting {coll}: batch {i // batch_size + 1}/{total_batches} ({inserted}/{len(docs)} docs)", flush=True)
                    break
                except BulkWriteError as bwe:
                    # Ignore duplicate key errors, re-raise anything else
                    write_errors = bwe.details.get("writeErrors", []) if getattr(bwe, "details", None) else []
                    non_dup = [e for e in write_errors if e.get("code") != 11000]
                    if non_dup:
                        raise
                    inserted += len(batch)
                    if not self._suppress_prnt:
                        print(f"Duplicate key errors encountered on insert_many batch {i // batch_size + 1}, continuing.", flush=True)
                        print(f"Inserting {coll}: batch {i // batch_size + 1}/{total_batches} ({inserted}/{len(docs)} docs)", flush=True)
                    break
                except AutoReconnect as err:
                    if attempt == self._config.conn_retries:
                        raise
                    if not self._suppress_prnt:
                        print(f"AutoReconnect on insert_many batch {i // batch_size + 1}, retry {attempt} in {delay}s: {err}")
                    sleep(delay)
                    delay *= self._config.conn_retry_delay_mult


    def drop_collection(self, coll: str) -> None:
        """
        Procedure for dropping a selected collection.

        :param coll: Collection name
        :return: None
        """
        print_coll_str, _ = self._arg_to_print_and_func[coll]
        if not self._suppress_prnt:
            s_print(f"Dropping {print_coll_str} collection...")
        self._mongo.db.drop_collection(coll)
        if not self._suppress_prnt:
            C.print_success("Dropped.")


    def update_collection(self, coll: str, now: Datetime, **kwargs) -> None:
        """
        Procedure for updating collections.

        :param coll: Collection name
        :param now: DateTime now
        :param kwargs: API keyward arguments
        :return: None
        """
        print_coll_str, api_call = self._arg_to_print_and_func[coll]
        if not self._suppress_prnt:
            C.print_underline(f"Updating {print_coll_str} collection")
        metadata = self._mongo.meta.find_one({"collection": coll})
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
            total_inserted = 0
            total_modified = 0
            total_upserted = 0
            batch_size = self._config.insert_batch_size
            for i in range(0, len(results), batch_size):
                chunk = results[i:i + batch_size]
                delay = self._config.conn_retry_delay
                for attempt in range(1, self._config.conn_retries + 1):
                    try:
                        try:
                            res = getattr(self._mongo, coll).bulk_write(
                                chunk, ordered=False, bypass_document_validation=True
                            )
                        except OperationFailure as ofe:
                            if "bypassDocumentValidation" in str(ofe):
                                res = getattr(self._mongo, coll).bulk_write(chunk, ordered=False)
                            else:
                                raise
                        total_inserted += res.inserted_count
                        total_modified += res.modified_count
                        total_upserted += res.upserted_count
                        break
                    except AutoReconnect as err:
                        if attempt == self._config.conn_retries:
                            raise
                        if not self._suppress_prnt:
                            print(f"AutoReconnect on bulk_write batch {i // batch_size + 1}, retry {attempt} in {delay}s: {err}")
                        sleep(delay)
                        delay *= self._config.conn_retry_delay_mult
            if not self._suppress_prnt:
                C.print_success("\n".join((
                    f"{total_upserted} {print_coll_str} Upserted."
                    if total_upserted else "",
                    f"{total_modified} {print_coll_str} Modified."
                    if total_modified else "",
                    f"{total_inserted} {print_coll_str} Inserted."
                    if total_inserted else ""
                )))
        elif not self._suppress_prnt:
            C.print_fail(f"No {print_coll_str} to update.")
        self.update_metadata(coll, now)


    def update_metadata(self, coll: str, now: Datetime) -> None:
        """
        Updates the metadata for the selected collection.

        :return: None
        """
        self._mongo.meta.update_one(
            {"collection": coll},
            {"$set": {"updated": now}},
            upsert=True
        )


def main() -> None:
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

    maintain = VaultMaintenance(config_path=args.config)

    d_now = Datetime.now()
    if args.init:
        maintain.initial_load(d_now)
    elif args.fetchcpes:
        maintain.insert_collection("cpes", d_now, drop=args.purge, **api_options)
    elif args.fetchcves:
        maintain.insert_collection("cves", d_now, drop=args.purge, **api_options)
    elif args.fetchcpematches:
        maintain.insert_collection("cpematches", d_now, drop=args.purge, **api_options)
    elif args.dropcpes:
        maintain.drop_collection("cpes")
    elif args.dropcves:
        maintain.drop_collection("cves")
    elif args.dropcpematches:
        maintain.drop_collection("cpematches")
    elif args.updatecpes:
        maintain.update_collection("cpes", d_now, **api_options)
    elif args.updatecves:
        maintain.update_collection("cves", d_now, **api_options)
    elif args.updatecpematches:
        maintain.update_collection("cpematches", d_now, **api_options)


if __name__ == "__main__":
    main()
