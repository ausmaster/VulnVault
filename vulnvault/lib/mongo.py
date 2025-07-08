"""
Provides Specialized MongoClient that works with VaultConfig.
"""
from __future__ import annotations

from typing import Self

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import ConnectionFailure

from .api import CPESchema, CVESchema
from .config import VaultConfig


class VaultMongoClient(MongoClient):
    """
    A specific MongoClient dedicated to working with VaultConfig.
    """
    def __init__(self, config: VaultConfig) -> None:
        self.vv_config = config
        super().__init__(f"mongodb://{config.mongo_host}/nvd", config.mongo_port)
        self.db: Database = self.get_default_database()
        self.meta: Collection = self.db.metadata
        self.cpes: Collection[CPESchema] = self.db.cpes
        self.cves: Collection[CVESchema] = self.db.cves
        self.cpematches: Collection = self.db.cpematches

    def raise_if_not_connected(
            self,
            exception_str: str = "Unable to successfully connect to MongoDB, "
                                 "check connectivity and configuration."
    ) -> Self:
        """
        Ensures conenctivity. Returns self if successful, else raises ConnectionFailure.

        :param exception_str: Custom exception string to raise.
        :return: self
        """
        try:
            self.server_info()
        except ConnectionFailure as err:
            raise ConnectionFailure(exception_str) from err
        return self
