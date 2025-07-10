"""
Provides Specialized MongoClient that works with VaultConfig.
"""
from __future__ import annotations

from typing import Self

from pymongo import MongoClient, AsyncMongoClient
from pymongo.asynchronous.collection import AsyncCollection
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import ConnectionFailure

from .api import CPESchema, CVESchema
from .config import VaultConfig


class VaultMongoClient(MongoClient):
    """
    A specific MongoClient dedicated to working with VaultConfig.
    """
    db: Database
    meta: Collection
    cpes: Collection[CPESchema]
    cves: Collection[CVESchema]
    cpematches: Collection
    vv_config: VaultConfig

    def __init__(self, config: VaultConfig, **kwargs) -> None:
        self.vv_config = config
        super().__init__(f"mongodb://{config.mongo_host}/nvd", config.mongo_port, **kwargs)
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
            self._connect()
        except ConnectionFailure as err:
            raise ConnectionFailure(exception_str) from err
        return self


class AsyncVaultMongoClient(AsyncMongoClient):
    """
    A specific MongoClient dedicated to working with VaultConfig.
    """
    db: AsyncDatabase
    meta: AsyncCollection
    cpes: AsyncCollection[CPESchema]
    cves: AsyncCollection[CVESchema]
    cpematches: AsyncCollection
    vv_config: VaultConfig

    def __init__(self, config: VaultConfig, **kwargs) -> None:
        self.vv_config = config
        super().__init__(f"mongodb://{config.mongo_host}/nvd", config.mongo_port, **kwargs)
        self.db: AsyncDatabase = self.get_default_database()
        self.meta: AsyncCollection = self.db.metadata
        self.cpes: AsyncCollection[CPESchema] = self.db.cpes
        self.cves: AsyncCollection[CVESchema] = self.db.cves
        self.cpematches: AsyncCollection = self.db.cpematches

    async def raise_if_not_connected(
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
            await self.aconnect()
        except ConnectionFailure as err:
            raise ConnectionFailure(exception_str) from err
        return self
