from typing import Self

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import ConnectionFailure

from .config import VaultConfig


class VaultMongoClient(MongoClient):
    def __init__(self, config: VaultConfig) -> None:
        super().__init__(f"mongodb://{config.mongo_host}/nvd", config.mongo_port)
        self.cves: Collection = self.get_default_database().cves

    def raise_if_not_connected(self, exception_str: str = "Unable to successfully connect to MongoDB, "
                                                          "check connectivity and configuration.") -> Self:
        """
        Ensures conenctivity. Returns self if successful, else raises ConnectionFailure.

        :param exception_str: Custom exception string to raise.
        :return: self
        """
        try:
            self.server_info()
        except ConnectionFailure:
            raise ConnectionFailure(exception_str)
        return self
