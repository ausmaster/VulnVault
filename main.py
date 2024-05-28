from datetime import datetime

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database

from nvdhttp import NVDFetch
from vaultconfig import VaultConfig

config = VaultConfig()
mongo = MongoClient(config.mongo_host, config.mongo_port)
nvd_db: Database = mongo.nvd
nvd_db.drop_collection("cves")
cve_collection: Collection = nvd_db.cves
api = NVDFetch(config)
cves = api.fetch_cves(
    last_mod_start_date=datetime(2023, 1, 1).isoformat(),
    last_mod_end_date=datetime(2023, 4, 30).isoformat()
)
cve_collection.insert_many(cves)
