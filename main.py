from datetime import datetime

from vaultlib.api import NVDFetch
from vaultlib.argparser import VaultArgumentParser
from vaultlib.mongo import VaultMongoClient
from vaultlib.config import VaultConfig
from vaultlib.utils import BColors as c

NVD_API: NVDFetch
VAULT_MONGO: VaultMongoClient


def initial_load() -> None:
    global VAULT_MONGO, NVD_API
    print("Dropping CVEs collection... ", end="")
    VAULT_MONGO.get_default_database().drop_collection("cves")
    print(f"{c.OKGREEN}Dropped.{c.ENDC}")
    print(f"{c.UNDERLINE}Starting Collection and Insertion Procedure{c.ENDC}")
    VAULT_MONGO.cves.insert_many(NVD_API.fetch_cves())
    print(f"{c.OKGREEN}Complete.{c.ENDC}")


if __name__ == "__main__":
    arg_parse = VaultArgumentParser()
    arg_parse.add_argument("-f", "--initialfetch", action="store_true",
                           help="purge all CVEs and fetch all CVEs from NVD")
    args = arg_parse.parse_args()

    config = VaultConfig(args.config)
    print("Connecting to MongoDB... ", end="")
    VAULT_MONGO = VaultMongoClient(config).raise_if_not_connected()
    print(f"{c.OKGREEN}Connected.{c.ENDC}")
    NVD_API = NVDFetch(config)

    if args.initialfetch:
        initial_load()
