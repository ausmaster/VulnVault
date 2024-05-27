from datetime import datetime
from nvdhttp import NVDFetch
from vaultconfig import VaultConfig

config = VaultConfig()
api = NVDFetch(config)
cves = api.fetch_cves(
    last_mod_start_date=datetime(2023, 1, 1).isoformat(),
    last_mod_end_date=datetime(2023, 4, 30).isoformat()
)
print(cves)