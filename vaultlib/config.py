"""
This is used to configure VulnVault based on a configuration file.
"""
from json import load
from pathlib import Path

from .utils import camel_to_snake


class VaultConfig:  # pylint: disable=R0902,R0903
    """
    Configuration of VulnVault.
    """
    def __init__(self, config_path: str = "config.json") -> None:
        # All config values have a default value and can be overridden via config.json file
        # NVD CVE API Endpoint
        self.nvd_cve_api: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        # NVD CVE Change History API Endpoint
        self.nvd_cve_ch_api: str = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
        # NVD CPE API Endpoint
        self.nvd_cpe_api: str = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        # NVD CPE Match Criteria API
        self.nvd_cpe_mc_api: str = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"
        # NVD API Key
        self.api_key: str = ""
        # MongoDB Docker Container Hostname
        self.mongo_host: str = "localhost"
        # MongoDB Docker Container Port
        self.mongo_port: int = 27017
        # Connection Retry Limit
        self.conn_retries: int = 3
        # Connection Retry Initial Sleep Duration in seconds
        self.conn_retry_delay: int = 10
        # Connection Retry Sleep Duration Multiplier
        # Ex: 10 secs w/ 3 mult - 1st retry 30 secs - 2nd retry 90 secs - 3rd retry 270 secs
        self.conn_retry_delay_mult: int = 3
        # Number of threads used to fetch API data
        self.fetch_threads: int = 3

        # All Config values from config.json are converted from camelCase to snake_case
        # overrides instance variable if exists
        if (config_path := Path(config_path)).exists():
            g_vars = dir(self)
            with open(config_path, "r", encoding="utf-8") as config_file:
                for config_key, config_value in load(config_file).items():
                    config_key = camel_to_snake(config_key)
                    if config_key not in g_vars:
                        continue

                    if (g_var_type := type(getattr(self, config_key))) is not str:
                        setattr(self, config_key, g_var_type(config_value))
                    else:
                        setattr(self, config_key, config_value)

    def __repr__(self) -> str:
        return f"VaultConfig({vars(self)})"
