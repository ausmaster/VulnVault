# VulnVault, an offline NVD CVE and CPE Database
NIST currently restricts NVD API usage to 50 requests with an API key and 5 requests without, per rolling 30 seconds.

For commercial usage, this is an issue when there are multiple users requesting NVD data. 

This solves this by storing a replica of NVD's CVE and CPE information in a MongoDB database.

Requires Python 3.8+
## Usage
By default, VulnVault will attempt to load a JSON configuration file located in the running directory called "config.json".
This can changed with the `-c` or `--config` command option with the path to the configuration file. 
All values in configuration file will override the default values. 
Below are the available options for the configuration file.
### config.json Options (defaults)
```JSON
{
  "nvdCveApi": "https://services.nvd.nist.gov/rest/json/cves/2.0",
  "nvdCveChApi": "https://services.nvd.nist.gov/rest/json/cvehistory/2.0",
  "nvdCpeApi": "https://services.nvd.nist.gov/rest/json/cpes/2.0",
  "nvdCpeMcApi": "https://services.nvd.nist.gov/rest/json/cpematch/2.0",
  "apiKey": "",
  "mongoHost": "localhost",
  "mongoPort": 27017,
  "connRetries": 3,
  "connRetryDelay": 10,
  "connRetryDelayMult": 3,
  "fetchThreads": 3
}
```
- nvdCveApi: NVD CVE API Endpoint
- nvdCveChApi: NVD CVE Change History API Endpoint
- nvdCpeApi: NVD CPE API Endpoint
- nvdCpeMcApi: NVD CPE Match Criteria API
- apiKey: NVD API Key
- mongoHost: MongoDB Docker Container Hostname
- mongoPort: MongoDB Docker Container Port
- connRetries: Connection Retry Limit
- connRetryDelay: Connection Retry Initial Sleep Duration in seconds
- connRetryDelayMult: Connection Retry Sleep Duration Multiplier. Ex: 10 secs w/ 3 mult - 1st retry 30 secs - 2nd retry 90 secs - 3rd retry 270 secs
- fetchThreads: Number of threads used to fetch API data

### Options
```
usage: VulnVault [-h] [-c CONFIG]
                 (--init | --cpefetch | --cvefetch | --dropcpe | --dropcve | --updatecpe | --updatecve)
                 [-p]

options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        configuration file path

Operations:
  Main Operations, must choose one.

  --init                fetch CPEs and CVEs from NVD
  --cpefetch            fetch CPEs from NVD
  --cvefetch            fetch CVEs from NVD
  --dropcpe             purges all CPEs from CPE collection
  --dropcve             purges all CVEs from CVE collection
  --updatecpe           updates the CPE collection
  --updatecve           updates the CVE collection

Operation Augments:
  -p, --purge           purges selected collection before performing operation

Specific NVD API arguments can be passed via a -- suffix and can be in
snake_case or camelCase. Example: --cvss_v3_severity HIGH or --cvssV3Severity
HIGH
```

