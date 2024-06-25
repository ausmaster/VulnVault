# VulnVault, an offline NVD CVE and CPE Database
NIST currently restricts NVD API usage to 50 requests with an API key and 5 requests without, per rolling 30 seconds.

For commercial usage, this is an issue when there are multiple users requesting NVD data. 

This solves this by storing a replica of NVD's CVE and CPE information in a localized MongoDB database.

Requires Python 3.8+
## Features
### Implemented
* Given a CPE name (ex: cpe:2.3:a:nsa:ghidra:9.2:\*:\*:\*:\*:\*:\*:\*) or CPE ID, find all CVEs.
### In Progress
* Machine Learning to obtain CPEs (and CVEs) from plain text entries.
## Usage
By default, VulnVault will attempt to load a JSON configuration file located in the running directory called "config.json" 
(if it exists, else will use default values).
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
  "fetchThreads": 3,
  "punktUrl": "punkt"
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
- punktUrl: URL to fetch NLTK "Punkt" pre-trained model, defaults to their repository

### maintain.py Options
```
usage: VulnVault Maintenance [-h] [-c CONFIG]
                             (--init | --fetchcpes | --fetchcves | --fetchcpematches | --dropcpes | --dropcves | --dropcpematches | --updatecpes | --updatecves | --updatecpematches)
                             [-p]

options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        configuration file path

Operations:
  Main Operations, must choose one.

  --init                load all collections from NVD
  --fetchcpes           fetch CPEs from NVD
  --fetchcves           fetch CVEs from NVD
  --fetchcpematches     fetch CPE matches from NVD
  --dropcpes            purges all CPEs from CPE collection
  --dropcves            purges all CVEs from CVE collection
  --dropcpematches      purges all CPE matches from CPE match collection
  --updatecpes          updates the CPE collection
  --updatecves          updates the CVE collection
  --updatecpematches    updates the CPE match collection

Operation Augments:
  -p, --purge           purges selected collection before performing
                        operation. Only functional for fetch operations.

Specific NVD API arguments can be passed via a -- suffix and can be in
snake_case or camelCase. Example: --cvss_v3_severity HIGH or --cvssV3Severity
HIGH
```

### query.py Options
```
usage: VulnVault Query [-h] [-c CONFIG]
                       (--cpe CPE | --cpeid CPEID | --cve CVE | --cpe2cves CPE2CVES | --str2cpes STR2CPES)

options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        configuration file path

Operations:
  Main Operations, must choose one.

  --cpe CPE             print CPE information about a specific CPE by CPE name
  --cpeid CPEID         print CPE information about a specific CPE by CPE ID
  --cve CVE             print CVE information about a specfic CVE by CVE ID
  --cpe2cves CPE2CVES   print all CVEs given a CPE name
  --str2cpes STR2CPES   find closest matching CPE given string in the form
                        '<VENDOR> <PRODUCT> <VERSION>'
```

