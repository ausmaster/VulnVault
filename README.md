# VulnVault, an offline NVD CVE and CPE Database
NIST currently restricts NVD API usage to 50 requests with an API key and 5 requests without, per rolling 30 seconds.

For commercial usage, this is an issue when there are multiple users requesting NVD data. 

This solves this by storing a replica of NVD's CVE and CPE information in a MongoDB database.

## Usage
By default, VulnVault will attempt to load a configuration file located in the running directory called "config.json".
This can changed with the `-c` or `--config` command option with the path to the configuration file.

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

