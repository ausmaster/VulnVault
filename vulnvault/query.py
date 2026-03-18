"""
CLI entry point for VulnVault queries and public re-exports.
"""
from sys import stdout

import nltk

# Re-exports for public API
from vulnvault._query import VaultQuery  # noqa: F401
from vulnvault.async_query import AsyncVaultQuery  # noqa: F401

from vulnvault.lib import VaultArgumentParser, VaultConfig, VaultMongoClient
from vulnvault.lib import BColors as C


if __name__ == '__main__':
    arg_parse = VaultArgumentParser(prog="VulnVault Query")
    op_group = arg_parse.add_argument_group("Operations", "Main Operations, must choose one.")
    op_select = op_group.add_mutually_exclusive_group(required=True)
    op_select.add_argument("--cpe",
                           help="print CPE information about a specific CPE by CPE name")
    op_select.add_argument("--cpeid",
                           help="print CPE information about a specific CPE by CPE reference _id")
    op_select.add_argument("--cve",
                           help="print CVE information about a specfic CVE by CVE ID")
    op_select.add_argument("--cpe2cves",
                           help="print all CVEs given a CPE name")
    op_select.add_argument("--str2cpes",
                           help="prints closest matching CPE(s) given "
                                "string in the form '<VENDOR> <PRODUCT> <VERSION>'.")
    args = arg_parse.parse_args()

    config = VaultConfig(args.config)
    mngo_client = VaultMongoClient(config).raise_if_not_connected()

    print("Ensuring NLTK Model downloaded...")
    nltk.download(config.punkt_url, print_error_to=stdout)
    C.print_success("Complete.")

    query = VaultQuery(mongo_client=mngo_client)

    if args.cve:
        query.cve_id(args.cve, prnt=True)
    elif args.cpe:
        query.cpe_name(args.cpe, prnt=True)
    elif args.cpeid:
        query.cpe_ref(args.cpeid, prnt=True)
    elif args.cpe2cves:
        query.cpe_name_to_cves(args.cpe2cves, prnt=True)
    elif args.str2cpes:
        query.p_ml_find_cpe(args.str2cpes)
