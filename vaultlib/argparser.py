"""
The universal parser for all future scripts.
"""
from argparse import ArgumentParser


class VaultArgumentParser(ArgumentParser):
    """
    A universal parser for all future scripts, can be extended later.
    """
    def __init__(self):
        super().__init__()
        self.add_argument("-c", "--config", nargs=1, default="config.json",
                          help="configuration file path")
