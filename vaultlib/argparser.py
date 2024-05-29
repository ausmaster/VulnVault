from argparse import ArgumentParser


class VaultArgumentParser(ArgumentParser):
    def __init__(self):
        super().__init__()
        self.add_argument("-c", "--config", nargs=1, default="config.json",
                          help="configuration file path")
