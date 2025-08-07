"""Entry point for running Crowd VPN as a module."""

import sys
from .cli import cli

if __name__ == '__main__':
    sys.exit(cli())

