"""Allow running as `python -m siemforge`."""

import sys

from siemforge.cli import main

if __name__ == "__main__":
    sys.exit(main())
