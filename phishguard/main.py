"""
main.py
--------
Single entry point for PhishGuard.

    python main.py            -> launches the desktop GUI
    python main.py --file ... -> runs the CLI (see cli.py for all flags)
"""

import sys
import os

# Ensure the parent directory (which contains the 'phishguard' package) is
# importable even when this script is run directly from inside the folder,
# e.g. `python main.py` from within phishguard/.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT_DIR = os.path.dirname(_THIS_DIR)
if _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)


def main():
    if len(sys.argv) > 1:
        from phishguard.cli import main as cli_main
        cli_main()
    else:
        from phishguard.gui import main as gui_main
        gui_main()


if __name__ == "__main__":
    main()
