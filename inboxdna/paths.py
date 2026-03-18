"""Centralized path resolution for InboxDNA.

Package assets (templates, static, bundled credentials) live next to the code.
User data (database, OAuth token) lives in a platform-appropriate location
so it persists across upgrades and works correctly when installed via pip.

Data locations:
    pip install:  ~/.inboxdna/ (all platforms)
    Windows exe:  %LOCALAPPDATA%/InboxDNA
    macOS exe:    ~/Library/Application Support/InboxDNA
    Linux exe:    ~/.local/share/InboxDNA
    Override:     INBOXDNA_DATA_DIR environment variable
"""

import os
import platform
import sys

# Directory containing the package source files
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))

# User data directory — writable location for database and tokens
if os.environ.get("INBOXDNA_DATA_DIR"):
    USER_DATA_DIR = os.path.abspath(os.environ["INBOXDNA_DATA_DIR"])
elif getattr(sys, "frozen", False):
    # PyInstaller binary — use platform-appropriate app data directory
    _system = platform.system()
    if _system == "Windows":
        _base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    elif _system == "Darwin":
        _base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        _base = os.environ.get("XDG_DATA_HOME", os.path.join(os.path.expanduser("~"), ".local", "share"))
    USER_DATA_DIR = os.path.join(_base, "InboxDNA")
else:
    USER_DATA_DIR = os.path.join(os.path.expanduser("~"), ".inboxdna")

os.makedirs(USER_DATA_DIR, exist_ok=True)
