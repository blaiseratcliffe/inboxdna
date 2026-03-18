"""Build a standalone executable using PyInstaller.

Works on Windows, macOS, and Linux. Produces a single-file binary
that includes all dependencies, templates, and bundled OAuth credentials.

Usage:
    pip install pyinstaller
    python build_exe.py

Output:
    Windows: dist/InboxDNA.exe
    macOS:   dist/InboxDNA (Unix binary)
    Linux:   dist/InboxDNA (Unix binary)
"""

import glob
import os
import platform
import PyInstaller.__main__

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "inboxdna")

# Find the bundled client secret
client_secrets = glob.glob(os.path.join(PKG, "client_secret_*.json"))
if not client_secrets:
    raise FileNotFoundError("No client_secret_*.json found in inboxdna/")

datas = [
    (os.path.join(PKG, "templates"), "inboxdna/templates"),
    (os.path.join(PKG, "static"), "inboxdna/static"),
    (client_secrets[0], "inboxdna"),
]

system = platform.system()

args = [
    os.path.join(PKG, "app.py"),
    "--name=InboxDNA",
    "--onefile",
    "--console",
    *[f"--add-data={src}{os.pathsep}{dst}" for src, dst in datas],
    "--hidden-import=inboxdna",
    "--hidden-import=inboxdna.paths",
    "--hidden-import=inboxdna.auth",
    "--hidden-import=inboxdna.db",
    "--hidden-import=inboxdna.classifiers",
    "--distpath=dist",
    "--workpath=build",
    "--noconfirm",
]

# macOS: create a .app bundle as well
if system == "Darwin":
    args.append("--osx-bundle-identifier=com.inboxdna.app")

PyInstaller.__main__.run(args)

ext = ".exe" if system == "Windows" else ""
print(f"\nBuild complete! Executable: dist/InboxDNA{ext}")
