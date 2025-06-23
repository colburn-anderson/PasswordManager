# storage.py

import sys
from pathlib import Path

def get_usb_path() -> Path:
    """
    Return the folder containing:
      • the bundled executable (if frozen), or
      • this script file (when running under python).
    No prompts—always deterministic.
    """
    if getattr(sys, "frozen", False):
        # PyInstaller one‐file bundle
        return Path(sys.executable).parent
    # Dev mode: just use the directory where this file lives
    return Path(__file__).parent

def load_database(usb_path: Path = None) -> bytes | None:
    """
    Read and return the encrypted blob, or None if it doesn't exist.
    Accepts an optional usb_path (to satisfy calls that pass one), but
    always falls back to get_usb_path().
    """
    usb = Path(usb_path) if usb_path is not None else get_usb_path()
    f = usb / "passwords.enc"
    return f.read_bytes() if f.exists() else None

def save_database(blob: bytes, usb_path: Path = None) -> None:
    """
    Write the encrypted blob to passwords.enc.
    Accepts an optional usb_path (to satisfy calls that pass one), but
    always falls back to get_usb_path().
    """
    usb = Path(usb_path) if usb_path is not None else get_usb_path()
    out = usb / "passwords.enc"
    out.write_bytes(blob)
