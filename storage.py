# storage.py

import sys
from pathlib import Path

def get_usb_path() -> Path:
    """
    Always return the folder containing:
      • the bundled executable (if frozen), or
      • this script (when running under python).
    No prompts.
    """
    if getattr(sys, "frozen", False):
        # PyInstaller bundle
        return Path(sys.executable).parent
    # Development: use the directory where storage.py lives
    return Path(__file__).parent

def save_database(blob: bytes) -> None:
    """
    Write the encrypted blob to passwords.enc in the USB path.
    """
    path = get_usb_path() / "passwords.enc"
    path.write_bytes(blob)

def load_database() -> bytes | None:
    """
    Read and return passwords.enc, or None if it doesn't exist.
    """
    path = get_usb_path() / "passwords.enc"
    return path.read_bytes() if path.exists() else None
