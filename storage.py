# storage.py

import sys
from pathlib import Path

def get_usb_path() -> Path:
    """
    Return the folder containing:
      • the bundled executable (if frozen), or
      • this script (when running under python).
    No prompts.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent

def load_database(*args) -> bytes | None:
    """
    Read and return the encrypted blob from passwords.enc,
    or None if it doesn't exist. Extra args are ignored.
    """
    path = get_usb_path() / "passwords.enc"
    return path.read_bytes() if path.exists() else None

def save_database(data: bytes, *args) -> None:
    """
    Write the encrypted blob to passwords.enc.
    Extra args are ignored.
    """
    path = get_usb_path() / "passwords.enc"
    path.write_bytes(data)
