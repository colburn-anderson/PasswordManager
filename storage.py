# storage.py

import sys
from pathlib import Path

def get_usb_path() -> Path:
    """
    • When frozen (PyInstaller one-file), sys.argv[0] is the real bundle.
    • In dev, use this script’s folder.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.argv[0]).resolve().parent
    return Path(__file__).parent

def load_database(*args) -> bytes | None:
    """
    Read passwords.enc from the USB folder. Extra args ignored.
    """
    p = get_usb_path() / "passwords.enc"
    return p.read_bytes() if p.exists() else None

def save_database(data: bytes, *args) -> None:
    """
    Write passwords.enc into the USB folder. Extra args ignored.
    """
    p = get_usb_path() / "passwords.enc"
    p.write_bytes(data)
