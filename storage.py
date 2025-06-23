# storage.py

import sys
import json
from pathlib import Path

# config.json lives alongside your script (only used in dev mode)
CONFIG_FILE = Path(__file__).parent / "config.json"

def load_config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {}

def save_config(cfg: dict) -> None:
    CONFIG_FILE.write_text(json.dumps(cfg))

def get_usb_path() -> Path:
    """
    1) If frozen (PyInstaller one-file), return the executable’s folder.
    2) Else, try to read a saved path from config.json.
    3) If no saved path, prompt once and persist it (development only).
    """
    if getattr(sys, "frozen", False):
        # bundled app: use its containing folder
        return Path(sys.executable).parent

    cfg = load_config()
    if "usb_path" in cfg:
        return Path(cfg["usb_path"])

    # dev fallback: ask once, then save for next time
    p = Path(input("Enter your USB mount path: ").strip())
    save_config({"usb_path": str(p)})
    return p

def save_database(blob: bytes) -> None:
    """
    Write the encrypted blob as passwords.enc in the USB folder.
    """
    path = get_usb_path() / "passwords.enc"
    path.write_bytes(blob)

def load_database() -> bytes | None:
    """
    Read and return the encrypted blob, or None if it doesn’t exist.
    """
    path = get_usb_path() / "passwords.enc"
    return path.read_bytes() if path.exists() else None
