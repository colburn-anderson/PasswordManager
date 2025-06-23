# storage.py

import sys
import json
from pathlib import Path
from encryption import encrypt, decrypt

# ─── Base directory resolution ────────────────────────────────────────────────
# If frozen by PyInstaller, BASE_DIR is the folder containing the EXE;
# otherwise it’s the folder containing this script.
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent

# ─── Config file ──────────────────────────────────────────────────────────────
CONFIG_FILE = BASE_DIR / "config.json"

def load_config() -> dict:
    """Return parsed config.json, or empty dict if missing/invalid."""
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_config(cfg: dict):
    """Write the given dict to config.json (pretty-printed)."""
    CONFIG_FILE.write_text(json.dumps(cfg, indent=4))

def prompt_for_usb_path() -> Path:
    """
    Prompt user until they enter a valid USB mount directory.
    Examples:
      - WSL/Windows: /mnt/d
      - macOS:       /Volumes/MyUSB
      - Linux:       /media/$USER/MyUSB
    """
    while True:
        p = Path(input("Enter your USB mount path: ").strip())
        if p.exists() and p.is_dir():
            return p
        print("❌ Path not found or not a directory; try again.")

def get_usb_path() -> Path:
    """
    Load the saved usb_path from config.json (if valid),
    otherwise prompt & save it for next time.
    """
    cfg = load_config()
    if "usb_path" in cfg:
        candidate = Path(cfg["usb_path"])
        if candidate.exists() and candidate.is_dir():
            return candidate
        print(f"⚠️ Saved path {candidate} not found.")
    usb = prompt_for_usb_path()
    cfg["usb_path"] = str(usb)
    save_config(cfg)
    return usb

# ─── Determine USB root & data file ─────────────────────────────────────────
USB       = get_usb_path()
DATA_FILE = USB / "passwords.enc"
METADATA  = b"DBv1"   # version tag for your encrypted DB

def save_database(json_bytes: bytes, key: bytes):
    """
    Encrypt the JSON bytes (with METADATA) and atomically write to DATA_FILE.
    """
    blob = encrypt(json_bytes, METADATA, key)
    tmp = DATA_FILE.with_suffix(".tmp")
    tmp.write_bytes(blob)
    tmp.replace(DATA_FILE)

def load_database(key: bytes) -> bytes | None:
    """
    Read & decrypt DATA_FILE. Returns plaintext JSON bytes,
    or None if the file doesn’t exist yet.
    """
    if not DATA_FILE.exists():
        return None
    blob = DATA_FILE.read_bytes()
    meta, plaintext = decrypt(blob, key)
    if meta != METADATA:
        raise ValueError("Unexpected database format")
    return plaintext
