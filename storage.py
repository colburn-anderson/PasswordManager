# storage.py

import sys
import json
from pathlib import Path

# config.json lives alongside your scripts/binary
CONFIG_FILE = Path(__file__).parent / "config.json"

def load_config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {}

def save_config(cfg: dict) -> None:
    CONFIG_FILE.write_text(json.dumps(cfg))

def get_usb_path() -> Path:
    # 1) If running as a PyInstaller bundle, use the exe's parent folder
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent

    # 2) Otherwise, try to load a saved path from config.json
    cfg = load_config()
    if "usb_path" in cfg:
        return Path(cfg["usb_path"])

    # 3) Fallback for development: prompt once, then save it
    p = Path(input("Enter your USB mount path: ").strip())
    save_config({"usb_path": str(p)})
    return p
