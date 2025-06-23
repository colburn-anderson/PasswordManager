# auth.py

import bcrypt
import getpass
import re
from pathlib import Path
from encryption import derive_key
from storage import get_usb_path

MIN_PASSWORD_LENGTH = 12

# Paths on the USB (via storage.get_usb_path())
USB = get_usb_path()
MASTER_HASH_FILE = USB / "master.hash"
KEY_SALT_FILE    = USB / "key_salt.bin"

def check_password_strength(pw: str) -> bool:
    if len(pw) < MIN_PASSWORD_LENGTH:
        print(f"❌ Too short (min {MIN_PASSWORD_LENGTH} chars).")
        return False
    categories = sum(bool(re.search(cls, pw)) for cls in 
                     [r"[A-Z]", r"[a-z]", r"[0-9]", r"[^\w]"])
    if categories < 3:
        print("❌ Must include at least three of: uppercase, lowercase, digits, symbols.")
        return False
    return True

def create_master_password():
    while True:
        pw1 = getpass.getpass("Create a master password: ")
        pw2 = getpass.getpass("Confirm master password: ")
        if pw1 != pw2:
            print("❌ Passwords don’t match. Try again.")
            continue
        if not check_password_strength(pw1):
            continue
        break

    password_bytes = pw1.encode()
    # 1) Store bcrypt hash for login
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    MASTER_HASH_FILE.write_bytes(hashed)
    # 2) Store salt for key derivation
    salt = bcrypt.gensalt()
    KEY_SALT_FILE.write_bytes(salt)

    print("✅ Master password set and key‐salt stored on USB.")

def verify_master_password() -> bytes | None:
    if not MASTER_HASH_FILE.exists():
        print("ℹ️ No master password found. Let’s create one.")
        create_master_password()
        return None

    pw = getpass.getpass("Enter master password: ").encode()
    stored = MASTER_HASH_FILE.read_bytes()
    if not bcrypt.checkpw(pw, stored):
        print("❌ Access denied.")
        return None

    print("✅ Access granted.")
    # Derive and return the AES key
    salt = KEY_SALT_FILE.read_bytes()
    return derive_key(pw, salt)

def change_master_password() -> bytes | None:
    """
    Verify current master password, then prompt for a new one,
    re‐salt and re‐hash, and return the new AES key.
    """
    # 1) Verify current
    current_pw = getpass.getpass("Enter current master password: ").encode()
    stored = MASTER_HASH_FILE.read_bytes()
    if not bcrypt.checkpw(current_pw, stored):
        print("❌ Current password incorrect.")
        return None

    # 2) Prompt & validate new
    while True:
        pw1 = getpass.getpass("New master password: ")
        pw2 = getpass.getpass("Confirm new password: ")
        if pw1 != pw2:
            print("❌ Passwords don’t match.")
            continue
        if not check_password_strength(pw1):
            continue
        break

    new_bytes = pw1.encode()
    # 3) Write new bcrypt hash
    new_hash = bcrypt.hashpw(new_bytes, bcrypt.gensalt())
    MASTER_HASH_FILE.write_bytes(new_hash)
    # 4) Generate & store new salt for key derivation
    new_salt = bcrypt.gensalt()
    KEY_SALT_FILE.write_bytes(new_salt)
    # 5) Derive & return new key
    new_key = derive_key(new_bytes, new_salt)
    print("✅ Master password changed.")
    return new_key


def set_master_password_from_string(pw: str) -> bytes:
    """
    Create a new master password from the given string.
    Returns the derived AES key.
    """
    password_bytes = pw.encode()
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    MASTER_HASH_FILE.write_bytes(hashed)
    salt = bcrypt.gensalt()
    KEY_SALT_FILE.write_bytes(salt)
    return derive_key(password_bytes, salt)

def verify_master_password_from_string(pw: str) -> bytes | None:
    """
    Verify the given master-password string.
    Returns the derived AES key, or None on failure/not-found.
    """
    if not MASTER_HASH_FILE.exists():
        return None
    password_bytes = pw.encode()
    stored = MASTER_HASH_FILE.read_bytes()
    if not bcrypt.checkpw(password_bytes, stored):
        return None
    salt = KEY_SALT_FILE.read_bytes()
    return derive_key(password_bytes, salt)
