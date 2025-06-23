# manager.py

from dataclasses import dataclass
from typing import List, Optional
import json
import base64

from encryption import encrypt, decrypt
from storage import save_database, load_database

@dataclass
class PasswordEntry:
    """Stores everything except the decrypted password."""
    label: str
    username: str
    encrypted_password: bytes
    notes: Optional[str] = None

    def get_password(self, key: bytes) -> str:
        """
        Decrypts only this entry’s password on demand.
        Returns it as a Python str.
        """
        # decrypt() returns (metadata, plaintext_bytes)
        _, plaintext = decrypt(self.encrypted_password, key)
        return plaintext.decode()

    def to_dict(self) -> dict:
        """
        Prepare for JSON serialization:
        - Base64-encode the encrypted blob so it’s JSON-safe.
        """
        return {
            "label":    self.label,
            "username": self.username,
            "password": base64.b64encode(self.encrypted_password).decode(),
            "notes":    self.notes
        }

    @staticmethod
    def from_dict(d: dict) -> "PasswordEntry":
        """Reconstruct an entry from the JSON dict."""
        return PasswordEntry(
            label=d["label"],
            username=d["username"],
            encrypted_password=base64.b64decode(d["password"]),
            notes=d.get("notes")
        )

class PasswordManager:
    """Holds only encrypted entries until get_password() is called."""
    def __init__(self, entries: List[PasswordEntry] = None):
        self._entries = entries or []

    @classmethod
    def load(cls, key: bytes) -> "PasswordManager":
        raw = load_database(key)
        if raw is None:
            return cls()
        arr = json.loads(raw.decode())
        entries = [PasswordEntry.from_dict(d) for d in arr]
        return cls(entries)

    def save(self, key: bytes):
        arr = [e.to_dict() for e in self._entries]
        data = json.dumps(arr).encode()
        save_database(data, key)

    def add_entry(self, label: str, username: str,
                  plaintext_password: str, notes: Optional[str],
                  key: bytes):
        # Encrypt on ingest; metadata = label||username so it’s authenticated too
        meta = f"{label}||{username}".encode()
        blob = encrypt(plaintext_password.encode(), meta, key)
        self._entries.append(PasswordEntry(label, username, blob, notes))

    def list_entries(self) -> List[PasswordEntry]:
        return list(self._entries)

    def find_entries(self, keyword: str) -> List[PasswordEntry]:
        kw = keyword.lower()
        return [e for e in self._entries
                if kw in e.label.lower() or kw in e.username.lower()]

    def update_entry(self, index: int,
                     label: Optional[str], username: Optional[str],
                     plaintext_password: Optional[str],
                     notes: Optional[str], key: bytes) -> bool:
        try:
            e = self._entries[index]
        except IndexError:
            return False

        if label is not None:
            e.label = label
        if username is not None:
            e.username = username
        if plaintext_password is not None:
            meta = f"{e.label}||{e.username}".encode()
            e.encrypted_password = encrypt(plaintext_password.encode(), meta, key)
        if notes is not None:
            e.notes = notes
        return True

    def delete_entry(self, index: int) -> bool:
        try:
            self._entries.pop(index)
            return True
        except IndexError:
            return False
