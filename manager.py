# manager.py

import json
from dataclasses import dataclass, asdict
from typing import List

from encryption import encrypt, decrypt
from storage    import load_database, save_database

@dataclass
class Entry:
    label:    str
    username: str
    password: str
    notes:    str | None

    def get_password(self) -> str:
        return self.password

class PasswordManager:
    def __init__(self, entries: List[Entry] = None):
        self._entries = entries or []

    @classmethod
    def load(cls, key: bytes) -> "PasswordManager":
        blob = load_database()
        if blob is None:
            return cls()
        # metadata is ignored (you can store timestamps if you want)
        _, payload = decrypt(blob, key)
        raw = json.loads(payload.decode("utf-8"))
        entries = [Entry(**r) for r in raw]
        return cls(entries)

    def save(self, key: bytes) -> None:
        raw  = [asdict(e) for e in self._entries]
        data = json.dumps(raw).encode("utf-8")
        # metadata empty (b""), since everything is in JSON
        blob = encrypt(data, b"", key)
        save_database(blob)

    def list_entries(self) -> List[Entry]:
        return self._entries

    def add_entry(self,
                  label:    str,
                  username: str,
                  password: str,
                  notes:    str | None,
                  key:      bytes) -> None:
        self._entries.append(Entry(label, username, password, notes))
        self.save(key)

    def update_entry(self,
                     idx:      int,
                     label:    str | None,
                     username: str | None,
                     password: str | None,
                     notes:    str | None,
                     key:      bytes) -> None:
        e = self._entries[idx]
        if label    is not None: e.label    = label
        if username is not None: e.username = username
        if password is not None: e.password = password
        if notes    is not None: e.notes    = notes
        self.save(key)

    def delete_entry(self, idx: int, key: bytes) -> None:
        del self._entries[idx]
        self.save(key)
