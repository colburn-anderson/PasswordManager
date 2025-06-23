# utils.py

import secrets
import string
import threading
import time
import pyperclip

def generate_password(length: int = 16) -> str:
    """
    Build a random, high-entropy password of the given length.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def copy_to_clipboard(text: str, timeout: int = 30):
    """
    Copy `text` to the clipboard, then clear it after `timeout` seconds.
    """
    pyperclip.copy(text)
    def _clear():
        time.sleep(timeout)
        pyperclip.copy("")
    threading.Thread(target=_clear, daemon=True).start()
