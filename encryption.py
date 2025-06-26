# encryption.py

import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


BLOCK_SIZE = 256

def derive_key(password: bytes, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 → 32-byte key."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt(plaintext:bytes, metadata: bytes, key: bytes) -> bytes:
    """
    Combine metadata||plaintest and AES-GCM encrypt:
        ciphertext = AESGCM(key).encrypt(nonce, metadata||b'||'||plaintext, None)
        Returns nonce||ciphertext.
    """
    combined = metadata + b"||" + plaintext
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, combined, None)
    return nonce + ct

def decrypt(blob: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Splits nonce||ciphertext, decrypts with AES-GCM,
    then splits metadata||plaintext. Returns (metadata, plaintext).
    """
    aesgcm = AESGCM(key)
    nonce, ct = blob[:12], blob[12:]
    combined  = aesgcm.decrypt(nonce, ct, None)
    metadata, plaintext = combined.split(b"||", 1)
    return metadata, plaintext
