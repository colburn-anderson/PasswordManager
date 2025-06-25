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

def _pad(data: bytes) -> bytes:
    """
    Prefix a 4-byte big-endian length, then pad with random bytes
    up to the next multiple of BLOCK_SIZE.
    """
    length = len(data).to_bytes(4, "big")
    payload = length + data
    pad_len = (BLOCK_SIZE - len(payload) % BLOCK_SIZE) or BLOCK_SIZE
    return payload + os.urandom(pad_len)

def _unpad(padded: bytes) -> bytes:
    """
    Read the 4-byte length, then strip off that many plaintext bytes.
    """
    orig_len = int.from_bytes(padded[:4], "big")
    return padded[4:4 + orig_len]

def encrypt(plaintext: bytes, metadata: bytes, key: bytes) -> bytes:
    """
    Encrypts:
      pad( [4-byte len][metadata || b'||' || plaintext] )
    then AES-GCM over nonce || ciphertext.
    Returns nonce || ct.
    """
    combined = metadata + b"||" + plaintext
    padded   = _pad(combined)
    aesgcm   = AESGCM(key)
    nonce    = os.urandom(12)
    ct       = aesgcm.encrypt(nonce, padded, None)
    return nonce + ct

def decrypt(blob: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Splits nonce||ct, decrypts, unpads, then splits metadata||plaintext.
    Returns (metadata, plaintext).
    """
    aesgcm   = AESGCM(key)
    nonce, ct = blob[:12], blob[12:]
    padded    = aesgcm.decrypt(nonce, ct, None)
    combined  = _unpad(padded)
    metadata, plaintext = combined.split(b"||", 1)
    return metadata, plaintext
