# encryption.py
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 256  # bytes; adjust if you want larger or variable padding

def derive_key(password: bytes, salt: bytes) -> bytes:
    """As before: PBKDF2-HMAC-SHA256 → 32-byte key."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password)

def _pad(data: bytes) -> bytes:
    """Pad data to the next multiple of BLOCK_SIZE with random bytes."""
    pad_len = (BLOCK_SIZE - (len(data) % BLOCK_SIZE)) or BLOCK_SIZE
    return data + os.urandom(pad_len)

def _unpad(padded: bytes) -> bytes:
    """
    Remove padding.
    WARNING: since we used random bytes, we can only infer original length
    by storing it in the header. We’ll prefix the payload with a 4-byte length.
    """
    orig_len = int.from_bytes(padded[:4], "big")
    return padded[4:4+orig_len]

def encrypt(plaintext: bytes, metadata: bytes, key: bytes) -> bytes:
    """
    Encrypts: [4-byte length][metadata||separator||plaintext] + padding,
    then AES-GCM → nonce + ciphertext+tag.
    """
    # 1) Build the clear payload
    sep = b"||"
    combined = metadata + sep + plaintext
    # 2) Prefix with length so we can unpad
    payload = len(combined).to_bytes(4, "big") + combined
    # 3) Pad to hide actual size
    padded = _pad(payload)

    # 4) Encrypt with AES-GCM
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, padded, associated_data=None)
    return nonce + ct

def decrypt(blob: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Reverses encrypt(): splits nonce, decrypts, unpads, and returns (metadata, plaintext).
    """
    aesgcm = AESGCM(key)
    nonce, ct = blob[:12], blob[12:]
    padded = aesgcm.decrypt(nonce, ct, associated_data=None)

    # Unpad and separate
    payload = _unpad(padded)
    metadata, plaintext = payload.split(b"||", 1)
    return metadata, plaintext
