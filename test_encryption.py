# test_encryption.py

from auth import verify_master_password
from encryption import encrypt, decrypt

def main():
    # 1) Get your AES key (you’ll be prompted for your master password)
    key = verify_master_password()
    if not key:
        return

    # 2) Define some test data
    metadata  = b"UnitTestMeta"
    plaintext = b"The quick brown fox jumps over the lazy dog."

    # 3) Encrypt + decrypt
    blob = encrypt(plaintext, metadata, key)
    out_meta, out_plain = decrypt(blob, key)

    # 4) Check results
    print("Metadata OK: ", out_meta == metadata)
    print("Plaintext OK:", out_plain == plaintext)

if __name__ == "__main__":
    main()
