# main.py

import getpass
from auth import verify_master_password, change_master_password
from manager import PasswordManager, PasswordEntry
from utils import generate_password, copy_to_clipboard

def prompt_entry_fields(existing: PasswordEntry = None):
    """
    Ask the user for label, username, password, notes.
    If `existing` is provided, show current values and allow skipping.
    Returns a tuple (label, username, password, notes).
    """
    if existing:
        print(f"Press Enter to keep current value in [brackets].")
        label    = input(f"Label [{existing.label}]: ").strip() or existing.label
        username = input(f"Username [{existing.username}]: ").strip() or existing.username
        pwd      = getpass.getpass("Password [hidden]: ")
        password = pwd or None
        notes    = input(f"Notes [{existing.notes or ''}]: ").strip()
        notes    = notes if notes != "" else existing.notes
    else:
        label    = input("Label: ").strip()
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        notes    = input("Notes (optional): ").strip() or None

    return label, username, password, notes

def main():
    print("=== USB Password Manager ===")
    key = verify_master_password()
    if not key:
        return

    pm = PasswordManager.load(key)

    while True:
        print("""
Menu:
  1) Add new entry
  2) List all entries
  3) View entry (decrypt & copy)
  4) Update entry
  5) Delete entry
  6) Change master password
  7) Generate a secure password
  8) Exit
""")
        choice = input("Option (1–8): ").strip()

        if choice == "1":
            label, user, pwd, notes = prompt_entry_fields()
            pm.add_entry(label, user, pwd, notes, key)
            print("✅ Entry added.")

        elif choice == "2":
            for i, e in enumerate(pm.list_entries()):
                print(f"{i}: {e.label} ({e.username})")

        elif choice == "3":
            idx = int(input("Index to view: ").strip())
            try:
                e = pm.list_entries()[idx]
                secret = e.get_password(key)
                copy_to_clipboard(secret)
                print(f"🔑 {e.label} / {e.username}\nPassword copied to clipboard for 30s.")
            except (IndexError, ValueError):
                print("❌ Invalid index.")

        elif choice == "4":
            idx = int(input("Index to update: ").strip())
            try:
                e = pm.list_entries()[idx]
                label, user, pwd, notes = prompt_entry_fields(existing=e)
                pm.update_entry(idx, label, user, pwd, notes, key)
                print("✅ Entry updated.")
            except IndexError:
                print("❌ Invalid index.")

        elif choice == "5":
            idx = int(input("Index to delete: ").strip())
            if pm.delete_entry(idx):
                print("✅ Entry deleted.")
            else:
                print("❌ Invalid index.")

        elif choice == "6":
            new_key = change_master_password()
            if new_key:
                # Re-encrypt every entry under the new key
                old_key = key
                for i, e in enumerate(pm.list_entries()):
                    plain = e.get_password(old_key)
                    pm.update_entry(i, None, None, plain, None, new_key)
                key = new_key
                pm.save(key)
            # message already printed by change_master_password()

        elif choice == "7":
            length = input("Desired length [16]: ").strip()
            length = int(length) if length.isdigit() else 16
            pwd = generate_password(length)
            copy_to_clipboard(pwd)
            print(f"🔐 Generated and copied a {length}-char password.")

        elif choice == "8":
            pm.save(key)
            print("🔒 Saved. Goodbye!")
            break

        else:
            print("❌ Unknown option, try again.")

if __name__ == "__main__":
    main()