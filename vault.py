#!/usr/bin/env python3
import os
import json
import base64
import getpass
import time
import secrets
import string
import re

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend


VAULT_FILE = "vault.dat"
SALT_FILE = "vault.salt"
ITERATIONS = 390_000
AUTO_LOCK_SECONDS = 120


# ---------- Crypto ----------
def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def load_or_create_salt() -> bytes:
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt


# ---------- Password Generator ----------
def generate_password(length=16):
    alphabet = (
        string.ascii_lowercase +
        string.ascii_uppercase +
        string.digits +
        "!@#$%^&*()-_=+[]{};:,.<>?"
    )
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ---------- Password Strength ----------
def password_strength(password: str) -> str:
    score = 0

    if len(password) >= 12:
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*()\-\_=+\[\]{};:,.<>?]", password):
        score += 1

    if score <= 2:
        return "🐣 Weak"
    elif score == 3:
        return "🛡️ Medium"
    elif score == 4:
        return "💎 Strong"
    else:
        return "🔥 Very Strong"


# ---------- Vault ----------
def load_vault(fernet: Fernet) -> dict:
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()
    decrypted = fernet.decrypt(encrypted)
    return json.loads(decrypted.decode())


def save_vault(vault: dict, fernet: Fernet):
    data = json.dumps(vault, indent=2).encode()
    encrypted = fernet.encrypt(data)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)


# ---------- UI ----------
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    input("\nPress Enter to continue...")


def menu():
    print("""
🔐 Python Password Manager

1. List and View entries
2. Add entry
3. Edit entry
4. Delete entry
5. Exit
""")


# ---------- Actions ----------
def list_entries(vault):
    if not vault:
        print("Vault is empty.")
        return

    query = input("Search entries (leave empty to list all): ").strip().lower()

    if query:
        matches = [name for name in vault if query in name.lower()]
    else:
        matches = list(vault.keys())

    if not matches:
        print("No matching entries found.")
        return

    print("\nEntries:")
    for idx, name in enumerate(matches, start=1):
        print(f"{idx}. {name}")

    choice = input("\nEnter number to view details (or press Enter to return): ").strip()
    if not choice:
        return

    if not choice.isdigit():
        print("Invalid selection.")
        return

    index = int(choice) - 1
    if index < 0 or index >= len(matches):
        print("Invalid selection.")
        return

    name = matches[index]
    entry = vault[name]

    print(f"\n📌 {name}")
    print(f"Username: {entry['username']}")
    print(f"Password: {entry['password']}")
    print(f"Strength: {password_strength(entry['password'])}")

    if entry.get("notes"):
        print(f"\nNotes:\n{entry['notes']}")
    else:
        print("\nNotes: (none)")


def add_entry(vault):
    name = input("Entry name: ").strip()
    if name in vault:
        print("Entry already exists.")
        return

    username = input("Username: ")

    choice = input("Generate password? [y/N]: ").strip().lower()
    if choice == "y":
        length = input("Password length (default 16): ").strip()
        length = int(length) if length.isdigit() else 16
        password = generate_password(length)
        strength = password_strength(password)
        print(f"\nGenerated password: {password}")
        print(f"Strength: {strength}")
    else:
        password = getpass.getpass("Password: ")
        strength = password_strength(password)
        print(f"Strength: {strength}")

    print("\nAdd notes (optional). Leave empty to skip.")
    notes = input("Notes: ")

    vault[name] = {
        "username": username,
        "password": password,
        "notes": notes
    }
    print("Entry added.")


def delete_entry(vault):
    if not vault:
        print("Vault is empty.")
        return

    query = input("Search (leave empty to list all): ").strip().lower()

    if query:
        matches = [
            name for name in vault
            if query in name.lower()
        ]
    else:
        matches = list(vault.keys())

    if not matches:
        print("No matching entries found.")
        return

    print("\nEntries:")
    for idx, name in enumerate(matches, start=1):
        print(f"{idx}. {name}")

    choice = input("\nSelect entry number to delete (or Enter to cancel): ").strip()
    if not choice:
        print("Cancelled.")
        return

    if not choice.isdigit():
        print("Invalid selection.")
        return

    index = int(choice) - 1
    if index < 0 or index >= len(matches):
        print("Invalid selection.")
        return

    name = matches[index]

    confirm = input(f"Are you sure you want to delete '{name}'? [y/N]: ").strip().lower()
    if confirm == "y":
        del vault[name]
        print("Entry deleted.")
    else:
        print("Deletion cancelled.")


def edit_entry(vault):
    if not vault:
        print("Vault is empty.")
        return

    query = input("Search entry to edit (leave empty to list all): ").strip().lower()

    if query:
        matches = [name for name in vault if query in name.lower()]
    else:
        matches = list(vault.keys())

    if not matches:
        print("No matching entries found.")
        return

    print("\nEntries:")
    for idx, name in enumerate(matches, start=1):
        print(f"{idx}. {name}")

    choice = input("\nSelect entry number to edit (or Enter to cancel): ").strip()
    if not choice:
        print("Cancelled.")
        return

    if not choice.isdigit():
        print("Invalid selection.")
        return

    index = int(choice) - 1
    if index < 0 or index >= len(matches):
        print("Invalid selection.")
        return

    name = matches[index]
    entry = vault[name]

    print(f"\nEditing '{name}' (leave blank to keep current value)")

    new_username = input(f"Username [{entry['username']}]: ").strip()
    if new_username:
        entry['username'] = new_username

    change_password = input("Change password? [y/N]: ").strip().lower()
    if change_password == "y":
        generate = input("Generate new password? [y/N]: ").strip().lower()
        if generate == "y":
            length = input("Password length (default 16): ").strip()
            length = int(length) if length.isdigit() else 16
            entry['password'] = generate_password(length)
            print(f"Generated password: {entry['password']}")
        else:
            entry['password'] = getpass.getpass("New password: ")
        print(f"Strength: {password_strength(entry['password'])}")

    new_notes = input(f"Notes [{entry.get('notes','')}]: ").strip()
    if new_notes:
        entry['notes'] = new_notes

    vault[name] = entry
    print("Entry updated.")


# ---------- Auto-lock ----------
def check_auto_lock(last_activity):
    if time.time() - last_activity > AUTO_LOCK_SECONDS:
        print("\n🔒 Vault auto-locked due to inactivity.")
        return True
    return False


# ---------- Main ----------
def main():
    clear()
    print("🔐 Vault Login\n")
    master_password = getpass.getpass("Master password: ")

    salt = load_or_create_salt()
    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    try:
        vault = load_vault(fernet)
    except Exception:
        print("❌ Invalid password or corrupted vault.")
        return

    last_activity = time.time()

    while True:
        if check_auto_lock(last_activity):
            break

        clear()
        menu()
        choice = input("Select: ").strip()
        last_activity = time.time()

        clear()
        if choice == "1":
            list_entries(vault)
            pause()
        elif choice == "2":
            add_entry(vault)
            save_vault(vault, fernet)
            pause()        
        elif choice == "3":
            edit_entry(vault)
            save_vault(vault, fernet)
            pause()
        elif choice == "4":
            delete_entry(vault)
            save_vault(vault, fernet)
            pause()

        elif choice == "5":
            save_vault(vault, fernet)
            print("Goodbye 👋")
            break
        else:
            print("Invalid choice.")
            pause()


if __name__ == "__main__":
    main()