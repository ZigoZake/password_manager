# 🔐 Python Password Manager

A secure terminal-based password manager written in Python.

Passwords are encrypted locally using **PBKDF2-HMAC-SHA256** and **Fernet (AES encryption)** via the `cryptography` library.

---

## ✨ Features

- 🔐 Master password authentication
- 🔑 390,000 PBKDF2 iterations
- 🧂 Unique salt file
- 🔒 Encrypted vault storage
- 🔍 Search entries
- ➕ Add entries
- ✏️ Edit entries
- ❌ Delete entries
- 🔑 Secure password generator
- 💪 Password strength checker
- ⏳ Auto-lock after inactivity

---

## 🛠 Requirements

- Python 3.9+
- cryptography library

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run:
```bash
python password_manager.py
```

On first run:
- Enter a master password
- A salt file will be created
- Vault file will be generated after first entry

## Project Structure
python-password-manager/<br>
│<br>
├── vault.py<br>
├── requirements.txt<br>
├── README.md<br>
├── LICENSE<br>
└── .gitignore<br>

## 🛡️ Security Details
Key derivation: PBKDF2-HMAC-SHA256
Iterations: 390,000
Salt: 16 bytes (random)
Encryption: Fernet symmetric encryption
Auto-lock: 120 seconds

## ⚠️ Important
If you forget your master password, recovery is impossible.
Do NOT share vault.dat or vault.salt.
This project is intended for local personal use.