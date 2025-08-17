# 🔐 File Vault - AES-256 File Encryption Tool

A Python script for secure file encryption/decryption using **AES-256** with password-based key derivation (PBKDF2). Ideal for protecting sensitive files on Kali Linux or any Python-supported OS.

![Terminal Demo](https://img.shields.io/badge/Demo-Terminal-blue) ![Python](https://img.shields.io/badge/Python-3.6%2B-green) ![Cryptography](https://img.shields.io/badge/AES-256_Encryption-red)

---

## ✨ Features
- **Military-grade encryption** (AES-256)
- **Password-based key derivation** (PBKDF2 with HMAC-SHA256)
- **File integrity verification**
- **Salt generation** for rainbow table resistance
- Simple CLI interface

---

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/siddhanth36/file-vault.git
   cd file-vault
   # Install dependencies:
   pip install cryptography pyzipper
