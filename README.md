# 🛡️ Triple-Lock Vault
A hardware-bound file encryption tool using Python.

### Features
- **Hardware Binding:** Files are locked to a specific USB Serial ID and Motherboard UUID.
- **AES-256 Encryption:** Secure file processing via PBKDF2.
- **Auto-Cleanup:** Deletes source files after processing for maximum security.

### How to use
1. Install requirements: `pip install -r requirements.txt`
2. Run `python app.py`
3. Connect your USB key and secure your files.
