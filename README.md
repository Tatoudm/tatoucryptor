# 🛡️ Tatoucryptor

Tatoucryptor is a high-grade file encryption suite designed for Windows. It implements a **Triple-Lock** philosophy, ensuring that files are not just password-protected, but physically bound to your hardware.

The project provides two distinct security architectures (Standard & TPM) depending on the user's threat model.

---

## 🏗️ Core Architectures

### 1. Hardware Binding (v1.2.0 Standard)
This version focuses on machine-level persistence.
- **Key Derivation:** Combines your **Master Password** with the **Motherboard UUID** and a specific **USB Serial ID**.
- **Algorithm:** Uses **Argon2id** for key derivation and **AES-256-GCM** for authenticated encryption.
- **Use Case:** Ideal for users who need files to stay on one PC but might need to reinstall Windows or change user accounts.

### 2. Hardware + TPM & User Binding (v1.2.0 TPM)
This version adds a layer of forensic resistance by involving the Windows Data Protection API (DPAPI).
- **Security Layers:** In addition to the Hardware Binding, it "wraps" the encryption keys using the **TPM 2.0 chip** and the **current Windows User Session**.
- **Protection:** Even if a thief steals your hard drive and knows your password, they cannot decrypt the files without being logged into your specific Windows account on your specific PC.
- **Constraint:** Files are lost if the Windows profile is deleted or the OS is reinstalled.

---

## 📥 Downloads

If you want to use Tatoucryptor, you can download the standalone executables (`.exe`) directly from the **Releases** section of this repository.

👉 **[Go to Latest Releases](../../releases/latest)**

---

## ✨ Key Features

- **Zero-Knowledge:** No keys are ever stored on disk or sent to the cloud.
- **Hardware Required:** Encryption/Decryption is impossible without the physical "Key" (your USB drive).
- **Integrity Protection:** AES-GCM ensures that if a file is tampered with, it will fail to decrypt rather than providing corrupted data.
- **Safety First:** Integrated warning systems to ensure users understand the "No-Recovery" nature of the hardware binding.

---

## ⚠️ Critical Warning

Tatoucryptor is designed with **no backdoors**. 
Decryption is mathematically impossible if you lose:
1. Your **Master Password**.
2. Your **Specific USB Drive**.
3. (For TPM version) Access to your **Windows User Account**.

**Always keep backups of your critical data in a second secure location.**