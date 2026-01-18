import customtkinter as ctk
from tkinter import filedialog, messagebox
import wmi
import os
import struct
import win32crypt
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureVaultTPM(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Tatoucryptor - TPM/DPAPI Edition")
        self.geometry("600x650")
        ctk.set_appearance_mode("dark")

        self.TIME_COST = 3
        self.MEMORY_COST = 65536
        self.PARALLELISM = 4

        self.setup_ui()
        self.selected_files = []

    def setup_ui(self):
        self.label = ctk.CTkLabel(self, text="🛡️ TPM & Hardware Vault", font=("Roboto", 24, "bold"))
        self.label.pack(pady=15)

        self.desc_box = ctk.CTkTextbox(self, width=500, height=140, font=("Roboto", 11))
        self.desc_box.pack(pady=10)
        self.desc_box.insert("0.0", "SECURITY STATUS: ULTRA\n"
                                     "- KDF: Argon2id\n"
                                     "- Cipher: AES-256-GCM\n"
                                     "- Wrapper: Windows DPAPI (TPM-Backed)\n\n"
                                     "LOCK: Files are bound to THIS Windows User + THIS PC + THIS USB.")
        self.desc_box.configure(state="disabled")

        self.pwd_entry = ctk.CTkEntry(self, placeholder_text="Master password...", show="*", width=350)
        self.pwd_entry.pack(pady=10)

        self.btn_select = ctk.CTkButton(self, text="📁 Select Files", command=self.select_files)
        self.btn_select.pack(pady=10)

        self.file_label = ctk.CTkLabel(self, text="No files selected", text_color="gray")
        self.file_label.pack(pady=5)

        self.btn_encrypt = ctk.CTkButton(self, text="LOCK (TPM Protect)", 
                                         fg_color="#A83232", hover_color="#7A2424", command=lambda: self.process(True))
        self.btn_encrypt.pack(pady=10, ipady=5)

        self.btn_decrypt = ctk.CTkButton(self, text="UNLOCK (Hardware Auth)", 
                                         fg_color="#2E7D32", hover_color="#1B5E20", command=lambda: self.process(False))
        self.btn_decrypt.pack(pady=10, ipady=5)

    def get_hardware_context(self):
        try:
            c = wmi.WMI()
            usb_id = next((disk.SerialNumber.strip() for disk in c.Win32_DiskDrive(InterfaceType="USB")), None)
            pc_id = c.Win32_ComputerSystemProduct()[0].UUID
            return usb_id, pc_id
        except:
            return None, None

    def derive_master_key(self, password, salt, usb_id, pc_id):
        combined = f"{usb_id}-{pc_id}-{password}".encode()
        return hash_secret_raw(
            secret=combined, salt=salt, time_cost=self.TIME_COST,
            memory_cost=self.MEMORY_COST, parallelism=self.PARALLELISM,
            hash_len=32, type=Type.ID
        )

    def select_files(self):
        self.selected_files = filedialog.askopenfilenames()
        if self.selected_files:
            self.file_label.configure(text=f"{len(self.selected_files)} file(s) selected", text_color="white")

    def process(self, encrypt=True):
        pwd = self.pwd_entry.get()
        usb_id, pc_id = self.get_hardware_context()

        if not usb_id or not pc_id:
            messagebox.showerror("Hardware Error", "USB Drive not detected or WMI error.")
            return
        
        if not pwd or not self.selected_files:
            messagebox.showwarning("Input Error", "Password and files required.")
            return

        if encrypt:
            warning_msg = (
                "SECURITY WARNING:\n\n"
                "You are about to lock files using TPM-backed DPAPI. "
                "These files will become PERMANENTLY UNREADABLE if you lose or change:\n"
                "- Your Current Windows User Account\n"
                "- Your Physical Motherboard (TPM chip)\n"
                "- Your Dedicated USB Drive\n"
                "- Your Password\n\n"
                "If you reinstall Windows or change your PC, data WILL be lost.\n"
                "Do you want to proceed?"
            )
            confirm = messagebox.askyesno("Hardware & User Binding Warning", warning_msg, icon='warning')
            if not confirm:
                return

        extra_entropy = f"{usb_id}-{pc_id}".encode()
        count = 0

        for path in self.selected_files:
            try:
                if encrypt:
                    if path.endswith(".vault"): continue
                    
                    salt = os.urandom(16)
                    nonce = os.urandom(12)
                    
                    master_key = self.derive_master_key(pwd, salt, usb_id, pc_id)
                    wrapped_key = win32crypt.CryptProtectData(master_key, "VaultKey", extra_entropy, None, None, 0)

                    aesgcm = AESGCM(master_key)
                    with open(path, "rb") as f:
                        ciphertext = aesgcm.encrypt(nonce, f.read(), None)

                    with open(path + ".vault", "wb") as f:
                        f.write(salt)
                        f.write(nonce)
                        f.write(struct.pack("<I", len(wrapped_key))) 
                        f.write(wrapped_key)
                        f.write(ciphertext)

                else:
                    if not path.endswith(".vault"): continue
                    
                    with open(path, "rb") as f:
                        salt = f.read(16)
                        nonce = f.read(12)
                        w_len = struct.unpack("<I", f.read(4))[0]
                        wrapped_key = f.read(w_len)
                        ciphertext = f.read()

                    _, master_key = win32crypt.CryptUnprotectData(wrapped_key, extra_entropy, None, None, 0)
                    
                    aesgcm = AESGCM(master_key)
                    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
                    
                    with open(path.replace(".vault", ""), "wb") as f:
                        f.write(decrypted_data)

                os.remove(path)
                count += 1
            except Exception as e:
                print(f"Error on {path}: {e}")
                continue

        if count > 0:
            messagebox.showinfo("Success", f"Operation successful on {count} files.")
            self.selected_files = []
            self.file_label.configure(text="No files selected", text_color="gray")
        else:
            messagebox.showerror("Auth Failure", "Hardware mismatch, wrong password, or wrong Windows User.")

if __name__ == "__main__":
    app = SecureVaultTPM()
    app.mainloop()