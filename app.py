import customtkinter as ctk
from tkinter import filedialog, messagebox
import wmi
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

class SecureVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Tatoucryptor v1.0")
        self.geometry("600x650")
        ctk.set_appearance_mode("dark")

        self.label = ctk.CTkLabel(self, text="🛡️ Triple-Lock Vault", font=("Roboto", 24, "bold"))
        self.label.pack(pady=15)

        self.desc_box = ctk.CTkTextbox(self, width=500, height=120, font=("Roboto", 12))
        self.desc_box.pack(pady=10)
        self.desc_box.insert("0.0", "HOW TO USE:\n"
                             "1. Plug in your dedicated USB drive.\n"
                             "2. Enter a password and select your files.\n"
                             "3. Click LOCK to encrypt or UNLOCK to restore.\n\n"
                             "WARNING: Sources are deleted after processing. "
                             "Files can only be opened on THIS PC with THIS USB.")
        self.desc_box.configure(state="disabled")

        self.pwd_entry = ctk.CTkEntry(self, placeholder_text="Master password...", show="*", width=350)
        self.pwd_entry.pack(pady=10)

        self.btn_select = ctk.CTkButton(self, text="📁 Select Files", command=self.select_files)
        self.btn_select.pack(pady=10)

        self.file_label = ctk.CTkLabel(self, text="No files selected", text_color="gray")
        self.file_label.pack(pady=5)

        self.btn_encrypt = ctk.CTkButton(self, text="LOCK (Encrypt)", 
                                         fg_color="#A83232", hover_color="#7A2424", command=lambda: self.process(True))
        self.btn_encrypt.pack(pady=10, ipady=5)

        self.btn_decrypt = ctk.CTkButton(self, text="UNLOCK (Decrypt)", 
                                         fg_color="#2E7D32", hover_color="#1B5E20", command=lambda: self.process(False))
        self.btn_decrypt.pack(pady=10, ipady=5)

        self.selected_files = []

    def get_hw_ids(self):
        try:
            c = wmi.WMI()
            usb_id = next((disk.SerialNumber.strip() for disk in c.Win32_DiskDrive(InterfaceType="USB")), None)
            pc_id = c.Win32_ComputerSystemProduct()[0].UUID
            return usb_id, pc_id
        except:
            return None, None

    def generate_key(self, password):
        usb_id, pc_id = self.get_hw_ids()
        if not usb_id:
            messagebox.showerror("Error", "USB Drive not found! Connect the original drive.")
            return None
        
        combined = f"{usb_id}-{pc_id}-{password}".encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'hardened_static_salt_v1',
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(combined))

    def select_files(self):
        self.selected_files = filedialog.askopenfilenames()
        if self.selected_files:
            self.file_label.configure(text=f"{len(self.selected_files)} file(s) selected", text_color="white")

    def process(self, encrypt=True):
        pwd = self.pwd_entry.get()
        if not pwd or not self.selected_files:
            messagebox.showwarning("Warning", "Please enter a password and select files.")
            return

        key = self.generate_key(pwd)
        if not key: return
        
        f = Fernet(key)
        count = 0

        for path in self.selected_files:
            try:
                with open(path, "rb") as file:
                    data = file.read()
                
                if encrypt:
                    if path.endswith(".vault"): continue
                    result = f.encrypt(data)
                    new_path = path + ".vault"
                else:
                    if not path.endswith(".vault"): continue
                    result = f.decrypt(data)
                    new_path = path.replace(".vault", "")

                with open(new_path, "wb") as file:
                    file.write(result)
                
                os.remove(path)
                count += 1
            except Exception:
                continue

        if count > 0:
            messagebox.showinfo("Success", f"Operation complete: {count} files processed.\nOriginal sources have been deleted.")
            self.selected_files = []
            self.file_label.configure(text="No files selected", text_color="gray")
        else:
            messagebox.showerror("Failure", "Error: Incorrect password or invalid hardware.")

if __name__ == "__main__":
    app = SecureVaultApp()
    app.mainloop()