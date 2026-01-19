import customtkinter as ctk
from tkinter import filedialog, messagebox
import wmi
import os
import struct
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Tatoucryptor")
        self.geometry("600x650")
        ctk.set_appearance_mode("dark")

        self.TIME_COST = 3
        self.MEMORY_COST = 65536 
        self.PARALLELISM = 4

        self.setup_ui()
        self.selected_files = []

    def setup_ui(self):
        self.label = ctk.CTkLabel(self, text="🛡️ Triple-Lock Vault GCM", font=("Roboto", 24, "bold"))
        self.label.pack(pady=15)

        self.desc_box = ctk.CTkTextbox(self, width=500, height=120, font=("Roboto", 12))
        self.desc_box.pack(pady=10)
        self.desc_box.insert("0.0", "SECURITY INFO:\n"
                                     "- Key: Argon2id (PWD + PC UUID + USB Serial)\n"
                                     "- Cipher: AES-256-GCM\n"
                                     "- Mode: Pure Software-Based Hardware Binding\n\n"
                                     "Files only open on THIS PC with THIS USB plugged in.")
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

    def get_hw_ids(self):
        try:
            c = wmi.WMI()
            usb_disks = [disk.SerialNumber.strip() for disk in c.Win32_DiskDrive(InterfaceType="USB")]
            if not usb_disks:
                return None, None
            pc_id = c.Win32_ComputerSystemProduct()[0].UUID
            return usb_disks[0], pc_id
        except:
            return None, None

    def derive_key(self, password, salt, usb_id, pc_id):
        combined = f"{usb_id}{pc_id}{password}".encode()
        return hash_secret_raw(
            secret=combined,
            salt=salt,
            time_cost=self.TIME_COST,
            memory_cost=self.MEMORY_COST,
            parallelism=self.PARALLELISM,
            hash_len=32,
            type=Type.ID
        )

    def select_files(self):
        self.selected_files = filedialog.askopenfilenames()
        if self.selected_files:
            self.file_label.configure(text=f"{len(self.selected_files)} file(s) selected", text_color="white")

    def process(self, encrypt=True):
        pwd = self.pwd_entry.get()
        usb_id, pc_id = self.get_hw_ids()

        if not usb_id or not pc_id:
            messagebox.showerror("Hardware Error", "USB Drive not found or system error.")
            return

        if not pwd or not self.selected_files:
            messagebox.showwarning("Warning", "Please enter a password and select files.")
            return

        if encrypt:
            msg = "Locking files to this PC and USB. Proceed?"
            if not messagebox.askyesno("Confirm", msg):
                return 

        count = 0
        for path in self.selected_files:
            try:
                if encrypt:
                    if path.endswith(".vault"): continue
                    
                    salt = os.urandom(16)
                    nonce = os.urandom(12)
                    key = self.derive_key(pwd, salt, usb_id, pc_id)

                    with open(path, "rb") as f:
                        data = f.read()

                    aesgcm = AESGCM(key)
                    ciphertext = aesgcm.encrypt(nonce, data, None)

                    with open(path + ".vault", "wb") as f:
                        f.write(salt)  
                        f.write(nonce) 
                        f.write(ciphertext)
                
                else:
                    if not path.endswith(".vault"): continue
                    
                    with open(path, "rb") as f:
                        salt = f.read(16)
                        nonce = f.read(12)
                        ciphertext = f.read()
                    
                    key = self.derive_key(pwd, salt, usb_id, pc_id)
                    aesgcm = AESGCM(key)
                    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
                    
                    with open(path.replace(".vault", ""), "wb") as f:
                        f.write(decrypted_data)

                os.remove(path)
                count += 1
            except:
                continue

        if count > 0:
            messagebox.showinfo("Success", f"Done: {count} files processed.")
            self.pwd_entry.delete(0, 'end')
            self.selected_files = []
            self.file_label.configure(text="No files selected", text_color="gray")
        else:
            messagebox.showerror("Error", "Auth failure or hardware mismatch.")

if __name__ == "__main__":
    app = SecureVaultApp()
    app.mainloop()