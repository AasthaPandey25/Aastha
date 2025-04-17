from cryptography.fernet import Fernet
import json
import os
import tkinter as tk
from tkinter import messagebox
import time
import base64
import secrets
import string
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Generate a key from the Master Password (No static key storage)
def derive_key(master_password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Generate a new salt for new users
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Harder to brute-force
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key, salt

# Encrypt entire password database
def encrypt_data(data, key):
    cipher = Fernet(key)
    return cipher.encrypt(json.dumps(data).encode())

# Decrypt entire password database
def decrypt_data(encrypted_data, key):
    cipher = Fernet(key)
    return json.loads(cipher.decrypt(encrypted_data).decode())

# Save the encrypted database to a file
def save_passwords(data, key):
    encrypted_data = encrypt_data(data, key)
    with open("passwords.enc", "wb") as f:
        f.write(encrypted_data)

# Load and decrypt the password database
def load_passwords(key):
    try:
        with open("passwords.enc", "rb") as f:
            encrypted_data = f.read()
        return decrypt_data(encrypted_data, key)
    except FileNotFoundError:
        return {}  # No passwords stored
    except Exception:
        return None  # Incorrect password

# Generate a secure password
def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

# GUI for the Password Manager
class PasswordManagerGUI:
    def __init__(self, root, key):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("400x350")

        self.key = key
        self.last_activity_time = time.time()

        self.service_label = tk.Label(root, text="Service Name:")
        self.service_label.pack()

        self.service_entry = tk.Entry(root)
        self.service_entry.pack()

        self.password_label = tk.Label(root, text="Password:")
        self.password_label.pack()

        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()

        self.generate_button = tk.Button(root, text="Generate Password", command=self.generate_password)
        self.generate_button.pack(pady=5)

        self.save_button = tk.Button(root, text="Save Password", command=self.save_password)
        self.save_button.pack(pady=5)

        self.get_button = tk.Button(root, text="Get Password", command=self.get_password)
        self.get_button.pack(pady=5)

        self.delete_button = tk.Button(root, text="Delete Password", command=self.delete_password)
        self.delete_button.pack(pady=5)

        self.result_label = tk.Label(root, text="", fg="green")
        self.result_label.pack()

        self.root.after(1000, self.check_timeout)  # Start auto-lock timer

    def reset_timer(self):
        self.last_activity_time = time.time()

    def check_timeout(self):
        if time.time() - self.last_activity_time > 300:  # 5 minutes timeout
            self.result_label.config(text="Session expired! Restart the app.", fg="red")
            self.root.quit()
        else:
            self.root.after(1000, self.check_timeout)

    def generate_password(self):
        password = generate_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)

    def save_password(self):
        service = self.service_entry.get()
        password = self.password_entry.get()
        passwords = load_passwords(self.key)

        if service and password:
            if service in passwords:
                overwrite = messagebox.askyesno("Confirm", f"Password for '{service}' already exists. Overwrite?")
                if not overwrite:
                    return

            passwords[service] = password
            save_passwords(passwords, self.key)
            self.result_label.config(text=f"Password for '{service}' saved!", fg="green")
        else:
            self.result_label.config(text="Please enter both service and password.", fg="red")

        self.reset_timer()

    def get_password(self):
        service = self.service_entry.get()
        passwords = load_passwords(self.key)

        if passwords is None:
            self.result_label.config(text="Incorrect password!", fg="red")
            return

        if service in passwords:
            self.result_label.config(text=f"Password for {service}: {passwords[service]}", fg="blue")
        else:
            self.result_label.config(text="Service not found.", fg="red")

        self.reset_timer()

    def delete_password(self):
        service = self.service_entry.get()
        passwords = load_passwords(self.key)

        if passwords is None:
            self.result_label.config(text="Incorrect password!", fg="red")
            return

        if service in passwords:
            del passwords[service]
            save_passwords(passwords, self.key)
            self.result_label.config(text=f"Password for '{service}' deleted.", fg="green")
        else:
            self.result_label.config(text="Service not found.", fg="red")

        self.reset_timer()

# Main function to start the GUI
def main():
    master_password = input("Enter your master password: ")

    if os.path.exists("salt.key"):
        salt = open("salt.key", "rb").read()
    else:
        salt = os.urandom(16)
        with open("salt.key", "wb") as f:
            f.write(salt)

    key, _ = derive_key(master_password, salt)

    root = tk.Tk()
    app = PasswordManagerGUI(root, key)
    root.mainloop()

if __name__ == "__main__":
    main()
