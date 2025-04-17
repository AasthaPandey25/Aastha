This is a simple yet secure password manager built with Python, featuring a Tkinter-based GUI and Fernet encryption from the cryptography library. It allows you to safely generate, store, retrieve, and delete passwords locally.

Features:
1- Encrypts your password database using a master password
2- Uses PBKDF2-HMAC with SHA256 for secure key derivation
3- GUI built with Tkinter for user-friendly interaction
4- Auto-locks after 5 minutes of inactivity
5 Secure password generation with letters, numbers, and symbols
6- Stores encrypted passwords in a local .enc file

How to Use:
Run the script: python cns_7.py

Enter your master password (used to generate the encryption key).

Use the GUI to:

Add a new service and password
Generate strong passwords
Retrieve saved passwords
Delete passwords
⚠️ Make sure to remember your master password, as it’s required to access your saved data.

Files:
cns_7.py – main script
passwords.enc – encrypted password storage (auto-created)
salt.key – securely stores the salt used for key derivation

Requirements:
Install required libraries using pip: pip install cryptography

** Note  **
This project stores data locally; it doesn’t use any cloud or network storage.
Make sure you don’t delete salt.key or forget your master password — the data can't be recovered otherwise.





