import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Constants
KEY_SIZE = 32  # AES-256 requires a 256-bit key
SALT_SIZE = 16
IV_SIZE = 16
BLOCK_SIZE = 128  # AES block size (128 bits)
ITERATIONS = 100000


def pad(data):
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    return padder.update(data) + padder.finalize()


def unpad(data):
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        salt = os.urandom(SALT_SIZE)
        iv = os.urandom(IV_SIZE)
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(pad(plaintext)) + encryptor.finalize()

        encrypted_data = salt + iv + ciphertext
        output_path = file_path + ".enc"

        with open(output_path, 'wb') as f:
            f.write(encrypted_data)

        messagebox.showinfo("Success", f"File encrypted: {output_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed:\n{e}")


def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        salt = data[:SALT_SIZE]
        iv = data[SALT_SIZE:SALT_SIZE + IV_SIZE]
        ciphertext = data[SALT_SIZE + IV_SIZE:]

        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = unpad(decryptor.update(ciphertext) + decryptor.finalize())

        output_path = file_path.replace(".enc", ".dec")
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", f"File decrypted: {output_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{e}")


# --- GUI SECTION ---

def select_file_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        password = password_entry.get()
        if not password:
            messagebox.showwarning("Input Needed", "Enter a password.")
            return
        encrypt_file(file_path, password)


def select_file_decrypt():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
    if file_path:
        password = password_entry.get()
        if not password:
            messagebox.showwarning("Input Needed", "Enter a password.")
            return
        decrypt_file(file_path, password)


# Main GUI
app = tk.Tk()
app.title("Advanced Encryption Tool - AES-256")
app.geometry("400x250")
app.resizable(False, False)

# Widgets
title = tk.Label(app, text="AES-256 File Encryptor/Decryptor", font=("Arial", 14, "bold"))
title.pack(pady=10)

pwd_label = tk.Label(app, text="Enter Password:")
pwd_label.pack()

password_entry = tk.Entry(app, show="*", width=30)
password_entry.pack(pady=5)

encrypt_btn = tk.Button(app, text="Select File to Encrypt", command=select_file_encrypt, width=30, bg="green", fg="white")
encrypt_btn.pack(pady=10)

decrypt_btn = tk.Button(app, text="Select File to Decrypt", command=select_file_decrypt, width=30, bg="blue", fg="white")
decrypt_btn.pack(pady=5)

exit_btn = tk.Button(app, text="Exit", command=app.quit, width=15)
exit_btn.pack(pady=15)

app.mainloop()
