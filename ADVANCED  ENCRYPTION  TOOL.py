import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import os

BLOCK_SIZE = 16  # AES block size

def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def get_key(password, salt):
    # PBKDF2 for secure key derivation
    return PBKDF2(password, salt, dkLen=32, count=100_000)

def encrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        plaintext = f.read()
    salt = get_random_bytes(16)
    key = get_key(password.encode(), salt)
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))
    # Save salt + iv + ciphertext
    enc_data = base64.b64encode(salt + iv + ciphertext)
    enc_path = filepath + ".enc"
    with open(enc_path, 'wb') as f:
        f.write(enc_data)
    return enc_path

def decrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        enc_data = base64.b64decode(f.read())
    salt = enc_data[:16]
    iv = enc_data[16:32]
    ciphertext = enc_data[32:]
    key = get_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    dec_path = filepath.replace('.enc', '.dec')
    with open(dec_path, 'wb') as f:
        f.write(plaintext)
    return dec_path

# --------- GUI ---------
def select_file():
    file_path = filedialog.askopenfilename()
    entry_file.delete(0, tk.END)
    entry_file.insert(0, file_path)

def encrypt_action():
    file_path = entry_file.get()
    password = entry_password.get()
    if not file_path or not password:
        messagebox.showerror("Error", "Please select a file and enter a password.")
        return
    try:
        out_path = encrypt_file(file_path, password)
        messagebox.showinfo("Success", f"File encrypted:\n{out_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed:\n{e}")

def decrypt_action():
    file_path = entry_file.get()
    password = entry_password.get()
    if not file_path or not password:
        messagebox.showerror("Error", "Please select a file and enter a password.")
        return
    try:
        out_path = decrypt_file(file_path, password)
        messagebox.showinfo("Success", f"File decrypted:\n{out_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{e}")

root = tk.Tk()
root.title("Advanced AES-256 Encryption Tool")
root.geometry("500x220")

tk.Label(root, text="Advanced AES-256 Encryption Tool", font=("Arial", 16, "bold")).pack(pady=10)

frame = tk.Frame(root)
frame.pack(pady=5)

tk.Label(frame, text="File:").grid(row=0, column=0, sticky="e")
entry_file = tk.Entry(frame, width=40)
entry_file.grid(row=0, column=1, padx=5)
tk.Button(frame, text="Browse", command=select_file).grid(row=0, column=2)

tk.Label(frame, text="Password:").grid(row=1, column=0, sticky="e")
entry_password = tk.Entry(frame, show="*", width=40)
entry_password.grid(row=1, column=1, padx=5)

tk.Button(root, text="Encrypt", width=15, command=encrypt_action, bg="lightblue").pack(pady=5)
tk.Button(root, text="Decrypt", width=15, command=decrypt_action, bg="lightgreen").pack(pady=5)

root.mainloop()
