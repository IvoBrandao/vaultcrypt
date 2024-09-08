import os
import argparse
import hashlib
import json
import shutil

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BLOCK_SIZE = 16
METADATA_FILE = 'metadata.json'


def backup_vault(vault_path: str, backup_path: str):
    """Create a backup of the vault directory."""

    shutil.copytree(vault_path, backup_path)

# Helper function to read the key from a file and derive an AES key
def derive_key_from_password(key_file_path: str) -> bytes:
    with open(key_file_path, 'rb') as key_file:
        password = key_file.readline().strip()  # Read the first line for the password

    salt = b'\x00' * 16  # Use a fixed salt; you can also generate a random one
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

# Function to encrypt or decrypt data
def aes_encrypt_decrypt(data: bytes, key: bytes, encrypt: bool = True) -> bytes:
    if encrypt:
        iv = os.urandom(16)  # Generate a random IV for encryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        padder = padding.PKCS7(BLOCK_SIZE * 8).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = cipher.encryptor()
        return iv + encryptor.update(padded_data) + encryptor.finalize()
    else:
        iv = data[:16]  # Extract the IV from the start of the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data[16:]) + decryptor.finalize()  # Skip the IV
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        try:
            return unpadder.update(decrypted_data) + unpadder.finalize()
        except ValueError as e:
            print(f"Padding error: {e}")
            return b""

# Hash the filename using SHA-256
def hash_filename(filename: str) -> str:
    return hashlib.sha256(filename.encode()).hexdigest()

# Collect all files and folders with their relative paths
def get_vault_files(vault_path):
    vault_structure = []
    for root, dirs, files in os.walk(vault_path):
        for name in files:
            vault_structure.append(os.path.relpath(os.path.join(root, name), vault_path))
        for name in dirs:
            vault_structure.append(os.path.relpath(os.path.join(root, name), vault_path))
    return vault_structure

# Map hash values to their original paths
def map_hash_value_to_path(vault_structure):
    return {hash_filename(path): path for path in vault_structure}

# Save the vault structure to a JSON file
def save_vault_structure(vault_structure_hash, file_path):
    with open(file_path, 'w') as f:
        json.dump(vault_structure_hash, f, indent=4)

# Load the vault structure from a JSON file
def load_vault_structure(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

# Encrypt or decrypt all files and folders in a directory
def encrypt_decrypt_vault(vault_path: str, key_file_path: str, encrypt: bool = True, vault_structure_hash=None):
    key = derive_key_from_password(key_file_path)

    if encrypt and vault_structure_hash is not None:
        # Collect metadata before encryption
        metadata = {}
        for root, dirs, files in os.walk(vault_path, topdown=False):
            for filename in files:
                file_path = os.path.join(root, filename)
                metadata[file_path] = hash_filename(filename)

            for dirname in dirs:
                dir_path = os.path.join(root, dirname)
                metadata[dir_path] = hash_filename(dirname)

        with open(METADATA_FILE, 'w') as meta_file:
            json.dump(metadata, meta_file)

        # Encrypt files
        for root, dirs, files in os.walk(vault_path, topdown=False):
            for filename in files:
                file_path = os.path.join(root, filename)
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                processed_data = aes_encrypt_decrypt(file_data, key, encrypt=encrypt)
                with open(file_path, 'wb') as f:
                    f.write(processed_data)

        # Encrypt directories
        for root, dirs, files in os.walk(vault_path, topdown=False):
            for dirname in dirs:
                dir_path = os.path.join(root, dirname)
                new_dirname = metadata.get(dir_path, hash_filename(dirname))
                os.rename(dir_path, os.path.join(root, new_dirname))

            for filename in files:
                file_path = os.path.join(root, filename)
                new_filename = metadata.get(file_path, hash_filename(filename))
                os.rename(file_path, os.path.join(root, new_filename))

    elif not encrypt and vault_structure_hash is not None:
        # Decrypt files
        for root, dirs, files in os.walk(vault_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                processed_data = aes_encrypt_decrypt(file_data, key, encrypt=encrypt)
                with open(file_path, 'wb') as f:
                    f.write(processed_data)

        # Decrypt directories names
        for root, dirs, files in os.walk(vault_path, topdown=False):
            for hashed_dirname in dirs:
                hashed_dir_path = os.path.join(root, hashed_dirname)

                for original_dirpath , hash_value in vault_structure_hash.items():
                    if str(hashed_dirname) == str(hash_value):
                      print(hashed_dirname + " -> "+ original_dirpath)
                      os.rename(hashed_dir_path,original_dirpath)

        for root, dirs, files in os.walk(vault_path, topdown=False):
            for hashed_filename in files:
                hashed_filename_path = os.path.join(root, hashed_filename)

                for original_filepath , hash_value in vault_structure_hash.items():
                  if str(hashed_filename) == str(hash_value):
                    print(hashed_filename + " -> "+ original_filepath)
                    if os.path.exists(hashed_filename_path):
                      os.rename(hashed_filename_path, original_filepath)

# Main function to either encrypt or decrypt
def main(vault_path: str, key_file_path: str, encrypt: bool = True):
    backup_path =vault_path + "_bak"

    if backup_path:
        # Backup the vault before any operations
        print(f"Backing up the vault to {backup_path}...")
        backup_vault(vault_path, backup_path)
        print("Backup completed.")

    if encrypt:
        # Get the folder list
        vault_structure = get_vault_files(vault_path)
        # Create the hash for each folder and file name
        vault_structure_hash = map_hash_value_to_path(vault_structure)
        # Save the vault structure hash dictionary to metadata.json
        save_vault_structure(vault_structure_hash, METADATA_FILE)
    else:
        vault_structure_hash = load_vault_structure(METADATA_FILE)

    encrypt_decrypt_vault(vault_path, key_file_path, encrypt, vault_structure_hash)
    action = "encrypted" if encrypt else "decrypted"
    print(f"The vault has been successfully {action}.")

# Parse command-line arguments
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt or decrypt an Obsidian vault.")
    parser.add_argument('--vault', required=True, help='Path to the Obsidian vault folder')
    parser.add_argument('--key', required=True, help='Path to the file containing the password key')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--encrypt', action='store_true', help='Encrypt the vault')
    group.add_argument('--decrypt', action='store_true', help='Decrypt the vault')

    args = parser.parse_args()

    # Determine whether to encrypt or decrypt
    encrypt = args.encrypt

    # Call the main function
    main(args.vault, args.key, encrypt)
