# Obsidian Vault Encryption/Decryption

This Python script allows you to encrypt or decrypt an Obsidian vault. It uses AES encryption with a key derived from a password. The script also handles the encryption and decryption of filenames and folder names to ensure the entire vault is securely protected.

> [!IMPORTANT]
> Use at your own risk

## Features

- **Encryption and Decryption**: Securely encrypt or decrypt all files and folders in the specified vault.
- **Metadata Handling**: Saves and restores the structure of the vault using a metadata file.
- **Filename Hashing**: Ensures filenames and folder names are encrypted/decrypted by hashing them with SHA-256.

## Requirements

- Python 3.6 or higher
- `cryptography` package (install with `pip install cryptography`)

## Usage

### Encryption

To encrypt your Obsidian vault, run the script with the `--encrypt` flag:

```sh
python encrypt_decrypt_vault.py --vault /path/to/vault --key /path/to/keyfile --encrypt
```

### Decryption

To decrypt your Obsidian vault, run the script with the `--decrypt` flag:

```sh
python encrypt_decrypt_vault.py --vault /path/to/vault --key /path/to/keyfile --decrypt
```

## Arguments

- `--vault`: The path to the Obsidian vault folder you want to encrypt or decrypt.
- `--key`: The path to the file containing the password key for deriving the AES encryption key.
- `--encrypt`: Encrypt the vault (use this flag for encryption).
- `--decrypt`: Decrypt the vault (use this flag for decryption).

## Key Derivation

The key for AES encryption is derived from a password stored in the key file using PBKDF2 with a fixed salt.
Ensure that your key file contains only the password on the first line.

> [!IMPORTANT]
> Never share yout key in a public repository.

## Metadata File

The script creates a `metadata.json` file to store the original filenames and folder names mapped to their hashed values.

> [!IMPORTANT]
> This file is essential for the decryption process. **It is crucial to keep the `metadata.json` file safe and secure**, as it contains the mappings needed to restore the original filenames and folder names.

### Importance of `metadata.json`

- **For Encryption**: The `metadata.json` file is generated during the encryption process. It maps the original filenames and folder names to their encrypted versions.
- **For Decryption**: The `metadata.json` file must be present for the decryption process to correctly map the hashed names back to their original names. Without this file, the script will not be able to restore the original names, and you may lose access to your files.

## Example

1. **Encrypting the Vault**:

   ```sh
   python encrypt_decrypt_vault.py --vault /path/to/obsidian_vault --key /path/to/password_keyfile --encrypt
   ```

   This command will encrypt all files and folders in `/path/to/obsidian_vault` using the password from `/path/to/password_keyfile`. The `metadata.json` file will be created in the vault directory.

2. **Decrypting the Vault**:

   ```sh
   python encrypt_decrypt_vault.py --vault /path/to/obsidian_vault --key /path/to/password_keyfile --decrypt
   ```

   This command will decrypt all files and folders in `/path/to/obsidian_vault` using the password from `/path/to/password_keyfile`. The script will use the `metadata.json` file to restore the original filenames and folder names.

## Notes

- **Backup**: Ensure you keep a backup of your `metadata.json` file and key file in a secure location. Losing this file could result in losing access to your encrypted data.
- **Salt**: This script uses a fixed salt for key derivation. For better security, consider using a unique salt for each encryption operation.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

