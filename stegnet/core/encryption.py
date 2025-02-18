from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

class Encryption:
    def __init__(self, key: str):
        """Initialize encryption with a passphrase-derived key."""
        salt = b"stegnet_salt"  # Can be randomized per session
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        self.key = kdf.derive(key.encode())

    def aes_encrypt(self, plaintext: str) -> str:
        """Encrypts a message using AES-256 in CBC mode."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_message = plaintext.ljust(16 * ((len(plaintext) // 16) + 1))  # Padding
        ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    def aes_decrypt(self, ciphertext: str) -> str:
        """Decrypts AES-256 encrypted data."""
        raw_data = base64.b64decode(ciphertext)
        iv, actual_ciphertext = raw_data[:16], raw_data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(actual_ciphertext).decode().strip()

    def xor_encrypt(self, plaintext: str) -> str:
        """XOR encryption for lightweight obfuscation."""
        return ''.join(chr(ord(c) ^ ord(self.key[i % len(self.key)])) for i, c in enumerate(plaintext))

    def xor_decrypt(self, ciphertext: str) -> str:
        """Decrypts XOR encrypted data."""
        return self.xor_encrypt(ciphertext)  # XOR is symmetrical
