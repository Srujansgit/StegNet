from stegnet.core.encryption import Encryption

class StegNetBase:
    def __init__(self, encryption_key):
        """Base class for network steganography handlers, handles encryption."""
        self.encryption = Encryption(encryption_key)

    def encrypt(self, message: str) -> str:
        """Encrypts a message using AES-256."""
        return self.encryption.aes_encrypt(message)

    def decrypt(self, encrypted_message: str) -> str:
        """Decrypts an AES-256 encrypted message."""
        return self.encryption.aes_decrypt(encrypted_message)
