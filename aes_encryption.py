"""
AES-256-GCM Encryption Module for Phase 3
Replaces CP-ABSC with fast authenticated encryption.

AES-GCM provides:
- Confidentiality (AES encryption)
- Integrity (GCM authentication tag)
- ~97% faster decryption on RPi vs CP-ABSC
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_aes_key():
    """Generate a random 256-bit AES key.

    Returns:
        bytes: 32-byte random key
    """
    return os.urandom(32)


def aes_encrypt(key, plaintext):
    """Encrypt data with AES-256-GCM.

    Args:
        key: 32-byte AES key
        plaintext: bytes to encrypt

    Returns:
        dict with base64-encoded nonce and ciphertext (includes GCM tag)
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce (recommended for GCM)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    # ciphertext includes 16-byte GCM auth tag appended

    return {
        'nonce': base64.b64encode(nonce).decode('ascii'),
        'ciphertext': base64.b64encode(ciphertext).decode('ascii')
    }


def aes_decrypt(key, nonce_b64, ciphertext_b64):
    """Decrypt AES-256-GCM encrypted data.

    Args:
        key: 32-byte AES key
        nonce_b64: base64-encoded 12-byte nonce
        ciphertext_b64: base64-encoded ciphertext (includes GCM tag)

    Returns:
        bytes: decrypted plaintext

    Raises:
        cryptography.exceptions.InvalidTag: if data was tampered
    """
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    return aesgcm.decrypt(nonce, ciphertext, None)
