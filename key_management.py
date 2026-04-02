"""
RSA Key Management Module for Phase 3
Handles RSA-2048 keypair generation and AES key wrapping.

Each IoT device generates an RSA keypair. The PC encrypts per-file
AES keys with each device's RSA public key (OAEP padding).
"""
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def generate_rsa_keypair():
    """Generate RSA-2048 keypair for AES key wrapping.

    Returns:
        tuple: (private_key, public_key) RSA key objects
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    """Serialize RSA public key to PEM string."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')


def deserialize_public_key(pem_str):
    """Deserialize RSA public key from PEM string."""
    return serialization.load_pem_public_key(pem_str.encode('utf-8'))


def encrypt_aes_key(aes_key, rsa_public_key):
    """Encrypt AES key with RSA public key using OAEP padding.

    Args:
        aes_key: 32-byte AES key
        rsa_public_key: RSA public key object

    Returns:
        str: base64-encoded encrypted key
    """
    encrypted = rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode('ascii')


def decrypt_aes_key(encrypted_key_b64, rsa_private_key):
    """Decrypt AES key with RSA private key.

    Args:
        encrypted_key_b64: base64-encoded RSA-encrypted AES key
        rsa_private_key: RSA private key object

    Returns:
        bytes: 32-byte AES key
    """
    encrypted = base64.b64decode(encrypted_key_b64)
    return rsa_private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def save_private_key(private_key, filepath):
    """Save RSA private key to PEM file."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filepath, 'wb') as f:
        f.write(pem)


def load_private_key(filepath):
    """Load RSA private key from PEM file."""
    with open(filepath, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def save_public_key(public_key, filepath):
    """Save RSA public key to PEM file."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filepath, 'wb') as f:
        f.write(pem)


def load_public_key(filepath):
    """Load RSA public key from PEM file."""
    with open(filepath, 'rb') as f:
        return serialization.load_pem_public_key(f.read())
