"""
DID Manager - Decentralized Identifier Generation and Management

This module handles DID generation using the did:avsd method.
DID format: did:avsd:{SHA256(public_key)[:16]}

Uses cryptography library for Ed25519 keypair generation (no custom implementation).
"""

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import hashlib
import json
from pathlib import Path

# Backward compatibility: older cryptography versions (<3.0) require backend parameter
try:
    from cryptography.hazmat.backends import default_backend
    _BACKEND = default_backend()
except ImportError:
    # Newer versions (>=3.0) don't need backend
    _BACKEND = None


class DIDManager:
    """Manages DID generation and resolution using did:avsd method"""

    def __init__(self):
        """Initialize DID manager with empty state. Call generate_keypair_and_did() or load_private_key()."""
        self.private_key = None
        self.public_key = None
        self.did = None

    def generate_keypair_and_did(self):
        """
        Generate Ed25519 keypair and derive DID

        Returns:
            tuple: (did_string, private_key, public_key)
        """
        # Generate Ed25519 keypair using cryptography library
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        # Serialize public key to bytes
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Create DID: did:avsd:{SHA256(public_key)[:16]}
        pk_hash = hashlib.sha256(public_key_bytes).hexdigest()
        self.did = f"did:avsd:{pk_hash[:16]}"

        return self.did, self.private_key, self.public_key

    def resolve_did(self, did_string):
        """
        Resolve did:avsd to public key
        NOTE: This requires external storage/registry in production.
        For now, returns None (need to query blockchain or local registry)

        Args:
            did_string: DID in format "did:avsd:abc123..."

        Returns:
            Ed25519PublicKey object or None
        """
        if not did_string.startswith("did:avsd:"):
            raise ValueError("Invalid did:avsd format")

        # In production, this would query blockchain or DID registry
        # For now, return None - caller must provide public key separately
        return None

    def save_private_key(self, filepath):
        """
        Persist private key to file in PEM format

        Args:
            filepath: Path to save private key (e.g., 'device_private_key.pem')
        """
        if self.private_key is None:
            raise ValueError("No private key to save. Call generate_keypair_and_did() first.")

        # Serialize private key to PEM format (unencrypted for simplicity)
        private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(filepath, 'wb') as f:
            f.write(private_bytes)

        print(f"[OK] Private key saved to {filepath}")

    def load_private_key(self, filepath):
        """
        Load private key from file and derive DID

        Args:
            filepath: Path to private key file

        Returns:
            tuple: (did_string, private_key, public_key)
        """
        with open(filepath, 'rb') as f:
            private_bytes = f.read()

        # Load private key using cryptography library
        # Backward compatibility: pass backend for older versions
        if _BACKEND is not None:
            self.private_key = serialization.load_pem_private_key(
                private_bytes,
                password=None,
                backend=_BACKEND
            )
        else:
            self.private_key = serialization.load_pem_private_key(
                private_bytes,
                password=None
            )

        # Derive public key
        self.public_key = self.private_key.public_key()

        # Derive DID
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        pk_hash = hashlib.sha256(public_key_bytes).hexdigest()
        self.did = f"did:avsd:{pk_hash[:16]}"

        return self.did, self.private_key, self.public_key

    def save_public_key(self, filepath):
        """
        Save public key to file for sharing with other nodes

        Args:
            filepath: Path to save public key (e.g., 'device_public_key.pem')
        """
        if self.public_key is None:
            raise ValueError("No public key to save. Call generate_keypair_and_did() first.")

        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(filepath, 'wb') as f:
            f.write(public_bytes)

        print(f"[OK] Public key saved to {filepath}")

    def load_public_key(self, filepath):
        """
        Load public key from file

        Args:
            filepath: Path to public key file

        Returns:
            Ed25519PublicKey object
        """
        with open(filepath, 'rb') as f:
            public_bytes = f.read()

        # Backward compatibility: pass backend for older versions
        if _BACKEND is not None:
            public_key = serialization.load_pem_public_key(public_bytes, backend=_BACKEND)
        else:
            public_key = serialization.load_pem_public_key(public_bytes)
        return public_key

    def get_did_info(self):
        """
        Get DID information for sharing with validator

        Returns:
            dict: {'did': str, 'public_key_pem': str}
        """
        if self.did is None or self.public_key is None:
            raise ValueError("No DID generated. Call generate_keypair_and_did() first.")

        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return {
            'did': self.did,
            'public_key_pem': public_key_pem
        }


# Utility function for quick testing
def test_did_manager():
    """Test DID manager functionality"""
    print("\n=== Testing DID Manager ===\n")

    # Create DID manager
    manager = DIDManager()

    # Generate keypair and DID
    did, priv_key, pub_key = manager.generate_keypair_and_did()
    print(f"[OK] Generated DID: {did}")

    # Save keys
    manager.save_private_key("test_private_key.pem")
    manager.save_public_key("test_public_key.pem")

    # Load keys and verify DID matches
    manager2 = DIDManager()
    did2, _, _ = manager2.load_private_key("test_private_key.pem")
    print(f"[OK] Loaded DID: {did2}")

    assert did == did2, "DID mismatch after save/load!"
    print("[OK] DID matches after save/load")

    # Test DID info export
    did_info = manager.get_did_info()
    print(f"[OK] DID Info: {json.dumps({'did': did_info['did']}, indent=2)}")

    # Cleanup test files
    import os
    os.remove("test_private_key.pem")
    os.remove("test_public_key.pem")
    print("\n[OK] All tests passed!\n")


if __name__ == "__main__":
    test_did_manager()
