"""
Verifiable Credential Manager

This module handles VC issuance, verification, and policy evaluation.
Uses Ed25519 signatures via cryptography library (no custom implementation).

VC Structure (simplified):
{
    "issuer": "did:avsd:abc123...",
    "subject": "did:avsd:xyz789...",
    "issued_at": 1234567890,
    "expires_at": 1234654290,
    "claims": {
        "role": "sensor",
        "region": "Hyderabad",
        "attributes": ["ONE", "TWO"]
    },
    "signature": "base64_encoded_ed25519_signature"
}
"""

import json
import time
import base64
import hashlib
import re


class VCManager:
    """Manages Verifiable Credential creation, signing, and verification"""

    def __init__(self, did_manager=None):
        """
        Initialize VC Manager

        Args:
            did_manager: DIDManager instance (for issuer's private key)
        """
        self.did_manager = did_manager

    def issue_credential(self, subject_did, claims, validity_hours=24):
        """
        Issue a Verifiable Credential for a device

        Args:
            subject_did: DID of the device receiving the credential
            claims: dict with device attributes/claims
                   Example: {"role": "sensor", "region": "Hyderabad", "attributes": ["ONE", "TWO"]}
            validity_hours: Credential validity period in hours

        Returns:
            dict: Signed Verifiable Credential
        """
        if self.did_manager is None or self.did_manager.did is None:
            raise ValueError("DIDManager not initialized. Cannot issue VC without issuer DID.")

        # Create credential structure
        now = int(time.time())
        expires_at = now + (validity_hours * 3600)

        credential = {
            "issuer": self.did_manager.did,
            "subject": subject_did,
            "issued_at": now,
            "expires_at": expires_at,
            "claims": claims
        }

        # Sign credential with issuer's private key
        signature = self._sign_credential(credential)
        credential["signature"] = signature

        return credential

    def _sign_credential(self, credential):
        """
        Sign credential using Ed25519

        Args:
            credential: Credential dict without signature

        Returns:
            str: Base64-encoded signature
        """
        if self.did_manager is None or self.did_manager.private_key is None:
            raise ValueError("Private key not available for signing")

        # Canonical JSON serialization (sorted keys for consistency)
        canonical = json.dumps(credential, sort_keys=True, separators=(',', ':'))
        message_bytes = canonical.encode('utf-8')

        # Sign using Ed25519 (cryptography library)
        signature_bytes = self.did_manager.private_key.sign(message_bytes)

        # Encode as base64 for JSON storage
        signature_b64 = base64.b64encode(signature_bytes).decode('ascii')

        return signature_b64

    def verify_credential(self, credential, issuer_public_key):
        """
        Verify a Verifiable Credential's signature and validity

        Args:
            credential: VC dict with signature
            issuer_public_key: Ed25519PublicKey of the issuer

        Returns:
            tuple: (is_valid: bool, error_message: str)
        """
        # 1. Check structure
        required_fields = ["issuer", "subject", "issued_at", "expires_at", "claims", "signature"]
        for field in required_fields:
            if field not in credential:
                return False, f"Missing required field: {field}"

        # 2. Check expiration
        now = int(time.time())
        if now > credential["expires_at"]:
            return False, f"Credential expired at {credential['expires_at']} (now: {now})"

        # 3. Extract and verify signature
        signature_b64 = credential["signature"]

        # Make a copy without signature for verification
        cred_copy = credential.copy()
        del cred_copy["signature"]

        try:
            # Canonical serialization (same as signing)
            canonical = json.dumps(cred_copy, sort_keys=True, separators=(',', ':'))
            message_bytes = canonical.encode('utf-8')

            # Decode signature
            signature_bytes = base64.b64decode(signature_b64)

            # Verify signature using Ed25519 (cryptography library)
            issuer_public_key.verify(signature_bytes, message_bytes)

            return True, "Valid"

        except Exception as e:
            return False, f"Signature verification failed: {str(e)}"

    def check_policy(self, device_claims, access_policy):
        """
        Simple policy evaluation - check if device claims satisfy access policy

        Policy format examples:
        - "(ONE and TWO)" - requires attributes ONE AND TWO
        - "(ONE or TWO)" - requires either ONE OR TWO
        - "(role = sensor)" - requires role claim to be "sensor"
        - "(role = sensor AND region = Hyderabad)" - both conditions must match

        Device claims example:
        {
            "role": "sensor",
            "region": "Hyderabad",
            "attributes": ["ONE", "TWO", "THREE"]
        }

        Args:
            device_claims: dict with device claims
            access_policy: str with policy expression

        Returns:
            bool: True if policy satisfied
        """
        policy_expr = access_policy

        # Extract attribute list if present
        device_attributes = device_claims.get("attributes", [])
        device_attributes_set = set(attr.upper() for attr in device_attributes)

        # Step 1: Handle role/region checks (e.g., "role = sensor")
        for key, value in device_claims.items():
            if key != "attributes":  # Skip attributes list
                # Replace "key = value" with True/False (case-insensitive)
                pattern = rf'\b{re.escape(key)}\s*=\s*{re.escape(str(value))}\b'
                policy_expr = re.sub(pattern, 'True', policy_expr, flags=re.IGNORECASE)

        # Step 2: Replace attribute names with True/False
        # Only replace whole words that are uppercase attribute names
        def replace_attribute(match):
            attr_name = match.group(0)
            # Skip operators
            if attr_name in ['AND', 'OR', 'NOT']:
                return attr_name
            # Check if attribute exists in device claims
            if attr_name in device_attributes_set:
                return 'True'
            else:
                return 'False'

        # Replace uppercase words that are not operators
        policy_expr = re.sub(r'\b[A-Z_][A-Z_0-9]*\b', replace_attribute, policy_expr)

        # Step 3: Replace AND/OR/NOT with Python operators
        policy_expr = policy_expr.replace(' AND ', ' and ')
        policy_expr = policy_expr.replace(' OR ', ' or ')
        policy_expr = policy_expr.replace(' NOT ', ' not ')

        # Clean up
        policy_expr = policy_expr.strip()

        try:
            # Evaluate expression
            result = eval(policy_expr)
            return result
        except Exception as e:
            print(f"[WARNING] Policy evaluation failed: {e}")
            print(f"Original policy: {access_policy}")
            print(f"Processed policy: {policy_expr}")
            return False

    def get_claims(self, credential):
        """Extract claims from verified credential"""
        return credential.get("claims", {})

    def hash_credential(self, credential):
        """
        Create hash of credential for blockchain anchoring

        Returns:
            str: Hex-encoded SHA-256 hash
        """
        canonical = json.dumps(credential, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


# Utility functions for testing
def test_vc_manager():
    """Test VC manager functionality"""
    print("\n=== Testing VC Manager ===\n")

    # Import DIDManager for testing
    from did_manager import DIDManager

    # Create issuer (validator)
    issuer_dm = DIDManager()
    issuer_did, issuer_priv, issuer_pub = issuer_dm.generate_keypair_and_did()
    print(f"[OK] Issuer DID: {issuer_did}")

    # Create subject (IoT device)
    subject_dm = DIDManager()
    subject_did, subject_priv, subject_pub = subject_dm.generate_keypair_and_did()
    print(f"[OK] Subject DID: {subject_did}")

    # Create VC Manager
    vc_mgr = VCManager(issuer_dm)

    # Issue credential
    claims = {
        "role": "sensor",
        "region": "Hyderabad",
        "attributes": ["ONE", "TWO"]
    }
    vc = vc_mgr.issue_credential(subject_did, claims, validity_hours=24)
    print(f"[OK] Issued VC: {json.dumps(vc, indent=2)}")

    # Verify credential
    is_valid, msg = vc_mgr.verify_credential(vc, issuer_pub)
    print(f"[OK] VC Verification: {is_valid} - {msg}")
    assert is_valid, "VC verification failed!"

    # Test VC hash
    vc_hash = vc_mgr.hash_credential(vc)
    print(f"[OK] VC Hash: {vc_hash}")

    # Test policy evaluation
    policies = [
        ("(ONE and TWO)", True),
        ("(ONE or THREE)", True),
        ("(ONE and FOUR)", False),
        ("(role = sensor)", True),
        ("(role = actuator)", False),
        ("(role = sensor AND region = Hyderabad)", True),
        ("(role = sensor AND region = Mumbai)", False),
        ("((ONE and TWO) or (THREE and FOUR))", True),
        ("(FOUR and FIVE)", False),
    ]

    print("\n[Testing Policy Evaluation]")
    for policy, expected in policies:
        result = vc_mgr.check_policy(claims, policy)
        status = "[OK]" if result == expected else "[FAIL]"
        print(f"{status} Policy: {policy} => {result} (expected: {expected})")
        assert result == expected, f"Policy check failed for: {policy}"

    # Test expired credential
    print("\n[Testing Expired Credential]")
    expired_vc = vc_mgr.issue_credential(subject_did, claims, validity_hours=-1)  # Already expired
    is_valid, msg = vc_mgr.verify_credential(expired_vc, issuer_pub)
    print(f"[OK] Expired VC Verification: {is_valid} - {msg}")
    assert not is_valid, "Expired VC should not be valid!"

    # Test tampered credential
    print("\n[Testing Tampered Credential]")
    tampered_vc = vc.copy()
    tampered_vc["claims"]["attributes"] = ["THREE", "FOUR"]  # Tamper with claims
    is_valid, msg = vc_mgr.verify_credential(tampered_vc, issuer_pub)
    print(f"[OK] Tampered VC Verification: {is_valid} - {msg}")
    assert not is_valid, "Tampered VC should not be valid!"

    print("\n[OK] All tests passed!\n")


if __name__ == "__main__":
    test_vc_manager()
