import os
from flask import Flask, jsonify, request
from uuid import uuid4
import threading
import hashlib
import subprocess
import urllib.parse
from pathlib import Path
import json
import requests

# Phase 1: DID/VC imports
from did_manager import DIDManager
from vc_manager import VCManager
from cryptography.hazmat.primitives import serialization

# Phase 2: Azure + Merkle imports
from merkle_tree import MerkleTree
from azure_storage import AzureStorage

# Phase 3: AES-256-GCM + RSA key management
from aes_encryption import aes_decrypt
from key_management import (generate_rsa_keypair, save_private_key, load_private_key,
                            save_public_key, serialize_public_key, decrypt_aes_key)

app = Flask(__name__)

# Initialize keys at startup
def initialize_keys():
    """Initialize or load cryptographic keys and DID (Phase 1) + RSA (Phase 3)"""
    global device_did_manager, device_vc_manager, device_vc
    global device_rsa_private_key, device_rsa_public_key

    # Phase 1: Initialize DID Manager
    print("\n=== Initializing DID (Phase 1) ===")
    device_did_manager = DIDManager()
    device_did_path = Path("device_private_key.pem")

    if device_did_path.is_file():
        print("[INFO] Loading existing device DID...")
        device_did, device_priv, device_pub = device_did_manager.load_private_key("device_private_key.pem")
        print(f"[OK] Device DID: {device_did}")
    else:
        print("[INFO] Generating new device DID...")
        device_did, device_priv, device_pub = device_did_manager.generate_keypair_and_did()
        device_did_manager.save_private_key("device_private_key.pem")
        device_did_manager.save_public_key("device_public_key.pem")
        print(f"[OK] Generated Device DID: {device_did}")

    # Initialize VC Manager (for verification)
    device_vc_manager = VCManager(device_did_manager)

    # Load device credential if exists
    vc_path = Path("device_credential.json")
    if vc_path.is_file():
        print("[INFO] Loading existing device credential...")
        with open("device_credential.json", 'r') as f:
            device_vc = json.load(f)
        print(f"[OK] Device VC loaded")
    else:
        print("\n" + "="*60)
        print("[INFO] No credential found.")
        print("[INFO] To register, use one of these methods:")
        print("  1. From validator: Add RPi with VC (GUI menu)")
        print("  2. Use curl command (see documentation)")
        print("  3. Use /register endpoint (below)")
        print("="*60 + "\n")
        device_vc = None

    print("=" * 60 + "\n")

    # Phase 3: RSA keypair for AES key decryption
    rsa_priv_path = Path("device_rsa_private_key.pem")
    if rsa_priv_path.is_file():
        print("[INFO] Loading existing RSA keypair...")
        device_rsa_private_key = load_private_key("device_rsa_private_key.pem")
        device_rsa_public_key = device_rsa_private_key.public_key()
        print("[OK] RSA keypair loaded")
    else:
        print("[INFO] Generating new RSA-2048 keypair...")
        device_rsa_private_key, device_rsa_public_key = generate_rsa_keypair()
        save_private_key(device_rsa_private_key, "device_rsa_private_key.pem")
        save_public_key(device_rsa_public_key, "device_rsa_public_key.pem")
        print("[OK] RSA-2048 keypair generated")

    print("=" * 60)

def start_listening():
    """Initialize keys and start Flask server on port 5001."""
    initialize_keys()
    app.app_context()
    app.run(host='0.0.0.0', port=5001)

# Phase 1: DID/VC endpoints
@app.route('/did/info', methods=['GET'])
def get_did_info():
    """Return device's DID, Ed25519 public key, and RSA public key"""
    global device_did_manager, device_rsa_public_key

    if device_did_manager is None or device_did_manager.did is None:
        return jsonify({'error': 'DID not initialized'}), 500

    did_info = device_did_manager.get_did_info()

    # Phase 3: Include RSA public key for AES key wrapping
    if device_rsa_public_key:
        did_info['rsa_public_key_pem'] = serialize_public_key(device_rsa_public_key)

    return jsonify(did_info), 200

@app.route('/vc/receive', methods=['POST'])
def receive_credential():
    """
    Receive and verify Verifiable Credential from validator

    Flow:
    1. Receive VC and validator's public key
    2. Verify VC signature
    3. Check that VC is issued to this device
    4. Store VC locally
    """
    global device_vc_manager, device_did_manager, device_vc

    values = request.get_json(silent=True)
    if values is None or 'credential' not in values:
        return jsonify({'error': 'Missing credential'}), 400

    credential = values['credential']
    validator_public_key_pem = values.get('validator_public_key_pem')

    # Get validator's public key
    try:
        # Extract issuer DID
        issuer_did = credential.get('issuer')
        if not issuer_did:
            return jsonify({'error': 'Missing issuer DID in credential'}), 400

        # Load validator public key from request or file
        if validator_public_key_pem:
            # Save validator public key for future use
            with open("validator_public_key.pem", "w") as f:
                f.write(validator_public_key_pem)

            # Load it using cryptography library
            from cryptography.hazmat.primitives import serialization
            try:
                from cryptography.hazmat.backends import default_backend
                _BACKEND = default_backend()
            except ImportError:
                _BACKEND = None

            if _BACKEND is not None:
                validator_public_key = serialization.load_pem_public_key(
                    validator_public_key_pem.encode('utf-8'),
                    backend=_BACKEND
                )
            else:
                validator_public_key = serialization.load_pem_public_key(
                    validator_public_key_pem.encode('utf-8')
                )
        else:
            # Try to load from file
            validator_pub_key_path = Path("validator_public_key.pem")
            if validator_pub_key_path.is_file():
                validator_public_key = device_did_manager.load_public_key("validator_public_key.pem")
            else:
                print("[ERROR] Validator public key not provided and not found locally")
                return jsonify({'error': 'Validator public key required for verification'}), 400

        # Verify VC signature
        is_valid, error_msg = device_vc_manager.verify_credential(credential, validator_public_key)
        if not is_valid:
            print(f"[ERROR] Invalid credential: {error_msg}")
            return jsonify({'error': f'Invalid credential: {error_msg}'}), 400

        # Check that VC is issued to this device
        subject_did = credential.get('subject')
        if subject_did != device_did_manager.did:
            return jsonify({'error': 'Credential not issued to this device'}), 403

        # Store VC
        device_vc = credential
        vc_hash = device_vc_manager.hash_credential(credential)

        with open('device_credential.json', 'w') as f:
            json.dump(credential, f, indent=2)

        print(f"[OK] Received and verified VC")
        print(f"[OK] VC Hash: {vc_hash}")
        print(f"[OK] Claims: {json.dumps(credential.get('claims', {}), indent=2)}")

        return jsonify({
            'message': 'Credential received and verified',
            'vc_hash': vc_hash,
            'claims': credential.get('claims', {})
        }), 200

    except Exception as e:
        print(f"[ERROR] Failed to process credential: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to process credential: {str(e)}'}), 500

@app.route('/ping', methods=['GET'])
def ping():
    """Flask endpoint: health check."""
    return jsonify({'message': 'PONG!'}), 200

@app.route('/updates/new', methods=['POST'])
def post_updates_new():
    """Flask endpoint: receive file update from disseminator, route to AES-GCM handler."""
    values = request.get_json(silent=True)
    if values is None:
        values = request.values

    if values.get('type') == 'file_update':
        return handle_azure_update(values)

    return 'Unsupported update format', 400


def handle_azure_update(values):
    """Download from Azure, verify Merkle tree, decrypt with AES-256-GCM."""
    global device_rsa_private_key

    required = ['name', 'azure_blob_name', 'merkle_root', 'file_hash']
    if not all(k in values for k in required):
        return 'Missing values for file_update', 400

    name = values['name']
    azure_blob_name = values['azure_blob_name']
    expected_merkle_root = values['merkle_root']
    expected_file_hash = values['file_hash']
    encryption_type = values.get('encryption', 'cp-absc')

    print(f"\n{'='*60}")
    print(f"[INFO] Azure file update received")
    print(f"[INFO] File: {name}")
    print(f"[INFO] Encryption: {encryption_type}")
    print(f"[INFO] Azure blob: {azure_blob_name}")
    print(f"[INFO] Expected Merkle root: {expected_merkle_root[:32]}...")
    print(f"{'='*60}")

    # Step 1: Download blob from Azure
    print("[1/4] Downloading from Azure Blob Storage...")
    try:
        azure = AzureStorage()
        blob_data = azure.download_blob(azure_blob_name)
    except Exception as e:
        print(f"[ERROR] Azure download failed: {e}")
        return f'Azure download failed: {e}', 500

    # Step 2: Verify Merkle tree integrity
    print("[2/4] Verifying Merkle tree integrity...")
    merkle = MerkleTree()
    if not merkle.verify_root(blob_data, expected_merkle_root):
        print("[ERROR] Merkle tree verification FAILED - data may be tampered!")
        return 'Merkle verification failed - data tampered!', 400
    print(f"[OK] Merkle tree verified - data integrity confirmed")

    # Step 3: Parse blob data
    print("[3/4] Parsing blob data...")
    try:
        data = json.loads(blob_data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"[ERROR] Failed to parse blob data: {e}")
        return f'Failed to parse blob data: {e}', 500

    # Step 4: Decrypt with AES-256-GCM
    return _handle_aes_gcm_decrypt(name, data, values, expected_file_hash)


def _handle_aes_gcm_decrypt(name, data, values, expected_file_hash):
    """Phase 3: AES-256-GCM decryption with RSA key unwrapping"""
    global device_rsa_private_key

    import time as time_mod
    start_time = time_mod.time()

    print("[4/4] Decrypting with AES-256-GCM (Phase 3)...")

    # Step 4a: Decrypt AES key using RSA private key
    encrypted_aes_key = values.get('encrypted_aes_key')
    if not encrypted_aes_key:
        print("[ERROR] No encrypted AES key received!")
        return 'No encrypted AES key in metadata', 400

    try:
        aes_key = decrypt_aes_key(encrypted_aes_key, device_rsa_private_key)
        print(f"[OK] AES key decrypted via RSA ({len(aes_key)*8}-bit)")
    except Exception as e:
        print(f"[ERROR] RSA key decryption failed: {e}")
        return f'RSA key decryption failed: {e}', 400

    # Step 4b: AES-GCM decrypt the file
    try:
        decrypted_file = aes_decrypt(aes_key, data['nonce'], data['ciphertext'])
        print(f"[OK] AES-GCM decrypted ({len(decrypted_file)} bytes)")
    except Exception as e:
        print(f"[ERROR] AES-GCM decryption failed (tampered data?): {e}")
        return f'AES-GCM decryption failed: {e}', 400

    # Step 4c: Verify file hash
    actual_hash = hashlib.sha256(decrypted_file).hexdigest()
    if actual_hash != expected_file_hash:
        print(f"[ERROR] File hash mismatch!")
        return 'File hash mismatch after decryption', 400
    print(f"[OK] File hash verified: {actual_hash[:32]}...")

    # Step 4d: Write decrypted file
    decrypt_time = (time_mod.time() - start_time) * 1000
    cur_directory = os.getcwd()
    file_path = os.path.join(cur_directory, name)
    open(file_path, 'wb').write(decrypted_file)
    print(f"[OK] File written: {file_path}")

    # Step 4e: Execute file
    if os.name == "posix":
        os.chmod(file_path, 0o777)
    try:
        subprocess.call(file_path, shell=True)
        print("The message has been reached!")
    except OSError as e:
        print(f"[WARN] File not executable: {e}")

    print(f"\n{'='*60}")
    print(f"[OK] Phase 3 file update complete!")
    print(f"[OK] File: {name}")
    print(f"[OK] Merkle verified + AES-GCM decrypted + Hash verified")
    print(f"[OK] Decryption time: {decrypt_time:.1f}ms")
    print(f"{'='*60}\n")
    return 'File received, Merkle verified, AES-GCM decrypted!', 200


node_identifier = str(uuid4()).replace('-', '')

listening_thread = threading.Thread(name="listening", target=start_listening, daemon=True)
listening_thread.start()

# Keep main thread alive
import signal
signal.pause() if os.name == 'posix' else input("Press Enter to exit...\n")