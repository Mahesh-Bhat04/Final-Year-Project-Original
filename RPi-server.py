from tkinter import *
from tkinter import simpledialog, messagebox
from CPABSC_Hybrid_R import *
import os
from flask import Flask, jsonify, request
from uuid import uuid4
import threading
import hashlib
import base64
import subprocess
import urllib.parse
from pathlib import Path
from charm.core.engine.util import objectToBytes, bytesToObject
import json
import requests

# Phase 1: DID/VC imports
from did_manager import DIDManager
from vc_manager import VCManager
from cryptography.hazmat.primitives import serialization

# Phase 2: Azure + Merkle imports
from merkle_tree import MerkleTree
from azure_storage import AzureStorage

app = Flask(__name__)

groupObj = PairingGroup('SS512')
cpabe = CPabe_BSW07(groupObj)
hyb_abe = HybridABEnc(cpabe, groupObj)

# Initialize keys at startup
def initialize_keys():
    """Initialize or load cryptographic keys and DID (Phase 1)"""
    global pk, msk, sk, k_sign, device_did_manager, device_vc_manager, device_vc

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

    # CP-ABE keys (backward compatibility)
    pkpath = Path("pk.txt")
    mskpath = Path("msk.txt")
    skpath = Path("sk.txt")
    k_signpath = Path("k_sign.txt")

    # Check if all key files exist
    if pkpath.is_file() and skpath.is_file():
        print("Loading existing CP-ABE keys...")

        # Load pk
        with open("pk.txt", 'r') as f:
            pk_str = f.read()
            pk_bytes = pk_str.encode("utf8")
            pk = bytesToObject(pk_bytes, groupObj)

        # Load sk
        with open("sk.txt", 'r') as f:
            sk_str = f.read()
            sk_bytes = sk_str.encode("utf8")
            sk = bytesToObject(sk_bytes, groupObj)

        # Load k_sign if exists
        if k_signpath.is_file():
            with open("k_sign.txt", 'r') as f:
                k_sign_str = f.read()
                k_sign_bytes = k_sign_str.encode("utf8")
                k_sign = bytesToObject(k_sign_bytes, groupObj)
        else:
            k_sign = None

        # Load msk if exists (might not be needed on RPi)
        if mskpath.is_file():
            with open("msk.txt", 'r') as f:
                msk_str = f.read()
                msk_bytes = msk_str.encode("utf8")
                msk = bytesToObject(msk_bytes, groupObj)
        else:
            msk = None

        print("CP-ABE keys loaded successfully")
    else:
        print("Warning: CP-ABE key files not found. Will use VC-based auth only.")
        pk = None
        sk = None
        k_sign = None
        msk = None

def start_listening():
    initialize_keys()
    app.app_context()
    app.run(host='0.0.0.0', port=5001)

# Phase 1: DID/VC endpoints
@app.route('/did/info', methods=['GET'])
def get_did_info():
    """Return device's DID and public key"""
    global device_did_manager

    if device_did_manager is None or device_did_manager.did is None:
        return jsonify({'error': 'DID not initialized'}), 500

    did_info = device_did_manager.get_did_info()
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
def transactions():
    response = {
        'message': "PONG!",
    }
    return jsonify(response), 200

@app.route('/keys/receive', methods=['POST'])
def receive_keys():
    """Receive cryptographic keys from PC node"""
    global pk, sk, k_sign, msk
    
    # Try to get JSON data first, fall back to form/URL parameters
    values = request.get_json(silent=True)
    if values is None:
        values = request.values
    
    required = ['pk', 'sk']  # Minimum required keys
    if not all(k in values for k in required):
        return jsonify({'error': 'Missing required keys'}), 400
    
    try:
        # Save and load pk
        with open("pk.txt", 'w') as f:
            f.write(values['pk'])
        pk_bytes = values['pk'].encode("utf8")
        pk = bytesToObject(pk_bytes, groupObj)
        
        # Save and load sk
        with open("sk.txt", 'w') as f:
            f.write(values['sk'])
        sk_bytes = values['sk'].encode("utf8")
        sk = bytesToObject(sk_bytes, groupObj)
        
        # Save k_sign if provided
        if 'k_sign' in values:
            with open("k_sign.txt", 'w') as f:
                f.write(values['k_sign'])
            k_sign_bytes = values['k_sign'].encode("utf8")
            k_sign = bytesToObject(k_sign_bytes, groupObj)
        
        # Save msk if provided (usually not needed on RPi)
        if 'msk' in values:
            with open("msk.txt", 'w') as f:
                f.write(values['msk'])
            msk_bytes = values['msk'].encode("utf8")
            msk = bytesToObject(msk_bytes, groupObj)
        
        print("Successfully received and saved keys from PC node")
        
        # Update UI if available
        try:
            text_keygen_time.set("Keys received from PC node")
        except:
            pass
            
        return jsonify({'message': 'Keys received successfully'}), 200
        
    except Exception as e:
        print(f"Error receiving keys: {e}")
        return jsonify({'error': str(e)}), 500

def install_sw(name, ct, pk, sk, pi, file):
    (file_pr_, delta_pr) = hyb_abe.decrypt(pk, sk, ct)
    file_pr = base64.b64decode(file_pr_).decode('utf-8')

    print("Writing Received Message: " + str(name))
    cur_directory = os.getcwd()
    file_path = os.path.join(cur_directory, name)
    open(file_path, 'w').write(file_pr)

    delta_bytes = objectToBytes(delta_pr, groupObj)
    # Pi verification: hash raw file bytes (matching PC's calculation)
    pi_pr = hashlib.sha256(base64.b64decode(file)).hexdigest() + hashlib.sha256(delta_bytes).hexdigest()

    print('-----------------------------------------------------------------------------------')

    if pi == pi_pr:

        print('Successfully Verified!')

        if os.name == "posix":
            os.chmod(file_path, 0o777)
        try:
            print("Running Files....")
            subprocess.call(file_path)
            print("The message has been reached!")
            print('-----------------------------------------------------------------------------------')
            return True

        except OSError as e:
            print("ERROR - The file is not a valid application: " + str(e))
            print('-----------------------------------------------------------------------------------')
            return False

    else:

        print('Verification Failed.. !!')
        print('-----------------------------------------------------------------------------------')
        return False


@app.route('/updates/new', methods=['POST'])
def post_updates_new():
    global pk, sk  # Use global keys if available

    # Try to get JSON data first, fall back to form/URL parameters
    values = request.get_json(silent=True)
    if values is None:
        values = request.values

    # Phase 2: Handle Azure file_update transactions
    if values.get('type') == 'file_update':
        return handle_azure_update(values)

    # Original format: full file data sent directly
    required = ['name', 'file', 'file_hash', 'ct', 'pi', 'pk']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # write ct
    print("Writing file as ct")
    ct_write = open("ct", 'w')
    ct_write.write(values['ct'])
    ct_write.close()

    # write pk
    print("Writing file as pk.txt")
    pk_write = open("pk.txt", 'w')
    pk_write.write(values['pk'])
    pk_write.close()

    name = values['name']
    file = values['file']
    file_hash = values['file_hash']
    pi = values['pi']

    ct_str = values['ct']
    ct_bytes = ct_str.encode("utf8")
    ct = bytesToObject(ct_bytes, groupObj)

    pk_str = values['pk']
    pk_bytes = pk_str.encode("utf8")
    pk = bytesToObject(pk_bytes, groupObj)

    # Check if sk exists, either from initialization or needs to be loaded
    if sk is None:
        if not os.path.exists("sk.txt"):
            print("ERROR - Secret key (sk.txt) not found!")
            print("Please ensure this RPi has received keys from a PC node.")
            return 'Secret key not found - RPi needs keys from PC node', 500

        print("Reading sk from saved file")
        sk_read = open("sk.txt", 'r')
        sk_str = sk_read.read()
        sk_bytes = sk_str.encode("utf8")
        sk = bytesToObject(sk_bytes, groupObj)
        sk_read.close()

    print("INFO - Received message...")
    if install_sw(name, ct, pk, sk, pi, file):
        return 'File reached!', 200
    else:
        return 'Failed!', 400


def handle_azure_update(values):
    """Phase 2: Download from Azure, verify Merkle tree, then decrypt.

    Flow:
    1. Receive lightweight metadata from PC (azure_blob_name, merkle_root, file_hash)
    2. Download encrypted blob from Azure Blob Storage
    3. Build Merkle tree from downloaded data, verify root matches on-chain root
    4. Parse blob JSON to extract file, ct, pk, pi
    5. Verify file hash matches
    6. Proceed with existing CP-ABSC decryption via install_sw()
    """
    global pk, sk

    required = ['name', 'azure_blob_name', 'merkle_root', 'file_hash']
    if not all(k in values for k in required):
        return 'Missing values for file_update', 400

    name = values['name']
    azure_blob_name = values['azure_blob_name']
    expected_merkle_root = values['merkle_root']
    expected_file_hash = values['file_hash']

    print(f"\n{'='*60}")
    print(f"[INFO] Phase 2: Azure file update received")
    print(f"[INFO] File: {name}")
    print(f"[INFO] Azure blob: {azure_blob_name}")
    print(f"[INFO] Expected Merkle root: {expected_merkle_root[:32]}...")
    print(f"{'='*60}")

    # Step 1: Download blob from Azure
    print("[1/5] Downloading from Azure Blob Storage...")
    try:
        azure = AzureStorage()
        blob_data = azure.download_blob(azure_blob_name)
    except Exception as e:
        print(f"[ERROR] Azure download failed: {e}")
        return f'Azure download failed: {e}', 500

    # Step 2: Verify Merkle tree integrity
    print("[2/5] Verifying Merkle tree integrity...")
    merkle = MerkleTree()
    if not merkle.verify_root(blob_data, expected_merkle_root):
        print("[ERROR] Merkle tree verification FAILED - data may be tampered!")
        return 'Merkle verification failed - data tampered!', 400

    print(f"[OK] Merkle tree verified - data integrity confirmed")

    # Step 3: Parse blob data
    print("[3/5] Parsing blob data...")
    try:
        data = json.loads(blob_data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"[ERROR] Failed to parse blob data: {e}")
        return f'Failed to parse blob data: {e}', 500

    file_content = data['file']
    ct_str = data['ct']
    pk_str = data['pk']
    pi = data['pi']

    # Step 4: Verify file hash
    print("[4/5] Verifying file hash...")
    file_bytes = base64.b64decode(file_content)
    actual_file_hash = hashlib.sha256(file_bytes).hexdigest()

    if actual_file_hash != expected_file_hash:
        print(f"[ERROR] File hash mismatch!")
        print(f"  Expected: {expected_file_hash}")
        print(f"  Actual:   {actual_file_hash}")
        return 'File hash verification failed!', 400

    print(f"[OK] File hash verified: {actual_file_hash[:32]}...")

    # Step 5: Deserialize and decrypt
    print("[5/5] Decrypting with CP-ABSC...")

    # Write ct and pk to local files (for compatibility)
    with open("ct", 'w') as f:
        f.write(ct_str)
    with open("pk.txt", 'w') as f:
        f.write(pk_str)

    ct = bytesToObject(ct_str.encode("utf8"), groupObj)
    pk = bytesToObject(pk_str.encode("utf8"), groupObj)

    # Load sk if needed
    if sk is None:
        if not os.path.exists("sk.txt"):
            print("[ERROR] Secret key (sk.txt) not found!")
            return 'Secret key not found', 500
        with open("sk.txt", 'r') as f:
            sk = bytesToObject(f.read().encode("utf8"), groupObj)

    # Decrypt and verify using existing install_sw function
    if install_sw(name, ct, pk, sk, pi, file_content):
        print(f"\n{'='*60}")
        print(f"[OK] Phase 2 file update complete!")
        print(f"[OK] File: {name}")
        print(f"[OK] Merkle verified + Hash verified + Decrypted + Pi verified")
        print(f"{'='*60}\n")
        return 'File received, Merkle verified, and decrypted!', 200
    else:
        return 'Decryption or Pi verification failed!', 400

def _line(line):
    if line == 1:
        return 10
    else:
        return 10 + 30*(line-1)

def _column(col):
    if col == 1:
        return 10
    else:
        return 10 + 120*(col-1)

node_identifier = str(uuid4()).replace('-', '')

main_window = Tk()
main_window.title("Blockchain Based Message Dissemination - Smart Device Window")
main_window.geometry("600x250")
text_keygen_time = StringVar()
label_keygen_time = Label(main_window, text="Integrity Checking:").place(x=_column(1), y=_line(1))
entry_keygen_time = Entry(main_window, textvariable=text_keygen_time).place(x=_column(3)-35, y=_line(1))

listening_thread = threading.Thread(name="listening", target=start_listening, daemon=True)
listening_thread.start()
mainloop()