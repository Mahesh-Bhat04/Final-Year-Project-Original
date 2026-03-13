from tkinter import *
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

# Phase 1: DID/VC imports
from did_manager import DIDManager
from vc_manager import VCManager

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
        print("[INFO] No credential found. Register with validator to receive VC.")
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
    1. Receive VC
    2. Verify VC signature
    3. Check that VC is issued to this device
    4. Store VC locally
    """
    global device_vc_manager, device_did_manager, device_vc

    values = request.get_json(silent=True)
    if values is None or 'credential' not in values:
        return jsonify({'error': 'Missing credential'}), 400

    credential = values['credential']

    # Get validator's public key (should fetch from blockchain in production)
    # For now, we'll verify using the signature in the VC
    try:
        # Extract issuer DID
        issuer_did = credential.get('issuer')
        if not issuer_did:
            return jsonify({'error': 'Missing issuer DID in credential'}), 400

        # For verification, we need the validator's public key
        # In production, fetch this from blockchain or DID registry
        # For now, we'll rely on the signature verification in VC

        # Load validator public key from file if available
        validator_pub_key_path = Path("validator_public_key.pem")
        if validator_pub_key_path.is_file():
            validator_public_key = device_did_manager.load_public_key("validator_public_key.pem")
        else:
            # Try to fetch from PC node
            print("[WARNING] Validator public key not found locally")
            return jsonify({'error': 'Validator public key not available for verification'}), 500

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
    file_pr = base64.b64decode(file_pr_).decode('ascii')

    print("Writing Received Message: " + str(name))
    cur_directory = os.getcwd()
    file_path = os.path.join(cur_directory, name)
    open(file_path, 'w').write(file_pr)

    delta_bytes = objectToBytes(delta_pr, groupObj)
    pi_pr = hashlib.sha256(bytes(str(file), 'utf-8')).hexdigest() + hashlib.sha256(delta_bytes).hexdigest()

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