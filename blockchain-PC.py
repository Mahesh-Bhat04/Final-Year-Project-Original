from time import strftime
import time, os, threading
from tkinter import *
from tkinter import ttk
import tkinter.simpledialog as simpledialog
import tkinter.messagebox as messagebox
import tkinter.filedialog as filedialog
from pathlib import Path
from CPABSC_Hybrid_R import *
from definitions import *
from random import SystemRandom
from uuid import uuid4
import requests
from flask import Flask, jsonify, request
from pyclamd import *
import base64
import json

# Phase 1: DID/VC imports
from did_manager import DIDManager
from vc_manager import VCManager

# Phase 2: Azure + Merkle imports
from merkle_tree import MerkleTree
from azure_storage import AzureStorage

# We will mine automatically every 15 seconds and then propagate blockchain with other nodes
# Working, need to connect with Blockchain First!
def periodic_spread():
    while True:
        time.sleep(15)
        print("INFO: Waiting for transactions...")
        verify_block_action(blockchain.current_transactions, None, None, None)

        if blockchain.connected and not blockchain.chain_updated:
            print("INFO: Syncing blockchain from network...")
            blockchain.resolve_conflicts()
            blockchain.chain_updated = True

# Definition to run the Flask Framework in a separated thread from Tkinter
def init_blockchain():
    blockchain_spread.start()
    app.app_context()
    app.run(host='0.0.0.0', port=5000)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Keys Generation
groupObj = PairingGroup('SS512')
cpabe = CPabe_BSW07(groupObj)
hyb_abe = HybridABEnc(cpabe, groupObj)

# access_policy = '((four or three) and (three or one))'
# S = ['ONE', 'TWO', 'THREE']

access_policy = '(ONE and TWO) or (THREE and (FOUR and FIVE))' # 5
S = ['ONE', 'TWO'] # 2

(pk, msk) = hyb_abe.setup()
(sk, k_sign) = hyb_abe.keygen(pk, msk, S)

pkpath = Path("pk.txt")
mskpath = Path("msk.txt")
skpath = Path("sk.txt")
k_signpath = Path("k_sign.txt")

if pkpath.is_file():
    print("Reading File pk.txt")
    pk_read = open("pk.txt", 'r')
    pk_str = pk_read.read() # it's a string
    pk_bytes = pk_str.encode("utf8")
    pk = bytesToObject(pk_bytes, groupObj)
    pk_read.close()

else:
    print("Writing file File pk.txt")
    pk_read = open("pk.txt", 'w')
    pk_read.write(str(objectToBytes(pk, groupObj), 'utf-8'))  # saving as a string
    pk_read.close()

if mskpath.is_file():
    print("Reading File msk.txt")
    msk_read = open("msk.txt", 'r')
    msk_str = msk_read.read() # it's a string
    msk_bytes = msk_str.encode("utf8")
    msk = bytesToObject(msk_bytes, groupObj)
    msk_read.close()

else:
    print("Writing file File msk.txt")
    msk_read = open("msk.txt", 'w')
    msk_read.write(str(objectToBytes(msk, groupObj), 'utf-8'))  # saving as a string
    msk_read.close()

if skpath.is_file():
    print("Reading File sk.txt")
    sk_read = open("sk.txt", 'r')
    sk_str = sk_read.read()  # it's a string
    sk_bytes = sk_str.encode("utf8")
    sk = bytesToObject(sk_bytes, groupObj)
    sk_read.close()

else:
    print("Writing file File sk.txt")
    sk_read = open("sk.txt", 'w')
    sk_read.write(str(objectToBytes(sk, groupObj), 'utf-8'))  # saving as a string
    sk_read.close()

if k_signpath.is_file():
    print("Reading File k_sign.txt")
    k_sign_read = open("k_sign.txt", 'r')
    k_sign_str = k_sign_read.read()  # it's a string
    k_sign_bytes = k_sign_str.encode("utf8")
    k_sign = bytesToObject(k_sign_bytes, groupObj)
    k_sign_read.close()

else:
    print("Writing file k_sign.txt")
    k_sign_read = open("k_sign.txt", 'w')
    k_sign_read.write(str(objectToBytes(k_sign, groupObj), 'utf-8'))  # saving as a string
    k_sign_read.close()
# Keys Generation End ========== x ==========

# Phase 1: DID/VC Initialization
print("\n=== Initializing DID/VC Infrastructure (Phase 1) ===")
validator_did_manager = DIDManager()
validator_did_path = Path("validator_private_key.pem")

if validator_did_path.is_file():
    print("[INFO] Loading existing validator DID...")
    validator_did, validator_priv, validator_pub = validator_did_manager.load_private_key("validator_private_key.pem")
    print(f"[OK] Validator DID: {validator_did}")
else:
    print("[INFO] Generating new validator DID...")
    validator_did, validator_priv, validator_pub = validator_did_manager.generate_keypair_and_did()
    validator_did_manager.save_private_key("validator_private_key.pem")
    validator_did_manager.save_public_key("validator_public_key.pem")
    print(f"[OK] Generated Validator DID: {validator_did}")

# Initialize VC Manager with validator's DID manager
validator_vc_manager = VCManager(validator_did_manager)
print("[OK] VC Manager initialized")
print("=" * 60 + "\n")

# Store validator DID in blockchain after initialization
# This will be saved when blockchain.save_values() is called

# print("INFO pk: ", pk)
keys_generation_time = time.time()
print("INFO: Node Identifier:" + node_identifier)

# Instantiate the Blockchain
blockchain = Blockchain()
blockchain_thread = threading.Thread(name="blockchain", target=init_blockchain, daemon=True)

#Node List and Chain Loading...
blockchain.load_values() # From definitions

# Phase 1: Store validator DID in blockchain (will be saved with blockchain.save_values())
blockchain.validator_did = validator_did_manager.did

# Instantiate the Node
app = Flask(__name__)

# Other separated thread to mining and sharing blockchain periodically
blockchain_spread = threading.Thread(name="spread", target=periodic_spread, daemon=True)

@app.route('/blocks/new', methods=['POST'])
def blocks_new():
    # Try to get JSON data first, fall back to form/URL parameters
    values = request.get_json(silent=True)
    if values is None:
        values = request.values

    # Create a new Block
    added = blockchain.new_block(_transactions=values)
    if added:
        response = {
            'message': 'The block is added to the chain',
        }
    else:
        response = {
            'message': 'The block was rejected',
        }
    return jsonify(response), 201
    
@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block

    if len(blockchain.current_transactions) <= 0:
        response = {
            'message': 'No transactions to validate'
        }
        return jsonify(response), 200

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)

    block = blockchain.new_block(previous_hash)
    if block == False:
        response = {
            'message': "Invalid Transaction!",
        }
        return jsonify(response), 400
    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():   # from Definition
    # Try to get JSON data first, fall back to form/URL parameters
    values = request.get_json(silent=True)
    if values is None:
        values = request.values

    # Phase 2: Handle Azure file_update transactions
    if values.get('type') == 'file_update':
        required = ['name', 'azure_blob_name', 'merkle_root', 'file_hash']
        if not all(k in values for k in required):
            return 'Missing values for file_update', 400
        index = blockchain.new_azure_transaction(
            values['name'], values['azure_blob_name'], values['merkle_root'],
            values['file_hash'], values.get('file_size', 0), values.get('chunk_count', 0)
        )
        response = {'message': f'Azure transaction will be added to Block {index}'}
        return jsonify(response), 201

    # Phase 1: Handle VC transactions
    if values.get('type') == 'vc_issuance':
        required = ['vc_hash', 'issuer_did', 'subject_did']
        if not all(k in values for k in required):
            return 'Missing values for vc_issuance', 400
        index = blockchain.new_vc_transaction(
            values['vc_hash'], values['issuer_did'], values['subject_did']
        )
        response = {'message': f'VC transaction will be added to Block {index}'}
        return jsonify(response), 201

    # Original format: full file transaction
    required = ['name', 'file', 'file_hash', 'ct', 'pi', 'pk']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(values['name'], values['file'], values['file_hash'],
                                       values['ct'], values['pi'], values['pk'])
    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

@app.route('/transactions', methods=['GET'])
def transactions():
    response = {
        'chain': blockchain.current_transactions,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

# Phase 1: VC query endpoint
@app.route('/vc/<vc_hash>', methods=['GET'])
def get_vc(vc_hash):
    """Get Verifiable Credential by hash"""
    if vc_hash in blockchain.issued_vcs:
        return jsonify(blockchain.issued_vcs[vc_hash]), 200
    else:
        return jsonify({'error': 'VC not found'}), 404

@app.route('/vc/validator/did', methods=['GET'])
def get_validator_did():
    """Get validator's DID and public key"""
    return jsonify({
        'did': validator_did_manager.did,
        'public_key_pem': validator_did_manager.get_did_info()['public_key_pem']
    }), 200

@app.route('/add_rpi_with_vc', methods=['POST'])
def add_rpi_with_vc_api():
    """
    Phase 1: Register RPi device via REST API

    Request body:
    {
        "device_did": "did:avsd:...",
        "device_public_key_pem": "-----BEGIN PUBLIC KEY-----...",
        "claims": {
            "role": "sensor",
            "region": "Hyderabad",
            "attributes": ["ONE", "TWO"]
        },
        "validity_hours": 24
    }
    """
    try:
        data = request.get_json()

        # Extract parameters
        device_did = data.get('device_did')
        device_public_key_pem = data.get('device_public_key_pem')
        claims = data.get('claims', {})
        validity_hours = data.get('validity_hours', 24)

        # Validate inputs
        if not device_did or not device_public_key_pem or not claims:
            return jsonify({
                'status': 'error',
                'message': 'Missing required fields: device_did, device_public_key_pem, claims'
            }), 400

        print(f"\n[API] Device registration request")
        print(f"  Device DID: {device_did}")
        print(f"  Claims: {claims}")

        # Check if device already registered
        if device_did in blockchain.device_dids:
            existing_vc_hash = blockchain.device_dids[device_did]['vc_hash']
            print(f"[INFO] Device already registered with VC hash: {existing_vc_hash}")

            # Check if existing VC is still valid
            if existing_vc_hash in blockchain.issued_vcs:
                existing_vc = blockchain.issued_vcs[existing_vc_hash]['vc']

                # Simple expiration check
                import time
                if time.time() < existing_vc['expires_at']:
                    print(f"[INFO] Existing VC is still valid. Returning existing VC.")
                    return jsonify({
                        'status': 'success',
                        'message': 'Device already registered (existing VC returned)',
                        'vc_hash': existing_vc_hash,
                        'vc': existing_vc,
                        'validator_public_key_pem': validator_did_manager.get_did_info()['public_key_pem'],
                        'blockchain_anchored': True,
                        'is_new': False
                    }), 200
                else:
                    print(f"[INFO] Existing VC expired. Issuing new VC.")
            else:
                print(f"[INFO] Existing VC not found. Issuing new VC.")

        # Issue Verifiable Credential
        vc = validator_vc_manager.issue_credential(
            subject_did=device_did,
            claims=claims,
            validity_hours=validity_hours
        )

        # Compute VC hash
        vc_hash = validator_vc_manager.hash_credential(vc)

        # Store VC
        blockchain.issued_vcs[vc_hash] = {
            'vc': vc,
            'validator_public_key_pem': device_public_key_pem  # Store device's public key
        }

        # Create blockchain transaction for VC anchoring
        blockchain.new_vc_transaction(
            vc_hash=vc_hash,
            issuer_did=validator_did_manager.did,
            subject_did=device_did
        )

        # Store device DID mapping
        blockchain.device_dids[device_did] = {
            'did': device_did,
            'vc_hash': vc_hash,
            'public_key_pem': device_public_key_pem,
            'registered_at': vc['issued_at']
        }

        # Save state
        blockchain.save_values()

        print(f"[OK] VC issued with hash: {vc_hash}")
        print(f"[OK] VC transaction anchored on blockchain")

        return jsonify({
            'status': 'success',
            'message': 'Device registered with VC',
            'vc_hash': vc_hash,
            'vc': vc,
            'validator_public_key_pem': validator_did_manager.get_did_info()['public_key_pem'],
            'blockchain_anchored': True
        }), 200

    except Exception as e:
        print(f"[ERROR] Registration failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():  # From Definitions
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

def foo():
    print("foo action")

def disconnect_exit():
    blockchain.save_values() # From Definitions
    main_window.quit()

def add_node():
    _title = "Add new node"
    _node_address = simpledialog.askstring(_title, "Node Address:")
    if (blockchain.register_node(address = _node_address) == True):
        messagebox.showinfo(title=_title, message="Node added to node list:\nCurrent nodes: " + str(blockchain.nodes.__len__()))

def print_rpi():
    print(blockchain.rpis)

def add_rpi():
    _title = "Add new RPi"
    _node_address = simpledialog.askstring(_title, "RPi Address:")
    if (blockchain.register_rpi(address = _node_address) == True): # Definitions
        messagebox.showinfo(title=_title, message="RPi added to RPi list:\nCurrent RPis: " + str(blockchain.rpis.__len__()))
        # Optionally send keys immediately
        result = messagebox.askyesno("Send Keys", "Do you want to send cryptographic keys to this RPi now?")
        if result:
            send_keys_to_rpi(_node_address)

def add_rpi_with_vc():
    """
    Phase 1: Register RPi with DID-based authentication

    Flow:
    1. Request RPi's DID and public key
    2. Check if VC already exists for this device
    3. If exists and valid, just send it to RPi
    4. If not, get device attributes from user with pre-filled defaults
    5. Issue Verifiable Credential
    6. Send VC to RPi along with validator's public key
    7. Anchor VC hash on blockchain
    """
    _title = "Add RPi (DID-based)"

    # Step 1: Get RPi address
    _rpi_address = simpledialog.askstring(_title, "RPi Address (e.g., 192.168.1.10:5001):")
    if not _rpi_address:
        return

    # Ensure address has scheme
    if not _rpi_address.startswith('http'):
        _rpi_address_url = f"http://{_rpi_address}"
    else:
        _rpi_address_url = _rpi_address

    # Step 2: Request DID from RPi
    try:
        print(f"[INFO] Requesting DID from {_rpi_address_url}/did/info")
        response = requests.get(f"{_rpi_address_url}/did/info", timeout=5)
        if response.status_code != 200:
            messagebox.showerror(_title, f"Failed to get DID from RPi\nStatus: {response.status_code}")
            return

        rpi_info = response.json()
        rpi_did = rpi_info['did']
        rpi_public_key_pem = rpi_info.get('public_key_pem', '')

        print(f"[OK] Received DID: {rpi_did}")

    except Exception as e:
        messagebox.showerror(_title, f"Connection error: {e}")
        return

    # Step 3: Check if device already registered with valid VC
    import time
    vc = None
    vc_hash = None
    is_new_vc = True
    role = "sensor"
    region = "Hyderabad"
    attributes = []

    if rpi_did in blockchain.device_dids:
        existing_vc_hash = blockchain.device_dids[rpi_did]['vc_hash']
        print(f"[INFO] Device already registered with VC hash: {existing_vc_hash}")

        # Check if existing VC is still valid
        if existing_vc_hash in blockchain.issued_vcs:
            existing_vc = blockchain.issued_vcs[existing_vc_hash]['vc']

            # Check expiration
            if time.time() < existing_vc['expires_at']:
                print(f"[INFO] Existing VC is still valid. Using existing VC.")
                vc = existing_vc
                vc_hash = existing_vc_hash
                is_new_vc = False

                # Extract existing claims for display
                role = existing_vc['claims'].get('role', 'sensor')
                region = existing_vc['claims'].get('region', 'Hyderabad')
                attributes = existing_vc['claims'].get('attributes', [])

                # Ask user if they want to use existing or create new
                use_existing = messagebox.askyesno(
                    _title,
                    f"Device already has a valid credential.\n\n"
                    f"Current claims:\n"
                    f"  Role: {role}\n"
                    f"  Region: {region}\n"
                    f"  Attributes: {', '.join(attributes) if attributes else 'None'}\n\n"
                    f"Use existing credential?\n"
                    f"(No = create new credential)"
                )

                if not use_existing:
                    vc = None  # User wants to create new VC

    # Step 4: If no valid VC, create new one
    if vc is None:
        # Get device attributes from user with pre-filled defaults
        default_attributes = ', '.join(attributes) if attributes else "ONE, TWO"

        attributes_str = simpledialog.askstring(
            _title,
            f"Enter attributes for device {rpi_did}\n(comma-separated):",
            initialvalue=default_attributes
        )
        if attributes_str is None:
            return  # User cancelled
        elif not attributes_str:
            attributes = []
        else:
            attributes = [attr.strip().upper() for attr in attributes_str.split(',')]

        # Get role with default
        role = simpledialog.askstring(
            _title,
            "Device role:",
            initialvalue=role
        )
        if role is None:
            return  # User cancelled
        if not role:
            role = "sensor"

        # Get region with default
        region = simpledialog.askstring(
            _title,
            "Device region:",
            initialvalue=region
        )
        if region is None:
            return  # User cancelled
        if not region:
            region = "Hyderabad"

        # Issue new Verifiable Credential
        claims = {
            "role": role,
            "region": region,
            "attributes": attributes
        }

        vc = validator_vc_manager.issue_credential(
            subject_did=rpi_did,
            claims=claims,
            validity_hours=24
        )

        vc_hash = validator_vc_manager.hash_credential(vc)
        is_new_vc = True

        print(f"[OK] Issued VC: {json.dumps(vc, indent=2)}")

    # Step 5: Send VC to RPi along with validator's public key
    try:
        print(f"[INFO] Sending VC to {_rpi_address_url}/vc/receive")

        # Get validator's public key
        validator_public_key_pem = validator_did_manager.get_did_info()['public_key_pem']

        vc_response = requests.post(
            f"{_rpi_address_url}/vc/receive",
            json={
                'credential': vc,
                'validator_public_key_pem': validator_public_key_pem
            },
            timeout=5
        )

        if vc_response.status_code != 200:
            messagebox.showerror(_title, f"Failed to send VC to RPi\nResponse: {vc_response.text}")
            return

        print("[OK] VC sent successfully")

    except Exception as e:
        messagebox.showerror(_title, f"Failed to send VC: {e}")
        return

    # Step 6: Anchor VC hash on blockchain (only if new VC)
    if is_new_vc:
        blockchain.new_vc_transaction(
            vc_hash=vc_hash,
            issuer_did=validator_did_manager.did,
            subject_did=rpi_did
        )

        # Store VC in blockchain's registry
        blockchain.issued_vcs[vc_hash] = {'vc': vc, 'device_public_key_pem': rpi_public_key_pem}

        # Update device registry
        blockchain.device_dids[rpi_did] = {
            'vc_hash': vc_hash,
            'address': _rpi_address
        }
    else:
        pass

    # Step 7: Register/update in RPi registry
    blockchain.register_rpi_with_vc(_rpi_address, rpi_did, vc)

    # Save state
    blockchain.save_values()

    messagebox.showinfo(
        _title,
        f"RPi {'registered' if is_new_vc else 'credential sent'} successfully!\n\n"
        f"DID: {rpi_did}\n"
        f"Role: {role}\n"
        f"Region: {region}\n"
        f"Attributes: {', '.join(attributes) if attributes else 'None'}\n"
        f"VC Hash: {vc_hash[:16]}...\n"
        f"Status: {'New VC issued' if is_new_vc else 'Existing VC reused'}"
    )

    print(f"[OK] RPi {_rpi_address} {'registered' if is_new_vc else 'credential sent'} with DID-based auth")

def _filepath_get(window, filename, filepath):
    file = filedialog.askopenfile(title="Select File")
    _filepath = file.name.split("/")
    _filename = _filepath[_filepath.__len__()-1]
    filename.set(_filename)
    filepath.set(file.name)
    window.lift()

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

# Phase 2: Upload file to Azure Blob Storage with Merkle tree integrity
def _upload_file(window, filepath, filename, text_keygen, text_keygentime, text_signedtime):
    _file = open(filepath, 'br').read()  # byte
    _file_str = base64.b64encode(_file).decode('ascii')
    timestamp = time.time()

    _file_hash = hashlib.sha256(_file).hexdigest()

    # Step 1: Encrypt base64-encoded file with CP-ABSC
    # We encrypt _file_str (base64) so RPi's install_sw can b64decode the decrypted result
    (ct, delta) = hyb_abe.encrypt(pk, k_sign, _file_str, access_policy)
    delta_bytes = objectToBytes(delta, groupObj)
    _pi = hashlib.sha256(_file).hexdigest() + hashlib.sha256(delta_bytes).hexdigest()

    _pk = str(objectToBytes(pk, groupObj), 'utf-8')
    _ct = str(objectToBytes(ct, groupObj), 'utf-8')

    # Step 2: Package encrypted data for Azure (everything RPi needs for decryption)
    blob_data = json.dumps({
        'file': _file_str,
        'ct': _ct,
        'pk': _pk,
        'pi': _pi
    }).encode('utf-8')

    print(f"[INFO] Blob data size: {len(blob_data)} bytes (vs on-chain would be same)")

    # Step 3: Build Merkle tree from blob data
    merkle = MerkleTree()
    tree_info = merkle.build_tree(blob_data)
    merkle_root = tree_info['root']
    chunk_count = tree_info['chunk_count']

    print(f"[OK] Merkle tree built: root={merkle_root[:16]}..., chunks={chunk_count}")

    # Step 4: Upload to Azure Blob Storage
    blob_name = f"{_file_hash}.json"
    try:
        azure = AzureStorage()
        azure.upload_blob(blob_name, blob_data)
    except Exception as e:
        messagebox.showerror("Azure Upload Error", f"Failed to upload to Azure: {e}")
        window.lift()
        return

    # Step 5: Create LIGHTWEIGHT transaction (only ~2KB instead of full file)
    _newblock = blockchain.new_azure_transaction(
        filename, blob_name, merkle_root, _file_hash, len(blob_data), chunk_count
    )

    print(f"[OK] Lightweight transaction created (blob: {blob_name}, ~2KB on-chain)")

    # Fill form fields
    text_keygen.set(str(objectToBytes(pk, groupObj), 'utf-8'))
    text_keygentime.set(strftime('%x %X', time.localtime(keys_generation_time)))
    text_signedtime.set(strftime('%x %X', time.localtime(timestamp)))

    messagebox.showinfo("File Upload",
        f"File uploaded to Azure Blob Storage!\n"
        f"Blob: {blob_name}\n"
        f"Merkle root: {merkle_root[:32]}...\n"
        f"Chunks: {chunk_count}\n"
        f"Transaction will be added to block {_newblock}")
    window.lift()

# Tough things
def verify_block_action(current_transaction, text_keygen_time, text_sign_verif_time, text_block_creation_time):
    if len(current_transaction) <= 0:
        return False
    transaction = current_transaction.pop(0)

    # Phase 1: Skip VC transactions (they don't have 'file' key)
    if transaction.get('type') == 'vc_issuance':
        print("[INFO] Skipping VC transaction verification (no file to verify)")
        # VC transactions are already validated during issuance
        # Re-insert the VC transaction into current_transactions for block creation
        blockchain.current_transactions.insert(0, transaction)

        # Mine the block with VC transaction
        previous_hash = blockchain.hash(blockchain.last_block)
        blockchain.new_block(previous_hash, text_block_creation_time)
        blockchain.save_values()  # Save blockchain after creating block
        return True

    # Phase 2: Handle Azure file_update transactions (data is in Azure, not on-chain)
    if transaction.get('type') == 'file_update':
        print(f"[INFO] Azure file_update transaction - blob: {transaction.get('azure_blob_name')}")
        print(f"[INFO] Merkle root: {transaction.get('merkle_root', '')[:32]}...")
        # Re-insert and create block (integrity verified via Merkle tree on RPi side)
        blockchain.current_transactions.insert(0, transaction)

        previous_hash = blockchain.hash(blockchain.last_block)
        blockchain.new_block(previous_hash, text_block_creation_time)
        blockchain.save_values()
        return True

    if not blockchain.valid_file(transaction): # From definitions
        print("verify_block_action: valid_file is False")
        return False

    _file = transaction['file']
    _filename = transaction['name']
    _hash = transaction['file_hash']

    if text_keygen_time is not None:
        text_keygen_time.set(strftime('%x %X', time.localtime(keys_generation_time)))
    if text_sign_verif_time is not None:
        text_sign_verif_time.set(strftime('%x %X', time.localtime(time.time())))
    if text_block_creation_time is not None:
        text_block_creation_time.set(strftime('%x %X', time.localtime(time.time())))

    (ct, delta) = hyb_abe.encrypt(pk, k_sign, _file, access_policy)
    delta_bytes = objectToBytes(delta, groupObj)
    type(ct)
    type(delta_bytes)
    _pi = hashlib.sha256(bytes(str(_file), 'utf-8')).hexdigest() + hashlib.sha256(delta_bytes).hexdigest()

    _pk = str(objectToBytes(pk, groupObj), 'utf-8')
    _ct = str(objectToBytes(ct, groupObj), 'utf-8')

    blockchain.current_transactions.insert(0,{
        'name': _filename,
        'file': _file,
        'file_hash': _hash,
        'ct': _ct,
        'pi': _pi,
        'pk': _pk
    })

    #Block Creation # Defination
    blockchain.new_block(blockchain.last_block['previous_hash']) # new_block >> from Definition
    blockchain.save_values()  # Save blockchain after creating block

# Need to understand how things are sending to RPi.
def send_keys_to_rpi(rpi_address=None):
    """Send cryptographic keys to one or all RPi nodes"""
    import requests
    
    # Read keys from files
    keys_to_send = {}
    
    try:
        # Read pk
        with open("pk.txt", 'r') as f:
            keys_to_send['pk'] = f.read()
        
        # Read sk
        with open("sk.txt", 'r') as f:
            keys_to_send['sk'] = f.read()
        
        # Read k_sign if exists
        if os.path.exists("k_sign.txt"):
            with open("k_sign.txt", 'r') as f:
                keys_to_send['k_sign'] = f.read()
        
        # Read msk if exists (optional)
        if os.path.exists("msk.txt"):
            with open("msk.txt", 'r') as f:
                keys_to_send['msk'] = f.read()
    
    except Exception as e:
        print(f"ERROR - Could not read key files: {e}")
        messagebox.showerror("Key Distribution", f"Failed to read key files: {e}")
        return False
    
    # Determine which RPis to send to
    if rpi_address:
        rpis_to_update = [rpi_address]
    else:
        rpis_to_update = list(blockchain.rpis.keys())
    
    if len(rpis_to_update) == 0:
        print("ERROR - No RPis registered")
        messagebox.showwarning("Key Distribution", "No RPis registered. Please add RPi nodes first.")
        return False
    
    success_count = 0
    for rpi in rpis_to_update:
        try:
            # Clean up the address if needed
            if not rpi.startswith("http://"):
                rpi_url = f"http://{rpi}"
            else:
                rpi_url = rpi
            
            # Add port 5001 if not specified
            if ":5001" not in rpi_url:
                if ":" in rpi_url.split("//")[1]:
                    # Has a port but not 5001
                    pass
                else:
                    # No port specified, add 5001
                    rpi_url = rpi_url.replace(rpi, rpi + ":5001")
            
            print(f"INFO - Sending keys to RPi: {rpi_url}")
            
            headers = {'Content-Type': 'application/json'}
            response = requests.post(f"{rpi_url}/keys/receive", json=keys_to_send, headers=headers, timeout=5)
            
            if response.status_code == 200:
                print(f"SUCCESS - Keys sent to {rpi}")
                success_count += 1
            else:
                print(f"ERROR - Failed to send keys to {rpi}: {response.text}")
                
        except requests.exceptions.ConnectionError:
            print(f"ERROR - Could not connect to RPi at {rpi}")
        except requests.exceptions.Timeout:
            print(f"ERROR - Timeout connecting to RPi at {rpi}")
        except Exception as e:
            print(f"ERROR - Failed to send keys to {rpi}: {e}")
    
    if success_count > 0:
        messagebox.showinfo("Key Distribution", f"Successfully sent keys to {success_count}/{len(rpis_to_update)} RPi(s)")
    else:
        messagebox.showerror("Key Distribution", "Failed to send keys to any RPi")
    
    return success_count > 0

def send_update_button_click(file_name):
    print("INFO - Retrieving data for file " + file_name)
    values = {}
    is_azure = False
    #Get block number to send it to RPis
    for blocks in blockchain.chain:
        for trans in blocks['transactions']:
            if trans.get('name') == file_name:
                print("INFO - File found in block " + str(blocks['index']))
                values = trans.copy()
                # Phase 2: Detect Azure file_update transactions
                if trans.get('type') == 'file_update':
                    is_azure = True

    if len(blockchain.rpis) <= 0:
        print("ERROR - There are no RPis registered!")
    for rpi_address in blockchain.rpis:
        print("INFO - Sending " + values.get('name', '') + " to RPi " + rpi_address)
        if is_azure:
            # Phase 2: Send lightweight metadata (RPi downloads from Azure)
            blockchain.send_azure_update(rpi_address, values)
        else:
            # Original format: send full file data
            blockchain.send_updates(rpi_address, values['name'], values['file'], values['file_hash'],
                                    values['ct'], values['pi'], values['pk'])

# Sending Updates to RPi, can we send sk seprately and save the sk at RPi?
# Need to understand how it's working.
def send_update():
    window_su = Toplevel()
    window_su.title = "Disseminate Messages to RPIs"
    window_su.geometry("400x100")

    label = Label(window_su, text="Select the file:").place(x=_column(1), y=_line(1))

    #Define Combobox with its values
    files = blockchain.get_file_names() # from Definitions
    cb = ttk.Combobox(window_su, values=files)
    cb.place(x=_column(2), y=_line(1))

    button_send = Button(window_su, text="Send", command=lambda: send_update_button_click(cb.get())).place(x=_column(3)-15, y=_line(2))

# def verify_software():
def verify_file():
    if len(blockchain.current_transactions) <= 0:
        messagebox.showinfo("Verify the Files","There are no Files in Transactions")
        return False

    window_vs = Toplevel()
    window_vs.title = "Verify Transactions Manually"
    window_vs.geometry("300x200")

    text_keygen_time = StringVar()
    label_keygen_time = Label(window_vs, text="KeyGen Timestamp:").place(x=_column(1), y=_line(1))
    entry_keygen_time = Entry(window_vs, textvariable=text_keygen_time).place(x=_column(2),y=_line(1))

    text_sign_verif_time = StringVar()
    label_sign_verif_time = Label(window_vs, text="Sign Timestamp:").place(x=_column(1), y=_line(2))
    entry_sign_verif_time = Entry(window_vs, textvariable=text_sign_verif_time).place(x=_column(2), y=_line(2))

    text_block_creation_time = StringVar()
    label_block_creation_time = Label(window_vs, text="BlockGen Timestamp:").place(x=_column(1), y=_line(3))
    entry_block_creation_time = Entry(window_vs, textvariable=text_block_creation_time).place(x=_column(2), y=_line(3))

    button_Mine = Button(window_vs, text="Verify Transactions",
                         command=lambda: verify_block_action(blockchain.current_transactions, text_keygen_time,
                                                             text_sign_verif_time, text_block_creation_time)).place(
        x=_column(3) - 85, y=_line(4))

# def upload_software():
def upload_file():
    windows_us = Toplevel()
    windows_us.title = "Message Upload"
    windows_us.geometry("300x200")

    text_filename = StringVar()
    label_filename = Label(windows_us, text="Message Name:").place(x=_column(1),y=_line(2))
    entry_filename = Entry(windows_us, textvariable=text_filename).place(x=_column(2), y=_line(2))

    text_filepath = StringVar()
    label_filepath = Label(windows_us, text="File Path:").place(x=_column(1), y=_line(1))
    entry_filepath = Entry(windows_us, textvariable=text_filepath).place(x=_column(2), y=_line(1))
    button_filepath = Button(windows_us, text="...", command=lambda: _filepath_get(windows_us, text_filename, text_filepath)).place(
        x=_column(3), y=_line(1)-4)

    text_keygentime = StringVar()
    label_keygentime = Label(windows_us, text="KeyGen Timestamp:").place(x=_column(1), y=_line(3))
    entry_filepath = Entry(windows_us, textvariable=text_keygentime).place(x=_column(2),y=_line(3))

    text_keygen = StringVar()
    label_keygen = Label(windows_us, text="Public Key:").place(x=_column(1), y=_line(4))
    entry_keygen = Entry(windows_us, textvariable=text_keygen).place(x=_column(2), y=_line(4))

    text_signedtime = StringVar()
    label_signedtime = Label(windows_us, text="Signed Timestamp:").place(x=_column(1), y=_line(5))
    entry_signedtime = Entry(windows_us, textvariable=text_signedtime).place(x=_column(2), y=_line(5))

    button_Send = Button(windows_us, text="Upload",
                         command=lambda: _upload_file(windows_us, text_filepath.get(), text_filename.get(), text_keygen,
                                                      text_keygentime, text_signedtime)).place(x=_column(2), y=_line(6))
    button_Cancel = Button(windows_us, text="Cancel", command=windows_us.quit).place(x=_column(3)-42, y=_line(6))

main_window = Tk()
main_window.title("Blockchain Based Message Dissemination System")
main_window.geometry("650x300")
def _create_main_window_structure():
    Menu_Bar = Menu(main_window)
    Connection_Menu = Menu(Menu_Bar, tearoff=0)
    Connection_Menu.add_command(label="Add node", command=add_node)
    Connection_Menu.add_separator()
    Connection_Menu.add_command(label="Add RPi", command=add_rpi)
    Connection_Menu.add_command(label="Add RPi with VC (Phase 1)", command=add_rpi_with_vc)
    Connection_Menu.add_command(label="Print RPi list", command=print_rpi)
    Connection_Menu.add_command(label="Send Keys to RPIs", command=lambda: send_keys_to_rpi())
    Connection_Menu.add_separator()
    Connection_Menu.add_command(label="Connect Blockchain", command=blockchain_thread.start)
    Connection_Menu.add_command(label="Disconnect and Exit", command=disconnect_exit)
    Menu_Bar.add_cascade(label="Blockchain", menu=Connection_Menu)

    Actions_Menu = Menu(Menu_Bar, tearoff=0)
    Actions_Menu.add_command(label="Upload Messages (Make Transaction)", command=upload_file)
    Actions_Menu.add_command(label="Verify Transaction (Manually)", command=verify_file)
    Actions_Menu.add_command(label="Disseminate Messages to RPi (Targetted)", command=send_update)
    Actions_Menu.add_separator()
    Actions_Menu.add_command(label="Print Chain", command=blockchain.print_chain) # Defination
    Actions_Menu.add_command(label="Print Transactions", command=blockchain.print_transactions) # Defination
    Menu_Bar.add_cascade(label="Actions", menu=Actions_Menu)

    # Show menu
    main_window.config(menu=Menu_Bar)

_create_main_window_structure()

mainloop()