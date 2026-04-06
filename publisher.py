"""
Publisher Node (Ubuntu-1)
=========================
Roles:
  - DID Registry / Validator: Issues VCs to IoT devices
  - Publisher: Encrypts files with AES-256-GCM, uploads to Azure
  - Blockchain: Creates and maintains the permissioned chain

Architecture:
  Ubuntu-1 (this) ──── Permissioned Chain
       │                     │
       ├─ VC Issuance ──→ IoT Devices
       ├─ File Upload ──→ Azure Blob Storage
       └─ Anchor tx   ──→ Blockchain
"""

from time import strftime
import time, os, threading
from tkinter import *
from tkinter import ttk
import tkinter.simpledialog as simpledialog
import tkinter.messagebox as messagebox
import tkinter.filedialog as filedialog
from pathlib import Path
from definitions import *
from uuid import uuid4
import requests
from flask import Flask, jsonify, request
import base64
import json

# Phase 1: DID/VC imports
from did_manager import DIDManager
from vc_manager import VCManager

# Phase 2: Azure + Merkle imports
from merkle_tree import MerkleTree
from azure_storage import AzureStorage

# Phase 3: AES-256-GCM + RSA key management
from aes_encryption import generate_aes_key, aes_encrypt
from key_management import encrypt_aes_key, deserialize_public_key

# ============================================================
# Mining Thread
# ============================================================
def periodic_spread():
    while True:
        time.sleep(15)
        print("INFO: Waiting for transactions...")
        verify_block_action(blockchain.current_transactions)

        if blockchain.connected and not blockchain.chain_updated:
            print("INFO: Syncing blockchain from network...")
            blockchain.resolve_conflicts()
            blockchain.chain_updated = True

def init_blockchain():
    blockchain_spread.start()
    app.app_context()
    app.run(host='0.0.0.0', port=5000)

# ============================================================
# Initialization
# ============================================================
node_identifier = str(uuid4()).replace('-', '')

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

validator_vc_manager = VCManager(validator_did_manager)
print("[OK] VC Manager initialized")
print("=" * 60 + "\n")

print("INFO: Node Identifier:" + node_identifier)

# Instantiate the Blockchain
blockchain = Blockchain()
blockchain_thread = threading.Thread(name="blockchain", target=init_blockchain, daemon=True)

blockchain.load_values()
blockchain.validator_did = validator_did_manager.did

# Instantiate Flask
app = Flask(__name__)
blockchain_spread = threading.Thread(name="spread", target=periodic_spread, daemon=True)

# ============================================================
# Flask Endpoints
# ============================================================

@app.route('/blocks/new', methods=['POST'])
def blocks_new():
    values = request.get_json(silent=True)
    if values is None:
        values = request.values
    added = blockchain.new_block(_transactions=values)
    if added:
        response = {'message': 'The block is added to the chain'}
    else:
        response = {'message': 'The block was rejected'}
    return jsonify(response), 201

@app.route('/mine', methods=['GET'])
def mine():
    if len(blockchain.current_transactions) <= 0:
        return jsonify({'message': 'No transactions to validate'}), 200
    previous_hash = blockchain.hash(blockchain.last_block)
    block = blockchain.new_block(previous_hash)
    if block == False:
        return jsonify({'message': "Invalid Transaction!"}), 400
    return jsonify({
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'previous_hash': block['previous_hash'],
    }), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json(silent=True)
    if values is None:
        values = request.values

    if values.get('type') == 'file_update':
        required = ['name', 'azure_blob_name', 'merkle_root', 'file_hash']
        if not all(k in values for k in required):
            return 'Missing values for file_update', 400
        index = blockchain.new_azure_transaction(
            values['name'], values['azure_blob_name'], values['merkle_root'],
            values['file_hash'], values.get('file_size', 0), values.get('chunk_count', 0)
        )
        return jsonify({'message': f'Azure transaction will be added to Block {index}'}), 201

    if values.get('type') == 'vc_issuance':
        required = ['vc_hash', 'issuer_did', 'subject_did']
        if not all(k in values for k in required):
            return 'Missing values for vc_issuance', 400
        index = blockchain.new_vc_transaction(
            values['vc_hash'], values['issuer_did'], values['subject_did']
        )
        return jsonify({'message': f'VC transaction will be added to Block {index}'}), 201

    return 'Unsupported transaction format', 400

@app.route('/transactions', methods=['GET'])
def transactions():
    return jsonify({'chain': blockchain.current_transactions, 'length': len(blockchain.chain)}), 200

@app.route('/vc/<vc_hash>', methods=['GET'])
def get_vc(vc_hash):
    if vc_hash in blockchain.issued_vcs:
        return jsonify(blockchain.issued_vcs[vc_hash]), 200
    return jsonify({'error': 'VC not found'}), 404

@app.route('/vc/validator/did', methods=['GET'])
def get_validator_did():
    return jsonify({
        'did': validator_did_manager.did,
        'public_key_pem': validator_did_manager.get_did_info()['public_key_pem']
    }), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    return jsonify({'chain': blockchain.chain, 'length': len(blockchain.chain)}), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400
    for node in nodes:
        blockchain.register_node(node)
    return jsonify({'message': 'New nodes have been added', 'total_nodes': list(blockchain.nodes)}), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        return jsonify({'message': 'Our chain was replaced', 'new_chain': blockchain.chain}), 200
    return jsonify({'message': 'Our chain is authoritative', 'chain': blockchain.chain}), 200

# ============================================================
# Block Verification (Auto-mining)
# ============================================================
def verify_block_action(current_transaction):
    if len(current_transaction) <= 0:
        return False
    transaction = current_transaction.pop(0)

    if transaction.get('type') == 'vc_issuance':
        print("[INFO] Mining VC transaction...")
        blockchain.current_transactions.insert(0, transaction)
        previous_hash = blockchain.hash(blockchain.last_block)
        blockchain.new_block(previous_hash)
        blockchain.save_values()
        return True

    if transaction.get('type') == 'file_update':
        print(f"[INFO] Mining file_update transaction: {transaction.get('azure_blob_name')}")
        blockchain.current_transactions.insert(0, transaction)
        previous_hash = blockchain.hash(blockchain.last_block)
        blockchain.new_block(previous_hash)
        blockchain.save_values()
        return True

    print(f"[WARN] Unknown transaction type, skipping")
    return False

# ============================================================
# GUI Functions
# ============================================================
def disconnect_exit():
    blockchain.save_values()
    main_window.quit()

def print_rpi():
    if len(blockchain.rpis) == 0:
        print("INFO - No RPi devices registered")
        return
    print(f"\n--- Registered RPi Devices ({len(blockchain.rpis)}) ---")
    for addr, info in blockchain.rpis.items():
        print(f"  {addr}: {info}")
    print()

def add_node():
    _title = "Add Blockchain Node"
    _node_address = simpledialog.askstring(_title, "Node Address (e.g., 192.168.1.20:5000):")
    if _node_address and blockchain.register_node(address=_node_address):
        messagebox.showinfo(title=_title, message=f"Node added!\nTotal nodes: {len(blockchain.nodes)}")

def add_rpi_with_vc():
    """Register RPi with DID-based authentication and VC issuance"""
    _title = "Add RPi (DID-based)"

    _rpi_address = simpledialog.askstring(_title, "RPi Address (e.g., 192.168.1.10:5001):")
    if not _rpi_address:
        return

    if not _rpi_address.startswith('http'):
        _rpi_address_url = f"http://{_rpi_address}"
    else:
        _rpi_address_url = _rpi_address

    # Step 1: Request DID from RPi
    try:
        print(f"[INFO] Requesting DID from {_rpi_address_url}/did/info")
        response = requests.get(f"{_rpi_address_url}/did/info", timeout=5)
        if response.status_code != 200:
            messagebox.showerror(_title, f"Failed to get DID from RPi\nStatus: {response.status_code}")
            return

        rpi_info = response.json()
        rpi_did = rpi_info['did']
        rpi_public_key_pem = rpi_info.get('public_key_pem', '')
        rpi_rsa_public_key_pem = rpi_info.get('rsa_public_key_pem', '')

        print(f"[OK] Received DID: {rpi_did}")

        if rpi_rsa_public_key_pem:
            blockchain.device_rsa_keys[rpi_did] = rpi_rsa_public_key_pem
            print(f"[OK] Stored RSA public key for {rpi_did}")

    except Exception as e:
        messagebox.showerror(_title, f"Connection error: {e}")
        return

    # Step 2: Check existing VC
    vc = None
    vc_hash = None
    is_new_vc = True
    role = "sensor"
    region = "Hyderabad"
    attributes = []

    if rpi_did in blockchain.device_dids:
        existing_vc_hash = blockchain.device_dids[rpi_did]['vc_hash']
        if existing_vc_hash in blockchain.issued_vcs:
            existing_vc = blockchain.issued_vcs[existing_vc_hash]['vc']
            if time.time() < existing_vc['expires_at']:
                vc = existing_vc
                vc_hash = existing_vc_hash
                is_new_vc = False
                role = existing_vc['claims'].get('role', 'sensor')
                region = existing_vc['claims'].get('region', 'Hyderabad')
                attributes = existing_vc['claims'].get('attributes', [])

                use_existing = messagebox.askyesno(_title,
                    f"Device already has a valid credential.\n\n"
                    f"  Role: {role}\n  Region: {region}\n"
                    f"  Attributes: {', '.join(attributes) if attributes else 'None'}\n\n"
                    f"Use existing credential?")

                if not use_existing:
                    vc = None

    # Step 3: Create new VC if needed
    if vc is None:
        default_attributes = ', '.join(attributes) if attributes else "ONE, TWO"
        attributes_str = simpledialog.askstring(_title, f"Attributes (comma-separated):", initialvalue=default_attributes)
        if attributes_str is None:
            return
        attributes = [attr.strip().upper() for attr in attributes_str.split(',')] if attributes_str else []

        role = simpledialog.askstring(_title, "Device role:", initialvalue=role)
        if role is None:
            return
        role = role or "sensor"

        region = simpledialog.askstring(_title, "Device region:", initialvalue=region)
        if region is None:
            return
        region = region or "Hyderabad"

        vc = validator_vc_manager.issue_credential(
            subject_did=rpi_did,
            claims={"role": role, "region": region, "attributes": attributes},
            validity_hours=24
        )
        vc_hash = validator_vc_manager.hash_credential(vc)
        is_new_vc = True
        print(f"[OK] Issued VC: {json.dumps(vc, indent=2)}")

    # Step 4: Send VC to RPi
    try:
        validator_public_key_pem = validator_did_manager.get_did_info()['public_key_pem']
        vc_response = requests.post(
            f"{_rpi_address_url}/vc/receive",
            json={'credential': vc, 'validator_public_key_pem': validator_public_key_pem},
            timeout=5
        )
        if vc_response.status_code != 200:
            messagebox.showerror(_title, f"Failed to send VC to RPi\nResponse: {vc_response.text}")
            return
        print("[OK] VC sent successfully")
    except Exception as e:
        messagebox.showerror(_title, f"Failed to send VC: {e}")
        return

    # Step 5: Anchor on blockchain
    if is_new_vc:
        blockchain.new_vc_transaction(vc_hash=vc_hash, issuer_did=validator_did_manager.did, subject_did=rpi_did)
        blockchain.issued_vcs[vc_hash] = {'vc': vc, 'device_public_key_pem': rpi_public_key_pem}
        blockchain.device_dids[rpi_did] = {'vc_hash': vc_hash, 'address': _rpi_address}

    blockchain.register_rpi_with_vc(_rpi_address, rpi_did, vc)
    blockchain.save_values()

    messagebox.showinfo(_title,
        f"RPi {'registered' if is_new_vc else 'credential sent'} successfully!\n\n"
        f"DID: {rpi_did}\nRole: {role}\nRegion: {region}\n"
        f"Attributes: {', '.join(attributes) if attributes else 'None'}\n"
        f"VC Hash: {vc_hash[:16]}...")
    print(f"[OK] RPi {_rpi_address} {'registered' if is_new_vc else 'credential sent'} with DID-based auth")

# ============================================================
# File Upload (AES-256-GCM + Azure)
# ============================================================
def _filepath_get(window, filename, filepath):
    file = filedialog.askopenfile(title="Select File")
    if file is None:
        return
    _filepath = file.name.split("/")
    _filename = _filepath[-1]
    filename.set(_filename)
    filepath.set(file.name)
    window.lift()

def _line(line):
    return 10 if line == 1 else 10 + 30 * (line - 1)

def _column(col):
    return 10 if col == 1 else 10 + 120 * (col - 1)

def _upload_file(window, filepath, filename, text_keygen, text_keygentime, text_signedtime):
    _file = open(filepath, 'br').read()
    _file_hash = hashlib.sha256(_file).hexdigest()

    # Step 1: AES-256-GCM encrypt
    aes_key = generate_aes_key()
    encrypted = aes_encrypt(aes_key, _file)
    print(f"[OK] AES-256-GCM encrypted ({len(_file)} bytes -> {len(encrypted['ciphertext'])} b64 chars)")

    # Step 2: Package for Azure
    blob_data = json.dumps({
        'encryption': 'aes-256-gcm',
        'nonce': encrypted['nonce'],
        'ciphertext': encrypted['ciphertext'],
        'file_hash': _file_hash
    }).encode('utf-8')
    print(f"[INFO] Blob data size: {len(blob_data)} bytes")

    # Step 3: Merkle tree
    merkle = MerkleTree()
    tree_info = merkle.build_tree(blob_data)
    merkle_root = tree_info['root']
    chunk_count = tree_info['chunk_count']
    print(f"[OK] Merkle tree built: root={merkle_root[:16]}..., chunks={chunk_count}")

    # Step 4: Upload to Azure
    blob_name = f"{_file_hash}.json"
    window.destroy()

    try:
        azure = AzureStorage()
        azure.upload_blob(blob_name, blob_data)
    except Exception as e:
        messagebox.showerror("Azure Upload Error", f"Failed to upload to Azure: {e}")
        return

    # Step 5: Store AES key
    import base64 as b64mod
    blockchain.file_aes_keys[_file_hash] = b64mod.b64encode(aes_key).decode('ascii')
    blockchain.save_values()

    # Step 6: Lightweight blockchain transaction
    _newblock = blockchain.new_azure_transaction(
        filename, blob_name, merkle_root, _file_hash, len(blob_data), chunk_count
    )
    print(f"[OK] Phase 3: AES-256-GCM encrypted, uploaded to Azure, lightweight transaction created")

    messagebox.showinfo("File Upload",
        f"File encrypted and uploaded to Azure!\n"
        f"Blob: {blob_name}\nMerkle root: {merkle_root[:32]}...\n"
        f"Transaction will be added to block {_newblock}")

def upload_file():
    windows_us = Toplevel()
    windows_us.title = "Message Upload"
    windows_us.geometry("300x200")

    text_filename = StringVar()
    Label(windows_us, text="Message Name:").place(x=_column(1), y=_line(2))
    Entry(windows_us, textvariable=text_filename).place(x=_column(2), y=_line(2))

    text_filepath = StringVar()
    Label(windows_us, text="File Path:").place(x=_column(1), y=_line(1))
    Entry(windows_us, textvariable=text_filepath).place(x=_column(2), y=_line(1))
    Button(windows_us, text="...",
           command=lambda: _filepath_get(windows_us, text_filename, text_filepath)).place(x=_column(3), y=_line(1)-4)

    text_keygentime = StringVar()
    text_keygen = StringVar()
    text_signedtime = StringVar()

    Button(windows_us, text="Upload",
           command=lambda: _upload_file(windows_us, text_filepath.get(), text_filename.get(),
                                         text_keygen, text_keygentime, text_signedtime)).place(x=_column(2), y=_line(4))
    Button(windows_us, text="Cancel", command=windows_us.destroy).place(x=_column(3)-42, y=_line(4))

# ============================================================
# Main Window
# ============================================================
main_window = Tk()
main_window.title("Publisher + Validator (Ubuntu-1)")
main_window.geometry("650x300")

def _create_main_window_structure():
    Menu_Bar = Menu(main_window)

    Connection_Menu = Menu(Menu_Bar, tearoff=0)
    Connection_Menu.add_command(label="Add RPi (DID-based)", command=add_rpi_with_vc)
    Connection_Menu.add_command(label="Add Node (Edge Disseminator)", command=add_node)
    Connection_Menu.add_command(label="Print RPi list", command=print_rpi)
    Connection_Menu.add_separator()
    Connection_Menu.add_command(label="Connect Blockchain", command=blockchain_thread.start)
    Connection_Menu.add_command(label="Disconnect and Exit", command=disconnect_exit)
    Menu_Bar.add_cascade(label="Blockchain", menu=Connection_Menu)

    Actions_Menu = Menu(Menu_Bar, tearoff=0)
    Actions_Menu.add_command(label="Upload Message (AES-256-GCM + Azure)", command=upload_file)
    Actions_Menu.add_separator()
    Actions_Menu.add_command(label="Print Chain", command=blockchain.print_chain)
    Actions_Menu.add_command(label="Print Transactions", command=blockchain.print_transactions)
    Menu_Bar.add_cascade(label="Actions", menu=Actions_Menu)

    main_window.config(menu=Menu_Bar)

_create_main_window_structure()
mainloop()
