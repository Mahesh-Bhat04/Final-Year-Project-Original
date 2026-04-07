"""
Publisher + Validator Node (Ubuntu-1)
=====================================
Roles:
  - DID Registry / Validator: Issues VCs to disseminators and IoT devices
  - Publisher: Encrypts files with AES-256-GCM, uploads to Azure
  - Blockchain: Creates and maintains the permissioned chain

Flow:
  1. Connect Blockchain → genesis block (block 1)
  2. Add Edge Disseminator → VC issuance (block 2)
  3. Disseminator notifies about new RPi → VC issuance (block 3+)
  4. Upload Message → select target RPis → encrypt → Azure → blockchain tx
  5. Send AES key to disseminator → disseminator auto-delivers to RPis
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
    """Background thread: auto-mines pending transactions every 15s and syncs with network."""
    while True:
        time.sleep(15)
        print("INFO: Waiting for transactions...")
        verify_block_action(blockchain.current_transactions)

        if blockchain.connected and not blockchain.chain_updated:
            blockchain.resolve_conflicts()
            blockchain.chain_updated = True

def init_blockchain():
    """Start blockchain: create genesis block, start mining thread, and run Flask server."""
    blockchain.create_genesis()
    blockchain.connected = True
    blockchain_spread.start()
    app.app_context()
    app.run(host='0.0.0.0', port=5000)

# ============================================================
# Initialization
# ============================================================
node_identifier = str(uuid4()).replace('-', '')

# Phase 1: DID/VC Initialization
print("\n=== Initializing Publisher + Validator (Phase 1) ===")
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

# Instantiate the Blockchain (no genesis yet - created on Connect)
blockchain = Blockchain()
blockchain_thread = threading.Thread(name="blockchain", target=init_blockchain, daemon=True)
blockchain.load_values()
blockchain.validator_did = validator_did_manager.did

# Flask app
app = Flask(__name__)
blockchain_spread = threading.Thread(name="spread", target=periodic_spread, daemon=True)

# ============================================================
# Flask Endpoints
# ============================================================

@app.route('/blocks/new', methods=['POST'])
def blocks_new():
    """Flask endpoint: receive a new block from a peer node."""
    values = request.get_json(silent=True)
    if values is None:
        values = request.values
    added = blockchain.new_block(_transactions=values)
    if added:
        return jsonify({'message': 'Block added'}), 201
    return jsonify({'message': 'Block rejected'}), 400

@app.route('/mine', methods=['GET'])
def mine():
    """Flask endpoint: manually trigger mining of pending transactions."""
    if len(blockchain.current_transactions) <= 0:
        return jsonify({'message': 'No transactions to validate'}), 200
    previous_hash = blockchain.hash(blockchain.last_block)
    block = blockchain.new_block(previous_hash)
    if block == False:
        return jsonify({'message': "Invalid Transaction!"}), 400
    return jsonify({
        'message': "New Block Forged",
        'index': block['index'],
        'previous_hash': block['previous_hash'],
    }), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    """Flask endpoint: receive a transaction from a peer node (broadcast=False to avoid loop)."""
    values = request.get_json(silent=True)
    if values is None:
        values = request.values

    if values.get('type') == 'file_update':
        required = ['name', 'azure_blob_name', 'merkle_root', 'file_hash']
        if not all(k in values for k in required):
            return 'Missing values', 400
        index = blockchain.new_azure_transaction(
            values['name'], values['azure_blob_name'], values['merkle_root'],
            values['file_hash'], values.get('file_size', 0), values.get('chunk_count', 0),
            target_rpis=values.get('target_rpis', []), broadcast=False
        )
        return jsonify({'message': f'Transaction added for Block {index}'}), 201

    if values.get('type') == 'vc_issuance':
        required = ['vc_hash', 'issuer_did', 'subject_did']
        if not all(k in values for k in required):
            return 'Missing values', 400
        index = blockchain.new_vc_transaction(
            values['vc_hash'], values['issuer_did'], values['subject_did'], broadcast=False
        )
        return jsonify({'message': f'VC transaction added for Block {index}'}), 201

    return 'Unsupported format', 400

@app.route('/transactions', methods=['GET'])
def transactions():
    """Flask endpoint: return current pending transactions."""
    return jsonify({'chain': blockchain.current_transactions, 'length': len(blockchain.chain)}), 200

@app.route('/vc/<vc_hash>', methods=['GET'])
def get_vc(vc_hash):
    """Flask endpoint: retrieve a Verifiable Credential by its hash."""
    if vc_hash in blockchain.issued_vcs:
        return jsonify(blockchain.issued_vcs[vc_hash]), 200
    return jsonify({'error': 'VC not found'}), 404

@app.route('/vc/validator/did', methods=['GET'])
def get_validator_did():
    """Flask endpoint: return the validator's DID and public key."""
    return jsonify({
        'did': validator_did_manager.did,
        'public_key_pem': validator_did_manager.get_did_info()['public_key_pem']
    }), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    """Flask endpoint: return the full blockchain."""
    return jsonify({'chain': blockchain.chain, 'length': len(blockchain.chain)}), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    """Flask endpoint: register new peer nodes for blockchain sync."""
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Missing nodes", 400
    for node in nodes:
        blockchain.register_node(node)
    return jsonify({'message': 'Nodes added', 'total_nodes': list(blockchain.nodes)}), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    """Flask endpoint: trigger consensus algorithm to sync with longest chain."""
    replaced = blockchain.resolve_conflicts()
    if replaced:
        return jsonify({'message': 'Chain replaced', 'length': len(blockchain.chain)}), 200
    return jsonify({'message': 'Chain is authoritative', 'length': len(blockchain.chain)}), 200

# ============================================================
# RPi Notification from Disseminator
# ============================================================
@app.route('/rpi/notify', methods=['POST'])
def rpi_notify():
    """Disseminator notifies publisher about a new RPi device. Publisher issues VC."""
    values = request.get_json(silent=True)
    if not values:
        return jsonify({'error': 'Missing data'}), 400

    rpi_did = values.get('rpi_did')
    rpi_address = values.get('rpi_address')
    rpi_public_key_pem = values.get('rpi_public_key_pem', '')
    rpi_rsa_public_key_pem = values.get('rpi_rsa_public_key_pem', '')

    if not rpi_did or not rpi_address:
        return jsonify({'error': 'Missing rpi_did or rpi_address'}), 400

    print(f"\n[INFO] RPi notification received from disseminator")
    print(f"[INFO] RPi DID: {rpi_did}, Address: {rpi_address}")

    # Store RSA public key
    if rpi_rsa_public_key_pem:
        blockchain.device_rsa_keys[rpi_did] = rpi_rsa_public_key_pem

    # Issue VC for the RPi
    vc = validator_vc_manager.issue_credential(
        subject_did=rpi_did,
        claims={"role": "sensor", "region": "Hyderabad", "attributes": ["ONE", "TWO"], "ip_address": rpi_address},
        validity_hours=24
    )
    vc_hash = validator_vc_manager.hash_credential(vc)

    # Send VC directly to RPi
    try:
        rpi_url = f"http://{rpi_address}" if not rpi_address.startswith('http') else rpi_address
        validator_pub_pem = validator_did_manager.get_did_info()['public_key_pem']
        resp = requests.post(f"{rpi_url}/vc/receive",
            json={'credential': vc, 'validator_public_key_pem': validator_pub_pem}, timeout=5)
        if resp.status_code != 200:
            return jsonify({'error': f'RPi rejected VC: {resp.text}'}), 500
        print(f"[OK] VC sent to RPi at {rpi_address}")
    except Exception as e:
        return jsonify({'error': f'Failed to send VC to RPi: {e}'}), 500

    # Anchor on blockchain
    blockchain.new_vc_transaction(vc_hash=vc_hash, issuer_did=validator_did_manager.did, subject_did=rpi_did)
    blockchain.issued_vcs[vc_hash] = {'vc': vc, 'device_public_key_pem': rpi_public_key_pem}
    blockchain.device_dids[rpi_did] = {'vc_hash': vc_hash, 'address': rpi_address}
    blockchain.register_rpi_with_vc(rpi_address, rpi_did, vc)
    blockchain.save_values()

    print(f"[OK] VC issued for RPi {rpi_did}, anchored on blockchain")

    return jsonify({
        'message': 'RPi registered and VC issued',
        'vc_hash': vc_hash,
        'rpi_did': rpi_did
    }), 200

# ============================================================
# Block Verification (Auto-mining)
# ============================================================
def verify_block_action(current_transaction):
    """Process pending transactions: pop one, re-insert into blockchain, and mine a new block."""
    if len(current_transaction) <= 0:
        return False
    transaction = current_transaction.pop(0)

    if transaction.get('type') in ('vc_issuance', 'file_update'):
        tx_type = transaction.get('type')
        print(f"[INFO] Mining {tx_type} transaction...")
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
    """Save blockchain state and exit the application."""
    blockchain.save_values()
    main_window.quit()

def print_rpi():
    """Print all registered RPi devices to console."""
    if len(blockchain.rpis) == 0:
        print("INFO - No RPi devices registered")
        return
    print(f"\n--- Registered RPi Devices ({len(blockchain.rpis)}) ---")
    for addr, info in blockchain.rpis.items():
        print(f"  {addr}: {info}")
    print()

def add_edge_disseminator():
    """Register an edge disseminator node with VC issuance"""
    _title = "Add Edge Disseminator"
    _diss_address = simpledialog.askstring(_title, "Disseminator Address (e.g., 192.168.1.20:5000):")
    if not _diss_address:
        return

    _diss_url = f"http://{_diss_address}" if not _diss_address.startswith('http') else _diss_address

    # Step 1: Get DID from disseminator
    try:
        print(f"[INFO] Requesting DID from {_diss_url}/did/info")
        response = requests.get(f"{_diss_url}/did/info", timeout=5)
        if response.status_code != 200:
            messagebox.showerror(_title, f"Failed to connect to disseminator")
            return

        diss_info = response.json()
        diss_did = diss_info['did']
        diss_pub_key_pem = diss_info.get('public_key_pem', '')
        diss_rsa_pub_pem = diss_info.get('rsa_public_key_pem', '')
        print(f"[OK] Disseminator DID: {diss_did}")

    except Exception as e:
        messagebox.showerror(_title, f"Connection error: {e}")
        return

    # Step 2: Issue VC with role='edge_disseminator'
    vc = validator_vc_manager.issue_credential(
        subject_did=diss_did,
        claims={"role": "edge_disseminator", "region": "network", "attributes": [], "ip_address": _diss_address},
        validity_hours=720  # 30 days
    )
    vc_hash = validator_vc_manager.hash_credential(vc)
    print(f"[OK] Issued VC for disseminator: {json.dumps(vc, indent=2)}")

    # Step 3: Send VC to disseminator
    try:
        validator_pub_pem = validator_did_manager.get_did_info()['public_key_pem']
        resp = requests.post(f"{_diss_url}/vc/receive",
            json={'credential': vc, 'validator_public_key_pem': validator_pub_pem}, timeout=5)
        if resp.status_code != 200:
            messagebox.showerror(_title, f"Disseminator rejected VC: {resp.text}")
            return
        print("[OK] VC sent to disseminator")
    except Exception as e:
        messagebox.showerror(_title, f"Failed to send VC: {e}")
        return

    # Step 4: Anchor VC on blockchain
    blockchain.new_vc_transaction(vc_hash=vc_hash, issuer_did=validator_did_manager.did, subject_did=diss_did)
    blockchain.issued_vcs[vc_hash] = {'vc': vc, 'device_public_key_pem': diss_pub_key_pem}
    blockchain.device_dids[diss_did] = {'vc_hash': vc_hash, 'address': _diss_address}

    # Step 5: Register disseminator as blockchain node
    blockchain.register_node(_diss_address)

    # Step 6: Tell disseminator to register publisher as its node
    try:
        # Get real IP by connecting to the disseminator's network
        import socket
        diss_host = _diss_address.split(':')[0]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((diss_host, 80))
        my_ip = s.getsockname()[0]
        s.close()
        my_address = f"{my_ip}:5000"
        requests.post(f"{_diss_url}/nodes/register",
            json={'nodes': [my_address]}, timeout=5)
        print(f"[OK] Registered publisher ({my_address}) on disseminator")
    except Exception as e:
        print(f"[WARN] Could not register publisher on disseminator: {e}")

    # Step 7: Store disseminator info
    blockchain.disseminators[_diss_address] = {
        'did': diss_did, 'vc_hash': vc_hash,
        'rsa_public_key_pem': diss_rsa_pub_pem, 'managed_rpis': []
    }
    if diss_rsa_pub_pem:
        blockchain.device_rsa_keys[diss_did] = diss_rsa_pub_pem

    blockchain.save_values()

    messagebox.showinfo(_title,
        f"Edge Disseminator added!\n\n"
        f"DID: {diss_did}\n"
        f"Address: {_diss_address}\n"
        f"VC anchored on blockchain")
    print(f"[OK] Edge Disseminator {_diss_address} registered")

# ============================================================
# File Upload (AES-256-GCM + Azure + Target RPi Selection)
# ============================================================
def _filepath_get(window, filename, filepath):
    """Open file dialog and populate filename/filepath fields."""
    file = filedialog.askopenfile(title="Select File")
    if file is None:
        return
    _filepath = file.name.split("/")
    _filename = _filepath[-1]
    filename.set(_filename)
    filepath.set(file.name)
    window.lift()

def _line(line):
    """Calculate Y position for GUI element placement."""
    return 10 if line == 1 else 10 + 30 * (line - 1)

def _column(col):
    """Calculate X position for GUI element placement."""
    return 10 if col == 1 else 10 + 120 * (col - 1)

def _upload_file(window, filepath, filename, target_rpis):
    """Encrypt file with AES-256-GCM, upload to Azure, send AES key to disseminators, create blockchain tx."""
    _file = open(filepath, 'br').read()
    _file_hash = hashlib.sha256(_file).hexdigest()

    # Step 1: AES-256-GCM encrypt
    aes_key = generate_aes_key()
    encrypted = aes_encrypt(aes_key, _file)
    print(f"[OK] AES-256-GCM encrypted ({len(_file)} bytes)")

    # Step 2: Package for Azure
    blob_data = json.dumps({
        'encryption': 'aes-256-gcm',
        'nonce': encrypted['nonce'],
        'ciphertext': encrypted['ciphertext'],
        'file_hash': _file_hash
    }).encode('utf-8')

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
        print(f"[OK] Uploaded to Azure: {blob_name}")
    except Exception as e:
        messagebox.showerror("Azure Upload Error", f"Failed: {e}")
        return

    # Step 5: Store AES key locally
    blockchain.file_aes_keys[_file_hash] = base64.b64encode(aes_key).decode('ascii')

    # Step 6: Send AES key to each disseminator (RSA-encrypted)
    for diss_addr, diss_info in blockchain.disseminators.items():
        if diss_info.get('rsa_public_key_pem'):
            try:
                diss_rsa_pub = deserialize_public_key(diss_info['rsa_public_key_pem'])
                enc_key_for_diss = encrypt_aes_key(aes_key, diss_rsa_pub)
                requests.post(f"http://{diss_addr}/aes-key/receive",
                    json={'file_hash': _file_hash, 'encrypted_aes_key': enc_key_for_diss}, timeout=5)
                print(f"[OK] AES key sent to disseminator {diss_addr}")
            except Exception as e:
                print(f"[WARN] Could not send AES key to {diss_addr}: {e}")

    # Step 7: Lightweight blockchain transaction with target RPis
    _newblock = blockchain.new_azure_transaction(
        filename, blob_name, merkle_root, _file_hash, len(blob_data), chunk_count,
        target_rpis=target_rpis
    )
    blockchain.save_values()

    # Size comparison
    import json as jsonmod
    tx = blockchain.current_transactions[-1] if blockchain.current_transactions else {}
    on_chain_size = len(jsonmod.dumps(tx).encode('utf-8'))
    original_size = len(_file)
    reduction = (1 - on_chain_size / original_size) * 100 if original_size > 0 else 0

    print(f"\n{'─' * 55}")
    print(f"  Original file size:     {original_size:>10,} bytes")
    print(f"  Encrypted blob (Azure): {len(blob_data):>10,} bytes")
    print(f"  On-chain metadata:      {on_chain_size:>10,} bytes")
    print(f"  Blockchain reduction:   {reduction:>9.3f}%")
    print(f"  Merkle chunks:          {chunk_count:>10}")
    print(f"  Targets:                {target_rpis}")
    print(f"{'─' * 55}\n")

    messagebox.showinfo("File Upload",
        f"File encrypted and uploaded!\n\n"
        f"Blob: {blob_name}\n"
        f"Targets: {', '.join(target_rpis) if target_rpis else 'All RPis'}\n"
        f"Block: {_newblock}")

def upload_file():
    """Open file upload dialog with target RPi selection."""
    windows_us = Toplevel()
    windows_us.title("Upload Message")
    windows_us.geometry("400x350")

    # File selection
    text_filepath = StringVar()
    Label(windows_us, text="File Path:").place(x=10, y=10)
    Entry(windows_us, textvariable=text_filepath, width=25).place(x=130, y=10)
    Button(windows_us, text="...",
           command=lambda: _filepath_get(windows_us, text_filename, text_filepath)).place(x=340, y=6)

    text_filename = StringVar()
    Label(windows_us, text="Message Name:").place(x=10, y=40)
    Entry(windows_us, textvariable=text_filename, width=25).place(x=130, y=40)

    # Target RPi selection
    Label(windows_us, text="Target RPi Devices:").place(x=10, y=80)
    rpi_listbox = Listbox(windows_us, selectmode=MULTIPLE, height=6)
    rpi_addresses = list(blockchain.rpis.keys())
    for addr in rpi_addresses:
        rpi_listbox.insert(END, addr)
    rpi_listbox.place(x=10, y=105, width=280, height=120)

    def select_all():
        rpi_listbox.select_set(0, END)
    Button(windows_us, text="Select All", command=select_all).place(x=300, y=105)

    def do_upload():
        selected = [rpi_addresses[i] for i in rpi_listbox.curselection()]
        if not text_filepath.get():
            messagebox.showwarning("Upload", "Please select a file first")
            return
        if not selected:
            if not messagebox.askyesno("Upload", "No RPis selected. Send to all?"):
                return
            selected = rpi_addresses
        _upload_file(windows_us, text_filepath.get(), text_filename.get(), selected)

    Button(windows_us, text="Upload & Encrypt", command=do_upload).place(x=130, y=240)
    Button(windows_us, text="Cancel", command=windows_us.destroy).place(x=280, y=240)

# ============================================================
# Main Window
# ============================================================
main_window = Tk()
main_window.title("Publisher + Validator (Ubuntu-1)")
main_window.geometry("650x300")

def _create_main_window_structure():
    """Build the publisher GUI menu bar."""
    Menu_Bar = Menu(main_window)

    Connection_Menu = Menu(Menu_Bar, tearoff=0)
    Connection_Menu.add_command(label="Add Edge Disseminator", command=add_edge_disseminator)
    Connection_Menu.add_command(label="Print RPi list", command=print_rpi)
    Connection_Menu.add_separator()
    Connection_Menu.add_command(label="Connect Blockchain", command=blockchain_thread.start)
    Connection_Menu.add_command(label="Disconnect and Exit", command=disconnect_exit)
    Menu_Bar.add_cascade(label="Blockchain", menu=Connection_Menu)

    Actions_Menu = Menu(Menu_Bar, tearoff=0)
    Actions_Menu.add_command(label="Upload Message", command=upload_file)
    Actions_Menu.add_separator()
    Actions_Menu.add_command(label="Print Chain", command=blockchain.print_chain)
    Menu_Bar.add_cascade(label="Actions", menu=Actions_Menu)

    main_window.config(menu=Menu_Bar)

_create_main_window_structure()
mainloop()
