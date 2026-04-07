"""
Edge Disseminator Node (Ubuntu-2)
=================================
Roles:
  - Edge Disseminator: Auto-pushes file updates to target IoT devices
  - Blockchain Sync: Syncs chain from Publisher (Ubuntu-1)
  - RPi Management: Registers RPi devices, notifies publisher for VC issuance

Flow:
  1. Start → Connect Blockchain (Flask, no genesis)
  2. Publisher adds this node via "Add Edge Disseminator" → receives VC
  3. This node adds RPi → notifies publisher → publisher issues VC to RPi
  4. Publisher uploads file (with target RPis) → sends AES key to this node
  5. This node auto-detects new blocks → sends to target RPis
"""

from time import strftime
import time, os, threading
from tkinter import *
from tkinter import ttk
import tkinter.simpledialog as simpledialog
import tkinter.messagebox as messagebox
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
from cryptography.hazmat.primitives import serialization

# Phase 3: RSA key management
from key_management import (
    generate_rsa_keypair, save_private_key, load_private_key,
    save_public_key, serialize_public_key,
    encrypt_aes_key, decrypt_aes_key, deserialize_public_key
)

# ============================================================
# Track last processed block for auto-dissemination
# ============================================================
last_processed_block = 0

def periodic_sync():
    """Sync blockchain from publisher and auto-disseminate new file updates"""
    global last_processed_block

    while True:
        time.sleep(15)

        # Sync blockchain from publisher
        if blockchain.connected and len(blockchain.nodes) > 0:
            old_length = len(blockchain.chain)
            replaced = blockchain.resolve_conflicts()

            if replaced and len(blockchain.chain) > old_length:
                print(f"[INFO] Blockchain synced: {old_length} -> {len(blockchain.chain)} blocks")

        # Auto-disseminate new file_update blocks
        chain_len = len(blockchain.chain)
        if chain_len > last_processed_block:
            for i in range(last_processed_block, chain_len):
                block = blockchain.chain[i]
                for tx in block['transactions']:
                    if tx.get('type') == 'file_update':
                        target_rpis = tx.get('target_rpis', [])
                        # Only send to RPis this disseminator manages
                        my_rpis = set(blockchain.rpis.keys())
                        targets = [r for r in target_rpis if r in my_rpis]

                        if not targets and not target_rpis:
                            # No target specified, send to all our RPis
                            targets = list(my_rpis)

                        for rpi_address in targets:
                            auto_send_to_rpi(rpi_address, tx)

            last_processed_block = chain_len

        print(f"INFO: Chain: {chain_len} blocks, RPis: {len(blockchain.rpis)}, Nodes: {len(blockchain.nodes)}")


def auto_send_to_rpi(rpi_address, transaction):
    """Auto-send file update to a specific RPi with RSA-encrypted AES key"""
    file_hash = transaction.get('file_hash', '')
    encrypted_key = None

    if file_hash in blockchain.file_aes_keys:
        aes_key = base64.b64decode(blockchain.file_aes_keys[file_hash])

        # Find device DID for this RPi
        device_did = None
        for did, info in blockchain.device_dids.items():
            if info.get('address') == rpi_address:
                device_did = did
                break

        if device_did and device_did in blockchain.device_rsa_keys:
            rsa_pub = deserialize_public_key(blockchain.device_rsa_keys[device_did])
            encrypted_key = encrypt_aes_key(aes_key, rsa_pub)
            print(f"[OK] AES key encrypted with RSA for {rpi_address}")
        else:
            print(f"[WARN] No RSA key for {rpi_address}, skipping")
            return
    else:
        print(f"[WARN] No AES key for file {file_hash[:16]}..., skipping")
        return

    print(f"[INFO] Auto-disseminating {transaction.get('name', '')} to {rpi_address}")
    blockchain.send_azure_update(rpi_address, transaction, encrypted_aes_key=encrypted_key)


def init_blockchain():
    """Start Flask server and sync thread. No genesis block — syncs from publisher."""
    blockchain.connected = True
    blockchain.chain_updated = False
    blockchain_sync.start()
    app.app_context()
    app.run(host='0.0.0.0', port=5000)


# ============================================================
# Initialization
# ============================================================
node_identifier = str(uuid4()).replace('-', '')

# DID initialization for disseminator
print(f"\n{'=' * 60}")
print(f"  Edge Disseminator Node (Ubuntu-2)")
print(f"{'=' * 60}")
print(f"\n=== Initializing Disseminator DID ===")

diss_did_manager = DIDManager()
diss_did_path = Path("disseminator_private_key.pem")

if diss_did_path.is_file():
    print("[INFO] Loading existing disseminator DID...")
    diss_did, diss_priv, diss_pub = diss_did_manager.load_private_key("disseminator_private_key.pem")
    print(f"[OK] Disseminator DID: {diss_did}")
else:
    print("[INFO] Generating new disseminator DID...")
    diss_did, diss_priv, diss_pub = diss_did_manager.generate_keypair_and_did()
    diss_did_manager.save_private_key("disseminator_private_key.pem")
    diss_did_manager.save_public_key("disseminator_public_key.pem")
    print(f"[OK] Generated Disseminator DID: {diss_did}")

diss_vc_manager = VCManager(diss_did_manager)

# RSA keypair for disseminator
diss_rsa_priv_path = Path("disseminator_rsa_private_key.pem")
if diss_rsa_priv_path.is_file():
    diss_rsa_private_key = load_private_key("disseminator_rsa_private_key.pem")
    diss_rsa_public_key = diss_rsa_private_key.public_key()
    print("[OK] RSA-2048 keypair loaded")
else:
    print("[INFO] Generating new RSA-2048 keypair...")
    diss_rsa_private_key, diss_rsa_public_key = generate_rsa_keypair()
    save_private_key(diss_rsa_private_key, "disseminator_rsa_private_key.pem")
    save_public_key(diss_rsa_public_key, "disseminator_rsa_public_key.pem")
    print("[OK] RSA-2048 keypair generated")

# VC storage
disseminator_vc = None
vc_path = Path("disseminator_credential.json")
if vc_path.is_file():
    with open("disseminator_credential.json", 'r') as f:
        disseminator_vc = json.load(f)
    print("[OK] Disseminator VC loaded")

print("=" * 60 + "\n")

# Instantiate blockchain (no genesis - will sync from publisher)
blockchain = Blockchain()
blockchain_thread = threading.Thread(name="blockchain", target=init_blockchain, daemon=True)
blockchain.load_values()

# Set last_processed_block to current chain length to avoid re-disseminating old blocks
last_processed_block = len(blockchain.chain)

# Flask app
app = Flask(__name__)
blockchain_sync = threading.Thread(name="sync", target=periodic_sync, daemon=True)

# ============================================================
# Flask Endpoints
# ============================================================

@app.route('/did/info', methods=['GET'])
def get_did_info():
    """Return disseminator DID and RSA public key (used by publisher for registration)"""
    did_info = diss_did_manager.get_did_info()
    did_info['rsa_public_key_pem'] = serialize_public_key(diss_rsa_public_key)
    return jsonify(did_info), 200

@app.route('/vc/receive', methods=['POST'])
def receive_credential():
    """Receive VC from publisher (role='edge_disseminator')"""
    global disseminator_vc

    values = request.get_json(silent=True)
    if not values or 'credential' not in values:
        return jsonify({'error': 'Missing credential'}), 400

    credential = values['credential']
    validator_public_key_pem = values.get('validator_public_key_pem')

    try:
        # Save validator public key
        if validator_public_key_pem:
            with open("validator_public_key.pem", "w") as f:
                f.write(validator_public_key_pem)

        # Store VC
        disseminator_vc = credential
        with open('disseminator_credential.json', 'w') as f:
            json.dump(credential, f, indent=2)

        print(f"[OK] Received VC from publisher")
        print(f"[OK] Role: {credential.get('claims', {}).get('role', 'unknown')}")

        vc_hash = diss_vc_manager.hash_credential(credential)
        return jsonify({'message': 'Credential received', 'vc_hash': vc_hash}), 200

    except Exception as e:
        print(f"[ERROR] VC reception failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/aes-key/receive', methods=['POST'])
def receive_aes_key():
    """Receive RSA-encrypted AES key from publisher for a file"""
    values = request.get_json(silent=True)
    if not values:
        return jsonify({'error': 'Missing data'}), 400

    file_hash = values.get('file_hash')
    encrypted_aes_key = values.get('encrypted_aes_key')

    if not file_hash or not encrypted_aes_key:
        return jsonify({'error': 'Missing file_hash or encrypted_aes_key'}), 400

    try:
        # Decrypt AES key with disseminator's RSA private key
        aes_key = decrypt_aes_key(encrypted_aes_key, diss_rsa_private_key)
        # Store for later per-device re-encryption
        blockchain.file_aes_keys[file_hash] = base64.b64encode(aes_key).decode('ascii')
        blockchain.save_values()
        print(f"[OK] Received AES key for file {file_hash[:16]}...")
        return jsonify({'message': 'AES key received'}), 200
    except Exception as e:
        print(f"[ERROR] AES key reception failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/blocks/new', methods=['POST'])
def blocks_new():
    """Flask endpoint: receive a new block from publisher."""
    values = request.get_json(silent=True)
    if values is None:
        values = request.values
    added = blockchain.new_block(_transactions=values)
    if added:
        return jsonify({'message': 'Block added'}), 201
    return jsonify({'message': 'Block rejected'}), 400

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    """Flask endpoint: receive transaction from publisher (broadcast=False to avoid loop)."""
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
    """Flask endpoint: return pending transactions."""
    return jsonify({'chain': blockchain.current_transactions, 'length': len(blockchain.chain)}), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    """Flask endpoint: return the full blockchain."""
    return jsonify({'chain': blockchain.chain, 'length': len(blockchain.chain)}), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    """Called by publisher to register itself as a blockchain node"""
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Missing nodes", 400
    for node in nodes:
        blockchain.register_node(node)
    blockchain.connected = True
    blockchain.chain_updated = False  # Trigger sync
    blockchain.save_values()
    print(f"[OK] Publisher registered as node: {nodes}")
    return jsonify({'message': 'Publisher node registered', 'total_nodes': list(blockchain.nodes)}), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    """Flask endpoint: trigger blockchain sync with publisher."""
    replaced = blockchain.resolve_conflicts()
    if replaced:
        return jsonify({'message': 'Chain synced', 'length': len(blockchain.chain)}), 200
    return jsonify({'message': 'Up to date', 'length': len(blockchain.chain)}), 200

@app.route('/ping', methods=['GET'])
def ping():
    """Flask endpoint: health check."""
    return jsonify({'message': 'PONG!'}), 200

# ============================================================
# GUI Functions
# ============================================================
def disconnect_exit():
    """Save blockchain state and exit the application."""
    blockchain.save_values()
    main_window.quit()

def add_rpi():
    """Register RPi device and notify publisher to issue VC"""
    _title = "Add RPi Device"
    _rpi_address = simpledialog.askstring(_title, "RPi Address (e.g., 192.168.1.10:5001):")
    if not _rpi_address:
        return

    _rpi_url = f"http://{_rpi_address}" if not _rpi_address.startswith('http') else _rpi_address

    # Step 1: Get RPi DID and RSA key
    try:
        print(f"[INFO] Requesting DID from {_rpi_url}/did/info")
        response = requests.get(f"{_rpi_url}/did/info", timeout=5)
        if response.status_code != 200:
            messagebox.showerror(_title, f"Failed to reach RPi at {_rpi_address}")
            return

        rpi_info = response.json()
        rpi_did = rpi_info['did']
        rpi_rsa_pub = rpi_info.get('rsa_public_key_pem', '')
        rpi_pub_key = rpi_info.get('public_key_pem', '')
        print(f"[OK] Received DID: {rpi_did}")

    except Exception as e:
        messagebox.showerror(_title, f"Connection error: {e}")
        return

    # Step 2: Store RSA key locally
    if rpi_rsa_pub:
        blockchain.device_rsa_keys[rpi_did] = rpi_rsa_pub

    # Step 3: Register RPi locally
    blockchain.register_rpi(address=_rpi_address)
    if rpi_did not in blockchain.device_dids:
        blockchain.device_dids[rpi_did] = {'address': _rpi_address, 'vc_hash': None}
    else:
        blockchain.device_dids[rpi_did]['address'] = _rpi_address

    blockchain.save_values()

    # Step 4: Notify publisher to issue VC for this RPi
    publisher_notified = False
    for node in blockchain.nodes:
        try:
            print(f"[INFO] Notifying publisher at {node} about RPi {rpi_did}")
            resp = requests.post(f"http://{node}/rpi/notify", json={
                'rpi_did': rpi_did,
                'rpi_address': _rpi_address,
                'rpi_public_key_pem': rpi_pub_key,
                'rpi_rsa_public_key_pem': rpi_rsa_pub,
                'disseminator_address': f"{node}"  # Publisher already knows our address
            }, timeout=10)

            if resp.status_code == 200:
                result = resp.json()
                print(f"[OK] Publisher issued VC for RPi: {result.get('vc_hash', '')[:16]}...")
                publisher_notified = True
                break
        except Exception as e:
            print(f"[WARN] Could not notify publisher at {node}: {e}")

    if publisher_notified:
        messagebox.showinfo(title=_title,
            message=f"RPi registered and VC issued!\n\n"
                    f"Address: {_rpi_address}\n"
                    f"DID: {rpi_did}\n"
                    f"Publisher notified: Yes")
    else:
        messagebox.showwarning(title=_title,
            message=f"RPi registered locally but publisher unreachable.\n"
                    f"VC not issued yet.\n\n"
                    f"Address: {_rpi_address}\nDID: {rpi_did}")

    print(f"[OK] RPi {_rpi_address} registered (DID: {rpi_did})")

def print_rpi():
    """Print all registered RPi devices to console."""
    if len(blockchain.rpis) == 0:
        print("INFO - No RPi devices registered")
        return
    print(f"\n--- Registered RPi Devices ({len(blockchain.rpis)}) ---")
    for addr, info in blockchain.rpis.items():
        print(f"  {addr}: {info}")
    print()

def sync_now():
    """Manually trigger blockchain sync from publisher"""
    if len(blockchain.nodes) == 0:
        messagebox.showwarning("Sync", "No publisher node connected yet.\nWait for publisher to add this disseminator.")
        return
    replaced = blockchain.resolve_conflicts()
    if replaced:
        messagebox.showinfo("Sync", f"Blockchain synced!\nChain length: {len(blockchain.chain)}")
    else:
        messagebox.showinfo("Sync", f"Already up to date.\nChain length: {len(blockchain.chain)}")

# ============================================================
# Main Window
# ============================================================
main_window = Tk()
main_window.title("Edge Disseminator (Ubuntu-2)")
main_window.geometry("650x300")

def _create_main_window_structure():
    """Build the disseminator GUI menu bar."""
    Menu_Bar = Menu(main_window)

    Connection_Menu = Menu(Menu_Bar, tearoff=0)
    Connection_Menu.add_command(label="Add RPi Device", command=add_rpi)
    Connection_Menu.add_command(label="Print RPi list", command=print_rpi)
    Connection_Menu.add_separator()
    Connection_Menu.add_command(label="Connect Blockchain", command=blockchain_thread.start)
    Connection_Menu.add_command(label="Sync from Publisher", command=sync_now)
    Connection_Menu.add_command(label="Disconnect and Exit", command=disconnect_exit)
    Menu_Bar.add_cascade(label="Blockchain", menu=Connection_Menu)

    Actions_Menu = Menu(Menu_Bar, tearoff=0)
    Actions_Menu.add_command(label="Print Chain", command=blockchain.print_chain)
    Menu_Bar.add_cascade(label="Actions", menu=Actions_Menu)

    main_window.config(menu=Menu_Bar)

_create_main_window_structure()
mainloop()
