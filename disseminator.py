"""
Edge Disseminator Node (Ubuntu-2)
=================================
Roles:
  - Edge Disseminator: Pushes {uri, merkle_root, vc_hash} to IoT devices
  - Blockchain Sync: Syncs chain from Publisher (Ubuntu-1)
  - RPi Management: Registers and manages IoT device connections

Architecture:
  Ubuntu-1 (Publisher) ──→ Permissioned Chain ──→ Ubuntu-2 (this)
                                                       │
                                                       ├─ push {uri, merkle_root} ──→ IoT Devices
                                                       └─ Off-chain Storage (Azure) ←── IoT Devices
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

# Phase 3: RSA key management for per-device AES key encryption
from key_management import encrypt_aes_key, deserialize_public_key

# ============================================================
# Blockchain Sync Thread
# ============================================================
def periodic_sync():
    """Periodically sync blockchain from publisher node and process new blocks"""
    while True:
        time.sleep(15)

        # Sync blockchain from publisher
        if blockchain.connected and not blockchain.chain_updated:
            print("INFO: Syncing blockchain from publisher...")
            blockchain.resolve_conflicts()
            blockchain.chain_updated = True

        # Check for new file_update transactions to disseminate
        print(f"INFO: Chain length: {len(blockchain.chain)}, Connected nodes: {len(blockchain.nodes)}")

def init_blockchain():
    blockchain_sync.start()
    app.app_context()
    app.run(host='0.0.0.0', port=5000)

# ============================================================
# Initialization
# ============================================================
node_identifier = str(uuid4()).replace('-', '')
print(f"\n{'=' * 60}")
print(f"  Edge Disseminator Node (Ubuntu-2)")
print(f"  Node ID: {node_identifier}")
print(f"{'=' * 60}\n")

# Instantiate the Blockchain (will sync from publisher)
blockchain = Blockchain()
blockchain_thread = threading.Thread(name="blockchain", target=init_blockchain, daemon=True)

blockchain.load_values()

# Instantiate Flask
app = Flask(__name__)
blockchain_sync = threading.Thread(name="sync", target=periodic_sync, daemon=True)

# ============================================================
# Flask Endpoints (for receiving chain updates from publisher)
# ============================================================

@app.route('/blocks/new', methods=['POST'])
def blocks_new():
    values = request.get_json(silent=True)
    if values is None:
        values = request.values
    added = blockchain.new_block(_transactions=values)
    if added:
        return jsonify({'message': 'Block added to chain'}), 201
    return jsonify({'message': 'Block rejected'}), 400

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
        return jsonify({'message': f'Transaction will be added to Block {index}'}), 201

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
    return jsonify({'message': 'Nodes added', 'total_nodes': list(blockchain.nodes)}), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        return jsonify({'message': 'Chain synced from publisher', 'length': len(blockchain.chain)}), 200
    return jsonify({'message': 'Chain is up to date', 'length': len(blockchain.chain)}), 200

# ============================================================
# GUI Functions
# ============================================================
def disconnect_exit():
    blockchain.save_values()
    main_window.quit()

def add_node():
    """Add publisher node address to sync blockchain from"""
    _title = "Add Publisher Node"
    _node_address = simpledialog.askstring(_title,
        "Publisher Address (e.g., 192.168.1.10:5000):")
    if _node_address and blockchain.register_node(address=_node_address):
        blockchain.connected = True
        blockchain.chain_updated = False  # Trigger sync
        messagebox.showinfo(title=_title,
            message=f"Publisher node added!\nAddress: {_node_address}\n"
                    f"Blockchain will sync automatically.")

def add_rpi():
    """Register RPi device for dissemination"""
    _title = "Add RPi Device"
    _rpi_address = simpledialog.askstring(_title, "RPi Address (e.g., 192.168.1.10:5001):")
    if not _rpi_address:
        return

    if not _rpi_address.startswith('http'):
        _rpi_url = f"http://{_rpi_address}"
    else:
        _rpi_url = _rpi_address

    # Verify RPi is reachable and get its DID info
    try:
        response = requests.get(f"{_rpi_url}/did/info", timeout=5)
        if response.status_code != 200:
            messagebox.showerror(_title, f"Failed to reach RPi at {_rpi_address}")
            return

        rpi_info = response.json()
        rpi_did = rpi_info['did']
        rpi_rsa_pub = rpi_info.get('rsa_public_key_pem', '')

        # Store RSA public key for AES key wrapping during dissemination
        if rpi_rsa_pub:
            blockchain.device_rsa_keys[rpi_did] = rpi_rsa_pub
            print(f"[OK] Stored RSA public key for {rpi_did}")

        # Register in RPi list
        blockchain.register_rpi(address=_rpi_address)

        # Map DID to address
        if rpi_did not in blockchain.device_dids:
            blockchain.device_dids[rpi_did] = {'address': _rpi_address, 'vc_hash': None}
        else:
            blockchain.device_dids[rpi_did]['address'] = _rpi_address

        blockchain.save_values()

        messagebox.showinfo(title=_title,
            message=f"RPi registered for dissemination!\n"
                    f"Address: {_rpi_address}\n"
                    f"DID: {rpi_did}")
        print(f"[OK] RPi {_rpi_address} registered (DID: {rpi_did})")

    except Exception as e:
        messagebox.showerror(_title, f"Connection error: {e}")

def print_rpi():
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
        messagebox.showwarning("Sync", "No publisher node configured.\nUse 'Add Publisher Node' first.")
        return
    replaced = blockchain.resolve_conflicts()
    if replaced:
        messagebox.showinfo("Sync", f"Blockchain synced!\nChain length: {len(blockchain.chain)}")
    else:
        messagebox.showinfo("Sync", f"Already up to date.\nChain length: {len(blockchain.chain)}")

# ============================================================
# Dissemination
# ============================================================
def send_update_button_click(file_name):
    """Send file update to all registered RPi devices"""
    print(f"INFO - Retrieving data for file {file_name}")
    values = {}

    for blocks in blockchain.chain:
        for trans in blocks['transactions']:
            if trans.get('name') == file_name:
                print(f"INFO - File found in block {blocks['index']}")
                values = trans.copy()

    if not values:
        print(f"ERROR - File '{file_name}' not found in blockchain!")
        return

    if len(blockchain.rpis) <= 0:
        print("ERROR - There are no RPis registered!")
        return

    for rpi_address in blockchain.rpis:
        print(f"INFO - Sending {values.get('name', '')} to RPi {rpi_address}")

        # Encrypt AES key per-device with RSA
        encrypted_key = None
        file_hash = values.get('file_hash', '')

        if file_hash in blockchain.file_aes_keys:
            import base64 as b64mod
            aes_key = b64mod.b64decode(blockchain.file_aes_keys[file_hash])

            # Find device DID for this RPi address
            device_did = None
            for did, info in blockchain.device_dids.items():
                if info.get('address') == rpi_address:
                    device_did = did
                    break

            if device_did and device_did in blockchain.device_rsa_keys:
                rsa_pub_pem = blockchain.device_rsa_keys[device_did]
                rsa_pub = deserialize_public_key(rsa_pub_pem)
                encrypted_key = encrypt_aes_key(aes_key, rsa_pub)
                print(f"[OK] AES key encrypted with RSA for {device_did}")
            else:
                print(f"[WARN] No RSA key for device at {rpi_address}")

        blockchain.send_azure_update(rpi_address, values, encrypted_aes_key=encrypted_key)

def send_update():
    window_su = Toplevel()
    window_su.title("Disseminate Messages to RPi Devices")
    window_su.geometry("400x100")

    Label(window_su, text="Select file:").place(x=10, y=10)

    files = blockchain.get_file_names()
    cb = ttk.Combobox(window_su, values=files)
    cb.place(x=130, y=10)

    Button(window_su, text="Send to All RPis",
           command=lambda: send_update_button_click(cb.get())).place(x=130, y=50)

# ============================================================
# Main Window
# ============================================================
main_window = Tk()
main_window.title("Edge Disseminator (Ubuntu-2)")
main_window.geometry("650x300")

def _create_main_window_structure():
    Menu_Bar = Menu(main_window)

    Connection_Menu = Menu(Menu_Bar, tearoff=0)
    Connection_Menu.add_command(label="Add Publisher Node", command=add_node)
    Connection_Menu.add_command(label="Add RPi Device", command=add_rpi)
    Connection_Menu.add_command(label="Print RPi list", command=print_rpi)
    Connection_Menu.add_separator()
    Connection_Menu.add_command(label="Connect Blockchain", command=blockchain_thread.start)
    Connection_Menu.add_command(label="Sync from Publisher", command=sync_now)
    Connection_Menu.add_command(label="Disconnect and Exit", command=disconnect_exit)
    Menu_Bar.add_cascade(label="Blockchain", menu=Connection_Menu)

    Actions_Menu = Menu(Menu_Bar, tearoff=0)
    Actions_Menu.add_command(label="Disseminate to RPi Devices", command=send_update)
    Actions_Menu.add_separator()
    Actions_Menu.add_command(label="Print Chain", command=blockchain.print_chain)
    Actions_Menu.add_command(label="Print Transactions", command=blockchain.print_transactions)
    Menu_Bar.add_cascade(label="Actions", menu=Actions_Menu)

    main_window.config(menu=Menu_Bar)

_create_main_window_structure()
mainloop()
