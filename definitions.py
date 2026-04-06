import os
import hashlib
import json
from urllib.parse import urlparse
import time
import requests
import tkinter.messagebox as messagebox
from math import ceil
import pickle
import subprocess
from time import strftime

class Blockchain:

    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        self.rpis = {}
        self.connected = False
        self.chain_updated = False

        # DID and VC infrastructure (Phase 1)
        self.validator_did = None
        self.issued_vcs = {}  # vc_hash -> vc mapping
        self.device_dids = {}  # device_address -> DID mapping

        # Phase 3: AES key management and device RSA keys
        self.device_rsa_keys = {}  # device_did -> rsa_public_key_pem
        self.file_aes_keys = {}    # file_hash -> base64(aes_key)

        # Disseminator tracking
        self.disseminators = {}    # address -> {did, vc_hash, rsa_public_key_pem, managed_rpis}

        # NOTE: Genesis block is NOT created here.
        # Call create_genesis() explicitly when starting the publisher node.

        # Define names for storage files
        self.nodes_filename = 'nodes.pkl'
        self.blockchain_filename = 'blockchain.pkl'
        self.rpis_filename = 'rpis.pkl'
        self.vcs_filename = 'vcs.pkl'
        self.validator_did_filename = 'validator_did.pkl'
        self.device_dids_filename = 'device_dids.pkl'
        self.rsa_keys_filename = 'device_rsa_keys.pkl'
        self.aes_keys_filename = 'file_aes_keys.pkl'
        self.disseminators_filename = 'disseminators.pkl'

    def create_genesis(self):
        """Create genesis block. Only called by publisher on 'Connect Blockchain' click."""
        if len(self.chain) == 0:
            self.new_block(previous_hash='1')
            return True
        return False

    def get_file_names(self):
        aux = []
        for block in self.chain:
            for transaction in block['transactions']:
                # Skip VC transactions (no file name)
                if transaction.get('type') == 'vc_issuance':
                    continue
                if 'name' in transaction:
                    aux.append(transaction['name'])
        return aux

    def print_chain(self):
        """Print blockchain in a visual block-chain format"""
        if len(self.chain) == 0:
            print("INFO - Blockchain is empty")
            return

        print(f"\n{'=' * 65}")
        print(f"  BLOCKCHAIN VISUALIZATION ({len(self.chain)} blocks)")
        print(f"{'=' * 65}")

        for i, block in enumerate(self.chain):
            ts = strftime('%Y-%m-%d %H:%M:%S', time.localtime(block["timestamp"]))
            block_hash = block.get('hash', 'N/A')[:16]
            prev_hash = block['previous_hash'][:16] if block['previous_hash'] != '1' else 'GENESIS'
            txns = block['transactions']

            # Block box
            print(f"  +{'─' * 55}+")
            print(f"  │ Block #{block['index']:<8}  Hash: {block_hash}...{' ' * 10}│")
            print(f"  │ Time: {ts}{' ' * 24}│")
            print(f"  │ Prev: {prev_hash}{'...' if prev_hash != 'GENESIS' else '   '}{' ' * 24}│")

            if len(txns) == 0:
                print(f"  │ Transactions: (none - genesis){' ' * 22}│")
            else:
                print(f"  │ Transactions: {len(txns)}{' ' * 38}│")
                for tx in txns:
                    tx_type = tx.get('type', 'file')
                    if tx_type == 'vc_issuance':
                        subject = tx.get('subject_did', '')[:24]
                        print(f"  │   [VC] Subject: {subject}...{' ' * (17 - len(subject) + 24)}│")
                    elif tx_type == 'file_update':
                        name = tx.get('name', '')[:20]
                        enc = tx.get('encryption', 'aes-256-gcm')
                        size = tx.get('file_size', 0)
                        print(f"  │   [FILE] {name} ({size}B, {enc}){' ' * max(0, 29 - len(name) - len(str(size)) - len(enc))}│")
                    else:
                        print(f"  │   [{tx_type}]{' ' * 46}│")

            print(f"  +{'─' * 55}+")

            # Chain link
            if i < len(self.chain) - 1:
                print(f"  {'.' * 10} ↓ {'.' * 10}")

        print(f"\n{'=' * 65}\n")

    def print_transactions(self):
        """Print pending transactions"""
        if len(self.current_transactions) == 0:
            print("INFO - Currently there are no pending transactions")
            return

        print(f"\n--- Pending Transactions ({len(self.current_transactions)}) ---")
        for i, tx in enumerate(self.current_transactions):
            tx_type = tx.get('type', 'unknown')
            if tx_type == 'vc_issuance':
                print(f"  [{i+1}] VC Issuance: subject={tx.get('subject_did', '')[:24]}...")
            elif tx_type == 'file_update':
                print(f"  [{i+1}] File Update: {tx.get('name', '')} ({tx.get('file_size', 0)}B)")
            else:
                print(f"  [{i+1}] {tx_type}: {tx.get('name', '')}")
        print()

    def send_azure_update(self, rpi_address, transaction, encrypted_aes_key=None):
        """Phase 2/3: Send lightweight metadata to RPi (file data is in Azure)"""
        update = {
            'type': 'file_update',
            'name': transaction['name'],
            'azure_blob_name': transaction['azure_blob_name'],
            'merkle_root': transaction['merkle_root'],
            'file_hash': transaction['file_hash'],
            'file_size': transaction.get('file_size', 0),
            'chunk_count': transaction.get('chunk_count', 0),
            'encryption': transaction.get('encryption', 'cp-absc')
        }
        # Phase 3: Include per-device RSA-encrypted AES key
        if encrypted_aes_key:
            update['encrypted_aes_key'] = encrypted_aes_key

        try:
            headers = {'Content-Type': 'application/json'}
            resp = requests.post("http://" + rpi_address + "/updates/new", json=update, headers=headers)
            print(f"[OK] Sent Azure update to {rpi_address}: {resp.text[:200]}")
        except requests.exceptions.Timeout as e:
            print(f"ERROR: RPi {rpi_address} - Timeout {e}")
            return False
        except requests.exceptions.ConnectionError:
            print(f"ERROR: RPi {rpi_address} - Failed to establish connection")
            return False

        self.rpis[rpi_address] = {'file_hash': transaction['file_hash'], 'name': transaction['name'],
                                   'date': time.time(), 'status': 'OK'}
        return True

    def manage_updates(self):

        last_block = self.chain[len(self.chain)-1]
        for transaction in last_block['transactions']:

            # Phase 2: Handle Azure-based file updates
            if transaction.get('type') == 'file_update':
                _name = transaction['name']
                _file_hash = transaction['file_hash']
                for r in self.rpis:
                    if not 'hash' in self.rpis[r]:
                        self.send_azure_update(r.title(), transaction)
                    elif _file_hash not in self.rpis[r]['hash']:
                        self.send_azure_update(r.title(), transaction)
                    elif self.rpis[r].get('Status') == "ERROR":
                        self.send_azure_update(r.title(), transaction)
                    else:
                        print(r.title() + ": Up to date for " + _name)
                continue

            # Skip VC transactions (no file to send)
            if transaction.get('type') == 'vc_issuance':
                continue

    def load_values(self):
        """
        Load previously saved values
        """
        dirname = os.path.dirname(__file__)
        if os.path.exists(dirname + '/' + self.nodes_filename):
            with open(dirname + '/' + self.nodes_filename, 'rb') as f:
                self.nodes = pickle.load(f)

        if os.path.exists(dirname + '/' + self.blockchain_filename):
            with open(dirname + '/' + self.blockchain_filename, 'rb') as f:
                self.chain = pickle.load(f)

        if os.path.exists(dirname + '/' + self.rpis_filename):
            with open(dirname + '/' + self.rpis_filename, 'rb') as f:
                self.rpis = pickle.load(f)

        # Load DID/VC data (Phase 1)
        if os.path.exists(dirname + '/' + self.vcs_filename):
            with open(dirname + '/' + self.vcs_filename, 'rb') as f:
                self.issued_vcs = pickle.load(f)

        if os.path.exists(dirname + '/' + self.validator_did_filename):
            with open(dirname + '/' + self.validator_did_filename, 'rb') as f:
                self.validator_did = pickle.load(f)

        if os.path.exists(dirname + '/' + self.device_dids_filename):
            with open(dirname + '/' + self.device_dids_filename, 'rb') as f:
                self.device_dids = pickle.load(f)

        # Phase 3: Load RSA keys and AES keys
        if os.path.exists(dirname + '/' + self.rsa_keys_filename):
            with open(dirname + '/' + self.rsa_keys_filename, 'rb') as f:
                self.device_rsa_keys = pickle.load(f)

        if os.path.exists(dirname + '/' + self.aes_keys_filename):
            with open(dirname + '/' + self.aes_keys_filename, 'rb') as f:
                self.file_aes_keys = pickle.load(f)

        if os.path.exists(dirname + '/' + self.disseminators_filename):
            with open(dirname + '/' + self.disseminators_filename, 'rb') as f:
                self.disseminators = pickle.load(f)

    def save_values(self):
        """
        Save values to files so we can close a node without losing information
        """
        dirname = os.path.dirname(__file__)
        with open(dirname + '/' + self.nodes_filename, 'wb') as f:
            pickle.dump(self.nodes, f, pickle.HIGHEST_PROTOCOL)

        with open(dirname + '/' + self.blockchain_filename, 'wb') as f:
            pickle.dump(self.chain, f, pickle.HIGHEST_PROTOCOL)

        with open(dirname + '/' + self.rpis_filename, 'wb') as f:
            pickle.dump(self.rpis, f, pickle.HIGHEST_PROTOCOL)

        # Save DID/VC data (Phase 1)
        with open(dirname + '/' + self.vcs_filename, 'wb') as f:
            pickle.dump(self.issued_vcs, f, pickle.HIGHEST_PROTOCOL)

        with open(dirname + '/' + self.validator_did_filename, 'wb') as f:
            pickle.dump(self.validator_did, f, pickle.HIGHEST_PROTOCOL)

        with open(dirname + '/' + self.device_dids_filename, 'wb') as f:
            pickle.dump(self.device_dids, f, pickle.HIGHEST_PROTOCOL)

        # Phase 3: Save RSA keys and AES keys
        with open(dirname + '/' + self.rsa_keys_filename, 'wb') as f:
            pickle.dump(self.device_rsa_keys, f, pickle.HIGHEST_PROTOCOL)

        with open(dirname + '/' + self.aes_keys_filename, 'wb') as f:
            pickle.dump(self.file_aes_keys, f, pickle.HIGHEST_PROTOCOL)

        with open(dirname + '/' + self.disseminators_filename, 'wb') as f:
            pickle.dump(self.disseminators, f, pickle.HIGHEST_PROTOCOL)

    def register_node(self, address):
        """
        Add a new node to the list of nodes
        :param address: Address of node. Eg. 'http://192.168.100.1:5000'
        """
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.100.1:5000'.
            self.nodes.add(parsed_url.path)
        else:
            messagebox.showerror("Register Node", "Invalid URL")
            return False
        return True

    def register_rpi(self, address):
        """
        Add a new RPi to the list of RPis
        :param address: Address of node. Eg. 'http://192.168.100.1:5000'
        """
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            if not parsed_url.netloc in self.rpis:
                self.rpis[parsed_url.netloc] = {}
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.100.1:5000'.
            #self.rpis.add(parsed_url.path)
            if not parsed_url.path in self.rpis:
                self.rpis[parsed_url.path] = {}
        else:
            messagebox.showerror("Register RPi", "Invalid URL")
            return False
        return True

    def register_rpi_with_vc(self, address, rpi_did, vc):
        """
        Register RPi with DID and Verifiable Credential (Phase 1)

        Args:
            address: IP:PORT of RPi
            rpi_did: DID of the RPi
            vc: Issued Verifiable Credential

        Returns:
            bool: True if successful
        """
        parsed_url = urlparse(address)
        rpi_key = parsed_url.netloc if parsed_url.netloc else parsed_url.path

        if not rpi_key:
            messagebox.showerror("Register RPi", "Invalid URL")
            return False

        # Store comprehensive device information
        self.rpis[rpi_key] = {
            'did': rpi_did,
            'credential': vc,
            'registered_at': time.time(),
            'last_seen': time.time(),
            'status': 'active'
        }

        # Map DID to device info (dict for consistency with add_rpi_with_vc)
        # Only update if not already set or if we have new info
        if rpi_did not in self.device_dids:
            self.device_dids[rpi_did] = {
                'address': rpi_key,
                'vc_hash': None  # Will be set by add_rpi_with_vc if issuing VC
            }

        return True

    def new_vc_transaction(self, vc_hash, issuer_did, subject_did):
        """
        Create blockchain transaction for VC issuance (Phase 1)

        Args:
            vc_hash: SHA-256 hash of the VC
            issuer_did: DID of VC issuer (validator)
            subject_did: DID of credential subject (device)

        Returns:
            int: Index of the block that will hold this transaction
        """
        transaction = {
            'type': 'vc_issuance',
            'vc_hash': vc_hash,
            'issuer_did': issuer_did,
            'subject_did': subject_did,
            'timestamp': time.time()
        }

        self.current_transactions.append(transaction)

        # Broadcast to network
        try:
            self.populate_transaction(transaction)
        except Exception as e:
            print(f"[WARNING] Could not broadcast VC transaction: {e}")

        return self.last_block['index'] + 1

    def valid_chain(self, chain): # Didn't use yet!

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.
        :return: True if our chain was replaced, False if not
        Other consensus can be used such as PBFT (https://github.com/LRAbbade/PBFT, https://github.com/luckydonald/pbft).
        """
        neighbours = self.nodes
        new_chain = None
        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/chain')

                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']

                    # Check if the length is longer and the chain is valid
                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except requests.exceptions.Timeout as e:
                print("ERROR: Node " + node + " - Timeout " + str(e))
                return False
            except requests.exceptions.ConnectionError as ce:
                print("ERROR: Node " + node + " - Failed to establish connection")
                return False

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def populate_block(self, block):

        for n in self.nodes:
            try:
                # Send as JSON with proper headers
                headers = {'Content-Type': 'application/json'}
                request = requests.post("http://" + n + "/blocks/new", json=block, headers=headers)
                print("Request Response Type: " + str(type(request.text)))
                print("Request Response: " + request.text[:200])  # Fixed: show first 200 chars, not from 200th
            except requests.exceptions.Timeout as e:
                print("ERROR: Node " + n + " - Timeout " + str(e))
                return False
            except requests.exceptions.ConnectionError as ce:
                print("ERROR: Node " + n + " - Failed to establish connection")
                return False

    def populate_transaction(self, transaction):
        if len(self.current_transactions) <= 0:
            return False

        for n in self.nodes:
            try:
                # Send as JSON with proper headers
                headers = {'Content-Type': 'application/json'}
                request = requests.post("http://" + n + "/transactions/new", json=transaction, headers=headers)
                print("Request Response Type: " + str(type(request.text)))
                print("Request Response: " + request.text[:200])  # Fixed: show first 200 chars, not from 200th
            except requests.exceptions.Timeout as e:
                print("ERROR: Node " + n + " - Timeout " + str(e))
                return False
            except requests.exceptions.ConnectionError as ce:
                print("ERROR: Node " + n + " - Failed to establish connection")
                return False

    def valid_file(self, transaction):
        # Phase 2: Azure file updates are verified via Merkle tree, not file content
        if transaction.get('type') == 'file_update':
            required = ['azure_blob_name', 'merkle_root', 'file_hash']
            if all(k in transaction for k in required):
                return True
            print("[ERROR] file_update transaction missing required fields")
            return 0

        return True

    def new_block(self, previous_hash, _transactions=None):
        # If there is no files to verify (transactions) and it is not the genesis block creation, exit
        if len(self.current_transactions) <= 0 and previous_hash != '1':
            if _transactions is None:
                return False

        if previous_hash != '1':
            txns = _transactions if _transactions else self.current_transactions
            for transaction in txns:
                if not self.valid_file(transaction):
                    return False
        if len(self.chain) > 0:
            print(self.chain[-1])
            previous_hash = self.chain[-1]['hash']

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(), #time is not coming as a right
            'transactions': self.current_transactions,
            'previous_hash': previous_hash or self.hash(self.chain[-1])
        }
        block['hash'] = self.hash(block) # block hash korte na parle? Separately test korbo!
        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        print("INFO - Added block " + str(block['index']) + " with hash: " + block['hash'])
        #self.resolve_conflicts()

        return block

    def new_azure_transaction(self, name, azure_blob_name, merkle_root, file_hash, file_size, chunk_count, target_rpis=None):
        """Create lightweight transaction with Azure reference and target RPi list."""
        transaction = {
            'type': 'file_update',
            'encryption': 'aes-256-gcm',
            'name': name,
            'azure_blob_name': azure_blob_name,
            'merkle_root': merkle_root,
            'file_hash': file_hash,
            'file_size': file_size,
            'chunk_count': chunk_count,
            'target_rpis': target_rpis or []
        }
        self.current_transactions.append(transaction)

        # Broadcast to network nodes
        self.populate_transaction(transaction)

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        if len(self.chain) == 0:
            return None
        return self.chain[-1]

# Tough things here, need to check every where, hash thing!
    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a CT or Block
        :param block: Block
        For block, we must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        """
        trns_list = block['transactions']

        if len(trns_list) > 0:

            print("Block ==> " + str(block))

            # Phase 1: Handle VC transactions (they don't have 'ct' key)
            if trns_list[0].get('type') == 'vc_issuance':
                # For VC transactions, hash the vc_hash field
                vc_hash = trns_list[0]['vc_hash']
                block_string = json.dumps(vc_hash, sort_keys=True).encode()
                return hashlib.sha256(block_string).hexdigest()

            # Phase 2: Handle Azure file_update transactions
            if trns_list[0].get('type') == 'file_update':
                # Hash the merkle_root (compact representation of all file data)
                merkle_root = trns_list[0]['merkle_root']
                block_string = json.dumps(merkle_root, sort_keys=True).encode()
                return hashlib.sha256(block_string).hexdigest()

            ct_hash = trns_list[0]['ct']
            # print("ct ==> " + str(ct_hash))
            block_string = json.dumps(ct_hash, sort_keys=True).encode()
            return hashlib.sha256(block_string).hexdigest()

        else:
            print("Block ==> " + str(block))
            block_string = json.dumps(block, sort_keys=True).encode()
            #print("block_string ==> " + str(block_string))
            return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"