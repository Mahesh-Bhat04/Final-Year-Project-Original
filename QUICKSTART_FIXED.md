# Quick Start Guide - Fixed HTTP 415 Error

## Problem Fixed

The HTTP 415 error was caused by inconsistent data transmission between nodes:

- **Issue**: Nodes were sending data as URL parameters but receiving endpoints expected JSON
- **Solution**: All inter-node communication now uses JSON with proper Content-Type headers

## Changes Made

### 1. blockchain-PC.py

- Fixed `/transactions/new` endpoint to handle both JSON and URL parameters
- Fixed `/blocks/new` endpoint to handle both JSON and URL parameters
- Corrected debug messages for k_sign.txt file operations

### 2. definitions.py

- Updated `populate_transaction()` to send JSON instead of URL parameters
- Updated `populate_block()` to send JSON instead of URL parameters
- Updated `send_updates()` to send JSON to RPi devices
- Fixed variable name bug in `manage_updates()` (\_hash → \_file_hash)
- Fixed string concatenation with exception objects

### 3. RPi-server.py

- Updated `/updates/new` endpoint to handle both JSON and URL parameters

## Testing the Fixed System

### Step 1: Start First Ubuntu Node (Primary)

```bash
cd ~/Blockchain-IoT
sudo python3.8 blockchain-PC.py
```

- Click "Blockchain" → "Connect Blockchain"
- Note the IP address (e.g., 192.168.1.100:5000)

### Step 2: Start Second Ubuntu Node

```bash
cd ~/Blockchain-IoT
sudo python3.8 blockchain-PC.py
```

- Click "Blockchain" → "Connect Blockchain"
- Click "Blockchain" → "Add node"
- Enter the first Ubuntu's address (e.g., 192.168.1.100:5000)

### Step 3: Start Raspberry Pi Nodes (if needed)

```bash
cd ~/Blockchain-IoT
sudo $(pyenv which python3.8) RPi-server.py
```

### Step 4: Test Communication

Use the included test script:

```bash
# Test first node
python3.8 test_node_communication.py localhost:5000

# Test second node (replace with actual IP)
python3.8 test_node_communication.py 192.168.1.101:5000
```

### Step 5: Upload and Share Files

1. On first Ubuntu: Click "Actions" → "Upload Messages (Make Transaction)"
2. Select a file and upload
3. The transaction should propagate to the second Ubuntu without errors
4. Check second Ubuntu's console - no HTTP 415 errors should appear

## Verification

- Both nodes should show "INFO: Waiting for transactions..." periodically
- When uploading a file, you should see:
  - First node: "Transaction will be added to Block X"
  - Second node: Receives the transaction without errors
  - No HTML error responses in console output

## Troubleshooting

If you still see errors:

1. Ensure both nodes are on the same network
2. Check firewall settings (port 5000 should be open)
3. Verify the IP addresses are correct
4. Make sure you've clicked "Connect Blockchain" on both nodes
5. Check that all Python dependencies are installed correctly

## Network Architecture

```
Ubuntu VM 1 (blockchain-PC.py) <--JSON--> Ubuntu VM 2 (blockchain-PC.py)
     |                                           |
     v                                           v
RPi VM 1 (RPi-server.py)                  RPi VM 2 (RPi-server.py)
```

All communication now uses JSON format with proper Content-Type headers.
