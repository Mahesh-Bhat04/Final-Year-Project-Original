# Fix Summary: Key Distribution for RPi Nodes

## What Was Causing the Error

When you run `blockchain-PC.py`, it creates 4 cryptographic key files:

- **pk.txt** (Public Key)
- **msk.txt** (Master Secret Key)
- **sk.txt** (Secret Key - needed for decryption)
- **k_sign.txt** (Signing Key)

The RPi nodes running `RPi-server.py` need at least `sk.txt` to decrypt messages, but they weren't receiving these keys, causing the error you saw.

## The Fix Applied

1. **Updated RPi-server.py:**

   - Added key initialization on startup
   - Added `/keys/receive` endpoint to receive keys from PC nodes
   - Better error handling when keys are missing

2. **Updated blockchain-PC.py:**

   - Added "Send Keys to RPIs" menu option
   - Automatic key distribution when adding RPi nodes
   - Function to send keys to one or all RPi nodes

3. **Added utilities:**
   - `copy_keys.py` - Script to manually copy keys between directories
   - `KEY_DISTRIBUTION_GUIDE.md` - Complete documentation

## How to Use the Fixed System

### Step 1: Start PC Node (Ubuntu)

```bash
cd ~/Blockchain-IoT
sudo python3.8 blockchain-PC.py
```

This generates the key files on first run.

### Step 2: Start RPi Node

```bash
cd ~/Blockchain-IoT
sudo $(pyenv which python3.8) RPi-server.py
```

RPi will start and wait for keys.

### Step 3: Distribute Keys (Choose One Method)

#### Method A: When Adding RPi (Automatic)

1. On PC node: Blockchain → Add RPi
2. Enter RPi address (e.g., `192.168.1.50:5001`)
3. Click "Yes" when asked to send keys

#### Method B: Send to All RPis

1. On PC node: Blockchain → Send Keys to RPIs
2. Keys sent to all registered RPis

#### Method C: Manual Copy

```bash
# From PC node directory
python3 copy_keys.py . ~/target_directory --minimal
```

### Step 4: Verify

- RPi console should show: "Successfully received and saved keys from PC node"
- No more "No such file or directory: 'sk.txt'" errors
- Messages can now be sent from PC to RPi successfully

## Testing the Complete Flow

1. **PC Node 1:** Upload a file (Actions → Upload Messages)
2. **PC Node 1:** Add RPi node and send keys
3. **PC Node 1:** Disseminate message to RPi
4. **RPi Node:** Should receive and verify the message successfully

## Key Points

- **Always distribute keys to RPi nodes before sending messages**
- **Keys only need to be sent once per RPi**
- **RPi saves keys for future use**
- **All nodes should ideally use the same keys for compatibility**

## If You Still Get Errors

1. Make sure RPi server is running on port 5001
2. Check firewall isn't blocking port 5001
3. Verify network connectivity between nodes
4. Manually copy key files if automatic distribution fails
