# Cryptographic Key Distribution Guide

## Understanding the Key Files

When you run `blockchain-PC.py` for the first time, it generates four cryptographic key files:

1. **pk.txt** - Public Key (used for encryption)
2. **msk.txt** - Master Secret Key (used for key generation)
3. **sk.txt** - Secret Key (used for decryption)
4. **k_sign.txt** - Signing Key (used for signatures)

These files are essential for the cryptographic operations in the blockchain system.

## The Problem

- **blockchain-PC.py** generates these keys automatically on first run
- **RPi-server.py** needs at least `sk.txt` to decrypt messages
- Without these keys, RPi nodes cannot process messages from PC nodes

## The Solution: Key Distribution System

### Method 1: Automatic Key Distribution (Recommended)

#### On PC Node (Ubuntu with blockchain-PC.py):

1. **Start the PC node first:**

   ```bash
   cd ~/Blockchain-IoT
   sudo python3.8 blockchain-PC.py
   ```

   This will generate the key files if they don't exist.

2. **Connect the blockchain:**

   - Click "Blockchain" → "Connect Blockchain"

3. **Add and configure RPi nodes:**

   - Click "Blockchain" → "Add RPi"
   - Enter RPi address (e.g., `192.168.1.50:5001`)
   - When prompted "Do you want to send cryptographic keys to this RPi now?", click **Yes**

4. **Or send keys to all RPis at once:**
   - Click "Blockchain" → "Send Keys to RPIs"
   - This will distribute keys to all registered RPi nodes

#### On RPi Node (Raspberry Pi with RPi-server.py):

1. **Start the RPi server:**

   ```bash
   cd ~/Blockchain-IoT
   sudo $(pyenv which python3.8) RPi-server.py
   ```

2. **The RPi will automatically:**
   - Check for existing key files
   - If not found, wait to receive keys from PC node
   - Save received keys for future use

### Method 2: Manual Key Distribution

If automatic distribution fails, you can manually copy the key files:

#### On PC Node:

```bash
# Navigate to the project directory
cd ~/Blockchain-IoT

# Check that key files exist
ls -la *.txt
```

#### Copy keys to RPi:

```bash
# Using SCP (replace with your RPi's IP)
scp pk.txt sk.txt k_sign.txt pi@192.168.1.50:~/Blockchain-IoT/

# Or if you need sudo access on RPi
scp pk.txt sk.txt k_sign.txt user@192.168.1.50:/tmp/
# Then on RPi:
sudo mv /tmp/*.txt ~/Blockchain-IoT/
```

### Method 3: Shared Key Generation (Alternative)

If you want all nodes to use the same keys from the start:

1. **Generate keys once on any PC node**
2. **Copy the key files to all nodes before starting them**
3. **All nodes will use the existing keys instead of generating new ones**

## Verification

### Check if keys are properly distributed:

#### On PC Node:

```bash
# Check key files exist
ls -la pk.txt msk.txt sk.txt k_sign.txt
```

#### On RPi Node:

```bash
# Check key files exist (at minimum pk.txt and sk.txt)
ls -la pk.txt sk.txt
```

### Test the system:

1. **From PC node:** Upload a message (Actions → Upload Messages)
2. **Send to RPi:** Actions → Disseminate Messages to RPi
3. **Check RPi console:** Should show "Successfully Verified!" without key errors

## Troubleshooting

### Error: "No such file or directory: 'sk.txt'"

- **Cause:** RPi doesn't have the secret key file
- **Solution:** Use "Send Keys to RPIs" from PC node or manually copy keys

### Error: "Secret key not found - RPi needs keys from PC node"

- **Cause:** RPi tried to process a message without keys
- **Solution:** Distribute keys from PC node first

### Error: "Could not connect to RPi"

- **Cause:** RPi server not running or network issue
- **Solution:**
  1. Ensure RPi server is running on port 5001
  2. Check firewall settings
  3. Verify network connectivity

### Keys not sending automatically

- **Cause:** Network or firewall blocking port 5001
- **Solution:**
  1. Check RPi is accessible: `ping <rpi-ip>`
  2. Test port: `telnet <rpi-ip> 5001`
  3. Use manual distribution method

## Security Considerations

1. **Key files contain sensitive cryptographic material**
2. **Protect key files with appropriate permissions:**
   ```bash
   chmod 600 *.txt
   ```
3. **Use secure channels (SSH/SCP) for manual key distribution**
4. **In production, implement proper key management and rotation**

## Network Architecture with Keys

```
PC Node 1 (Ubuntu)              PC Node 2 (Ubuntu)
[Generates Keys]                [Uses Same/Different Keys]
pk, msk, sk, k_sign            pk, msk, sk, k_sign
       |                              |
       | (Distributes keys)           | (Distributes keys)
       v                              v
RPi Node 1                      RPi Node 2
[Receives Keys]                 [Receives Keys]
pk, sk (minimum)                pk, sk (minimum)
```

## Best Practices

1. **Start PC nodes before RPi nodes**
2. **Distribute keys immediately after adding RPi nodes**
3. **Keep backup of key files in secure location**
4. **Use the same keys across all nodes for compatibility**
5. **Monitor console output for key-related errors**

## Quick Commands Reference

### PC Node Commands:

- Generate keys: Run `blockchain-PC.py` (automatic on first run)
- Send keys to one RPi: Add RPi and choose "Yes" when prompted
- Send keys to all RPis: Blockchain → Send Keys to RPIs

### RPi Node Commands:

- Receive keys: Automatic when PC sends them
- Check keys: `ls -la *.txt` in project directory

### Testing Commands:

```bash
# Test RPi endpoint
curl http://<rpi-ip>:5001/ping

# Check if RPi can receive keys
curl -X POST http://<rpi-ip>:5001/keys/receive \
  -H "Content-Type: application/json" \
  -d '{"pk":"test","sk":"test"}'
```
