#!/usr/bin/env python3
"""
Utility script to copy key files between nodes.
This can be used to ensure all nodes use the same cryptographic keys.
"""

import os
import sys
import shutil
import argparse
from pathlib import Path

def copy_keys_to_directory(source_dir, target_dir, keys_to_copy=None):
    """Copy key files from source to target directory"""
    
    if keys_to_copy is None:
        keys_to_copy = ['pk.txt', 'msk.txt', 'sk.txt', 'k_sign.txt']
    
    source_path = Path(source_dir)
    target_path = Path(target_dir)
    
    if not source_path.exists():
        print(f"Error: Source directory {source_dir} does not exist")
        return False
    
    if not target_path.exists():
        print(f"Creating target directory {target_dir}")
        target_path.mkdir(parents=True, exist_ok=True)
    
    copied_files = []
    missing_files = []
    
    for key_file in keys_to_copy:
        source_file = source_path / key_file
        target_file = target_path / key_file
        
        if source_file.exists():
            try:
                shutil.copy2(source_file, target_file)
                copied_files.append(key_file)
                print(f"✓ Copied {key_file}")
            except Exception as e:
                print(f"✗ Failed to copy {key_file}: {e}")
        else:
            missing_files.append(key_file)
    
    if missing_files:
        print(f"\nWarning: Following key files not found in source: {', '.join(missing_files)}")
    
    if copied_files:
        print(f"\nSuccessfully copied {len(copied_files)} key file(s) to {target_dir}")
        return True
    else:
        print("\nNo key files were copied")
        return False

def main():
    parser = argparse.ArgumentParser(description='Copy cryptographic key files between nodes')
    parser.add_argument('source', help='Source directory containing key files')
    parser.add_argument('target', help='Target directory to copy keys to')
    parser.add_argument('--minimal', action='store_true', 
                       help='Copy only minimal keys needed for RPi (pk.txt and sk.txt)')
    parser.add_argument('--backup', action='store_true',
                       help='Create backup of existing keys in target before copying')
    
    args = parser.parse_args()
    
    # Determine which keys to copy
    if args.minimal:
        keys_to_copy = ['pk.txt', 'sk.txt']
        print("Copying minimal key set (pk.txt, sk.txt)")
    else:
        keys_to_copy = ['pk.txt', 'msk.txt', 'sk.txt', 'k_sign.txt']
        print("Copying full key set")
    
    # Create backup if requested
    if args.backup:
        target_path = Path(args.target)
        backup_dir = target_path / 'key_backup'
        
        # Check if any key files exist in target
        existing_keys = [k for k in keys_to_copy if (target_path / k).exists()]
        
        if existing_keys:
            print(f"\nCreating backup of existing keys in {backup_dir}")
            backup_dir.mkdir(exist_ok=True)
            
            for key_file in existing_keys:
                source_file = target_path / key_file
                backup_file = backup_dir / key_file
                try:
                    shutil.copy2(source_file, backup_file)
                    print(f"  Backed up {key_file}")
                except Exception as e:
                    print(f"  Failed to backup {key_file}: {e}")
    
    # Copy the keys
    print(f"\nCopying keys from {args.source} to {args.target}")
    success = copy_keys_to_directory(args.source, args.target, keys_to_copy)
    
    if success:
        print("\n✓ Key distribution complete!")
        print("\nNext steps:")
        print("1. Start the node in the target directory")
        print("2. The node will use the copied keys instead of generating new ones")
    else:
        print("\n✗ Key distribution failed")
        sys.exit(1)

if __name__ == "__main__":
    main()