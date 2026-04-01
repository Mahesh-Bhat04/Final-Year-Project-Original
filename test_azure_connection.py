"""
Azure Blob Storage Connection Test
Run this to verify Azure credentials are configured correctly.

Usage:
    python3 test_azure_connection.py
"""

import os
import sys
import hashlib
from datetime import datetime

from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import AzureError
from dotenv import load_dotenv

# Load .env file
load_dotenv()


def test_azure_connection():
    """Test Azure Blob Storage connection and basic operations"""

    print("=" * 70)
    print("Azure Blob Storage Connection Test")
    print("=" * 70)
    print()

    # Step 1: Load credentials
    print("[1/6] Loading Azure credentials...")
    connection_string = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
    container_name = os.getenv('AZURE_CONTAINER_NAME', 'encrypted-files')

    if not connection_string:
        print("[FAIL] AZURE_STORAGE_CONNECTION_STRING not found in .env file")
        print("Please create .env file with your Azure credentials")
        return False

    print(f"[OK] Credentials loaded (container: {container_name})")
    print()

    # Step 2: Connect to Azure
    print("[2/6] Connecting to Azure Blob Storage...")
    try:
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        print("[OK] Connected successfully")
    except AzureError as e:
        print(f"[FAIL] Connection failed: {e}")
        return False
    print()

    # Step 3: Verify container exists
    print(f"[3/6] Verifying container '{container_name}'...")
    try:
        container_client = blob_service_client.get_container_client(container_name)
        if not container_client.exists():
            print(f"[FAIL] Container '{container_name}' does not exist")
            print("Create it in Azure Portal: Storage Account -> Containers -> + Container")
            return False
        print("[OK] Container exists")
    except AzureError as e:
        print(f"[FAIL] {e}")
        return False
    print()

    # Step 4: Test upload
    print("[4/6] Testing blob upload...")
    test_data = f"Test upload at {datetime.now().isoformat()}".encode('utf-8')
    test_blob_name = f"test/connection_test_{hashlib.md5(test_data).hexdigest()[:8]}.txt"

    try:
        blob_client = blob_service_client.get_blob_client(
            container=container_name,
            blob=test_blob_name
        )
        blob_client.upload_blob(test_data, overwrite=True)
        print(f"[OK] Uploaded test blob: {test_blob_name}")
    except AzureError as e:
        print(f"[FAIL] Upload failed: {e}")
        return False
    print()

    # Step 5: Test download
    print("[5/6] Testing blob download...")
    try:
        downloaded_data = blob_client.download_blob().readall()
        if downloaded_data == test_data:
            print("[OK] Downloaded and verified - data matches")
        else:
            print("[FAIL] Data mismatch after download")
            return False
    except AzureError as e:
        print(f"[FAIL] Download failed: {e}")
        return False
    print()

    # Step 6: Test delete
    print("[6/6] Cleaning up test blob...")
    try:
        blob_client.delete_blob()
        print("[OK] Deleted successfully")
    except AzureError as e:
        print(f"[FAIL] Delete failed: {e}")
        return False
    print()

    print("=" * 70)
    print("[OK] All tests passed! Azure connection is working!")
    print("=" * 70)
    print()
    print("You can now proceed with Phase 2 implementation.")
    return True


if __name__ == "__main__":
    if not test_azure_connection():
        print("\nTest failed. Please fix the errors above and retry.")
        sys.exit(1)
    sys.exit(0)
