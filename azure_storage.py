"""
Azure Blob Storage integration for Phase 2
Upload/download encrypted files to/from Azure Blob Storage.
"""
import os
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import AzureError
from dotenv import load_dotenv

# Load .env
load_dotenv()


class AzureStorage:
    """Azure Blob Storage wrapper for encrypted file storage"""

    def __init__(self):
        conn_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
        if not conn_str:
            raise ValueError("AZURE_STORAGE_CONNECTION_STRING not found in environment. "
                             "Please create .env file with Azure credentials.")

        self.container_name = os.getenv('AZURE_CONTAINER_NAME', 'encrypted-files')
        self.account_name = os.getenv('AZURE_STORAGE_ACCOUNT_NAME', '')
        self.client = BlobServiceClient.from_connection_string(conn_str)

    def upload_blob(self, blob_name, data):
        """Upload data to Azure Blob Storage.

        Args:
            blob_name: Name of the blob (e.g., 'abc123.json')
            data: bytes or str to upload

        Returns:
            str: blob_name for reference
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        try:
            blob_client = self.client.get_blob_client(
                container=self.container_name,
                blob=blob_name
            )
            blob_client.upload_blob(data, overwrite=True)
            print(f"[OK] Uploaded to Azure: {blob_name} ({len(data)} bytes)")
            return blob_name
        except AzureError as e:
            print(f"[ERROR] Azure upload failed: {e}")
            raise

    def download_blob(self, blob_name):
        """Download blob data from Azure.

        Args:
            blob_name: Name of the blob

        Returns:
            bytes: Downloaded data
        """
        try:
            blob_client = self.client.get_blob_client(
                container=self.container_name,
                blob=blob_name
            )
            data = blob_client.download_blob().readall()
            print(f"[OK] Downloaded from Azure: {blob_name} ({len(data)} bytes)")
            return data
        except AzureError as e:
            print(f"[ERROR] Azure download failed: {e}")
            raise

    def blob_exists(self, blob_name):
        """Check if a blob exists"""
        try:
            blob_client = self.client.get_blob_client(
                container=self.container_name,
                blob=blob_name
            )
            return blob_client.exists()
        except AzureError:
            return False

    def delete_blob(self, blob_name):
        """Delete a blob"""
        try:
            blob_client = self.client.get_blob_client(
                container=self.container_name,
                blob=blob_name
            )
            blob_client.delete_blob()
            print(f"[OK] Deleted blob: {blob_name}")
        except AzureError as e:
            print(f"[ERROR] Azure delete failed: {e}")
            raise
