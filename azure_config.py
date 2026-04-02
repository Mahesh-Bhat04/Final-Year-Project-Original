"""
Azure configuration loader for Phase 2
Loads Azure credentials and Merkle settings from .env file.
"""
import os
from dotenv import load_dotenv

# Load .env
load_dotenv()


def get_azure_config():
    """Load Azure configuration from environment.

    Returns:
        dict with Azure and Merkle configuration values
    """
    return {
        'account_name': os.getenv('AZURE_STORAGE_ACCOUNT_NAME', ''),
        'account_key': os.getenv('AZURE_STORAGE_ACCOUNT_KEY', ''),
        'connection_string': os.getenv('AZURE_STORAGE_CONNECTION_STRING', ''),
        'container_name': os.getenv('AZURE_CONTAINER_NAME', 'encrypted-files'),
        'merkle_chunk_size': int(os.getenv('MERKLE_CHUNK_SIZE', '262144')),
        'merkle_hash_algorithm': os.getenv('MERKLE_HASH_ALGORITHM', 'sha256'),
    }


def validate_azure_config():
    """Validate that required Azure configuration is present.

    Returns:
        True if valid

    Raises:
        ValueError if required config is missing
    """
    required = ['AZURE_STORAGE_CONNECTION_STRING']
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise ValueError(f"Missing required Azure config: {', '.join(missing)}")
    return True
