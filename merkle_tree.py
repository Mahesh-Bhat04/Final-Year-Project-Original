"""
Merkle Tree Library for Phase 2
SHA-256 based Merkle tree construction, proof generation, and verification.
Used to verify integrity of files stored in Azure Blob Storage.
"""
import hashlib


class MerkleTree:
    """SHA-256 Merkle tree for data integrity verification"""

    def __init__(self, chunk_size=262144):
        """Initialize Merkle tree with configurable chunk size (default 256KB)."""
        self.chunk_size = chunk_size

    def chunk_data(self, data):
        """Split data into fixed-size chunks.

        Args:
            data: bytes or str to chunk

        Returns:
            list of bytes chunks
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        chunks = []
        for i in range(0, len(data), self.chunk_size):
            chunks.append(data[i:i + self.chunk_size])
        return chunks

    def hash_chunk(self, chunk):
        """SHA-256 hash of a single chunk"""
        return hashlib.sha256(chunk).hexdigest()

    def _hash_pair(self, left, right):
        """Hash two node hashes together"""
        combined = (left + right).encode('utf-8')
        return hashlib.sha256(combined).hexdigest()

    def build_tree(self, data):
        """Build Merkle tree from raw data bytes.

        Args:
            data: bytes to build tree from

        Returns:
            dict with root, leaves, levels, chunk_count
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        chunks = self.chunk_data(data)

        if not chunks:
            empty_hash = hashlib.sha256(b'').hexdigest()
            return {
                'root': empty_hash,
                'leaves': [],
                'levels': [[empty_hash]],
                'chunk_count': 0
            }

        # Level 0: leaf hashes
        leaves = [self.hash_chunk(chunk) for chunk in chunks]
        levels = [leaves[:]]

        # Build tree bottom-up
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # If odd number of nodes, duplicate last
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
                next_level.append(self._hash_pair(left, right))
            levels.append(next_level)
            current_level = next_level

        return {
            'root': current_level[0],
            'leaves': leaves,
            'levels': levels,
            'chunk_count': len(chunks)
        }

    def get_root(self, data):
        """Get just the Merkle root hash for data"""
        return self.build_tree(data)['root']

    def verify_root(self, data, expected_root):
        """Verify data integrity by rebuilding tree and comparing root.

        Args:
            data: bytes to verify
            expected_root: expected Merkle root hash

        Returns:
            bool: True if data is intact
        """
        actual_root = self.get_root(data)
        return actual_root == expected_root

    def get_proof(self, levels, leaf_index):
        """Get Merkle proof (authentication path) for a specific chunk.

        Args:
            levels: tree levels from build_tree()
            leaf_index: index of the chunk to prove

        Returns:
            list of (hash, direction) tuples
        """
        proof = []
        index = leaf_index

        for level in levels[:-1]:  # Skip root level
            if index % 2 == 0:  # Left node
                sibling_idx = index + 1
                if sibling_idx < len(level):
                    proof.append((level[sibling_idx], 'right'))
                else:
                    proof.append((level[index], 'right'))  # Duplicate
            else:  # Right node
                proof.append((level[index - 1], 'left'))
            index = index // 2

        return proof

    def verify_proof(self, leaf_hash, proof, expected_root):
        """Verify a Merkle proof for a single chunk.

        Args:
            leaf_hash: SHA-256 hash of the chunk
            proof: list of (hash, direction) tuples from get_proof()
            expected_root: expected Merkle root

        Returns:
            bool: True if proof is valid
        """
        current = leaf_hash

        for sibling_hash, direction in proof:
            if direction == 'right':
                current = self._hash_pair(current, sibling_hash)
            else:
                current = self._hash_pair(sibling_hash, current)

        return current == expected_root
