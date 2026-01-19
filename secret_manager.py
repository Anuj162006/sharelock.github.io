"""
Improved secret management that properly handles string secrets.
Uses encryption + key splitting approach.
"""

import secrets
import hashlib
from typing import List, Tuple, Dict, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
from backend.shamir import ShamirSecretSharing


class SecretManager:
    """
    Manages secrets using encryption + Shamir's Secret Sharing for the key.
    This allows perfect reconstruction of string secrets.
    """
    
    def __init__(self):
        self.sss = ShamirSecretSharing()
    
    def split_secret(self, secret: str, n: int, k: int) -> Tuple[List[Dict], str, str]:
        """
        Split a secret into n shares using encryption + key splitting.
        
        Args:
            secret: The secret string to split
            n: Total number of shares
            k: Threshold (minimum shares needed)
            
        Returns:
            Tuple of (shares, master_key, encrypted_secret)
            - shares: List of share dictionaries
            - master_key: Master encryption key (store securely)
            - encrypted_secret: Encrypted secret (can be stored publicly)
        """
        # Generate encryption key
        encryption_key = secrets.token_bytes(32)
        
        # Encrypt the secret
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(encryption_key)
        ciphertext = aesgcm.encrypt(nonce, secret.encode('utf-8'), None)
        encrypted_secret = base64.b64encode(nonce + ciphertext).decode('utf-8')
        
        # Convert encryption key to integer for Shamir's
        key_int = int.from_bytes(encryption_key, 'big') % self.sss.prime
        
        # Split the encryption key using Shamir's
        coeffs = [key_int]
        for _ in range(k - 1):
            coeffs.append(secrets.randbelow(self.sss.prime))
        
        # Generate n shares of the key
        shares = []
        for i in range(1, n + 1):
            y = self.sss._eval_poly(coeffs, i)
            shares.append({
                'share_id': i,
                'key_share': y
            })
        
        # Master key is the hex representation of encryption key
        master_key = encryption_key.hex()
        
        return shares, master_key, encrypted_secret
    
    def reconstruct_secret(self, shares: List[Dict], encrypted_secret: str, 
                          master_key: Optional[str] = None) -> str:
        """
        Reconstruct a secret from shares.
        
        Args:
            shares: List of share dictionaries with share_id and key_share
            encrypted_secret: The encrypted secret
            master_key: Optional master key (if provided, skips reconstruction)
            
        Returns:
            Reconstructed secret string
        """
        if master_key:
            # Use provided master key directly
            encryption_key = bytes.fromhex(master_key)
        else:
            # Reconstruct encryption key from shares
            share_tuples = [(s['share_id'], s['key_share']) for s in shares]
            key_int = self.sss._lagrange_interpolate(0, share_tuples)
            
            # Convert back to bytes (pad to 32 bytes)
            encryption_key = key_int.to_bytes(32, 'big')
        
        # Decrypt the secret
        encrypted_bytes = base64.b64decode(encrypted_secret.encode('utf-8'))
        nonce = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]
        
        aesgcm = AESGCM(encryption_key)
        secret_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        return secret_bytes.decode('utf-8')

