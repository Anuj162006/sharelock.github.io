"""
Encryption utilities for secure share storage and transmission.
"""

import secrets
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64
import json


class ShareEncryption:
    """
    Handles encryption and decryption of shares.
    """
    
    @staticmethod
    def encrypt_share(share_id: int, share_value: int, encryption_key: str) -> str:
        """
        Encrypt a share value using AES-GCM.
        
        Args:
            share_id: Share identifier
            share_value: Share value to encrypt
            encryption_key: Encryption key (hex string)
            
        Returns:
            Base64-encoded encrypted share with metadata
        """
        key = bytes.fromhex(encryption_key)
        nonce = secrets.token_bytes(12)
        
        # Prepare share data
        share_data = {
            'id': share_id,
            'value': share_value
        }
        share_json = json.dumps(share_data).encode('utf-8')
        
        # Encrypt
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, share_json, None)
        
        # Combine nonce and ciphertext
        encrypted = nonce + ciphertext
        
        # Return base64-encoded
        return base64.b64encode(encrypted).decode('utf-8')
    
    @staticmethod
    def decrypt_share(encrypted_share: str, encryption_key: str) -> Tuple[int, int]:
        """
        Decrypt a share.
        
        Args:
            encrypted_share: Base64-encoded encrypted share
            encryption_key: Encryption key (hex string)
            
        Returns:
            Tuple of (share_id, share_value)
        """
        key = bytes.fromhex(encryption_key)
        
        # Decode from base64
        encrypted = base64.b64decode(encrypted_share.encode('utf-8'))
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        
        # Decrypt
        aesgcm = AESGCM(key)
        share_json = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Parse JSON
        share_data = json.loads(share_json.decode('utf-8'))
        
        return share_data['id'], share_data['value']
    
    @staticmethod
    def generate_key() -> str:
        """
        Generate a random encryption key.
        
        Returns:
            Hex-encoded 32-byte key
        """
        return secrets.token_hex(32)
    
    @staticmethod
    def derive_key_from_secret(secret: str, salt: Optional[str] = None) -> str:
        """
        Derive an encryption key from a secret using PBKDF2.
        
        Args:
            secret: Secret string
            salt: Optional salt (generated if not provided)
            
        Returns:
            Hex-encoded derived key
        """
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 to derive key
        key = hashlib.pbkdf2_hmac('sha256', secret.encode('utf-8'), 
                                  salt.encode('utf-8'), 100000, 32)
        return key.hex()

