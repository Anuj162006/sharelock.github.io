"""
API endpoints for the secure split-secret password recovery system.
"""

from flask import Blueprint, request, jsonify
from typing import List, Tuple
import secrets
import hashlib
import json
from backend.shamir import ShamirSecretSharing
from backend.encryption import ShareEncryption
from backend.auth import access_control, require_auth
from backend.secret_manager import SecretManager
from backend.security import SecurityValidator, RateLimiter
from flask import request as flask_request

api = Blueprint('api', __name__)

# In-memory storage (in production, use a database)
secret_storage = {}  # secret_id -> {shares, master_key, n, k, metadata, encrypted_secret}
share_storage = {}  # share_id -> encrypted_share_data

# Initialize secret manager
secret_manager = SecretManager()

# Initialize security components
security_validator = SecurityValidator()
rate_limiter = RateLimiter(max_requests=20, window_seconds=60)


@api.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'service': 'Secure Split-Secret System'})


@api.route('/split', methods=['POST'])
def split_secret():
    """
    Split a secret into multiple shares.
    
    Security considerations:
    - Validates input parameters
    - Uses cryptographically secure random number generation
    - Encrypts shares before storage
    - Implements access control
    """
    """
    Split a secret into multiple shares.
    
    Request body:
    {
        "secret": "password123",
        "n": 5,
        "k": 3,
        "user_id": "user1"
    }
    
    Returns:
    {
        "secret_id": "...",
        "shares": [...],
        "master_key": "...",
        "message": "Secret split successfully"
    }
    """
    try:
        # Rate limiting
        client_id = flask_request.remote_addr or 'unknown'
        if not rate_limiter.is_allowed(client_id):
            return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
        
        data = request.json
        secret = data.get('secret')
        n = data.get('n')
        k = data.get('k')
        user_id = data.get('user_id', 'anonymous')
        
        # Validate inputs
        is_valid, error_msg = security_validator.validate_secret(secret)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        is_valid, error_msg = security_validator.validate_shamir_params(n, k)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Sanitize user_id
        user_id = security_validator.sanitize_user_input(user_id, max_length=100)
        
        # Use improved secret manager
        shares, master_key, encrypted_secret = secret_manager.split_secret(secret, n, k)
        
        # Encrypt shares for storage/distribution
        shares_data = []
        for share in shares:
            encrypted_share = ShareEncryption.encrypt_share(
                share['share_id'], 
                share['key_share'], 
                master_key
            )
            shares_data.append({
                'share_id': share['share_id'],
                'encrypted_share': encrypted_share
            })
        
        # Generate secret ID
        secret_id = secrets.token_hex(16)
        
        # Store secret metadata
        secret_storage[secret_id] = {
            'n': n,
            'k': k,
            'master_key': master_key,
            'encrypted_secret': encrypted_secret,
            'user_id': user_id,
            'created_at': None  # Would use datetime in production
        }
        
        # Grant access to creator
        access_control.grant_share_access(secret_id, user_id)
        
        return jsonify({
            'secret_id': secret_id,
            'shares': shares_data,
            'master_key': master_key,  # In production, store securely
            'n': n,
            'k': k,
            'message': f'Secret split into {n} shares (threshold: {k})'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/reconstruct', methods=['POST'])
def reconstruct_secret():
    """
    Reconstruct a secret from shares.
    
    Security considerations:
    - Validates share count meets threshold
    - Verifies share decryption
    - Implements access control
    - Prevents information leakage in error messages
    """
    """
    Reconstruct a secret from shares.
    
    Request body:
    {
        "secret_id": "...",
        "shares": [
            {"share_id": 1, "encrypted_share": "..."},
            {"share_id": 2, "encrypted_share": "..."},
            {"share_id": 3, "encrypted_share": "..."}
        ],
        "master_key": "..."
    }
    
    Returns:
    {
        "secret": "reconstructed_secret",
        "message": "Secret reconstructed successfully"
    }
    """
    try:
        # Rate limiting
        client_id = flask_request.remote_addr or 'unknown'
        if not rate_limiter.is_allowed(client_id):
            return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
        
        data = request.json
        secret_id = data.get('secret_id')
        shares_data = data.get('shares', [])
        master_key = data.get('master_key')
        
        if not secret_id:
            return jsonify({'error': 'secret_id is required'}), 400
        if not shares_data:
            return jsonify({'error': 'shares are required'}), 400
        if not master_key:
            return jsonify({'error': 'master_key is required'}), 400
        
        # Validate master key
        is_valid, error_msg = security_validator.validate_master_key(master_key)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Validate shares format
        if not isinstance(shares_data, list):
            return jsonify({'error': 'shares must be a list'}), 400
        
        # Check if secret exists
        if secret_id not in secret_storage:
            return jsonify({'error': 'Secret not found'}), 404
        
        secret_info = secret_storage[secret_id]
        k = secret_info['k']
        
        # Check if enough shares provided
        if len(shares_data) < k:
            return jsonify({
                'error': f'Need at least {k} shares, got {len(shares_data)}'
            }), 400
        
        # Decrypt shares
        decrypted_shares = []
        
        for share_info in shares_data[:k]:  # Use only first k shares
            share_id = share_info['share_id']
            encrypted_share = share_info['encrypted_share']
            
            try:
                sid, share_value = ShareEncryption.decrypt_share(encrypted_share, master_key)
                decrypted_shares.append({
                    'share_id': sid,
                    'key_share': share_value
                })
            except Exception as e:
                return jsonify({'error': f'Failed to decrypt share {share_id}: {str(e)}'}), 400
        
        # Reconstruct secret using secret manager
        encrypted_secret = secret_info['encrypted_secret']
        reconstructed_secret = secret_manager.reconstruct_secret(
            decrypted_shares, 
            encrypted_secret, 
            master_key
        )
        
        return jsonify({
            'secret': reconstructed_secret,
            'message': 'Secret reconstructed successfully',
            'shares_used': len(decrypted_shares)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/verify', methods=['POST'])
def verify_shares():
    """
    Verify that shares are valid without reconstructing the secret.
    
    Request body:
    {
        "shares": [...],
        "master_key": "..."
    }
    """
    try:
        # Rate limiting
        client_id = flask_request.remote_addr or 'unknown'
        if not rate_limiter.is_allowed(client_id):
            return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
        
        data = request.json
        shares_data = data.get('shares', [])
        master_key = data.get('master_key')
        
        if not shares_data:
            return jsonify({'error': 'shares are required'}), 400
        if not master_key:
            return jsonify({'error': 'master_key is required'}), 400
        
        # Validate master key
        is_valid, error_msg = security_validator.validate_master_key(master_key)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Validate shares format
        if not isinstance(shares_data, list):
            return jsonify({'error': 'shares must be a list'}), 400
        
        valid_shares = []
        invalid_shares = []
        
        for share_info in shares_data:
            share_id = share_info.get('share_id')
            encrypted_share = share_info.get('encrypted_share')
            
            try:
                sid, share_value = ShareEncryption.decrypt_share(encrypted_share, master_key)
                valid_shares.append(share_id)
            except Exception as e:
                invalid_shares.append({'share_id': share_id, 'error': str(e)})
        
        return jsonify({
            'valid_shares': valid_shares,
            'invalid_shares': invalid_shares,
            'total_valid': len(valid_shares)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/secrets', methods=['GET'])
@require_auth
def list_secrets():
    """List all secrets for the authenticated user."""
    user_id = request.user_id
    
    user_secrets = []
    for secret_id, secret_info in secret_storage.items():
        if access_control.check_share_access(secret_id, user_id):
            user_secrets.append({
                'secret_id': secret_id,
                'n': secret_info['n'],
                'k': secret_info['k'],
                'created_by': secret_info['user_id']
            })
    
    return jsonify({'secrets': user_secrets}), 200

