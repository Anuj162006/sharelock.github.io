"""
Authentication and access control module.
"""

import hashlib
import secrets
import time
from typing import Optional, Dict
from functools import wraps
from flask import request, session, jsonify


class AccessControl:
    """
    Handles access control and session management.
    """
    
    def __init__(self):
        self.sessions: Dict[str, Dict] = {}
        self.share_access: Dict[str, set] = {}  # secret_id -> set of user_ids
    
    def create_session(self, user_id: str) -> str:
        """
        Create a new session for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Session token
        """
        session_token = secrets.token_hex(32)
        self.sessions[session_token] = {
            'user_id': user_id,
            'created_at': time.time(),
            'last_activity': time.time()
        }
        return session_token
    
    def validate_session(self, session_token: str) -> Optional[str]:
        """
        Validate a session token.
        
        Args:
            session_token: Session token to validate
            
        Returns:
            User ID if valid, None otherwise
        """
        if session_token not in self.sessions:
            return None
        
        session_data = self.sessions[session_token]
        
        # Check if session expired (24 hours)
        if time.time() - session_data['last_activity'] > 86400:
            del self.sessions[session_token]
            return None
        
        # Update last activity
        session_data['last_activity'] = time.time()
        
        return session_data['user_id']
    
    def revoke_session(self, session_token: str):
        """Revoke a session."""
        if session_token in self.sessions:
            del self.sessions[session_token]
    
    def grant_share_access(self, secret_id: str, user_id: str):
        """Grant a user access to a share."""
        if secret_id not in self.share_access:
            self.share_access[secret_id] = set()
        self.share_access[secret_id].add(user_id)
    
    def check_share_access(self, secret_id: str, user_id: str) -> bool:
        """Check if a user has access to a share."""
        return secret_id in self.share_access and user_id in self.share_access[secret_id]
    
    def revoke_share_access(self, secret_id: str, user_id: str):
        """Revoke a user's access to a share."""
        if secret_id in self.share_access:
            self.share_access[secret_id].discard(user_id)


# Global access control instance
access_control = AccessControl()


def require_auth(f):
    """
    Decorator to require authentication for API endpoints.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.headers.get('Authorization') or request.json.get('session_token')
        
        if not session_token:
            return jsonify({'error': 'Authentication required'}), 401
        
        user_id = access_control.validate_session(session_token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        # Add user_id to request context
        request.user_id = user_id
        return f(*args, **kwargs)
    
    return decorated_function


