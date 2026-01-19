"""
Additional security utilities and validations.
"""

import re
import hashlib
from typing import Optional, Tuple
import secrets


class SecurityValidator:
    """
    Validates inputs and implements security checks.
    """
    
    @staticmethod
    def validate_secret(secret: str, min_length: int = 1, max_length: int = 10000) -> Tuple[bool, Optional[str]]:
        """
        Validate secret input.
        
        Args:
            secret: Secret to validate
            min_length: Minimum length
            max_length: Maximum length
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not secret:
            return False, "Secret cannot be empty"
        
        if len(secret) < min_length:
            return False, f"Secret must be at least {min_length} characters"
        
        if len(secret) > max_length:
            return False, f"Secret must be at most {max_length} characters"
        
        # Check for null bytes
        if '\x00' in secret:
            return False, "Secret cannot contain null bytes"
        
        return True, None
    
    @staticmethod
    def validate_shamir_params(n: int, k: int) -> Tuple[bool, Optional[str]]:
        """
        Validate Shamir's Secret Sharing parameters.
        
        Args:
            n: Total number of shares
            k: Threshold
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(n, int) or not isinstance(k, int):
            return False, "n and k must be integers"
        
        if n < 2:
            return False, "n must be at least 2"
        
        if k < 2:
            return False, "k must be at least 2"
        
        if k > n:
            return False, "k cannot be greater than n"
        
        if n > 100:
            return False, "n cannot exceed 100 (security limit)"
        
        return True, None
    
    @staticmethod
    def validate_master_key(key: str) -> Tuple[bool, Optional[str]]:
        """
        Validate master key format.
        
        Args:
            key: Master key to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not key:
            return False, "Master key cannot be empty"
        
        # Master key should be hex-encoded (64 characters for 32 bytes)
        if len(key) != 64:
            return False, "Master key must be 64 hexadecimal characters"
        
        try:
            bytes.fromhex(key)
        except ValueError:
            return False, "Master key must be valid hexadecimal"
        
        return True, None
    
    @staticmethod
    def sanitize_user_input(input_str: str, max_length: int = 1000) -> str:
        """
        Sanitize user input to prevent injection attacks.
        
        Args:
            input_str: Input string to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
        """
        if not input_str:
            return ""
        
        # Remove null bytes
        sanitized = input_str.replace('\x00', '')
        
        # Truncate if too long
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized


class RateLimiter:
    """
    Simple rate limiting implementation.
    """
    
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests per window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}  # client_id -> list of timestamps
    
    def is_allowed(self, client_id: str) -> bool:
        """
        Check if request is allowed.
        
        Args:
            client_id: Client identifier (IP address, user ID, etc.)
            
        Returns:
            True if allowed, False if rate limited
        """
        import time
        current_time = time.time()
        
        if client_id not in self.requests:
            self.requests[client_id] = []
        
        # Remove old requests outside window
        self.requests[client_id] = [
            ts for ts in self.requests[client_id]
            if current_time - ts < self.window_seconds
        ]
        
        # Check if limit exceeded
        if len(self.requests[client_id]) >= self.max_requests:
            return False
        
        # Record this request
        self.requests[client_id].append(current_time)
        return True


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure token.
    
    Args:
        length: Token length in bytes
        
    Returns:
        Hex-encoded token
    """
    return secrets.token_hex(length)


def hash_secret(secret: str) -> str:
    """
    Hash a secret for storage/verification (one-way).
    
    Args:
        secret: Secret to hash
        
    Returns:
        SHA-256 hash (hex-encoded)
    """
    return hashlib.sha256(secret.encode('utf-8')).hexdigest()

