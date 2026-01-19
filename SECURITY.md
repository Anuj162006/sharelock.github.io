# Security Documentation

## Security Features

### 1. Shamir's Secret Sharing
- **Threshold Cryptography**: Secrets are split using Shamir's Secret Sharing algorithm
- **Collusion Resistance**: No single person can reconstruct the secret alone
- **Mathematical Security**: Based on polynomial interpolation over finite fields

### 2. Encryption
- **AES-GCM Encryption**: All shares are encrypted using AES-GCM (Authenticated Encryption)
- **Key Derivation**: Secure key generation using cryptographically secure random number generation
- **Separate Key Storage**: Encryption keys are stored separately from encrypted data

### 3. Access Control
- **Session Management**: Secure session tokens for user authentication
- **Share Access Control**: Granular access control for individual shares
- **Session Expiration**: Automatic session expiration after 24 hours of inactivity

### 4. Secure Communication
- **HTTPS Recommended**: Use HTTPS in production to encrypt data in transit
- **CORS Protection**: Cross-Origin Resource Sharing configured for security
- **Input Validation**: All inputs are validated and sanitized

## Security Best Practices

### For Users

1. **Master Key Storage**
   - Store the master key securely (password manager, hardware security module)
   - Never share the master key with share holders
   - Consider splitting the master key using the same system

2. **Share Distribution**
   - Distribute shares through secure channels
   - Verify share recipients' identities
   - Use different communication channels for different shares

3. **Share Storage**
   - Store shares in secure locations
   - Consider encrypting shares with additional passwords
   - Use hardware security modules for critical secrets

4. **Threshold Selection**
   - Choose appropriate threshold (k) based on trust model
   - Balance between security and availability
   - Consider recovery scenarios

### For Administrators

1. **Environment Variables**
   - Set strong SECRET_KEY in production
   - Use secure session cookies (SESSION_COOKIE_SECURE=True)
   - Enable HTTP-only cookies

2. **Database Security**
   - Use encrypted database connections
   - Implement proper access controls
   - Regular security audits

3. **Network Security**
   - Deploy behind reverse proxy (nginx, Apache)
   - Use HTTPS/TLS encryption
   - Implement rate limiting
   - Use firewall rules

4. **Monitoring**
   - Log all secret operations
   - Monitor for suspicious activity
   - Implement alerting for failed reconstruction attempts

## Threat Model

### Addressed Threats

1. **Password Loss**: Threshold system ensures recovery even if some shares are lost
2. **Unauthorized Access**: No single person can access the secret
3. **Coercion Attacks**: Requires multiple trusted parties to reconstruct
4. **Data Breach**: Encrypted shares protect against database breaches

### Limitations

1. **Master Key Compromise**: If master key is compromised, all shares can be decrypted
2. **Threshold Compromise**: If k or more share holders collude, secret can be reconstructed
3. **Key Storage**: Security depends on secure storage of master key
4. **Network Attacks**: Requires HTTPS for protection against man-in-the-middle attacks

## Implementation Security

### Cryptographic Primitives

- **Finite Field**: Uses prime 2^127 - 1 (Mersenne prime)
- **Random Generation**: Uses `secrets` module (cryptographically secure)
- **Encryption**: AES-GCM with 256-bit keys
- **Key Derivation**: SHA-256 for key derivation

### Code Security

- Input validation on all endpoints
- Error handling without information leakage
- Secure random number generation
- No hardcoded secrets or keys

## Compliance Considerations

- **GDPR**: Consider data retention policies for shares
- **HIPAA**: May require additional encryption for healthcare data
- **PCI-DSS**: Additional requirements for payment card data
- **SOC 2**: Audit logging and access controls

## Security Updates

Regularly update dependencies:
```bash
pip list --outdated
pip install --upgrade <package>
```

Monitor security advisories for:
- Flask
- cryptography
- pycryptodome

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:
1. Do not disclose publicly
2. Contact the maintainers privately
3. Provide detailed information about the vulnerability
4. Allow time for patching before disclosure


