# Usage Examples

## Basic Workflow

### 1. Split a Secret

**Request:**
```bash
curl -X POST http://localhost:5000/api/split \
  -H "Content-Type: application/json" \
  -d '{
    "secret": "MySuperSecretPassword123!",
    "n": 5,
    "k": 3,
    "user_id": "alice"
  }'
```

**Response:**
```json
{
  "secret_id": "a1b2c3d4e5f6...",
  "master_key": "0123456789abcdef...",
  "shares": [
    {
      "share_id": 1,
      "encrypted_share": "base64_encoded_share_1"
    },
    {
      "share_id": 2,
      "encrypted_share": "base64_encoded_share_2"
    },
    ...
  ],
  "n": 5,
  "k": 3,
  "message": "Secret split into 5 shares (threshold: 3)"
}
```

### 2. Reconstruct a Secret

**Request:**
```bash
curl -X POST http://localhost:5000/api/reconstruct \
  -H "Content-Type: application/json" \
  -d '{
    "secret_id": "a1b2c3d4e5f6...",
    "master_key": "0123456789abcdef...",
    "shares": [
      {"share_id": 1, "encrypted_share": "..."},
      {"share_id": 2, "encrypted_share": "..."},
      {"share_id": 3, "encrypted_share": "..."}
    ]
  }'
```

**Response:**
```json
{
  "secret": "MySuperSecretPassword123!",
  "message": "Secret reconstructed successfully",
  "shares_used": 3
}
```

### 3. Verify Shares

**Request:**
```bash
curl -X POST http://localhost:5000/api/verify \
  -H "Content-Type: application/json" \
  -d '{
    "master_key": "0123456789abcdef...",
    "shares": [
      {"share_id": 1, "encrypted_share": "..."},
      {"share_id": 2, "encrypted_share": "..."}
    ]
  }'
```

**Response:**
```json
{
  "valid_shares": [1, 2],
  "invalid_shares": [],
  "total_valid": 2
}
```

## Web Interface

1. Start the server:
   ```bash
   python app.py
   ```

2. Open your browser to `http://localhost:5000`

3. Use the tabs to:
   - **Split Secret**: Create shares from a secret
   - **Reconstruct Secret**: Recover a secret from shares
   - **Verify Shares**: Check if shares are valid

## Security Best Practices

### Share Distribution

1. **Physical Distribution**
   - Give Share 1 to Alice (in person)
   - Give Share 2 to Bob (via encrypted email)
   - Give Share 3 to Charlie (via secure messaging)
   - Give Share 4 to David (stored in safe)
   - Give Share 5 to Eve (backup location)

2. **Master Key Storage**
   - Store master key in a password manager
   - Consider splitting the master key itself
   - Use hardware security module for critical secrets
   - Never store master key with shares

3. **Threshold Selection**
   - For 5 shares, threshold of 3 is common
   - Balance security (higher k) vs. availability (lower k)
   - Consider recovery scenarios (what if 2 people are unavailable?)

### Example Scenarios

#### Scenario 1: Company Password Recovery
- **Secret**: Master password for company vault
- **n = 7**: 7 executives
- **k = 4**: Requires 4 executives to recover
- **Distribution**: Each executive gets one share
- **Master Key**: Stored in company safe with legal documents

#### Scenario 2: Personal Password Backup
- **Secret**: Personal password manager master password
- **n = 5**: 5 trusted family members/friends
- **k = 3**: Requires 3 people to recover
- **Distribution**: 
  - Share 1: Spouse
  - Share 2: Sibling
  - Share 3: Close friend
  - Share 4: Lawyer
  - Share 5: Safe deposit box
- **Master Key**: Stored in personal safe

#### Scenario 3: API Key Protection
- **Secret**: Production API key
- **n = 4**: 4 team leads
- **k = 2**: Requires 2 leads to recover
- **Distribution**: Each lead gets one share
- **Master Key**: Encrypted in version control (separate from shares)

## Python API Usage

```python
import requests

# Split a secret
response = requests.post('http://localhost:5000/api/split', json={
    'secret': 'MySecretPassword',
    'n': 5,
    'k': 3,
    'user_id': 'user1'
})
data = response.json()
secret_id = data['secret_id']
master_key = data['master_key']
shares = data['shares']

# Reconstruct secret (need at least k shares)
response = requests.post('http://localhost:5000/api/reconstruct', json={
    'secret_id': secret_id,
    'master_key': master_key,
    'shares': shares[:3]  # Use first 3 shares
})
reconstructed = response.json()['secret']
print(f"Reconstructed: {reconstructed}")
```

## Error Handling

Common errors and solutions:

1. **"Rate limit exceeded"**: Too many requests. Wait 60 seconds.
2. **"k cannot be greater than n"**: Fix threshold parameters.
3. **"Need at least k shares"**: Provide more shares.
4. **"Failed to decrypt share"**: Invalid master key or corrupted share.
5. **"Secret not found"**: Invalid secret_id.

## Advanced Usage

### Splitting the Master Key

You can also split the master key itself:

```python
# First split: Create shares for the secret
# Second split: Split the master_key using the same system
# This creates a two-level security system
```

### Share Verification Before Distribution

Always verify shares before distributing:

```python
# Verify all shares are valid
response = requests.post('http://localhost:5000/api/verify', json={
    'master_key': master_key,
    'shares': all_shares
})
```


