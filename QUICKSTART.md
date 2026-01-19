# Quick Start Guide

## Installation

1. **Create virtual environment** (recommended):
   ```bash
   python -m venv venv
   venv\Scripts\activate  # Windows
   # or
   source venv/bin/activate  # Linux/Mac
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Open in browser**:
   ```
   http://localhost:5000
   ```

## First Steps

### 1. Split Your First Secret

1. Go to the "Split Secret" tab
2. Enter a secret/password
3. Set:
   - **Total Shares (n)**: 5
   - **Threshold (k)**: 3
4. Click "Split Secret"
5. **IMPORTANT**: Save the Master Key and Secret ID securely!
6. Distribute the shares to trusted individuals

### 2. Reconstruct a Secret

1. Go to the "Reconstruct Secret" tab
2. Enter:
   - Secret ID
   - Master Key
   - At least k shares (in JSON format)
3. Click "Reconstruct Secret"
4. Your secret will be displayed

### 3. Verify Shares

1. Go to the "Verify Shares" tab
2. Enter Master Key and shares
3. Click "Verify Shares"
4. Check which shares are valid

## Example Workflow

```
1. Alice wants to protect her password: "MyPassword123!"
   - Creates 5 shares with threshold 3
   - Gets: secret_id, master_key, and 5 encrypted shares

2. Alice distributes shares:
   - Share 1 → Bob (in person)
   - Share 2 → Charlie (encrypted email)
   - Share 3 → David (secure messaging)
   - Share 4 → Safe deposit box
   - Share 5 → Lawyer's office

3. Alice stores master_key in password manager

4. Later, Alice forgets password:
   - Collects shares from Bob, Charlie, and David
   - Uses master_key and 3 shares to reconstruct
   - Recovers: "MyPassword123!"
```

## Security Checklist

- [ ] Use HTTPS in production
- [ ] Set strong SECRET_KEY in environment
- [ ] Store master_key securely (password manager)
- [ ] Distribute shares through secure channels
- [ ] Verify shares before distribution
- [ ] Choose appropriate threshold (k)
- [ ] Never store master_key with shares
- [ ] Consider splitting master_key itself

## Troubleshooting

**Port already in use?**
```bash
# Change port in app.py or use:
python app.py --port 5001
```

**Module not found?**
```bash
# Make sure virtual environment is activated
# Reinstall dependencies:
pip install -r requirements.txt
```

**CORS errors?**
- Make sure Flask-CORS is installed
- Check browser console for details

## Next Steps

- Read [README.md](README.md) for full documentation
- Read [SECURITY.md](SECURITY.md) for security best practices
- Read [USAGE_EXAMPLE.md](USAGE_EXAMPLE.md) for detailed examples


