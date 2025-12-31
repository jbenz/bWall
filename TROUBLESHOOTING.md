# Troubleshooting Guide

## Dashboard Not Working / Sidebar Links Not Responding

### Step 1: Check Browser Console

1. Open the dashboard in your browser
2. Press **F12** (or Right-click → Inspect)
3. Go to the **Console** tab
4. Look for errors (red text)

**Common errors to check:**
- `GET .../app.js 404` - JavaScript file not loading
- `Failed to fetch` - API endpoints not accessible
- `CORS error` - Cross-origin request blocked
- `TypeError` - JavaScript errors

### Step 2: Check Network Tab

1. In browser DevTools, go to **Network** tab
2. Refresh the page (F5)
3. Look for:
   - `app.js` - Should return **200 OK** (not 404)
   - `api/stats` - Should return **200 OK** (not 401/403)
   - `api/auth/user` - Should return **200 OK**

### Step 3: Check Flask Server Logs

Look at the terminal where you ran `./start_bwall.sh` for:
- Error messages
- Route access logs
- File not found errors

### Step 4: Verify Files Exist

On the server, run:
```bash
cd ~/bWall
ls -la app.js index.html
```

Both files should exist and be readable.

### Step 5: Test API Endpoints Directly

Test if the API is working:
```bash
# Test stats endpoint
curl http://localhost:5000/api/stats

# Test auth endpoint
curl http://localhost:5000/api/auth/user

# Test app.js
curl http://localhost:5000/app.js
```

### Step 6: Check File Permissions

```bash
# Make sure files are readable
chmod 644 app.js index.html
```

### Step 7: Verify Flask is Serving Files

Check if Flask can find the files:
```bash
python3 -c "
import os
print('Current directory:', os.getcwd())
print('app.js exists:', os.path.exists('app.js'))
print('index.html exists:', os.path.exists('index.html'))
"
```

## Common Issues and Fixes

### Issue: app.js returns 404

**Fix:**
1. Make sure you're in the correct directory when running the app
2. Check that `app.js` exists in the same directory as `app.py`
3. Restart the Flask application

### Issue: API endpoints return 401/403

**Fix:**
- If OIDC is not configured, the `@require_auth` decorator should allow access
- Check that `OIDC_AVAILABLE = False` in the Flask output
- If OIDC is enabled but not working, disable it temporarily

### Issue: Sidebar links don't work

**Fix:**
1. Check browser console for JavaScript errors
2. Verify `app.js` is loading (Network tab)
3. Check that `switchTab` function is defined (console: `typeof switchTab`)

### Issue: Nothing loads / Blank page

**Fix:**
1. Check if `index.html` is being served correctly
2. Verify database is configured (check `.env` file)
3. Check Flask logs for errors

## Quick Diagnostic Script

Run this on the server to check everything:

```bash
#!/bin/bash
echo "=== bWall Diagnostic ==="
echo ""
echo "1. Checking files..."
ls -la app.js index.html app.py 2>/dev/null || echo "ERROR: Files missing"
echo ""
echo "2. Checking Python..."
python3 --version
echo ""
echo "3. Checking Flask..."
python3 -c "import flask; print('Flask:', flask.__version__)" 2>/dev/null || echo "ERROR: Flask not installed"
echo ""
echo "4. Checking database config..."
if [ -f .env ]; then
    echo ".env file exists"
    grep -q "DB_HOST" .env && echo "✓ DB_HOST configured" || echo "✗ DB_HOST missing"
    grep -q "DB_USER" .env && echo "✓ DB_USER configured" || echo "✗ DB_USER missing"
else
    echo "ERROR: .env file not found"
fi
echo ""
echo "5. Testing Flask import..."
python3 -c "from app import app; print('✓ App imports successfully')" 2>/dev/null || echo "✗ App import failed"
echo ""
echo "=== End Diagnostic ==="
```

## Still Having Issues?

1. **Check Flask output** - Look for error messages when starting
2. **Check browser console** - Look for JavaScript errors
3. **Check network tab** - See which requests are failing
4. **Verify file paths** - Make sure all files are in the same directory
5. **Restart Flask** - Stop and restart the application

## Python 3.13 Compatibility Issues

### Issue: ModuleNotFoundError: No module named 'pkg_resources'

**Problem:** The `flask_pyoidc` package requires `pkg_resources`, which is provided by `setuptools`. In Python 3.13, `setuptools` is not always included by default.

**Solution:**
```bash
pip3 install --upgrade setuptools
# Or reinstall all requirements
pip3 install -r requirements.txt
```

The `requirements.txt` file includes `setuptools>=65.0.0` to prevent this issue.

### Issue: re.PatternError with Python 3.13

**Problem:** Python 3.13 has stricter regex parsing that's incompatible with older versions of the `future` package used by `flask_pyoidc`.

**Error Message:**
```
re.PatternError: global flags not at the start of the expression at position 5
```

**Solution:** The application automatically detects Python 3.13 and disables OIDC authentication gracefully. The application will run normally without OIDC.

**Status:**
- ✅ Application will start and run - OIDC is automatically disabled on Python 3.13
- ⚠️ OIDC authentication unavailable - You'll need to use Python 3.11 or 3.12 for OIDC support

**Options:**

1. **Run Without OIDC (Recommended for now)**
   ```bash
   ./start_bwall.sh
   ```
   You'll see a warning message, but the application will run normally.

2. **Use Python 3.12 (For OIDC Support)**
   ```bash
   # Install Python 3.12
   apt-get update
   apt-get install -y python3.12 python3.12-venv python3.12-pip
   
   # Create virtual environment
   python3.12 -m venv venv
   source venv/bin/activate
   
   # Install requirements
   pip install -r requirements.txt
   
   # Run application
   python app.py
   ```

3. **Wait for Package Updates**
   Monitor the `future` package for Python 3.13 compatibility:
   - https://github.com/PythonCharmers/future
   - https://pypi.org/project/future/

**What Changed:**
1. Automatic Detection: The app detects Python 3.13 and disables OIDC imports
2. Graceful Degradation: Application runs without OIDC instead of crashing
3. Clear Warnings: You'll see informative messages about OIDC being disabled

**Security Note:**
Without OIDC, the application runs without authentication. For production use:
- Use a reverse proxy (nginx/Apache) with authentication
- Restrict network access to the application
- Use firewall rules to limit access
- Consider using Python 3.12 for full OIDC support

## Database Connection Issues

### Issue: Access denied for user

**Error:** `(1045, "Access denied for user 'iptables_user'@'localhost' (using password: YES)")`

**Solution:** Use the diagnostic script:
```bash
./fix_db_connection.sh
```

Or manually check:
1. Verify credentials in `.env` file
2. Test connection: `mysql -u iptables_user -p iptables_db`
3. Check user privileges: `SHOW GRANTS FOR 'iptables_user'@'localhost';`

## Iptables Rule Ordering Issues

### Issue: Bans being placed before whitelist entries

**Problem:** Rules are not in the correct order (whitelist should come first).

**Solution:**
```bash
sudo ./fix_iptables_order.sh
```

Or use the sync script:
```bash
sudo python3 sync_rules.py
```

The application now uses separate chains (`BWALL_WHITELIST`, `BWALL_BLACKLIST`, `BWALL_RULES`) to ensure correct ordering.

## Getting Help

When reporting issues, include:
- Browser console errors (screenshot or copy/paste)
- Network tab showing failed requests
- Flask server output/errors
- Python version (`python3 --version`)
- Operating system
- Any error messages from the troubleshooting scripts

