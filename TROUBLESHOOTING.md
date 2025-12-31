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

## Getting Help

When reporting issues, include:
- Browser console errors (screenshot or copy/paste)
- Network tab showing failed requests
- Flask server output/errors
- Python version (`python3 --version`)
- Operating system

