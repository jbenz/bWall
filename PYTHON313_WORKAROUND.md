# Python 3.13 Compatibility Workaround

## Issue

Python 3.13 has stricter regex parsing that's incompatible with the `future` package (version 1.0.0) used by `flask_pyoidc`. The error occurs when trying to import OIDC libraries:

```
re.PatternError: global flags not at the start of the expression
```

## Solution

The application has been updated to **automatically disable OIDC authentication when running on Python 3.13**. The application will run normally without OIDC.

## Current Status

✅ **Application will start and run** - OIDC is automatically disabled on Python 3.13  
⚠️ **OIDC authentication unavailable** - You'll need to use Python 3.11 or 3.12 for OIDC support

## Options

### Option 1: Run Without OIDC (Recommended for now)

The application will work fine without OIDC authentication. Simply start it:

```bash
./start_bwall.sh
```

You'll see a warning message, but the application will run normally.

### Option 2: Use Python 3.12 (For OIDC Support)

If you need OIDC authentication, use Python 3.12:

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

### Option 3: Wait for Package Updates

The `future` package maintainers may release a Python 3.13 compatible version. Monitor:
- https://github.com/PythonCharmers/future
- https://pypi.org/project/future/

## What Changed

1. **Automatic Detection**: The app detects Python 3.13 and disables OIDC imports
2. **Graceful Degradation**: Application runs without OIDC instead of crashing
3. **Clear Warnings**: You'll see informative messages about OIDC being disabled

## Security Note

Without OIDC, the application runs without authentication. For production use:
- Use a reverse proxy (nginx/Apache) with authentication
- Restrict network access to the application
- Use firewall rules to limit access
- Consider using Python 3.12 for full OIDC support

## Testing

After starting the application, you should see:

```
Warning: Python 3.13 detected. OIDC authentication disabled due to compatibility issues.
Note: OIDC disabled due to Python 3.13 compatibility issues with 'future' package.
Application will run without OIDC authentication
```

The application will then start normally and be accessible at `http://localhost:5000`.

