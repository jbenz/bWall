# Fix for Python 3.13 Compatibility Issues

## Problem

Python 3.13 has stricter regex parsing that's incompatible with older versions of the `future` package used by `flask_pyoidc`.

## Solution

Update the `future` package to a version compatible with Python 3.13:

```bash
pip3 install --upgrade 'future>=0.18.3'
```

Or reinstall all requirements:

```bash
pip3 install -r requirements.txt
```

## Alternative: Use Python 3.11 or 3.12

If you continue to have issues, you can use Python 3.11 or 3.12 which are more compatible:

```bash
# Install Python 3.12 (example for Debian/Ubuntu)
apt-get update
apt-get install -y python3.12 python3.12-venv python3.12-pip

# Create virtual environment
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## What Was Fixed

1. Updated `requirements.txt` to include `future>=0.18.3`
2. Added error handling in `app.py` to gracefully handle OIDC import failures
3. Application will run without OIDC if dependencies aren't available

## After Fixing

Once you've updated the packages, restart the application:

```bash
./start_bwall.sh
```

The application will work with or without OIDC authentication configured.

