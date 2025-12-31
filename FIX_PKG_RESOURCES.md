# Quick Fix for pkg_resources Error

## Immediate Fix

Run this command to install the missing dependency:

```bash
pip3 install --upgrade setuptools
```

Or if you prefer to install all requirements again:

```bash
pip3 install -r requirements.txt
```

## What Happened

The `flask_pyoidc` package requires `pkg_resources`, which is provided by `setuptools`. In Python 3.13, `setuptools` is not always included by default, so it needs to be explicitly installed.

## Updated Requirements

The `requirements.txt` file has been updated to include `setuptools>=65.0.0` to prevent this issue in future installations.

## After Installing

Once setuptools is installed, you can start the application:

```bash
./start_bwall.sh
```

