# bWall - Firewall Management Dashboard

**bWall** is a comprehensive firewall management system developed by **bunit.net** that provides centralized management of iptables rules with MariaDB synchronization, active log monitoring, AbuseIPDB integration, and crowdsourced threat intelligence.

## Features

- **Centralized Management**: Web-based dashboard for managing iptables rules
- **Whitelist/Blacklist**: Separate chains for whitelist, blacklist, and custom rules
- **Active Monitoring**: Real-time log monitoring for SSH, Apache/Nginx, XRDP, LDAP, Kerberos, SMTP, RPC, Samba
- **AbuseIPDB Integration**: Automatic reporting of abusive IPs with configurable modes
- **Crowdsource Lists**: Import and sync IP lists from community-maintained sources (e.g., 3FIFTYnet)
- **Authentication**: OIDC/PocketID support with local MariaDB fallback
- **Reporting**: Comprehensive statistics and reports on firewall activity
- **Chain-based Rules View**: Hierarchical view of iptables chains for easy navigation
- **Pagination**: Efficient handling of large rule sets with filtering

## Quick Start

### Installation

Run the quickstart script:

```bash
sudo ./quickstart.sh
```

This will:
- Check prerequisites (Python, pip, iptables, MariaDB)
- Install Python dependencies
- Set up MariaDB database
- Configure OIDC (optional)
- Create startup script

### Starting the Application

**Option 1: Manual Start**
```bash
sudo ./start_bwall.sh
```

**Option 2: Systemd Service (Recommended for Production)**
```bash
sudo ./install_systemd_service.sh
```

This will:
- Create a systemd service file
- Enable automatic startup at boot
- Allow you to manage the service with systemctl

**Service Management:**
```bash
# Start service
sudo systemctl start bwall

# Stop service
sudo systemctl stop bwall

# Restart service
sudo systemctl restart bwall

# Check status
sudo systemctl status bwall

# View logs
sudo journalctl -u bwall -f

# Disable auto-start
sudo systemctl disable bwall
```

**Option 3: Web-based Installer**
```bash
sudo python3 app.py --installer
```

Then navigate to `http://your-server:5000/installer`

## Configuration

Configuration is stored in `.env` file:

```bash
# Database
DB_HOST=localhost
DB_USER=iptables_user
DB_PASSWORD=your_password
DB_NAME=iptables_db

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=5000
SECRET_KEY=your_secret_key

# OIDC (Optional)
OIDC_ISSUER_URL=https://your-oidc-provider
OIDC_CLIENT_ID=your_client_id
OIDC_CLIENT_SECRET=your_client_secret

# AbuseIPDB (Optional)
ABUSEIPDB_API_KEY=your_api_key
ABUSEIPDB_MODE=automatic  # log_only, log_and_hold, or automatic
```

## Maintenance

Use the unified maintenance script:

```bash
# Database diagnostics
sudo ./maintenance.sh database

# Fix iptables ordering
sudo ./maintenance.sh iptables

# Sync rules
sudo ./maintenance.sh sync

# Run all maintenance tasks
sudo ./maintenance.sh all
```

## Documentation

- **HISTORY.md**: Project history and changelog
- **TROUBLESHOOTING.md**: Common issues and solutions
- **OIDC_SETUP.md**: OIDC/PocketID configuration guide

## Requirements

- Python 3.11+ (3.12 recommended for OIDC support)
- MariaDB/MySQL
- iptables
- Root/sudo access for iptables management

## Security Notes

- The application requires root privileges to manage iptables
- Keep your `.env` file secure (chmod 600)
- Use OIDC authentication in production
- If OIDC is not available, use a reverse proxy with authentication
- Restrict network access to the application

## Support

For issues and troubleshooting, see **TROUBLESHOOTING.md**

## License

Developed by bunit.net

