# bWall - Firewall Management Dashboard

**bWall** is a modern Bootstrap 5 web dashboard for managing iptables firewall rules with centralized MariaDB synchronization. Developed by [bunit.net](https://bunit.net).

## Features

- **Whitelist Management**: Add, view, and remove whitelist entries
- **Blacklist Management**: Add, view, and remove blacklist entries
- **Rules Viewing**: View current iptables rules
- **Import/Export**: Import and export lists in JSON, CSV, or iptables command format
- **Database Synchronization**: Centralized management with MariaDB
- **Activity Logging**: Track all changes and operations
- **Modern UI**: Beautiful Bootstrap 5 interface with responsive design
- **PocketID OIDC Authentication**: Secure authentication with OpenID Connect (optional but recommended)

## Prerequisites

- Python 3.7+
- MariaDB/MySQL server
- Root/sudo access (required for iptables management)
- iptables installed on the system
- PocketID OIDC instance (optional, for authentication)

## Installation

### Quick Start (Recommended)

You have two options for installation:

#### Option 1: Web-Based Installer (Easiest)

1. Start the application (even without full setup):
   ```bash
   python3 app.py
   ```

2. Open your browser and navigate to:
   ```
   http://localhost:5000/installer
   ```

3. Follow the web-based installation wizard which will:
   - Check prerequisites
   - Configure database
   - Set up OIDC/PocketID authentication
   - Install Python packages
   - Create configuration files

#### Option 2: Command-Line Quickstart Script

Run the automated quickstart script:

```bash
./quickstart.sh
```

This script will:
- Check and install prerequisites
- Check for MariaDB and offer to install if needed
- Install Python dependencies
- Set up the database with views and stored procedures
- Configure OIDC/PocketID authentication interactively
- Create environment configuration file
- Generate a startup script

### Manual Installation

1. **Clone or download this repository**

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up MariaDB:**
   
   Create a database and user:
   ```sql
   CREATE DATABASE iptables_db;
   CREATE USER 'iptables_user'@'localhost' IDENTIFIED BY 'iptables_pass';
   GRANT ALL PRIVILEGES ON iptables_db.* TO 'iptables_user'@'localhost';
   FLUSH PRIVILEGES;
   ```

4. **Configure database connection:**
   
   Set environment variables or modify the `DB_CONFIG` in `app.py`:
   ```bash
   export DB_HOST=localhost
   export DB_USER=iptables_user
   export DB_PASSWORD=iptables_pass
   export DB_NAME=iptables_db
   ```

5. **Configure PocketID OIDC Authentication (Optional but Recommended):**
   
   The application supports PocketID OIDC authentication for secure access. To enable it:
   
   a. **Set up OIDC Client in PocketID:**
      - Access your PocketID admin dashboard
      - Navigate to "OIDC Clients" section
      - Click "Add OIDC Client"
      - Configure:
        - **Name**: `bwall_dashboard` (or your preferred name)
        - **Callback URL**: `http://localhost:5000/oidc_callback` (or your production URL)
        - **Post Logout Redirect URI**: `http://localhost:5000/` (or your production URL)
      - Save and note the **Client ID** and **Client Secret**
   
   b. **Set environment variables:**
      ```bash
      export OIDC_ISSUER=https://your-pocketid-instance.example.com
      export OIDC_CLIENT_ID=your_client_id
      export OIDC_CLIENT_SECRET=your_client_secret
      export OIDC_REDIRECT_URI=http://localhost:5000/oidc_callback
      export OIDC_POST_LOGOUT_REDIRECT_URI=http://localhost:5000/
      export SECRET_KEY=your-secret-key-for-sessions
      ```
   
   **Note**: If OIDC credentials are not configured, the application will run without authentication (development mode only - not recommended for production).

6. **Run the application:**
   
   If you used the quickstart script, simply run:
   ```bash
   ./start_bwall.sh
   ```
   
   Or manually:
   ```bash
   # Load environment variables
   export $(cat .env | grep -v '^#' | xargs)
   
   # Run with sudo (required for iptables)
   sudo python3 app.py
   ```
   
   **Important**: The application needs root privileges to manage iptables.

7. **Access the application:**
   
   The application runs on `0.0.0.0:5000` by default, making it accessible from:
   - Localhost: `http://localhost:5000`
   - Network IP: `http://<server-ip>:5000`
   
   **Access points:**
   - **Dashboard**: `http://localhost:5000/` (or your server IP)
   - **Web Installer**: `http://localhost:5000/installer` (or your server IP)
   
   If the application is not configured, accessing the root URL will automatically redirect to the installer.
   
   If OIDC is configured, you will be redirected to PocketID for authentication. After successful login, you'll be redirected back to the dashboard.
   
   **For detailed OIDC setup instructions, see [OIDC_SETUP.md](OIDC_SETUP.md)**
   
   **Note**: When running on `0.0.0.0`, the application is accessible from all network interfaces. For production, use a reverse proxy and restrict access.
   
   **For detailed OIDC setup instructions, see [OIDC_SETUP.md](OIDC_SETUP.md)**

## Configuration

### Database Configuration

Edit the `DB_CONFIG` dictionary in `app.py` or set environment variables:

```python
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'iptables_user'),
    'password': os.getenv('DB_PASSWORD', 'iptables_pass'),
    'database': os.getenv('DB_NAME', 'iptables_db'),
    'charset': 'utf8mb4'
}
```

### API Configuration

The Flask API runs on port 5000 by default. To change this, modify the last line in `app.py`:

```python
app.run(host='0.0.0.0', port=5000, debug=True)
```

## Usage

### Adding Whitelist/Blacklist Entries

1. Navigate to the Whitelist or Blacklist tab
2. Click "Add Entry"
3. Enter IP address or CIDR notation (e.g., `192.168.1.1` or `192.168.1.0/24`)
4. Optionally add a description
5. Click "Add Entry"

### Importing Data

1. Go to the Import/Export tab
2. Select the import type (Whitelist, Blacklist, or Rules)
3. Choose a file (JSON, CSV, or TXT format)
4. Optionally check "Overwrite existing entries"
5. Click "Import"

### Exporting Data

1. Go to the Import/Export tab
2. Select export type and format
3. Click "Export"
4. The file will be downloaded

### Synchronization

1. Navigate to the Synchronization tab
2. Check database connection status
3. Select sync direction:
   - **Bidirectional**: Sync both ways
   - **DB → IPTables**: Apply database entries to iptables
   - **IPTables → DB**: Import iptables rules to database
4. Click "Synchronize Now"

## File Formats

### JSON Import Format

```json
{
  "whitelist": [
    {
      "ip_address": "192.168.1.1",
      "description": "Trusted server"
    }
  ],
  "blacklist": [
    {
      "ip_address": "10.0.0.0/8",
      "description": "Blocked network"
    }
  ]
}
```

### CSV Import Format

```csv
Type,ID,IP Address,Description,Created At
whitelist,1,192.168.1.1,Trusted server,2024-01-01
blacklist,2,10.0.0.0/8,Blocked network,2024-01-01
```

### IPTables Commands Format

```
iptables -I INPUT -s 192.168.1.1 -j ACCEPT
iptables -I INPUT -s 10.0.0.0/8 -j DROP
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Root Access Required**: This application requires root privileges to modify iptables rules. Run with caution.

2. **Authentication**: 
   - **Always enable PocketID OIDC authentication in production**
   - Without OIDC, the application runs without authentication (development only)
   - Configure strong `SECRET_KEY` for session management
   - Use HTTPS in production to protect OIDC tokens

3. **Network Security**: The API runs on `0.0.0.0:5000` by default, making it accessible from any network interface. For production:
   - Use a reverse proxy (nginx, Apache) with HTTPS
   - Enable OIDC authentication (required)
   - Restrict access with firewall rules
   - Consider binding to localhost only if accessed through reverse proxy

4. **Database Security**: 
   - Use strong passwords
   - Restrict database user privileges
   - Use SSL for database connections in production

5. **Input Validation**: The application validates IP addresses, but always verify inputs before applying rules.

6. **OIDC Configuration**:
   - Keep Client Secret secure (use environment variables, never commit to version control)
   - Use HTTPS for OIDC redirect URIs in production
   - Regularly rotate Client Secrets
   - Configure appropriate session timeouts

## API Endpoints

All API endpoints (except `/api/auth/logout`) require OIDC authentication if configured.

**Authentication:**
- `GET /api/auth/user` - Get current authenticated user information
- `POST /api/auth/logout` - Logout user (redirects to PocketID logout)

**Dashboard:**
- `GET /api/stats` - Get dashboard statistics
- `GET /api/activity` - Get activity log

**Whitelist:**
- `GET /api/whitelist` - Get all whitelist entries
- `POST /api/whitelist` - Add whitelist entry
- `DELETE /api/whitelist/<id>` - Delete whitelist entry

**Blacklist:**
- `GET /api/blacklist` - Get all blacklist entries
- `POST /api/blacklist` - Add blacklist entry
- `DELETE /api/blacklist/<id>` - Delete blacklist entry

**Rules:**
- `GET /api/rules` - Get current iptables rules

**Import/Export:**
- `GET /api/export?type=<type>&format=<format>` - Export data
- `POST /api/import` - Import data from file

**Synchronization:**
- `GET /api/sync/status` - Get sync status
- `POST /api/sync` - Trigger synchronization

## Troubleshooting

### Database Connection Issues

- Verify MariaDB is running: `sudo systemctl status mariadb`
- Check database credentials in `app.py` or environment variables
- Ensure database and user exist
- Check firewall rules allowing localhost connections

### IPTables Permission Issues

- Ensure running with root privileges: `sudo python3 app.py`
- Check iptables is installed: `which iptables`
- Verify iptables modules are loaded

### Import/Export Issues

- Check file format matches expected structure
- Verify file permissions for upload directory
- Check disk space in `/tmp/iptables_uploads`

## Development

### Project Structure

```
.
├── index.html          # Bootstrap 5 dashboard UI
├── app.js              # Frontend JavaScript
├── app.py              # Flask backend API
├── requirements.txt    # Python dependencies
├── README.md           # This file
├── OIDC_SETUP.md       # PocketID OIDC setup guide
├── quickstart.sh       # Automated installation and setup script (recommended)
├── setup_db.sh         # Manual database setup script
├── start.sh            # Application startup script
└── start_bwall.sh      # Startup script with .env loading (created by quickstart.sh)
```

### Adding Features

The application is modular:
- Frontend: `index.html` and `app.js`
- Backend API: `app.py`
- Database schema: Auto-created on first run

## License

This project is provided as-is for educational and administrative purposes.

## About

**bWall** is developed by [bunit.net](https://bunit.net). For support, questions, or contributions, please visit [bunit.net](https://bunit.net).

## Contributing

Feel free to submit issues and enhancement requests!

