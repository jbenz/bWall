#!/bin/bash

# bWall - Firewall Management Dashboard - Quickstart Script
# bWall by bunit.net
# This script automates the installation and setup process

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="quickstart.log"
START_TIME=$(date +%s)

# Function to log messages
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    log "INFO" "$1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    log "SUCCESS" "$1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log "WARNING" "$1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    log "ERROR" "$1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "debian"
        elif command_exists yum; then
            echo "rhel"
        elif command_exists dnf; then
            echo "fedora"
        elif command_exists pacman; then
            echo "arch"
        else
            echo "unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Initialize log file
echo "=== bWall Quickstart Log ===" > "$LOG_FILE"
echo "Started: $(date)" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Banner
clear
echo "=========================================="
echo "  bWall - Firewall Management Dashboard"
echo "  Quickstart Installation Script"
echo "  by bunit.net"
echo "=========================================="
echo ""
print_info "Starting installation process..."
echo ""

# Check if running as root (will need for iptables)
if [ "$EUID" -ne 0 ]; then 
    print_warning "Not running as root. Some operations may require sudo."
    SUDO_CMD="sudo"
else
    SUDO_CMD=""
    print_info "Running as root"
fi

# Step 1: Check Prerequisites
print_info "Step 1: Checking prerequisites..."

MISSING_PREREQS=()

# Check Python 3
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    print_success "Python 3 found: $PYTHON_VERSION"
else
    print_error "Python 3 not found"
    MISSING_PREREQS+=("python3")
fi

# Check pip
if command_exists pip3 || command_exists pip; then
    PIP_CMD=$(command_exists pip3 && echo "pip3" || echo "pip")
    print_success "pip found: $PIP_CMD"
else
    print_error "pip not found"
    MISSING_PREREQS+=("python3-pip")
fi

# Check iptables
if command_exists iptables; then
    IPTABLES_VERSION=$(iptables --version 2>&1 | head -n1)
    print_success "iptables found: $IPTABLES_VERSION"
else
    print_error "iptables not found"
    MISSING_PREREQS+=("iptables")
fi

# Check MariaDB/MySQL client
if command_exists mysql; then
    print_success "MySQL/MariaDB client found"
else
    print_warning "MySQL/MariaDB client not found (will be installed with server)"
fi

if [ ${#MISSING_PREREQS[@]} -gt 0 ]; then
    print_warning "Missing prerequisites: ${MISSING_PREREQS[*]}"
    OS=$(detect_os)
    
    if [ "$OS" == "debian" ] || [ "$OS" == "ubuntu" ]; then
        print_info "To install missing prerequisites on Debian/Ubuntu, run:"
        echo "  $SUDO_CMD apt-get update && $SUDO_CMD apt-get install -y ${MISSING_PREREQS[*]}"
        read -p "Install missing prerequisites now? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            $SUDO_CMD apt-get update
            $SUDO_CMD apt-get install -y "${MISSING_PREREQS[@]}"
            print_success "Prerequisites installed"
        fi
    elif [ "$OS" == "rhel" ] || [ "$OS" == "fedora" ]; then
        print_info "To install missing prerequisites on RHEL/Fedora, run:"
        echo "  $SUDO_CMD yum install -y ${MISSING_PREREQS[*]}"
        read -p "Install missing prerequisites now? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            $SUDO_CMD yum install -y "${MISSING_PREREQS[@]}"
            print_success "Prerequisites installed"
        fi
    elif [ "$OS" == "macos" ]; then
        print_info "On macOS, install prerequisites using Homebrew:"
        echo "  brew install python3"
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        print_error "Unknown OS. Please install prerequisites manually."
        exit 1
    fi
fi

echo ""

# Step 2: Check MariaDB Server
print_info "Step 2: Checking MariaDB/MySQL server..."

MARIADB_RUNNING=false
if command_exists systemctl; then
    if systemctl is-active --quiet mariadb 2>/dev/null || systemctl is-active --quiet mysql 2>/dev/null; then
        MARIADB_RUNNING=true
        print_success "MariaDB/MySQL server is running"
    else
        print_warning "MariaDB/MySQL server is not running"
    fi
elif command_exists service; then
    if service mariadb status >/dev/null 2>&1 || service mysql status >/dev/null 2>&1; then
        MARIADB_RUNNING=true
        print_success "MariaDB/MySQL server is running"
    else
        print_warning "MariaDB/MySQL server is not running"
    fi
else
    # Try to connect to check if running
    if mysql -u root -e "SELECT 1" >/dev/null 2>&1; then
        MARIADB_RUNNING=true
        print_success "MariaDB/MySQL server is accessible"
    else
        print_warning "Cannot determine MariaDB/MySQL server status"
    fi
fi

if [ "$MARIADB_RUNNING" = false ]; then
    OS=$(detect_os)
    print_warning "MariaDB/MySQL server not detected"
    read -p "Would you like to install MariaDB server? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Installing MariaDB server..."
        
        if [ "$OS" == "debian" ] || [ "$OS" == "ubuntu" ]; then
            $SUDO_CMD apt-get update
            $SUDO_CMD apt-get install -y mariadb-server
            $SUDO_CMD systemctl start mariadb
            $SUDO_CMD systemctl enable mariadb
            print_success "MariaDB server installed and started"
        elif [ "$OS" == "rhel" ] || [ "$OS" == "fedora" ]; then
            $SUDO_CMD yum install -y mariadb-server
            $SUDO_CMD systemctl start mariadb
            $SUDO_CMD systemctl enable mariadb
            print_success "MariaDB server installed and started"
        elif [ "$OS" == "macos" ]; then
            if command_exists brew; then
                brew install mariadb
                brew services start mariadb
                print_success "MariaDB server installed and started"
            else
                print_error "Homebrew not found. Please install MariaDB manually."
                exit 1
            fi
        else
            print_error "Cannot auto-install MariaDB on this OS. Please install manually."
            exit 1
        fi
        
        # Secure installation
        print_info "Running MariaDB secure installation..."
        print_warning "You will be prompted to set a root password and configure security options"
        $SUDO_CMD mysql_secure_installation
    else
        print_warning "Skipping MariaDB installation. You'll need to set it up manually."
    fi
fi

echo ""

# Step 3: Install Python Requirements
print_info "Step 3: Installing Python requirements..."

if [ -f "requirements.txt" ]; then
    PIP_CMD=$(command_exists pip3 && echo "pip3" || echo "pip")
    
    # Ensure setuptools is installed first (required for pkg_resources)
    print_info "Installing setuptools (required dependency)..."
    $PIP_CMD install --upgrade setuptools >/dev/null 2>&1 || true
    
    # Ensure future package is compatible with Python 3.13
    print_info "Installing/upgrading future package (Python 3.13 compatibility)..."
    $PIP_CMD install --upgrade 'future>=0.18.3' >/dev/null 2>&1 || true
    
    print_info "Installing packages from requirements.txt..."
    
    if $PIP_CMD install -r requirements.txt; then
        print_success "Python requirements installed"
    else
        print_error "Failed to install Python requirements"
        print_warning "If you encounter Python 3.13 compatibility issues, see FIX_PYTHON313.md"
        exit 1
    fi
else
    print_error "requirements.txt not found"
    exit 1
fi

echo ""

# Step 4: Database Setup
print_info "Step 4: Setting up database..."

# Get database configuration
read -p "Database host [localhost]: " DB_HOST
DB_HOST=${DB_HOST:-localhost}

read -p "Database root user [root]: " DB_ROOT_USER
DB_ROOT_USER=${DB_ROOT_USER:-root}

read -sp "Database root password: " DB_ROOT_PASSWORD
echo ""

read -p "Database name [iptables_db]: " DB_NAME
DB_NAME=${DB_NAME:-iptables_db}

read -p "Database user [iptables_user]: " DB_USER
DB_USER=${DB_USER:-iptables_user}

read -sp "Database user password: " DB_PASSWORD
echo ""

# Test database connection
print_info "Testing database connection..."
if mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$DB_ROOT_PASSWORD" -e "SELECT 1" >/dev/null 2>&1; then
    print_success "Database connection successful"
else
    print_error "Cannot connect to database. Please check credentials."
    exit 1
fi

# Create database and user
print_info "Creating database and user..."
mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$DB_ROOT_PASSWORD" <<EOF
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF

if [ $? -eq 0 ]; then
    print_success "Database and user created"
else
    print_error "Failed to create database or user"
    exit 1
fi

# Create database schema (tables)
print_info "Creating database schema..."
mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$DB_ROOT_PASSWORD" "$DB_NAME" <<EOF
-- Whitelist table
CREATE TABLE IF NOT EXISTS whitelist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Blacklist table
CREATE TABLE IF NOT EXISTS blacklist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Rules table
CREATE TABLE IF NOT EXISTS rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    chain VARCHAR(50),
    target VARCHAR(50),
    protocol VARCHAR(10),
    source VARCHAR(45),
    destination VARCHAR(45),
    options TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_chain (chain),
    INDEX idx_source (source)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Activity log table
CREATE TABLE IF NOT EXISTS activity_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(50) NOT NULL,
    type VARCHAR(20),
    entry VARCHAR(255),
    status VARCHAR(20),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_type (type),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Sync log table
CREATE TABLE IF NOT EXISTS sync_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    direction VARCHAR(20),
    whitelist_synced INT DEFAULT 0,
    blacklist_synced INT DEFAULT 0,
    rules_synced INT DEFAULT 0,
    status VARCHAR(20),
    message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- AbuseIPDB report queue table
CREATE TABLE IF NOT EXISTS abuseipdb_queue (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    categories JSON NOT NULL,
    comment TEXT,
    service VARCHAR(50),
    attack_type VARCHAR(50),
    source VARCHAR(20) DEFAULT 'auto',
    status VARCHAR(20) DEFAULT 'pending',
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    submitted_at TIMESTAMP NULL,
    INDEX idx_status (status),
    INDEX idx_ip (ip_address),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- URL-based IP lists table
CREATE TABLE IF NOT EXISTS url_lists (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    list_type VARCHAR(20) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    auto_sync BOOLEAN DEFAULT FALSE,
    sync_interval INT DEFAULT 3600,
    last_sync TIMESTAMP NULL,
    last_success TIMESTAMP NULL,
    last_error TEXT,
    entry_count INT DEFAULT 0,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_type (list_type),
    INDEX idx_enabled (enabled),
    INDEX idx_last_sync (last_sync)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
EOF

if [ $? -eq 0 ]; then
    print_success "Database schema created"
else
    print_error "Failed to create database schema"
    exit 1
fi

# Create views
print_info "Creating database views..."
mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$DB_ROOT_PASSWORD" "$DB_NAME" <<EOF
-- View: Recent activity summary
CREATE OR REPLACE VIEW v_recent_activity AS
SELECT 
    DATE(timestamp) as date,
    type,
    status,
    COUNT(*) as count
FROM activity_log
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY DATE(timestamp), type, status
ORDER BY date DESC, type, status;

-- View: Whitelist summary
CREATE OR REPLACE VIEW v_whitelist_summary AS
SELECT 
    COUNT(*) as total_entries,
    COUNT(DISTINCT SUBSTRING_INDEX(ip_address, '/', 1)) as unique_ips,
    MIN(created_at) as first_entry,
    MAX(created_at) as last_entry
FROM whitelist;

-- View: Blacklist summary
CREATE OR REPLACE VIEW v_blacklist_summary AS
SELECT 
    COUNT(*) as total_entries,
    COUNT(DISTINCT SUBSTRING_INDEX(ip_address, '/', 1)) as unique_ips,
    MIN(created_at) as first_entry,
    MAX(created_at) as last_entry
FROM blacklist;

-- View: Sync status
CREATE OR REPLACE VIEW v_sync_status AS
SELECT 
    direction,
    SUM(whitelist_synced) as total_whitelist_synced,
    SUM(blacklist_synced) as total_blacklist_synced,
    SUM(rules_synced) as total_rules_synced,
    COUNT(*) as sync_count,
    MAX(timestamp) as last_sync
FROM sync_log
GROUP BY direction;
EOF

if [ $? -eq 0 ]; then
    print_success "Database views created"
else
    print_warning "Some views may not have been created (this is okay if they already exist)"
fi

# Create stored procedures for reports
print_info "Creating stored procedures for reports..."
mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$DB_ROOT_PASSWORD" "$DB_NAME" <<EOF
DELIMITER //

-- Procedure: Get daily activity report
CREATE PROCEDURE IF NOT EXISTS sp_daily_activity_report(IN days INT)
BEGIN
    SELECT 
        DATE(timestamp) as date,
        action,
        type,
        status,
        COUNT(*) as count
    FROM activity_log
    WHERE timestamp >= DATE_SUB(NOW(), INTERVAL days DAY)
    GROUP BY DATE(timestamp), action, type, status
    ORDER BY date DESC, action, type;
END //

-- Procedure: Get top blocked IPs
CREATE PROCEDURE IF NOT EXISTS sp_top_blocked_ips(IN limit_count INT)
BEGIN
    SELECT 
        ip_address,
        description,
        created_at,
        (SELECT COUNT(*) FROM activity_log 
         WHERE entry = blacklist.ip_address AND type = 'blacklist') as block_count
    FROM blacklist
    ORDER BY created_at DESC
    LIMIT limit_count;
END //

-- Procedure: Get sync statistics
CREATE PROCEDURE IF NOT EXISTS sp_sync_statistics(IN days INT)
BEGIN
    SELECT 
        direction,
        COUNT(*) as total_syncs,
        SUM(whitelist_synced) as total_whitelist,
        SUM(blacklist_synced) as total_blacklist,
        SUM(rules_synced) as total_rules,
        AVG(whitelist_synced + blacklist_synced + rules_synced) as avg_entries_per_sync,
        MAX(timestamp) as last_sync
    FROM sync_log
    WHERE timestamp >= DATE_SUB(NOW(), INTERVAL days DAY)
    GROUP BY direction;
END //

DELIMITER ;
EOF

if [ $? -eq 0 ]; then
    print_success "Stored procedures created"
else
    print_warning "Some procedures may not have been created (this is okay if they already exist)"
fi

echo ""

# Step 5: OIDC/PocketID Configuration
print_info "Step 5: OIDC/PocketID Configuration"

read -p "Would you like to configure PocketID OIDC authentication? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "PocketID OIDC Configuration"
    echo "Please have the following information ready:"
    echo "  - PocketID Issuer URL"
    echo "  - Client ID"
    echo "  - Client Secret"
    echo "  - Redirect URI (callback URL)"
    echo ""
    
    read -p "PocketID Issuer URL: " OIDC_ISSUER
    read -p "OIDC Client ID: " OIDC_CLIENT_ID
    read -sp "OIDC Client Secret: " OIDC_CLIENT_SECRET
    echo ""
    read -p "Redirect URI [http://localhost:5000/oidc_callback]: " OIDC_REDIRECT_URI
    OIDC_REDIRECT_URI=${OIDC_REDIRECT_URI:-http://localhost:5000/oidc_callback}
    
    read -p "Post-Logout Redirect URI [http://localhost:5000/]: " OIDC_POST_LOGOUT_URI
    OIDC_POST_LOGOUT_URI=${OIDC_POST_LOGOUT_URI:-http://localhost:5000/}
    
    # Generate secret key
    if command_exists openssl; then
        SECRET_KEY=$(openssl rand -hex 32)
    else
        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    fi
    
    print_success "OIDC configuration collected"
else
    print_info "Skipping OIDC configuration. You can configure it later using environment variables."
    OIDC_ISSUER=""
    OIDC_CLIENT_ID=""
    OIDC_CLIENT_SECRET=""
    OIDC_REDIRECT_URI=""
    OIDC_POST_LOGOUT_URI=""
    SECRET_KEY=""
fi

echo ""

# Step 5b: AbuseIPDB Configuration
print_info "Step 5b: AbuseIPDB Configuration (Optional)"
echo "AbuseIPDB integration allows you to report and check abusive IPs."
echo "Get your API key from: https://www.abuseipdb.com/pricing"
echo ""

read -p "Would you like to configure AbuseIPDB integration? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -sp "AbuseIPDB API Key: " ABUSEIPDB_API_KEY
    echo ""
    if [ -n "$ABUSEIPDB_API_KEY" ]; then
        print_success "AbuseIPDB API key collected"
        echo ""
        echo "AbuseIPDB Reporting Mode:"
        echo "  1) automatic - Report immediately when IPs are blocked"
        echo "  2) log_and_hold - Queue reports for review before submitting"
        echo "  3) log_only - Only log events, do not report"
        read -p "Select mode [1-3] (default: 1): " MODE_CHOICE
        case $MODE_CHOICE in
            2)
                ABUSEIPDB_MODE="log_and_hold"
                ;;
            3)
                ABUSEIPDB_MODE="log_only"
                ;;
            *)
                ABUSEIPDB_MODE="automatic"
                ;;
        esac
        print_success "AbuseIPDB mode set to: $ABUSEIPDB_MODE"
    else
        print_warning "No API key provided, skipping AbuseIPDB configuration"
        ABUSEIPDB_API_KEY=""
        ABUSEIPDB_MODE="automatic"
    fi
else
    print_info "Skipping AbuseIPDB configuration. You can configure it later in the .env file."
    ABUSEIPDB_API_KEY=""
    ABUSEIPDB_MODE="automatic"
fi

echo ""

# Step 6: Create Environment File
print_info "Step 6: Creating environment configuration file..."

ENV_FILE=".env"
cat > "$ENV_FILE" <<EOF
# bWall Configuration
# Generated by quickstart.sh on $(date)

# Database Configuration
DB_HOST=$DB_HOST
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_NAME=$DB_NAME

# OIDC Configuration
EOF

if [ -n "$OIDC_ISSUER" ]; then
    cat >> "$ENV_FILE" <<EOF
OIDC_ISSUER=$OIDC_ISSUER
OIDC_CLIENT_ID=$OIDC_CLIENT_ID
OIDC_CLIENT_SECRET=$OIDC_CLIENT_SECRET
OIDC_REDIRECT_URI=$OIDC_REDIRECT_URI
OIDC_POST_LOGOUT_REDIRECT_URI=$OIDC_POST_LOGOUT_URI
SECRET_KEY=$SECRET_KEY
EOF
else
    cat >> "$ENV_FILE" <<EOF
# OIDC not configured - set these to enable authentication
# OIDC_ISSUER=
# OIDC_CLIENT_ID=
# OIDC_CLIENT_SECRET=
# OIDC_REDIRECT_URI=
# OIDC_POST_LOGOUT_REDIRECT_URI=
# SECRET_KEY=
EOF
fi

# AbuseIPDB Configuration
if [ -n "$ABUSEIPDB_API_KEY" ]; then
    cat >> "$ENV_FILE" <<EOF

# AbuseIPDB Configuration
ABUSEIPDB_API_KEY=$ABUSEIPDB_API_KEY
ABUSEIPDB_MODE=$ABUSEIPDB_MODE
EOF
else
    cat >> "$ENV_FILE" <<EOF

# AbuseIPDB Configuration (optional)
# Get your API key from: https://www.abuseipdb.com/pricing
# ABUSEIPDB_API_KEY=
# ABUSEIPDB_MODE=automatic  # Options: automatic, log_and_hold, log_only
EOF
fi

# Make .env file readable only by owner
chmod 600 "$ENV_FILE"
print_success "Environment file created: $ENV_FILE"
print_warning "Keep this file secure! It contains sensitive credentials."

echo ""

# Step 7: Create startup helper script
print_info "Step 7: Creating startup helper script..."

cat > "start_bwall.sh" <<'STARTER'
#!/bin/bash
# bWall Startup Script
# Loads environment variables and starts the application

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "Error: .env file not found. Run quickstart.sh first."
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Warning: This application requires root privileges to manage iptables."
    echo "Attempting to run with sudo..."
    exec sudo -E python3 app.py
else
    python3 app.py
fi
STARTER

chmod +x start_bwall.sh
print_success "Startup script created: start_bwall.sh"

echo ""

# Summary
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

print_success "=========================================="
print_success "Installation Complete!"
print_success "=========================================="
echo ""
print_info "Summary:"
echo "  - Prerequisites: ✓"
echo "  - Python packages: ✓"
echo "  - Database: ✓"
echo "  - Database views: ✓"
echo "  - Stored procedures: ✓"
echo "  - Configuration: ✓"
echo ""
print_info "Next steps:"
echo "  1. Review the .env file and adjust if needed"
echo "  2. Start the application: ./start_bwall.sh"
echo "  3. Access the dashboard: http://localhost:5000"
echo ""
print_info "Log file: $LOG_FILE"
print_info "Installation time: ${DURATION} seconds"
echo ""

# Display database connection info
echo "Database Information:"
echo "  Host: $DB_HOST"
echo "  Database: $DB_NAME"
echo "  User: $DB_USER"
echo ""

if [ -n "$OIDC_ISSUER" ]; then
    echo "OIDC Configuration:"
    echo "  Issuer: $OIDC_ISSUER"
    echo "  Client ID: $OIDC_CLIENT_ID"
    echo "  ✓ OIDC authentication enabled"
    echo ""
else
    echo "OIDC Configuration:"
    echo "  ⚠ OIDC not configured (optional)"
    echo "  To configure later, edit .env file or set environment variables"
    echo ""
fi

if [ -n "$ABUSEIPDB_API_KEY" ]; then
    echo "AbuseIPDB Configuration:"
    echo "  ✓ AbuseIPDB integration enabled"
    echo ""
else
    echo "AbuseIPDB Configuration:"
    echo "  ⚠ AbuseIPDB not configured (optional)"
    echo "  To configure later, edit .env file and set ABUSEIPDB_API_KEY"
    echo ""
fi

print_warning "Remember:"
echo "  - The application requires root/sudo to manage iptables"
echo "  - Keep your .env file secure"
echo "  - Check $LOG_FILE for troubleshooting"
echo ""

print_success "bWall is ready to use! 🚀"
echo ""

