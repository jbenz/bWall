#!/bin/bash

# bWall - Firewall Management Dashboard - Database Setup Script
# bWall by bunit.net

echo "bWall - Firewall Management Dashboard - Database Setup"
echo "by bunit.net"
echo "=============================================="
echo ""

# Database configuration
DB_HOST="${DB_HOST:-localhost}"
DB_ROOT_USER="${DB_ROOT_USER:-root}"
DB_NAME="${DB_NAME:-iptables_db}"
DB_USER="${DB_USER:-iptables_user}"
DB_PASSWORD="${DB_PASSWORD:-iptables_pass}"

echo "Configuration:"
echo "  Database Host: $DB_HOST"
echo "  Database Name: $DB_NAME"
echo "  Database User: $DB_USER"
echo ""

# Prompt for root password
read -sp "Enter MySQL/MariaDB root password: " ROOT_PASSWORD
echo ""

# Create database
echo "Creating database..."
mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$ROOT_PASSWORD" <<EOF
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
EOF

if [ $? -eq 0 ]; then
    echo "✓ Database created successfully"
else
    echo "✗ Failed to create database"
    exit 1
fi

# Create user and grant privileges
echo "Creating user and granting privileges..."
mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$ROOT_PASSWORD" <<EOF
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF

if [ $? -eq 0 ]; then
    echo "✓ User created and privileges granted"
else
    echo "✗ Failed to create user"
    exit 1
fi

echo ""
echo "Database setup completed successfully!"
echo ""
echo "You can now start the application with:"
echo "  sudo python3 app.py"
echo ""
echo "Or set environment variables:"
echo "  export DB_HOST=$DB_HOST"
echo "  export DB_USER=$DB_USER"
echo "  export DB_PASSWORD=$DB_PASSWORD"
echo "  export DB_NAME=$DB_NAME"

