#!/bin/bash
# Script to diagnose and fix database connection issues for bWall

echo "=========================================="
echo "bWall Database Connection Diagnostic Tool"
echo "=========================================="
echo ""

# Load .env file if it exists
if [ -f .env ]; then
    echo "[INFO] Loading configuration from .env file..."
    export $(grep -v '^#' .env | xargs)
else
    echo "[WARNING] .env file not found. Using defaults or environment variables."
fi

DB_HOST="${DB_HOST:-localhost}"
DB_USER="${DB_USER:-iptables_user}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_NAME="${DB_NAME:-iptables_db}"
DB_ROOT_USER="${DB_ROOT_USER:-root}"
DB_ROOT_PASSWORD="${DB_ROOT_PASSWORD:-}"

echo "Current Configuration:"
echo "  Host: $DB_HOST"
echo "  User: $DB_USER"
echo "  Database: $DB_NAME"
echo "  Password: ${DB_PASSWORD:+***SET***}${DB_PASSWORD:-NOT SET}"
echo ""

# Function to test connection
test_connection() {
    local user=$1
    local password=$2
    local database=$3
    
    if [ -z "$password" ]; then
        mysql -h "$DB_HOST" -u "$user" -e "SELECT 1" 2>&1
    else
        mysql -h "$DB_HOST" -u "$user" -p"$password" -e "SELECT 1" 2>&1
    fi
}

# Test root connection
echo "[1] Testing root connection..."
if [ -z "$DB_ROOT_PASSWORD" ]; then
    echo "    Root password not set. Please enter root password when prompted:"
    ROOT_TEST=$(mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p -e "SELECT 1" 2>&1)
else
    ROOT_TEST=$(mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$DB_ROOT_PASSWORD" -e "SELECT 1" 2>&1)
fi

if [ $? -eq 0 ]; then
    echo "    ✓ Root connection successful"
    ROOT_ACCESS=true
else
    echo "    ✗ Root connection failed: $ROOT_TEST"
    ROOT_ACCESS=false
fi
echo ""

# Test user connection
echo "[2] Testing user connection ($DB_USER)..."
if [ -z "$DB_PASSWORD" ]; then
    USER_TEST=$(mysql -h "$DB_HOST" -u "$DB_USER" -e "SELECT 1" 2>&1)
else
    USER_TEST=$(mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" -e "SELECT 1" 2>&1)
fi

if [ $? -eq 0 ]; then
    echo "    ✓ User connection successful"
    USER_ACCESS=true
else
    echo "    ✗ User connection failed: $USER_TEST"
    USER_ACCESS=false
fi
echo ""

# Check if user exists
if [ "$ROOT_ACCESS" = true ]; then
    echo "[3] Checking if user exists..."
    if [ -z "$DB_ROOT_PASSWORD" ]; then
        USER_EXISTS=$(mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p -e "SELECT User, Host FROM mysql.user WHERE User='$DB_USER' AND Host='localhost';" 2>&1)
    else
        USER_EXISTS=$(mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$DB_ROOT_PASSWORD" -e "SELECT User, Host FROM mysql.user WHERE User='$DB_USER' AND Host='localhost';" 2>&1)
    fi
    
    if echo "$USER_EXISTS" | grep -q "$DB_USER"; then
        echo "    ✓ User exists"
    else
        echo "    ✗ User does not exist"
        echo ""
        echo "[FIX] Would you like to create the user? (y/n)"
        read -r CREATE_USER
        if [ "$CREATE_USER" = "y" ]; then
            if [ -z "$DB_PASSWORD" ]; then
                echo "    Please enter a password for the new user:"
                read -s NEW_PASSWORD
                echo "    Please confirm the password:"
                read -s NEW_PASSWORD_CONFIRM
                if [ "$NEW_PASSWORD" != "$NEW_PASSWORD_CONFIRM" ]; then
                    echo "    ✗ Passwords do not match"
                    exit 1
                fi
            else
                NEW_PASSWORD="$DB_PASSWORD"
            fi
            
            if [ -z "$DB_ROOT_PASSWORD" ]; then
                mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p <<EOF
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$NEW_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF
            else
                mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$DB_ROOT_PASSWORD" <<EOF
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$NEW_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF
            fi
            
            if [ $? -eq 0 ]; then
                echo "    ✓ User created successfully"
                # Update .env if password was set
                if [ -f .env ] && [ -n "$NEW_PASSWORD" ]; then
                    if grep -q "^DB_PASSWORD=" .env; then
                        sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=$NEW_PASSWORD/" .env
                    else
                        echo "DB_PASSWORD=$NEW_PASSWORD" >> .env
                    fi
                    echo "    ✓ Updated .env file with new password"
                fi
            else
                echo "    ✗ Failed to create user"
            fi
        fi
    fi
    echo ""
    
    # Check if database exists
    echo "[4] Checking if database exists..."
    if [ -z "$DB_ROOT_PASSWORD" ]; then
        DB_EXISTS=$(mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p -e "SHOW DATABASES LIKE '$DB_NAME';" 2>&1)
    else
        DB_EXISTS=$(mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$DB_ROOT_PASSWORD" -e "SHOW DATABASES LIKE '$DB_NAME';" 2>&1)
    fi
    
    if echo "$DB_EXISTS" | grep -q "$DB_NAME"; then
        echo "    ✓ Database exists"
    else
        echo "    ✗ Database does not exist"
        echo ""
        echo "[FIX] Would you like to create the database? (y/n)"
        read -r CREATE_DB
        if [ "$CREATE_DB" = "y" ]; then
            if [ -z "$DB_ROOT_PASSWORD" ]; then
                mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;" 2>&1
            else
                mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$DB_ROOT_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;" 2>&1
            fi
            
            if [ $? -eq 0 ]; then
                echo "    ✓ Database created successfully"
                echo "    [INFO] You may need to run ./quickstart.sh or setup_db.sh to create tables"
            else
                echo "    ✗ Failed to create database"
            fi
        fi
    fi
    echo ""
    
    # Check user privileges
    if [ "$USER_ACCESS" = false ] && [ "$ROOT_ACCESS" = true ]; then
        echo "[5] Attempting to fix user privileges..."
        echo "    Would you like to reset the user password and grant privileges? (y/n)"
        read -r FIX_USER
        if [ "$FIX_USER" = "y" ]; then
            if [ -z "$DB_PASSWORD" ]; then
                echo "    Please enter a new password for the user:"
                read -s NEW_PASSWORD
                echo "    Please confirm the password:"
                read -s NEW_PASSWORD_CONFIRM
                if [ "$NEW_PASSWORD" != "$NEW_PASSWORD_CONFIRM" ]; then
                    echo "    ✗ Passwords do not match"
                    exit 1
                fi
            else
                NEW_PASSWORD="$DB_PASSWORD"
            fi
            
            if [ -z "$DB_ROOT_PASSWORD" ]; then
                mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p <<EOF
ALTER USER '$DB_USER'@'localhost' IDENTIFIED BY '$NEW_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF
            else
                mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$DB_ROOT_PASSWORD" <<EOF
ALTER USER '$DB_USER'@'localhost' IDENTIFIED BY '$NEW_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF
            fi
            
            if [ $? -eq 0 ]; then
                echo "    ✓ User privileges updated"
                # Update .env if password was changed
                if [ -f .env ] && [ -n "$NEW_PASSWORD" ]; then
                    if grep -q "^DB_PASSWORD=" .env; then
                        sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=$NEW_PASSWORD/" .env
                    else
                        echo "DB_PASSWORD=$NEW_PASSWORD" >> .env
                    fi
                    echo "    ✓ Updated .env file with new password"
                fi
                
                # Test connection again
                echo ""
                echo "[6] Testing connection again..."
                if [ -z "$NEW_PASSWORD" ]; then
                    FINAL_TEST=$(mysql -h "$DB_HOST" -u "$DB_USER" -e "SELECT 1" 2>&1)
                else
                    FINAL_TEST=$(mysql -h "$DB_HOST" -u "$DB_USER" -p"$NEW_PASSWORD" -e "SELECT 1" 2>&1)
                fi
                
                if [ $? -eq 0 ]; then
                    echo "    ✓ Connection successful!"
                else
                    echo "    ✗ Connection still failing: $FINAL_TEST"
                fi
            else
                echo "    ✗ Failed to update user privileges"
            fi
        fi
    fi
fi

echo ""
echo "=========================================="
echo "Diagnostic complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. If connection is working, restart bWall: ./start_bwall.sh"
echo "  2. If issues persist, check the .env file for correct credentials"
echo "   Edit .env file: nano .env"
echo "   Required variables: DB_HOST, DB_USER, DB_PASSWORD, DB_NAME"
echo ""

