#!/bin/bash
# bWall - Unified Maintenance Script
# Consolidates common maintenance tasks
# Developed by bunit.net

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored message
print_msg() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Print header
print_header() {
    echo ""
    print_msg "$BLUE" "=========================================="
    print_msg "$BLUE" "$1"
    print_msg "$BLUE" "=========================================="
    echo ""
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_msg "$RED" "Error: This script must be run as root"
        print_msg "$YELLOW" "  Run with: sudo $0 $@"
        exit 1
    fi
}

# Load .env file
load_env() {
    if [ -f .env ]; then
        export $(grep -v '^#' .env | xargs)
        print_msg "$GREEN" "[INFO] Loaded configuration from .env"
    else
        print_msg "$YELLOW" "[WARNING] .env file not found"
    fi
}

# Database diagnostics
fix_database() {
    print_header "Database Connection Diagnostic"
    
    load_env
    
    DB_HOST="${DB_HOST:-localhost}"
    DB_USER="${DB_USER:-iptables_user}"
    DB_PASSWORD="${DB_PASSWORD:-}"
    DB_NAME="${DB_NAME:-iptables_db}"
    DB_ROOT_USER="${DB_ROOT_USER:-root}"
    DB_ROOT_PASSWORD="${DB_ROOT_PASSWORD:-}"
    
    print_msg "$BLUE" "Current Configuration:"
    echo "  Host: $DB_HOST"
    echo "  User: $DB_USER"
    echo "  Database: $DB_NAME"
    echo "  Password: ${DB_PASSWORD:+***SET***}${DB_PASSWORD:-NOT SET}"
    echo ""
    
    # Test root connection
    print_msg "$BLUE" "[1] Testing root connection..."
    if [ -z "$DB_ROOT_PASSWORD" ]; then
        if mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p -e "SELECT 1" 2>/dev/null; then
            print_msg "$GREEN" "    ✓ Root connection successful"
        else
            print_msg "$RED" "    ✗ Root connection failed"
            return 1
        fi
    else
        if mysql -h "$DB_HOST" -u "$DB_ROOT_USER" -p"$DB_ROOT_PASSWORD" -e "SELECT 1" 2>/dev/null; then
            print_msg "$GREEN" "    ✓ Root connection successful"
        else
            print_msg "$RED" "    ✗ Root connection failed"
            return 1
        fi
    fi
    
    # Test user connection
    print_msg "$BLUE" "[2] Testing user connection..."
    if [ -z "$DB_PASSWORD" ]; then
        if mysql -h "$DB_HOST" -u "$DB_USER" -e "SELECT 1" 2>/dev/null; then
            print_msg "$GREEN" "    ✓ User connection successful"
        else
            print_msg "$RED" "    ✗ User connection failed"
            print_msg "$YELLOW" "    Run the full fix_db_connection.sh for interactive repair"
        fi
    else
        if mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" -e "SELECT 1" 2>/dev/null; then
            print_msg "$GREEN" "    ✓ User connection successful"
        else
            print_msg "$RED" "    ✗ User connection failed"
            print_msg "$YELLOW" "    Run the full fix_db_connection.sh for interactive repair"
        fi
    fi
}

# Fix iptables ordering
fix_iptables() {
    print_header "Iptables Rule Order Fix"
    
    check_root
    
    print_msg "$YELLOW" "This will:"
    echo "  1. Remove all existing bWall rules"
    echo "  2. Re-add whitelist rules first"
    echo "  3. Re-add blacklist rules after whitelist"
    echo ""
    read -p "Continue? (y/n): " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_msg "$YELLOW" "Aborted."
        return
    fi
    
    print_msg "$BLUE" "[1] Removing existing bWall rules..."
    
    # Remove existing rules
    iptables -L INPUT -n --line-numbers | grep -E "ACCEPT.*source" | while read line; do
        num=$(echo $line | awk '{print $1}')
        if [ ! -z "$num" ]; then
            iptables -D INPUT $num 2>/dev/null || true
        fi
    done
    
    iptables -L INPUT -n --line-numbers | grep -E "DROP.*source" | while read line; do
        num=$(echo $line | awk '{print $1}')
        if [ ! -z "$num" ]; then
            iptables -D INPUT $num 2>/dev/null || true
        fi
    done
    
    print_msg "$BLUE" "[2] Re-adding rules in correct order..."
    
    # Use sync script
    if [ -f "sync_rules.py" ]; then
        python3 sync_rules.py
        if [ $? -eq 0 ]; then
            print_msg "$GREEN" "[SUCCESS] Rules re-added in correct order!"
        else
            print_msg "$RED" "[ERROR] Sync script failed"
        fi
    else
        print_msg "$RED" "[ERROR] sync_rules.py not found"
    fi
}

# Sync rules
sync_rules() {
    print_header "Synchronize Rules"
    
    check_root
    
    if [ -f "sync_rules.py" ]; then
        python3 sync_rules.py
    else
        print_msg "$RED" "[ERROR] sync_rules.py not found"
        exit 1
    fi
}

# Show usage
usage() {
    echo "bWall - Unified Maintenance Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  database    - Diagnose and fix database connection issues"
    echo "  iptables    - Fix iptables rule ordering"
    echo "  sync        - Synchronize rules from database to iptables"
    echo "  all         - Run all maintenance tasks"
    echo ""
    echo "Examples:"
    echo "  sudo $0 database"
    echo "  sudo $0 iptables"
    echo "  sudo $0 sync"
    echo "  sudo $0 all"
    echo ""
}

# Main
main() {
    case "${1:-}" in
        database)
            fix_database
            ;;
        iptables)
            fix_iptables
            ;;
        sync)
            sync_rules
            ;;
        all)
            fix_database
            echo ""
            fix_iptables
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"

