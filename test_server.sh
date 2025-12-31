#!/bin/bash
# Quick test script to verify server is working

echo "Testing bWall Server..."
echo "======================"
echo ""

SERVER_URL="${1:-http://localhost:5000}"

echo "1. Testing root endpoint..."
curl -s -o /dev/null -w "Status: %{http_code}\n" "$SERVER_URL/"

echo ""
echo "2. Testing app.js endpoint..."
curl -s -o /dev/null -w "Status: %{http_code}\n" "$SERVER_URL/app.js"

echo ""
echo "3. Testing API test endpoint..."
curl -s "$SERVER_URL/api/test" | python3 -m json.tool 2>/dev/null || curl -s "$SERVER_URL/api/test"

echo ""
echo "4. Testing auth endpoint..."
curl -s "$SERVER_URL/api/auth/user" | python3 -m json.tool 2>/dev/null || curl -s "$SERVER_URL/api/auth/user"

echo ""
echo "5. Testing stats endpoint..."
curl -s "$SERVER_URL/api/stats" | python3 -m json.tool 2>/dev/null || curl -s "$SERVER_URL/api/stats"

echo ""
echo "======================"
echo "Test complete"

