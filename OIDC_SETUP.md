# PocketID OIDC Authentication Setup Guide

This guide will help you configure PocketID OpenID Connect (OIDC) authentication for **bWall** - Firewall Management Dashboard by bunit.net.

## Prerequisites

- A running PocketID instance
- Admin access to PocketID
- The dashboard application installed and configured

## Step 1: Create OIDC Client in PocketID

1. Log in to your PocketID admin dashboard
2. Navigate to **OIDC Clients** (or **Applications** → **OIDC Clients**)
3. Click **Add OIDC Client** or **Create New Client**

## Step 2: Configure Client Settings

Fill in the following information:

### Basic Information
- **Client Name**: `bwall_dashboard` (or your preferred name)
- **Client Type**: `Confidential` (requires client secret)

### Redirect URIs
Add the following callback URLs:

**For Development:**
```
http://localhost:5000/oidc_callback
```

**For Production:**
```
https://your-domain.com/oidc_callback
```

### Post-Logout Redirect URIs
Add the following logout redirect URLs:

**For Development:**
```
http://localhost:5000/
```

**For Production:**
```
https://your-domain.com/
```

### Scopes
Ensure the following scopes are available:
- `openid` (required)
- `profile` (for user profile information)
- `email` (for user email)

## Step 3: Save and Note Credentials

After saving the client configuration:

1. **Copy the Client ID** - You'll need this for the environment variable
2. **Copy the Client Secret** - Keep this secure! You'll need it for the environment variable
3. **Note the Issuer URL** - Usually in the format: `https://your-pocketid-instance.example.com`

## Step 4: Configure Environment Variables

Set the following environment variables before starting the application:

```bash
# Required OIDC Configuration
export OIDC_ISSUER=https://your-pocketid-instance.example.com
export OIDC_CLIENT_ID=your_client_id_from_pocketid
export OIDC_CLIENT_SECRET=your_client_secret_from_pocketid

# Redirect URIs (adjust for your environment)
export OIDC_REDIRECT_URI=http://localhost:5000/oidc_callback
export OIDC_POST_LOGOUT_REDIRECT_URI=http://localhost:5000/

# Session Secret (generate a strong random string)
export SECRET_KEY=$(openssl rand -hex 32)

# Optional: CORS origins (comma-separated)
export CORS_ORIGINS=http://localhost:5000,https://your-domain.com
```

### Alternative: Create .env File

You can also create a `.env` file in the project root (make sure it's in `.gitignore`):

```env
OIDC_ISSUER=https://your-pocketid-instance.example.com
OIDC_CLIENT_ID=your_client_id
OIDC_CLIENT_SECRET=your_client_secret
OIDC_REDIRECT_URI=http://localhost:5000/oidc_callback
OIDC_POST_LOGOUT_REDIRECT_URI=http://localhost:5000/
SECRET_KEY=your-secret-key-here
```

Then load it before starting:
```bash
export $(cat .env | xargs)
```

## Step 5: Verify Configuration

1. Start the application:
   ```bash
   sudo python3 app.py
   ```

2. Check the console output. You should see:
   ```
   OIDC authentication configured successfully
   ```

3. If you see a warning instead, check:
   - All environment variables are set correctly
   - The Issuer URL is accessible
   - The Client ID and Secret are correct

## Step 6: Test Authentication

1. Open your browser and navigate to `http://localhost:5000`
2. You should be redirected to PocketID for authentication
3. After logging in, you'll be redirected back to the dashboard
4. You should see your user information in the top bar
5. Test the logout button to ensure it works correctly

## Troubleshooting

### "OIDC credentials not configured" Warning

**Cause**: Environment variables are not set or are empty.

**Solution**: 
- Verify all OIDC environment variables are set: `echo $OIDC_CLIENT_ID`
- Check that variables are exported in the same shell session
- Restart the application after setting variables

### "OIDC configuration failed" Error

**Cause**: Invalid configuration or network issues.

**Solutions**:
- Verify the Issuer URL is correct and accessible
- Check that Client ID and Secret match what's in PocketID
- Ensure the redirect URI matches exactly (including http/https and port)
- Check network connectivity to PocketID instance

### Redirect URI Mismatch Error

**Cause**: The redirect URI in the request doesn't match what's configured in PocketID.

**Solution**:
- Verify `OIDC_REDIRECT_URI` matches exactly what's in PocketID
- Check for trailing slashes, http vs https, port numbers
- Update either the environment variable or PocketID configuration to match

### Session/Cookie Issues

**Cause**: Cookies not being sent or received properly.

**Solutions**:
- Ensure `SECRET_KEY` is set (required for session management)
- Check CORS configuration if accessing from different domain
- Verify browser allows cookies for the domain
- Use HTTPS in production (required for secure cookies)

### Authentication Loop

**Cause**: Redirect URI mismatch or session issues.

**Solutions**:
- Clear browser cookies for the application
- Verify redirect URIs match exactly
- Check PocketID logs for authentication errors
- Ensure `SECRET_KEY` is consistent across restarts

## Production Considerations

1. **Use HTTPS**: OIDC requires HTTPS in production for security
2. **Strong Secret Key**: Generate a strong, random `SECRET_KEY`
3. **Secure Client Secret**: Never commit secrets to version control
4. **Environment Variables**: Use a secure secrets management system
5. **Session Security**: Configure appropriate session timeouts
6. **CORS**: Restrict CORS origins to your actual domains

## Security Best Practices

- ✅ Use HTTPS for all OIDC communications
- ✅ Store secrets in environment variables or secure vaults
- ✅ Rotate Client Secrets periodically
- ✅ Use strong, randomly generated `SECRET_KEY`
- ✅ Restrict CORS origins to known domains
- ✅ Monitor authentication logs for suspicious activity
- ✅ Implement rate limiting on authentication endpoints
- ✅ Use secure cookie settings (HttpOnly, Secure, SameSite)

## Additional Resources

- [PocketID GitHub Repository](https://github.com/pocket-id/pocket-id)
- [Flask-pyoidc Documentation](https://flask-pyoidc.readthedocs.io/)
- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)

