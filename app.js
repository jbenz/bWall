// API Base URL - Auto-detect from current location (works with 0.0.0.0)
const API_BASE = window.location.origin + '/api';

// Configure fetch to include credentials for OIDC
const fetchOptions = {
    credentials: 'include'
};

// Authentication state
let isAuthenticated = false;
let currentUser = null;

// Tab Navigation
document.addEventListener('DOMContentLoaded', function() {
    // Check authentication status first
    checkAuthentication().then(() => {
        // Initialize tabs
        const navLinks = document.querySelectorAll('.sidebar .nav-link');
        navLinks.forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const tab = this.getAttribute('data-tab');
                switchTab(tab);
            });
        });

        // Load initial data
        switchTab('dashboard');
        refreshStats();
    }).catch(error => {
        console.error('Authentication check failed:', error);
        // If authentication fails, the page will redirect to login
    });
});

// Authentication Functions
async function checkAuthentication() {
    try {
        const response = await fetch(`${API_BASE}/auth/user`, {
            credentials: 'include'
        });
        
        if (response.status === 401 || response.status === 403) {
            // Not authenticated, will be redirected by OIDC
            return;
        }
        
        if (response.ok) {
            const data = await response.json();
            if (data.authenticated) {
                isAuthenticated = true;
                currentUser = data.user;
                updateUserInterface();
            }
        }
    } catch (error) {
        console.error('Error checking authentication:', error);
        // If OIDC is not configured, continue without authentication
        if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
            // API might not be running or OIDC not configured
            console.log('Assuming OIDC is not configured, continuing without authentication');
            isAuthenticated = true; // Allow access if OIDC is not configured
        }
    }
}

function updateUserInterface() {
    const userInfoBar = document.getElementById('user-info-bar');
    const userName = document.getElementById('user-name');
    
    if (currentUser) {
        // Display user information (user is an object, not a Map)
        const displayName = currentUser.name || 
                          currentUser.preferred_username || 
                          currentUser.email || 
                          'User';
        userName.textContent = displayName;
        userInfoBar.style.display = 'flex';
    } else {
        userInfoBar.style.display = 'none';
    }
}

async function logout() {
    try {
        const response = await fetch(`${API_BASE}/auth/logout`, {
            method: 'POST',
            credentials: 'include'
        });
        
        // OIDC logout will redirect, so we don't need to handle the response
        if (response.ok || response.redirected) {
            window.location.href = response.url || '/';
        }
    } catch (error) {
        console.error('Error during logout:', error);
        // Try to redirect anyway
        window.location.href = '/';
    }
}

function switchTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.style.display = 'none';
    });

    // Remove active class from nav links
    document.querySelectorAll('.sidebar .nav-link').forEach(link => {
        link.classList.remove('active');
    });

    // Show selected tab
    const tabElement = document.getElementById(`${tabName}-tab`);
    if (tabElement) {
        tabElement.style.display = 'block';
    }

    // Add active class to nav link
    const navLink = document.querySelector(`[data-tab="${tabName}"]`);
    if (navLink) {
        navLink.classList.add('active');
    }

    // Load tab-specific data
    switch(tabName) {
        case 'whitelist':
            loadWhitelist();
            break;
        case 'blacklist':
            loadBlacklist();
            break;
        case 'rules':
            loadRules();
            break;
        case 'sync':
            checkDbStatus();
            break;
        case 'monitor':
            loadMonitorStatus();
            loadMonitorConfig();
            loadRecentBlocks();
            break;
    }
}

// Dashboard Functions
async function refreshStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`, fetchOptions);
        
        if (response.status === 401 || response.status === 403) {
            // Authentication required - will be handled by OIDC redirect
            return;
        }
        
        const data = await response.json();
        
        document.getElementById('stat-total-rules').textContent = data.total_rules || 0;
        document.getElementById('stat-whitelist').textContent = data.whitelist_count || 0;
        document.getElementById('stat-blacklist').textContent = data.blacklist_count || 0;
        document.getElementById('stat-sync-status').textContent = data.db_connected ? 'Connected' : 'Disconnected';
        
        loadActivityLog();
    } catch (error) {
        console.error('Error refreshing stats:', error);
        // Don't show alert if it's an authentication error (will redirect)
        if (!error.message.includes('401') && !error.message.includes('403')) {
            showAlert('Error loading statistics', 'danger');
        }
    }
}

async function loadActivityLog() {
    try {
        const response = await fetch(`${API_BASE}/activity`, fetchOptions);
        const activities = await response.json();
        
        const tbody = document.getElementById('activity-log');
        if (activities.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No recent activity</td></tr>';
            return;
        }
        
        tbody.innerHTML = activities.map(activity => `
            <tr>
                <td>${new Date(activity.timestamp).toLocaleString()}</td>
                <td>${activity.action}</td>
                <td><span class="badge bg-${activity.type === 'whitelist' ? 'success' : 'danger'}">${activity.type}</span></td>
                <td>${activity.entry || 'N/A'}</td>
                <td><span class="badge bg-${activity.status === 'success' ? 'success' : 'danger'}">${activity.status}</span></td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading activity log:', error);
    }
}

// Whitelist Functions
async function loadWhitelist() {
    try {
        const response = await fetch(`${API_BASE}/whitelist`, fetchOptions);
        const entries = await response.json();
        
        const tbody = document.getElementById('whitelist-table');
        if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No whitelist entries</td></tr>';
            return;
        }
        
        tbody.innerHTML = entries.map(entry => `
            <tr>
                <td>${entry.id}</td>
                <td><code>${entry.ip_address}</code></td>
                <td>${entry.description || '-'}</td>
                <td>${new Date(entry.created_at).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="deleteWhitelistEntry(${entry.id})">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading whitelist:', error);
        showAlert('Error loading whitelist', 'danger');
    }
}

async function addWhitelistEntry() {
    const ip = document.getElementById('whitelist-ip').value;
    const desc = document.getElementById('whitelist-desc').value;
    
    if (!ip) {
        showAlert('Please enter an IP address', 'warning');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/whitelist`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip_address: ip, description: desc }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert('Whitelist entry added successfully', 'success');
            bootstrap.Modal.getInstance(document.getElementById('addWhitelistModal')).hide();
            document.getElementById('whitelist-form').reset();
            loadWhitelist();
            refreshStats();
        } else {
            showAlert(result.error || 'Error adding whitelist entry', 'danger');
        }
    } catch (error) {
        console.error('Error adding whitelist entry:', error);
        showAlert('Error adding whitelist entry', 'danger');
    }
}

async function deleteWhitelistEntry(id) {
    if (!confirm('Are you sure you want to delete this whitelist entry?')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/whitelist/${id}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        
        if (response.ok) {
            showAlert('Whitelist entry deleted successfully', 'success');
            loadWhitelist();
            refreshStats();
        } else {
            showAlert('Error deleting whitelist entry', 'danger');
        }
    } catch (error) {
        console.error('Error deleting whitelist entry:', error);
        showAlert('Error deleting whitelist entry', 'danger');
    }
}

// Blacklist Functions
async function loadBlacklist() {
    try {
        const response = await fetch(`${API_BASE}/blacklist`, fetchOptions);
        const entries = await response.json();
        
        const tbody = document.getElementById('blacklist-table');
        if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No blacklist entries</td></tr>';
            return;
        }
        
        tbody.innerHTML = entries.map(entry => `
            <tr>
                <td>${entry.id}</td>
                <td><code>${entry.ip_address}</code></td>
                <td>${entry.description || '-'}</td>
                <td>${new Date(entry.created_at).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="deleteBlacklistEntry(${entry.id})">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading blacklist:', error);
        showAlert('Error loading blacklist', 'danger');
    }
}

async function addBlacklistEntry() {
    const ip = document.getElementById('blacklist-ip').value;
    const desc = document.getElementById('blacklist-desc').value;
    
    if (!ip) {
        showAlert('Please enter an IP address', 'warning');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/blacklist`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip_address: ip, description: desc }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert('Blacklist entry added successfully', 'success');
            bootstrap.Modal.getInstance(document.getElementById('addBlacklistModal')).hide();
            document.getElementById('blacklist-form').reset();
            loadBlacklist();
            refreshStats();
        } else {
            showAlert(result.error || 'Error adding blacklist entry', 'danger');
        }
    } catch (error) {
        console.error('Error adding blacklist entry:', error);
        showAlert('Error adding blacklist entry', 'danger');
    }
}

async function deleteBlacklistEntry(id) {
    if (!confirm('Are you sure you want to delete this blacklist entry?')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/blacklist/${id}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        
        if (response.ok) {
            showAlert('Blacklist entry deleted successfully', 'success');
            loadBlacklist();
            refreshStats();
        } else {
            showAlert('Error deleting blacklist entry', 'danger');
        }
    } catch (error) {
        console.error('Error deleting blacklist entry:', error);
        showAlert('Error deleting blacklist entry', 'danger');
    }
}

// Rules Functions
async function loadRules() {
    try {
        const response = await fetch(`${API_BASE}/rules`, fetchOptions);
        const rules = await response.json();
        
        const tbody = document.getElementById('rules-table');
        if (rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No rules found</td></tr>';
            return;
        }
        
        tbody.innerHTML = rules.map(rule => `
            <tr>
                <td><span class="badge bg-primary">${rule.chain || '-'}</span></td>
                <td>${rule.target || '-'}</td>
                <td>${rule.protocol || '-'}</td>
                <td><code>${rule.source || '-'}</code></td>
                <td><code>${rule.destination || '-'}</code></td>
                <td>${rule.options || '-'}</td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading rules:', error);
        showAlert('Error loading rules', 'danger');
    }
}

// Import/Export Functions
async function exportData() {
    const type = document.getElementById('export-type').value;
    const format = document.getElementById('export-format').value;
    
    try {
        const response = await fetch(`${API_BASE}/export?type=${type}&format=${format}`, fetchOptions);
        const blob = await response.blob();
        
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `bwall_${type}_${new Date().toISOString().split('T')[0]}.${format === 'iptables' ? 'txt' : format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        showAlert('Export completed successfully', 'success');
    } catch (error) {
        console.error('Error exporting data:', error);
        showAlert('Error exporting data', 'danger');
    }
}

async function importData() {
    const fileInput = document.getElementById('import-file');
    const type = document.getElementById('import-type').value;
    const overwrite = document.getElementById('import-overwrite').checked;
    
    if (!fileInput.files.length) {
        showAlert('Please select a file to import', 'warning');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('type', type);
    formData.append('overwrite', overwrite);
    
    try {
        const response = await fetch(`${API_BASE}/import`, {
            method: 'POST',
            body: formData,
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert(`Import completed: ${result.message}`, 'success');
            fileInput.value = '';
            refreshStats();
            if (type === 'whitelist') loadWhitelist();
            if (type === 'blacklist') loadBlacklist();
            if (type === 'rules') loadRules();
        } else {
            showAlert(result.error || 'Error importing data', 'danger');
        }
    } catch (error) {
        console.error('Error importing data:', error);
        showAlert('Error importing data', 'danger');
    }
}

// Sync Functions
async function checkDbStatus() {
    try {
        const response = await fetch(`${API_BASE}/sync/status`, fetchOptions);
        const status = await response.json();
        
        document.getElementById('db-status').textContent = status.connected ? 'Connected' : 'Disconnected';
        document.getElementById('db-status').className = `badge bg-${status.connected ? 'success' : 'danger'}`;
        document.getElementById('last-sync').textContent = status.last_sync ? new Date(status.last_sync).toLocaleString() : 'Never';
    } catch (error) {
        console.error('Error checking DB status:', error);
        document.getElementById('db-status').textContent = 'Error';
        document.getElementById('db-status').className = 'badge bg-danger';
    }
}

async function syncWithDatabase() {
    const direction = document.getElementById('sync-direction').value;
    const logDiv = document.getElementById('sync-log');
    
    logDiv.innerHTML = '<div class="text-info">Starting synchronization...</div>';
    
    try {
        const response = await fetch(`${API_BASE}/sync`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ direction: direction }),
            credentials: 'include'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            logDiv.innerHTML = `
                <div class="text-success">✓ Synchronization completed successfully</div>
                <div class="text-muted">${result.message || ''}</div>
                <div class="text-muted mt-2">Whitelist: ${result.whitelist_synced || 0} entries</div>
                <div class="text-muted">Blacklist: ${result.blacklist_synced || 0} entries</div>
                <div class="text-muted">Rules: ${result.rules_synced || 0} entries</div>
            `;
            showAlert('Synchronization completed successfully', 'success');
            checkDbStatus();
            refreshStats();
        } else {
            logDiv.innerHTML = `<div class="text-danger">✗ Error: ${result.error || 'Synchronization failed'}</div>`;
            showAlert('Synchronization failed', 'danger');
        }
    } catch (error) {
        console.error('Error syncing:', error);
        logDiv.innerHTML = `<div class="text-danger">✗ Error: ${error.message}</div>`;
        showAlert('Error during synchronization', 'danger');
    }
}

// Monitoring Functions
let monitorInterval = null;

async function loadMonitorStatus() {
    try {
        const response = await fetch(`${API_BASE}/monitor/status`, fetchOptions);
        if (response.ok) {
            const stats = await response.json();
            
            document.getElementById('monitor-status').textContent = stats.monitoring ? 'Active' : 'Stopped';
            document.getElementById('monitor-total-events').textContent = stats.total_events || 0;
            document.getElementById('monitor-blocked-ips').textContent = stats.blocked_ips || 0;
            document.getElementById('monitor-tracked-ips').textContent = stats.tracked_ips || 0;
            
            // Update button states
            if (stats.monitoring) {
                document.getElementById('btn-start-monitor').style.display = 'none';
                document.getElementById('btn-stop-monitor').style.display = 'inline-block';
            } else {
                document.getElementById('btn-start-monitor').style.display = 'inline-block';
                document.getElementById('btn-stop-monitor').style.display = 'none';
            }
            
            // Update last check time
            if (stats.last_check) {
                const lastCheck = new Date(stats.last_check);
                // Could display this somewhere
            }
        }
    } catch (error) {
        console.error('Error loading monitor status:', error);
    }
}

async function loadMonitorConfig() {
    try {
        const response = await fetch(`${API_BASE}/monitor/config`, fetchOptions);
        if (response.ok) {
            const config = await response.json();
            
            const tbody = document.getElementById('monitor-services-table');
            tbody.innerHTML = Object.entries(config.patterns).map(([service, info]) => `
                <tr>
                    <td><strong>${service.toUpperCase()}</strong></td>
                    <td>
                        <small>${info.log_paths.slice(0, 2).join('<br>')}</small>
                        ${info.log_paths.length > 2 ? `<br><small class="text-muted">+${info.log_paths.length - 2} more</small>` : ''}
                    </td>
                    <td><span class="badge bg-warning">${info.threshold} attempts</span></td>
                    <td><span class="badge bg-info">${info.window}s</span></td>
                    <td><span class="badge bg-success">Active</span></td>
                </tr>
            `).join('');
        }
    } catch (error) {
        console.error('Error loading monitor config:', error);
    }
}

async function loadRecentBlocks() {
    try {
        const response = await fetch(`${API_BASE}/monitor/recent-blocks?limit=20`, fetchOptions);
        if (response.ok) {
            const blocks = await response.json();
            
            const tbody = document.getElementById('recent-blocks-table');
            if (blocks.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No recent blocks</td></tr>';
                return;
            }
            
            tbody.innerHTML = blocks.map(block => {
                const entry = block.entry || '';
                const match = entry.match(/(\d+\.\d+\.\d+\.\d+)/);
                const ip = match ? match[1] : 'Unknown';
                const serviceMatch = entry.match(/\((\w+):/);
                const service = serviceMatch ? serviceMatch[1] : 'Unknown';
                const attackMatch = entry.match(/:\s*(\w+)\)/);
                const attackType = attackMatch ? attackMatch[1] : 'Unknown';
                
                return `
                    <tr>
                        <td>${new Date(block.timestamp).toLocaleString()}</td>
                        <td><code>${ip}</code></td>
                        <td><span class="badge bg-primary">${service}</span></td>
                        <td><span class="badge bg-danger">${attackType}</span></td>
                        <td><span class="badge bg-${block.status === 'success' ? 'success' : 'warning'}">${block.status}</span></td>
                    </tr>
                `;
            }).join('');
        }
    } catch (error) {
        console.error('Error loading recent blocks:', error);
    }
}

async function startMonitoring() {
    try {
        const response = await fetch(`${API_BASE}/monitor/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
            credentials: 'include'
        });
        
        if (response.ok) {
            showAlert('Monitoring started successfully', 'success');
            loadMonitorStatus();
            
            // Start auto-refresh
            if (monitorInterval) clearInterval(monitorInterval);
            monitorInterval = setInterval(loadMonitorStatus, 5000);
        } else {
            const result = await response.json();
            showAlert(result.error || 'Failed to start monitoring', 'danger');
        }
    } catch (error) {
        console.error('Error starting monitoring:', error);
        showAlert('Error starting monitoring', 'danger');
    }
}

async function stopMonitoring() {
    try {
        const response = await fetch(`${API_BASE}/monitor/stop`, {
            method: 'POST',
            credentials: 'include'
        });
        
        if (response.ok) {
            showAlert('Monitoring stopped', 'success');
            loadMonitorStatus();
            
            // Stop auto-refresh
            if (monitorInterval) {
                clearInterval(monitorInterval);
                monitorInterval = null;
            }
        } else {
            showAlert('Failed to stop monitoring', 'danger');
        }
    } catch (error) {
        console.error('Error stopping monitoring:', error);
        showAlert('Error stopping monitoring', 'danger');
    }
}

// Utility Functions
function showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 start-50 translate-middle-x mt-3`;
    alertDiv.style.zIndex = '9999';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.body.appendChild(alertDiv);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

