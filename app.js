// API Base URL - Auto-detect from current location (works with 0.0.0.0)
const API_BASE = window.location.origin + '/api';

// Configure fetch to include credentials for OIDC
const fetchOptions = {
    credentials: 'include'
};

// Authentication state
let isAuthenticated = false;
let currentUser = null;

// Show/hide AbuseIPDB categories when checkbox is toggled
document.addEventListener('DOMContentLoaded', function() {
    const reportCheckbox = document.getElementById('report-to-abuseipdb');
    const categoriesDiv = document.getElementById('abuseipdb-categories');
    
    if (reportCheckbox && categoriesDiv) {
        reportCheckbox.addEventListener('change', function() {
            categoriesDiv.style.display = this.checked ? 'block' : 'none';
        });
    }
});

// AbuseIPDB Queue Functions
async function loadAbuseIPDBStatus() {
    try {
        const response = await fetch(`${API_BASE}/abuseipdb/status`, fetchOptions);
        if (response.ok) {
            const status = await response.json();
            const queueCard = document.getElementById('abuseipdb-queue-card');
            
            // Show queue card only if mode is log_and_hold
            if (queueCard && status.mode === 'log_and_hold' && status.enabled) {
                queueCard.style.display = 'block';
                document.getElementById('queue-count').textContent = `${status.queue_count || 0} pending`;
                if (status.queue_count > 0) {
                    loadAbuseIPDBQueue();
                }
            } else if (queueCard) {
                queueCard.style.display = 'none';
            }
        }
    } catch (error) {
        console.error('Error loading AbuseIPDB status:', error);
    }
}

async function loadAbuseIPDBQueue() {
    try {
        const response = await fetch(`${API_BASE}/abuseipdb/queue?status=pending`, fetchOptions);
        if (response.ok) {
            const reports = await response.json();
            const tbody = document.getElementById('abuseipdb-queue-table');
            
            if (reports.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No pending reports</td></tr>';
                return;
            }
            
            tbody.innerHTML = reports.map(report => {
                let categories = 'N/A';
                if (Array.isArray(report.categories)) {
                    categories = report.categories.join(', ');
                } else if (typeof report.categories === 'string') {
                    try {
                        const parsed = JSON.parse(report.categories);
                        categories = Array.isArray(parsed) ? parsed.join(', ') : parsed;
                    } catch {
                        categories = report.categories;
                    }
                }
                
                return `
                    <tr>
                        <td><input type="checkbox" class="queue-checkbox" value="${report.id}"></td>
                        <td><code>${report.ip_address}</code></td>
                        <td><small>${categories}</small></td>
                        <td><small>${report.comment || '-'}</small></td>
                        <td><span class="badge bg-${report.source === 'auto' ? 'primary' : 'secondary'}">${report.source || 'manual'}</span></td>
                        <td><small>${new Date(report.created_at).toLocaleString()}</small></td>
                    </tr>
                `;
            }).join('');
        }
    } catch (error) {
        console.error('Error loading AbuseIPDB queue:', error);
    }
}

function toggleSelectAllQueue() {
    const selectAll = document.getElementById('select-all-checkbox') || document.getElementById('select-all-queue');
    const checkboxes = document.querySelectorAll('.queue-checkbox');
    checkboxes.forEach(cb => cb.checked = selectAll.checked);
}

async function submitSelectedReports() {
    const selected = Array.from(document.querySelectorAll('.queue-checkbox:checked')).map(cb => parseInt(cb.value));
    
    if (selected.length === 0) {
        showAlert('Please select at least one report to submit', 'warning');
        return;
    }
    
    if (!confirm(`Submit ${selected.length} report(s) to AbuseIPDB?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/abuseipdb/queue/submit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: selected }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert(result.message, 'success');
            loadAbuseIPDBQueue();
            loadAbuseIPDBStatus();
        } else {
            showAlert(result.error || 'Error submitting reports', 'danger');
        }
    } catch (error) {
        console.error('Error submitting reports:', error);
        showAlert('Error submitting reports', 'danger');
    }
}

async function deleteSelectedReports() {
    const selected = Array.from(document.querySelectorAll('.queue-checkbox:checked')).map(cb => parseInt(cb.value));
    
    if (selected.length === 0) {
        showAlert('Please select at least one report to delete', 'warning');
        return;
    }
    
    if (!confirm(`Delete ${selected.length} report(s)?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/abuseipdb/queue/delete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: selected }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert(result.message, 'success');
            loadAbuseIPDBQueue();
            loadAbuseIPDBStatus();
        } else {
            showAlert(result.error || 'Error deleting reports', 'danger');
        }
    } catch (error) {
        console.error('Error deleting reports:', error);
        showAlert('Error deleting reports', 'danger');
    }
}

// Reports Functions
function showReport(reportType) {
    // Hide all report sections
    document.querySelectorAll('.report-section').forEach(section => {
        section.style.display = 'none';
    });
    
    // Remove active class from all buttons
    document.querySelectorAll('.btn-group .btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected report
    const reportSection = document.getElementById(`report-${reportType}`);
    if (reportSection) {
        reportSection.style.display = 'block';
    }
    
    // Add active class to clicked button (if event exists)
    if (event && event.target) {
        event.target.classList.add('active');
    } else {
        // Find button by onclick attribute
        const buttons = document.querySelectorAll('.btn-group .btn');
        buttons.forEach(btn => {
            if (btn.getAttribute('onclick') && btn.getAttribute('onclick').includes(reportType)) {
                btn.classList.add('active');
            }
        });
    }
    
    // Load report data
    switch(reportType) {
        case 'top-offenders':
            loadTopOffenders();
            break;
        case 'packet-stats':
            loadPacketStats();
            break;
        case 'chain-stats':
            loadChainStats();
            break;
        case 'activity-timeline':
            loadActivityTimeline();
            break;
        case 'block-summary':
            loadBlockSummary();
            break;
    }
}

async function loadReports() {
    // Load default report (top offenders)
    showReport('top-offenders');
    loadTopOffenders();
}

async function refreshReports() {
    const activeReport = document.querySelector('.report-section[style*="block"]') || document.getElementById('report-top-offenders');
    if (activeReport) {
        const reportId = activeReport.id.replace('report-', '');
        showReport(reportId);
    }
}

async function loadTopOffenders() {
    const period = document.getElementById('top-offenders-period')?.value || 168;
    
    try {
        const response = await fetch(`${API_BASE}/reports/top-offenders?period=${period}`, fetchOptions);
        if (response.ok) {
            const data = await response.json();
            const tbody = document.getElementById('top-offenders-table');
            
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No data available</td></tr>';
                return;
            }
            
            tbody.innerHTML = data.map((item, index) => `
                <tr>
                    <td><span class="badge bg-${index < 3 ? 'danger' : 'secondary'}">#${index + 1}</span></td>
                    <td><code>${item.ip_address}</code></td>
                    <td><strong>${item.block_count || 0}</strong></td>
                    <td>${item.first_blocked ? new Date(item.first_blocked).toLocaleString() : 'N/A'}</td>
                    <td>${item.last_blocked ? new Date(item.last_blocked).toLocaleString() : 'N/A'}</td>
                    <td>${item.description || '-'}</td>
                </tr>
            `).join('');
        }
    } catch (error) {
        console.error('Error loading top offenders:', error);
        document.getElementById('top-offenders-table').innerHTML = 
            '<tr><td colspan="6" class="text-center text-danger">Error loading data</td></tr>';
    }
}

async function loadPacketStats() {
    try {
        const response = await fetch(`${API_BASE}/reports/packet-stats`, fetchOptions);
        if (response.ok) {
            const data = await response.json();
            
            // Chain packet stats
            const chainTbody = document.getElementById('chain-packet-stats-table');
            if (data.chains && data.chains.length > 0) {
                chainTbody.innerHTML = data.chains.map(chain => `
                    <tr>
                        <td><code>${chain.name}</code></td>
                        <td>${chain.packets.toLocaleString()}</td>
                        <td>${formatBytes(chain.bytes)}</td>
                    </tr>
                `).join('');
            } else {
                chainTbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No data available</td></tr>';
            }
            
            // IP packet stats
            const ipTbody = document.getElementById('ip-packet-stats-table');
            if (data.top_ips && data.top_ips.length > 0) {
                ipTbody.innerHTML = data.top_ips.map(ip => `
                    <tr>
                        <td><code>${ip.ip_address}</code></td>
                        <td>${ip.packets.toLocaleString()}</td>
                        <td>${formatBytes(ip.bytes)}</td>
                        <td><span class="badge bg-info">${ip.chain}</span></td>
                    </tr>
                `).join('');
            } else {
                ipTbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No data available</td></tr>';
            }
        }
    } catch (error) {
        console.error('Error loading packet stats:', error);
    }
}

async function loadChainStats() {
    try {
        const response = await fetch(`${API_BASE}/reports/chain-stats`, fetchOptions);
        if (response.ok) {
            const data = await response.json();
            
            // Update summary cards
            document.getElementById('whitelist-chain-rules').textContent = data.whitelist_rules || 0;
            document.getElementById('blacklist-chain-rules').textContent = data.blacklist_rules || 0;
            document.getElementById('rules-chain-rules').textContent = data.rules_count || 0;
            
            // Chain details table
            const tbody = document.getElementById('chain-stats-table');
            if (data.chains && data.chains.length > 0) {
                tbody.innerHTML = data.chains.map(chain => `
                    <tr>
                        <td><code>${chain.name}</code></td>
                        <td><span class="badge bg-${chain.policy === 'ACCEPT' ? 'success' : chain.policy === 'DROP' ? 'danger' : 'secondary'}">${chain.policy}</span></td>
                        <td>${chain.packets.toLocaleString()}</td>
                        <td>${formatBytes(chain.bytes)}</td>
                        <td>${chain.rule_count}</td>
                    </tr>
                `).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No data available</td></tr>';
            }
        }
    } catch (error) {
        console.error('Error loading chain stats:', error);
    }
}

async function loadActivityTimeline() {
    const period = document.getElementById('activity-period')?.value || 168;
    
    try {
        const response = await fetch(`${API_BASE}/reports/activity-timeline?period=${period}`, fetchOptions);
        if (response.ok) {
            const data = await response.json();
            const tbody = document.getElementById('activity-timeline-table');
            
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No activity in selected period</td></tr>';
                return;
            }
            
            tbody.innerHTML = data.map(activity => `
                <tr>
                    <td>${new Date(activity.timestamp).toLocaleString()}</td>
                    <td><span class="badge bg-info">${activity.action}</span></td>
                    <td>${activity.type || '-'}</td>
                    <td><code>${activity.entry || '-'}</code></td>
                    <td><span class="badge bg-${activity.status === 'success' ? 'success' : activity.status === 'error' ? 'danger' : 'warning'}">${activity.status}</span></td>
                </tr>
            `).join('');
        }
    } catch (error) {
        console.error('Error loading activity timeline:', error);
    }
}

async function loadBlockSummary() {
    try {
        const response = await fetch(`${API_BASE}/reports/block-summary`, fetchOptions);
        if (response.ok) {
            const data = await response.json();
            
            // Update summary stats
            document.getElementById('total-blocks').textContent = data.total_blocks || 0;
            document.getElementById('auto-blocks').textContent = data.auto_blocks || 0;
            document.getElementById('manual-blocks').textContent = data.manual_blocks || 0;
            document.getElementById('blocks-today').textContent = data.blocks_today || 0;
            document.getElementById('blocks-week').textContent = data.blocks_week || 0;
            
            // Block sources table
            const tbody = document.getElementById('block-sources-table');
            if (data.sources && data.sources.length > 0) {
                const total = data.sources.reduce((sum, s) => sum + s.count, 0);
                tbody.innerHTML = data.sources.map(source => {
                    const percentage = total > 0 ? ((source.count / total) * 100).toFixed(1) : 0;
                    return `
                        <tr>
                            <td>${source.source}</td>
                            <td>${source.count}</td>
                            <td>
                                <div class="progress" style="height: 20px;">
                                    <div class="progress-bar" role="progressbar" style="width: ${percentage}%">${percentage}%</div>
                                </div>
                            </td>
                        </tr>
                    `;
                }).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No data available</td></tr>';
            }
        }
    } catch (error) {
        console.error('Error loading block summary:', error);
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// URL Lists Functions
document.addEventListener('DOMContentLoaded', function() {
    const autoSyncCheckbox = document.getElementById('url-list-auto-sync');
    const syncIntervalGroup = document.getElementById('url-sync-interval-group');
    
    if (autoSyncCheckbox && syncIntervalGroup) {
        autoSyncCheckbox.addEventListener('change', function() {
            syncIntervalGroup.style.display = this.checked ? 'block' : 'none';
        });
    }
});

async function loadUrlLists() {
    try {
        const response = await fetch(`${API_BASE}/url-lists`, fetchOptions);
        if (response.ok) {
            const lists = await response.json();
            const tbody = document.getElementById('url-lists-table');
            
            if (lists.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No URL lists configured</td></tr>';
                return;
            }
            
            tbody.innerHTML = lists.map(list => {
                const statusBadge = list.enabled 
                    ? '<span class="badge bg-success">Enabled</span>'
                    : '<span class="badge bg-secondary">Disabled</span>';
                
                const autoSyncBadge = list.auto_sync
                    ? `<span class="badge bg-info">Every ${formatInterval(list.sync_interval)}</span>`
                    : '<span class="badge bg-secondary">Manual</span>';
                
                const lastSync = list.last_sync 
                    ? new Date(list.last_sync).toLocaleString()
                    : 'Never';
                
                const urlDisplay = list.url.length > 50 
                    ? list.url.substring(0, 50) + '...'
                    : list.url;
                
                return `
                    <tr>
                        <td><strong>${list.name}</strong></td>
                        <td><a href="${list.url}" target="_blank" title="${list.url}">${urlDisplay}</a></td>
                        <td><span class="badge bg-${list.list_type === 'whitelist' ? 'success' : 'danger'}">${list.list_type}</span></td>
                        <td>${statusBadge}</td>
                        <td><strong>${list.entry_count || 0}</strong></td>
                        <td><small>${lastSync}</small></td>
                        <td>${autoSyncBadge}</td>
                        <td>
                            <button class="btn btn-sm btn-primary" onclick="syncUrlList(${list.id})" title="Sync Now">
                                <i class="bi bi-arrow-clockwise"></i>
                            </button>
                            <button class="btn btn-sm btn-warning" onclick="toggleUrlList(${list.id}, ${!list.enabled})" title="${list.enabled ? 'Disable' : 'Enable'}">
                                <i class="bi bi-${list.enabled ? 'pause' : 'play'}-fill"></i>
                            </button>
                            <button class="btn btn-sm btn-danger" onclick="deleteUrlList(${list.id})" title="Delete">
                                <i class="bi bi-trash"></i>
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (error) {
        console.error('Error loading URL lists:', error);
        document.getElementById('url-lists-table').innerHTML = 
            '<tr><td colspan="8" class="text-center text-danger">Error loading URL lists</td></tr>';
    }
}

async function addUrlList() {
    const name = document.getElementById('url-list-name').value.trim();
    const url = document.getElementById('url-list-url').value.trim();
    const listType = document.getElementById('url-list-type').value;
    const description = document.getElementById('url-list-desc').value.trim();
    const enabled = document.getElementById('url-list-enabled').checked;
    const autoSync = document.getElementById('url-list-auto-sync').checked;
    const syncInterval = parseInt(document.getElementById('url-sync-interval').value) || 3600;
    
    if (!name || !url) {
        showAlert('Name and URL are required', 'warning');
        return;
    }
    
    if (autoSync && syncInterval < 60) {
        showAlert('Sync interval must be at least 60 seconds', 'warning');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/url-lists`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name,
                url,
                list_type: listType,
                description,
                enabled,
                auto_sync: autoSync,
                sync_interval: syncInterval
            }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert('URL list added successfully. Syncing now...', 'success');
            bootstrap.Modal.getInstance(document.getElementById('addUrlListModal')).hide();
            document.getElementById('url-list-form').reset();
            document.getElementById('url-sync-interval-group').style.display = 'none';
            
            // Auto-sync after adding
            if (result.id) {
                setTimeout(() => {
                    syncUrlList(result.id);
                    loadUrlLists();
                }, 500);
            }
        } else {
            showAlert(result.error || 'Error adding URL list', 'danger');
        }
    } catch (error) {
        console.error('Error adding URL list:', error);
        showAlert('Error adding URL list', 'danger');
    }
}

async function syncUrlList(id) {
    try {
        const response = await fetch(`${API_BASE}/url-lists/${id}/sync`, {
            method: 'POST',
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert(`Sync completed: ${result.entries_added || 0} entries added`, 'success');
            loadUrlLists();
            refreshStats();
            if (result.list_type === 'whitelist') loadWhitelist();
            if (result.list_type === 'blacklist') loadBlacklist();
        } else {
            showAlert(result.error || 'Error syncing URL list', 'danger');
        }
    } catch (error) {
        console.error('Error syncing URL list:', error);
        showAlert('Error syncing URL list', 'danger');
    }
}

async function toggleUrlList(id, enabled) {
    try {
        const response = await fetch(`${API_BASE}/url-lists/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert(`URL list ${enabled ? 'enabled' : 'disabled'}`, 'success');
            loadUrlLists();
        } else {
            showAlert(result.error || 'Error updating URL list', 'danger');
        }
    } catch (error) {
        console.error('Error toggling URL list:', error);
        showAlert('Error updating URL list', 'danger');
    }
}

async function deleteUrlList(id) {
    if (!confirm('Are you sure you want to delete this URL list? This will not remove the imported IPs.')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/url-lists/${id}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert('URL list deleted successfully', 'success');
            loadUrlLists();
        } else {
            showAlert(result.error || 'Error deleting URL list', 'danger');
        }
    } catch (error) {
        console.error('Error deleting URL list:', error);
        showAlert('Error deleting URL list', 'danger');
    }
}

function formatInterval(seconds) {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
    return `${Math.floor(seconds / 86400)}d`;
}

// AbuseIPDB Settings Functions
async function loadAbuseIPDBSettings() {
    try {
        const response = await fetch(`${API_BASE}/abuseipdb/status`, fetchOptions);
        if (response.ok) {
            const status = await response.json();
            
            // Update form fields (don't show full API key for security)
            const apiKeyInput = document.getElementById('abuseipdb-api-key');
            if (apiKeyInput) {
                if (status.api_key_configured) {
                    apiKeyInput.placeholder = 'API key is configured (enter new key to change)';
                    apiKeyInput.value = '';
                } else {
                    apiKeyInput.placeholder = 'Enter your AbuseIPDB API key';
                }
            }
            
            const modeSelect = document.getElementById('abuseipdb-mode');
            if (modeSelect) {
                modeSelect.value = status.mode || 'automatic';
            }
            
            const enabledCheckbox = document.getElementById('abuseipdb-enabled');
            if (enabledCheckbox) {
                enabledCheckbox.checked = status.enabled || false;
            }
            
            // Update status display
            const statusDisplay = document.getElementById('abuseipdb-status-display');
            if (statusDisplay) {
                const statusBadge = status.enabled 
                    ? '<span class="badge bg-success">Enabled</span>'
                    : '<span class="badge bg-secondary">Disabled</span>';
                
                const apiKeyStatus = status.api_key_configured
                    ? '<span class="badge bg-success">Configured</span>'
                    : '<span class="badge bg-warning">Not Configured</span>';
                
                statusDisplay.innerHTML = `
                    <div class="mb-2">
                        <strong>Status:</strong> ${statusBadge}
                    </div>
                    <div class="mb-2">
                        <strong>API Key:</strong> ${apiKeyStatus}
                    </div>
                    <div class="mb-2">
                        <strong>Mode:</strong> <span class="badge bg-info">${status.mode || 'automatic'}</span>
                    </div>
                    <div class="mb-2">
                        <strong>Queue Count:</strong> ${status.queue_count || 0} pending reports
                    </div>
                `;
            }
        }
    } catch (error) {
        console.error('Error loading AbuseIPDB settings:', error);
    }
}

async function saveAbuseIPDBSettings() {
    const apiKey = document.getElementById('abuseipdb-api-key').value.trim();
    const mode = document.getElementById('abuseipdb-mode').value;
    const enabled = document.getElementById('abuseipdb-enabled').checked;
    
    try {
        const response = await fetch(`${API_BASE}/settings/abuseipdb`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                api_key: apiKey || null,
                mode: mode,
                enabled: enabled
            }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert('AbuseIPDB settings saved successfully. Restart the server for changes to take full effect.', 'success');
            loadAbuseIPDBSettings();
        } else {
            showAlert(result.error || 'Error saving AbuseIPDB settings', 'danger');
        }
    } catch (error) {
        console.error('Error saving AbuseIPDB settings:', error);
        showAlert('Error saving AbuseIPDB settings', 'danger');
    }
}

async function testAbuseIPDBConnection() {
    try {
        const response = await fetch(`${API_BASE}/abuseipdb/status`, fetchOptions);
        if (response.ok) {
            const status = await response.json();
            if (status.enabled && status.api_key_configured) {
                showAlert('AbuseIPDB connection test successful', 'success');
            } else {
                showAlert('AbuseIPDB is not configured. Please enter an API key.', 'warning');
            }
        } else {
            showAlert('Error testing AbuseIPDB connection', 'danger');
        }
    } catch (error) {
        console.error('Error testing AbuseIPDB connection:', error);
        showAlert('Error testing AbuseIPDB connection', 'danger');
    }
}

function toggleApiKeyVisibility() {
    const apiKeyInput = document.getElementById('abuseipdb-api-key');
    const eyeIcon = document.getElementById('api-key-eye-icon');
    
    if (apiKeyInput.type === 'password') {
        apiKeyInput.type = 'text';
        eyeIcon.className = 'bi bi-eye-slash';
    } else {
        apiKeyInput.type = 'password';
        eyeIcon.className = 'bi bi-eye';
    }
}

// System Settings Functions
async function loadSystemSettings() {
    try {
        const response = await fetch(`${API_BASE}/settings`, fetchOptions);
        if (response.ok) {
            const settings = await response.json();
            
            // Server settings
            if (settings.server) {
                document.getElementById('server-host').value = settings.server.host || '';
                document.getElementById('server-port').value = settings.server.port || '';
                document.getElementById('secret-key').value = settings.server.secret_key || '';
            }
            
            // Database settings
            if (settings.database) {
                document.getElementById('db-host').value = settings.database.host || '';
                document.getElementById('db-name').value = settings.database.name || '';
                document.getElementById('db-user').value = settings.database.user || '';
                // Don't load password for security
            }
            
            // OIDC settings
            if (settings.oidc) {
                document.getElementById('oidc-issuer').value = settings.oidc.issuer || '';
                document.getElementById('oidc-client-id').value = settings.oidc.client_id || '';
                document.getElementById('oidc-client-secret').value = settings.oidc.client_secret || '';
                document.getElementById('oidc-redirect-uri').value = settings.oidc.redirect_uri || '';
                document.getElementById('oidc-post-logout-uri').value = settings.oidc.post_logout_uri || '';
            }
            
            // Monitoring settings
            if (settings.monitoring) {
                document.getElementById('enable-log-monitoring').checked = settings.monitoring.enabled || false;
                document.getElementById('monitor-services').value = settings.monitoring.services || '';
            }
        }
    } catch (error) {
        console.error('Error loading system settings:', error);
    }
}

async function saveServerSettings() {
    const host = document.getElementById('server-host').value.trim();
    const port = document.getElementById('server-port').value.trim();
    const secretKey = document.getElementById('secret-key').value.trim();
    
    try {
        const response = await fetch(`${API_BASE}/settings/server`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                host: host,
                port: port,
                secret_key: secretKey || null
            }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert('Server settings saved. Restart the server for changes to take effect.', 'success');
        } else {
            showAlert(result.error || 'Error saving server settings', 'danger');
        }
    } catch (error) {
        console.error('Error saving server settings:', error);
        showAlert('Error saving server settings', 'danger');
    }
}

async function saveDatabaseSettings() {
    const host = document.getElementById('db-host').value.trim();
    const name = document.getElementById('db-name').value.trim();
    const user = document.getElementById('db-user').value.trim();
    const password = document.getElementById('db-password').value.trim();
    
    try {
        const response = await fetch(`${API_BASE}/settings/database`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                host: host,
                name: name,
                user: user,
                password: password || null
            }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert('Database settings saved. Restart the server for changes to take effect.', 'success');
            document.getElementById('db-password').value = '';
        } else {
            showAlert(result.error || 'Error saving database settings', 'danger');
        }
    } catch (error) {
        console.error('Error saving database settings:', error);
        showAlert('Error saving database settings', 'danger');
    }
}

async function testDatabaseConnection() {
    const host = document.getElementById('db-host').value.trim();
    const name = document.getElementById('db-name').value.trim();
    const user = document.getElementById('db-user').value.trim();
    const password = document.getElementById('db-password').value.trim();
    
    try {
        const response = await fetch(`${API_BASE}/settings/database/test`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                host: host,
                name: name,
                user: user,
                password: password || null
            }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok && result.success) {
            showAlert('Database connection test successful', 'success');
        } else {
            showAlert(result.error || 'Database connection test failed', 'danger');
        }
    } catch (error) {
        console.error('Error testing database connection:', error);
        showAlert('Error testing database connection', 'danger');
    }
}

async function saveOIDCSettings() {
    const issuer = document.getElementById('oidc-issuer').value.trim();
    const clientId = document.getElementById('oidc-client-id').value.trim();
    const clientSecret = document.getElementById('oidc-client-secret').value.trim();
    const redirectUri = document.getElementById('oidc-redirect-uri').value.trim();
    const postLogoutUri = document.getElementById('oidc-post-logout-uri').value.trim();
    
    try {
        const response = await fetch(`${API_BASE}/settings/oidc`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                issuer: issuer,
                client_id: clientId,
                client_secret: clientSecret || null,
                redirect_uri: redirectUri,
                post_logout_uri: postLogoutUri
            }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert('OIDC settings saved. Restart the server for changes to take effect.', 'success');
        } else {
            showAlert(result.error || 'Error saving OIDC settings', 'danger');
        }
    } catch (error) {
        console.error('Error saving OIDC settings:', error);
        showAlert('Error saving OIDC settings', 'danger');
    }
}

async function saveMonitoringSettings() {
    const enabled = document.getElementById('enable-log-monitoring').checked;
    const services = document.getElementById('monitor-services').value.trim();
    
    try {
        const response = await fetch(`${API_BASE}/settings/monitoring`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                enabled: enabled,
                services: services
            }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert('Monitoring settings saved. Restart the server for changes to take effect.', 'success');
        } else {
            showAlert(result.error || 'Error saving monitoring settings', 'danger');
        }
    } catch (error) {
        console.error('Error saving monitoring settings:', error);
        showAlert('Error saving monitoring settings', 'danger');
    }
}

// Tab Navigation
document.addEventListener('DOMContentLoaded', function() {
    console.log('=== bWall Dashboard Initialization ===');
    console.log('DOM loaded, initializing...');
    console.log('API Base URL:', API_BASE);
    
    // Initialize tabs immediately (don't wait for auth)
    const navLinks = document.querySelectorAll('.sidebar .nav-link');
    console.log('Found nav links:', navLinks.length);
    
    if (navLinks.length === 0) {
        console.error('ERROR: No nav links found! Check HTML structure.');
    }
    
    navLinks.forEach((link, index) => {
        const tabName = link.getAttribute('data-tab');
        console.log(`Setting up nav link ${index + 1}: ${tabName}`);
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const tab = this.getAttribute('data-tab');
            console.log('Nav link clicked, switching to tab:', tab);
            if (typeof switchTab === 'function') {
                switchTab(tab);
            } else {
                console.error('ERROR: switchTab function not defined!');
            }
        });
    });

    // Load initial data
    console.log('Switching to dashboard tab...');
    if (typeof switchTab === 'function') {
        switchTab('dashboard');
    } else {
        console.error('ERROR: switchTab function not available on page load!');
    }
    
    // Check authentication in background (non-blocking)
    checkAuthentication().then(() => {
        console.log('Authentication check completed');
        if (typeof refreshStats === 'function') {
            refreshStats();
        } else {
            console.error('ERROR: refreshStats function not defined!');
        }
    }).catch(error => {
        console.error('Authentication check failed:', error);
        // Continue anyway - load stats
        console.log('Loading stats despite auth error...');
        if (typeof refreshStats === 'function') {
            refreshStats();
        } else {
            console.error('ERROR: refreshStats function not defined!');
        }
    });
    
    console.log('Initialization complete');
    console.log('Available functions:', {
        switchTab: typeof switchTab,
        refreshStats: typeof refreshStats,
        loadWhitelist: typeof loadWhitelist,
        loadBlacklist: typeof loadBlacklist
    });
});

// Authentication Functions
async function checkAuthentication() {
    try {
        const response = await fetch(`${API_BASE}/auth/user`, {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.authenticated) {
                isAuthenticated = true;
                currentUser = data.user;
                updateUserInterface();
            } else if (data.oidc_available === false) {
                // OIDC not available (e.g., Python 3.13), allow access
                console.log('OIDC not available, running without authentication');
                isAuthenticated = true;
            }
            // If authenticated is false but oidc_available is true, 
            // user needs to authenticate (will be handled by OIDC redirect)
        } else if (response.status === 401 || response.status === 403) {
            // Check if OIDC is available - if not, allow access
            try {
                const data = await response.json();
                if (data.oidc_available === false) {
                    isAuthenticated = true;
                    return;
                }
            } catch (e) {
                // If we can't parse response, assume OIDC redirect will handle it
            }
            // Not authenticated, will be redirected by OIDC if available
            return;
        }
    } catch (error) {
        console.error('Error checking authentication:', error);
        // If OIDC is not configured or not available, continue without authentication
        console.log('Continuing without authentication');
        isAuthenticated = true; // Allow access if OIDC is not configured
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
    console.log('Switching to tab:', tabName);
    
    if (!tabName) {
        console.error('No tab name provided');
        return;
    }
    
    // Hide all tabs
    const allTabs = document.querySelectorAll('.tab-content');
    console.log('Found tab-content elements:', allTabs.length);
    allTabs.forEach(tab => {
        tab.style.display = 'none';
    });

    // Remove active class from nav links
    const allNavLinks = document.querySelectorAll('.sidebar .nav-link');
    allNavLinks.forEach(link => {
        link.classList.remove('active');
    });

    // Show selected tab
    const tabId = `${tabName}-tab`;
    const tabElement = document.getElementById(tabId);
    if (tabElement) {
        tabElement.style.display = 'block';
        console.log('Tab displayed:', tabName, 'ID:', tabId);
    } else {
        console.error('Tab element not found. Looking for ID:', tabId);
        console.log('Available tab IDs:', Array.from(document.querySelectorAll('.tab-content')).map(t => t.id));
    }

    // Add active class to nav link
    const navLink = document.querySelector(`[data-tab="${tabName}"]`);
    if (navLink) {
        navLink.classList.add('active');
        console.log('Nav link activated for:', tabName);
    } else {
        console.error('Nav link not found for tab:', tabName);
        console.log('Available data-tab values:', Array.from(document.querySelectorAll('[data-tab]')).map(l => l.getAttribute('data-tab')));
    }

    // Load tab-specific data
    try {
        switch(tabName) {
            case 'whitelist':
                console.log('Loading whitelist data...');
                loadWhitelist();
                break;
            case 'blacklist':
                console.log('Loading blacklist data...');
                loadBlacklist();
                loadAbuseIPDBStatus();
                break;
            case 'rules':
                console.log('Loading rules data...');
                loadRules();
                break;
            case 'sync':
                console.log('Loading sync data...');
                checkDbStatus();
                break;
            case 'monitor':
                console.log('Loading monitor data...');
                loadMonitorStatus();
                loadMonitorConfig();
                loadRecentBlocks();
                break;
            case 'dashboard':
                console.log('Loading dashboard data...');
                refreshStats();
                break;
            case 'import-export':
                console.log('Import/Export tab - no data to load');
                break;
            case 'reports':
                console.log('Loading reports data...');
                loadReports();
                break;
            case 'url-lists':
                console.log('Loading URL lists data...');
                loadUrlLists();
                break;
            case 'abuseipdb-settings':
                console.log('Loading AbuseIPDB settings...');
                loadAbuseIPDBSettings();
                break;
            case 'settings':
                console.log('Loading system settings...');
                loadSystemSettings();
                break;
            default:
                console.warn('Unknown tab:', tabName);
        }
    } catch (error) {
        console.error('Error loading tab data for', tabName, ':', error);
    }
}

// Dashboard Functions
async function refreshStats() {
    try {
        console.log('Fetching stats from:', `${API_BASE}/stats`);
        const response = await fetch(`${API_BASE}/stats`, fetchOptions);
        
        console.log('Stats response status:', response.status);
        
        if (response.status === 401 || response.status === 403) {
            console.warn('Stats endpoint returned 401/403 - checking auth status');
            // Check if OIDC is available
            try {
                const authCheck = await fetch(`${API_BASE}/auth/user`, fetchOptions);
                const authData = await authCheck.json();
                console.log('Auth check result:', authData);
                if (authData.oidc_available === false) {
                    // OIDC not available, but we should still be able to access
                    console.warn('Stats endpoint returned 401/403 but OIDC not available - this is unexpected');
                }
            } catch (e) {
                console.error('Error checking auth:', e);
            }
            return;
        }
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Stats endpoint error:', response.status, errorText);
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }
        
        const data = await response.json();
        console.log('Stats data received:', data);
        
        if (document.getElementById('stat-total-rules')) {
            document.getElementById('stat-total-rules').textContent = data.total_rules || 0;
        }
        if (document.getElementById('stat-whitelist')) {
            document.getElementById('stat-whitelist').textContent = data.whitelist_count || 0;
        }
        if (document.getElementById('stat-blacklist')) {
            document.getElementById('stat-blacklist').textContent = data.blacklist_count || 0;
        }
        if (document.getElementById('stat-sync-status')) {
            document.getElementById('stat-sync-status').textContent = data.db_connected ? 'Connected' : 'Disconnected';
        }
        
        loadActivityLog();
    } catch (error) {
        console.error('Error refreshing stats:', error);
        console.error('Error details:', error.message, error.stack);
        // Show error in console but don't block the UI
        if (error.message && !error.message.includes('401') && !error.message.includes('403')) {
            console.warn('Could not load statistics:', error.message);
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
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No blacklist entries</td></tr>';
            return;
        }
        
        // Check AbuseIPDB status for each entry (async, will update as results come in)
        tbody.innerHTML = entries.map(entry => `
            <tr id="blacklist-row-${entry.id}">
                <td>${entry.id}</td>
                <td><code>${entry.ip_address}</code></td>
                <td>${entry.description || '-'}</td>
                <td id="abuseipdb-${entry.id}">
                    <button class="btn btn-sm btn-outline-info" onclick="checkAbuseIPDBForEntry('${entry.ip_address}', ${entry.id})" title="Check AbuseIPDB">
                        <i class="bi bi-search"></i>
                    </button>
                </td>
                <td>${new Date(entry.created_at).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="deleteBlacklistEntry(${entry.id})">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
        
        // Optionally pre-check AbuseIPDB for all entries (can be slow, so commented out)
        // entries.forEach(entry => {
        //     checkAbuseIPDBForEntry(entry.ip_address, entry.id, false);
        // });
    } catch (error) {
        console.error('Error loading blacklist:', error);
        showAlert('Error loading blacklist', 'danger');
    }
}

async function checkAbuseIPDB() {
    const ip = document.getElementById('blacklist-ip').value.trim();
    const resultDiv = document.getElementById('abuseipdb-check-result');
    
    if (!ip) {
        resultDiv.innerHTML = '<div class="alert alert-warning">Please enter an IP address first</div>';
        return;
    }
    
    resultDiv.innerHTML = '<div class="text-info"><i class="bi bi-hourglass-split"></i> Checking...</div>';
    
    try {
        const response = await fetch(`${API_BASE}/abuseipdb/check?ip=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`, fetchOptions);
        const result = await response.json();
        
        if (response.ok && result.data) {
            const data = result.data;
            const score = data.abuseConfidenceScore || 0;
            const scoreClass = score >= 75 ? 'danger' : score >= 50 ? 'warning' : 'success';
            
            let html = `<div class="alert alert-${scoreClass}">`;
            html += `<strong>Abuse Confidence Score: ${score}%</strong><br>`;
            html += `Total Reports: ${data.totalReports || 0}<br>`;
            html += `Country: ${data.countryName || 'Unknown'} (${data.countryCode || 'N/A'})<br>`;
            html += `ISP: ${data.isp || 'Unknown'}<br>`;
            if (data.isWhitelisted) {
                html += `<span class="badge bg-info">Whitelisted</span> `;
            }
            if (data.isTor) {
                html += `<span class="badge bg-dark">Tor Exit Node</span>`;
            }
            html += `</div>`;
            
            if (data.reports && data.reports.length > 0) {
                html += `<details class="mt-2"><summary>Recent Reports (${data.reports.length})</summary><ul class="small mt-2">`;
                data.reports.slice(0, 5).forEach(report => {
                    html += `<li>${new Date(report.reportedAt).toLocaleString()}: ${report.comment || 'No comment'}</li>`;
                });
                html += `</ul></details>`;
            }
            
            resultDiv.innerHTML = html;
        } else {
            resultDiv.innerHTML = `<div class="alert alert-warning">${result.error || 'Unable to check AbuseIPDB'}</div>`;
        }
    } catch (error) {
        console.error('Error checking AbuseIPDB:', error);
        resultDiv.innerHTML = `<div class="alert alert-danger">Error checking AbuseIPDB: ${error.message}</div>`;
    }
}

async function addBlacklistEntry() {
    const ip = document.getElementById('blacklist-ip').value.trim();
    const desc = document.getElementById('blacklist-desc').value.trim();
    const reportToAbuseIPDB = document.getElementById('report-to-abuseipdb')?.checked || false;
    
    if (!ip) {
        showAlert('Please enter an IP address', 'warning');
        return;
    }
    
    const body = {
        ip_address: ip,
        description: desc,
        report_to_abuseipdb: reportToAbuseIPDB
    };
    
    if (reportToAbuseIPDB) {
        const categories = Array.from(document.querySelectorAll('input[name="abuseipdb-cat"]:checked'))
            .map(cb => cb.value);
        if (categories.length > 0) {
            body.abuseipdb_categories = categories;
        }
    }
    
    try {
        const response = await fetch(`${API_BASE}/blacklist`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            let message = 'Blacklist entry added successfully';
            if (result.abuseipdb_reported) {
                message += ' and reported to AbuseIPDB';
            }
            showAlert(message, 'success');
            bootstrap.Modal.getInstance(document.getElementById('addBlacklistModal')).hide();
            document.getElementById('blacklist-form').reset();
            const resultDiv = document.getElementById('abuseipdb-check-result');
            if (resultDiv) resultDiv.innerHTML = '';
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

async function checkAbuseIPDBForEntry(ip, entryId, showDetails = true) {
    const cell = document.getElementById(`abuseipdb-${entryId}`);
    if (!cell) return;
    
    cell.innerHTML = '<i class="bi bi-hourglass-split"></i>';
    
    try {
        const response = await fetch(`${API_BASE}/abuseipdb/check?ip=${encodeURIComponent(ip)}&maxAgeInDays=90`, fetchOptions);
        const result = await response.json();
        
        if (response.ok && result.data) {
            const data = result.data;
            const score = data.abuseConfidenceScore || 0;
            const scoreClass = score >= 75 ? 'danger' : score >= 50 ? 'warning' : 'success';
            const badgeClass = score >= 75 ? 'bg-danger' : score >= 50 ? 'bg-warning' : 'bg-success';
            
            let html = `<span class="badge ${badgeClass}" title="Abuse Confidence Score: ${score}%">${score}%</span>`;
            if (showDetails && data.totalReports > 0) {
                html += ` <small class="text-muted">(${data.totalReports} reports)</small>`;
            }
            cell.innerHTML = html;
        } else {
            cell.innerHTML = '<span class="badge bg-secondary" title="Unable to check">N/A</span>';
        }
    } catch (error) {
        console.error('Error checking AbuseIPDB for entry:', error);
        cell.innerHTML = '<span class="badge bg-secondary" title="Error checking">Error</span>';
    }
}

async function deleteBlacklistEntry(id) {
    if (!confirm('Are you sure you want to delete this blacklist entry?')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/blacklist/${id}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showAlert(result.message || 'Blacklist entry deleted successfully', 'success');
            loadBlacklist();
            refreshStats();
        } else {
            const errorMsg = result.error || result.message || 'Error deleting blacklist entry';
            console.error('Delete blacklist error:', errorMsg);
            showAlert(errorMsg, 'danger');
        }
    } catch (error) {
        console.error('Error deleting blacklist entry:', error);
        showAlert(`Error deleting blacklist entry: ${error.message}`, 'danger');
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
    const statusDiv = document.getElementById('db-status');
    const lastSyncDiv = document.getElementById('last-sync');
    
    try {
        // First test the connection
        const testResponse = await fetch(`${API_BASE}/db/test`, fetchOptions);
        const testResult = await testResponse.json();
        
        if (testResult.connected) {
            // If connected, get sync status
            const response = await fetch(`${API_BASE}/sync/status`, fetchOptions);
            const status = await response.json();
            
            statusDiv.textContent = 'Connected';
            statusDiv.className = 'badge bg-success';
            if (lastSyncDiv) {
                lastSyncDiv.textContent = status.last_sync ? new Date(status.last_sync).toLocaleString() : 'Never';
            }
        } else {
            statusDiv.textContent = 'Disconnected';
            statusDiv.className = 'badge bg-danger';
            if (lastSyncDiv) {
                lastSyncDiv.textContent = 'N/A';
            }
            
            // Show error details in console
            console.error('Database connection error:', testResult.error);
            if (testResult.suggestions) {
                console.log('Suggestions:', testResult.suggestions);
            }
        }
    } catch (error) {
        console.error('Error checking DB status:', error);
        statusDiv.textContent = 'Error';
        statusDiv.className = 'badge bg-danger';
        if (lastSyncDiv) {
            lastSyncDiv.textContent = 'N/A';
        }
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
            let html = `
                <div class="text-success">✓ Synchronization completed successfully</div>
                <div class="text-muted">${result.message || ''}</div>
                <div class="text-muted mt-2">Whitelist: ${result.whitelist_synced || 0} entries</div>
                <div class="text-muted">Blacklist: ${result.blacklist_synced || 0} entries</div>
                <div class="text-muted">Rules: ${result.rules_synced || 0} entries</div>
            `;
            
            // Show warnings if any
            if (result.warnings) {
                if (result.warnings.whitelist_errors && result.warnings.whitelist_errors.length > 0) {
                    html += `<div class="text-warning mt-2">⚠ Whitelist errors: ${result.warnings.whitelist_errors.length}</div>`;
                }
                if (result.warnings.blacklist_errors && result.warnings.blacklist_errors.length > 0) {
                    html += `<div class="text-warning">⚠ Blacklist errors: ${result.warnings.blacklist_errors.length}</div>`;
                }
            }
            
            logDiv.innerHTML = html;
            showAlert('Synchronization completed successfully', 'success');
            checkDbStatus();
            refreshStats();
        } else {
            const errorMsg = result.error || result.message || 'Synchronization failed';
            console.error('Sync error:', errorMsg, result);
            logDiv.innerHTML = `<div class="text-danger">✗ Error: ${errorMsg}</div>`;
            showAlert(`Synchronization failed: ${errorMsg}`, 'danger');
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

