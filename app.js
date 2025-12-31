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

// Crowdsource Lists Functions
document.addEventListener('DOMContentLoaded', function() {
    const autoSyncCheckbox = document.getElementById('crowdsource-auto-sync');
    const syncIntervalGroup = document.getElementById('crowdsource-sync-interval-group');
    
    if (autoSyncCheckbox && syncIntervalGroup) {
        autoSyncCheckbox.addEventListener('change', function() {
            syncIntervalGroup.style.display = this.checked ? 'block' : 'none';
        });
    }
});

function load3FIFTYnetList() {
    document.getElementById('crowdsource-name').value = '3FIFTYnet Abusive Subnets';
    document.getElementById('crowdsource-url').value = 'https://raw.githubusercontent.com/3FIFTYnet/dbl/refs/heads/main/abusive_subnet_24_blacklist.txt';
    document.getElementById('crowdsource-type').value = 'blacklist';
    document.getElementById('crowdsource-desc').value = 'Community-maintained list of abusive /24 subnets from 3FIFTYnet. Based on known and verifiable abusive and excessive network traffic.';
    document.getElementById('crowdsource-auto-sync').checked = true;
    document.getElementById('crowdsource-sync-interval-group').style.display = 'block';
    showAlert('3FIFTYnet list loaded. Review settings and click "Add List" to import.', 'info');
}

async function loadCrowdsourceLists() {
    try {
        const response = await fetch(`${API_BASE}/url-lists`, fetchOptions);
        if (response.ok) {
            const lists = await response.json();
            const tbody = document.getElementById('crowdsource-table');
            
            if (lists.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No crowdsource lists configured. Click "Add Crowdsource List" to get started.</td></tr>';
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
                            <button class="btn btn-sm btn-primary" onclick="syncCrowdsourceList(${list.id})" title="Sync Now">
                                <i class="bi bi-arrow-clockwise"></i>
                            </button>
                            <button class="btn btn-sm btn-warning" onclick="toggleCrowdsourceList(${list.id}, ${!list.enabled})" title="${list.enabled ? 'Disable' : 'Enable'}">
                                <i class="bi bi-${list.enabled ? 'pause' : 'play'}-fill"></i>
                            </button>
                            <button class="btn btn-sm btn-danger" onclick="deleteCrowdsourceList(${list.id})" title="Delete">
                                <i class="bi bi-trash"></i>
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (error) {
        console.error('Error loading crowdsource lists:', error);
        document.getElementById('crowdsource-table').innerHTML = 
            '<tr><td colspan="8" class="text-center text-danger">Error loading crowdsource lists</td></tr>';
    }
}

async function addCrowdsourceList() {
    const name = document.getElementById('crowdsource-name').value.trim();
    const url = document.getElementById('crowdsource-url').value.trim();
    const listType = document.getElementById('crowdsource-type').value;
    const description = document.getElementById('crowdsource-desc').value.trim();
    const enabled = document.getElementById('crowdsource-enabled').checked;
    const autoSync = document.getElementById('crowdsource-auto-sync').checked;
    const syncInterval = parseInt(document.getElementById('crowdsource-sync-interval').value) || 3600;
    
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
            showAlert('Crowdsource list added successfully. Syncing now...', 'success');
            bootstrap.Modal.getInstance(document.getElementById('addCrowdsourceModal')).hide();
            document.getElementById('crowdsource-form').reset();
            document.getElementById('crowdsource-sync-interval-group').style.display = 'none';
            
            // Auto-sync after adding
            if (result.id) {
                setTimeout(() => {
                    syncCrowdsourceList(result.id);
                    loadCrowdsourceLists();
                }, 500);
            }
        } else {
            showAlert(result.error || 'Error adding crowdsource list', 'danger');
        }
    } catch (error) {
        console.error('Error adding crowdsource list:', error);
        showAlert('Error adding crowdsource list', 'danger');
    }
}

async function syncCrowdsourceList(id) {
    try {
        const response = await fetch(`${API_BASE}/url-lists/${id}/sync`, {
            method: 'POST',
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert(`Sync completed: ${result.entries_added || 0} entries added`, 'success');
            loadCrowdsourceLists();
            refreshStats();
            if (result.list_type === 'whitelist') loadWhitelist();
            if (result.list_type === 'blacklist') loadBlacklist();
        } else {
            showAlert(result.error || 'Error syncing crowdsource list', 'danger');
        }
    } catch (error) {
        console.error('Error syncing crowdsource list:', error);
        showAlert('Error syncing crowdsource list', 'danger');
    }
}

async function toggleCrowdsourceList(id, enabled) {
    try {
        const response = await fetch(`${API_BASE}/url-lists/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert(`Crowdsource list ${enabled ? 'enabled' : 'disabled'}`, 'success');
            loadCrowdsourceLists();
        } else {
            showAlert(result.error || 'Error updating crowdsource list', 'danger');
        }
    } catch (error) {
        console.error('Error toggling crowdsource list:', error);
        showAlert('Error updating crowdsource list', 'danger');
    }
}

async function deleteCrowdsourceList(id) {
    if (!confirm('Are you sure you want to delete this crowdsource list? This will not remove the imported IPs.')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/url-lists/${id}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert('Crowdsource list deleted successfully', 'success');
            loadCrowdsourceLists();
        } else {
            showAlert(result.error || 'Error deleting crowdsource list', 'danger');
        }
    } catch (error) {
        console.error('Error deleting crowdsource list:', error);
        showAlert('Error deleting crowdsource list', 'danger');
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
        }
        
        // Load appearance, proxy, and monitoring settings
        await loadAppearanceSettings();
        await loadProxySettings();
        await loadMonitoringSettings();
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

async function loadMonitoringSettings() {
    try {
        // Load monitoring settings
        const settingsResponse = await fetch(`${API_BASE}/monitoring/settings`, fetchOptions);
        if (settingsResponse.ok) {
            const settings = await settingsResponse.json();
            
            document.getElementById('enable-log-monitoring').checked = settings.enabled || false;
            document.getElementById('monitor-threshold').value = settings.threshold || 5;
            document.getElementById('monitor-duration').value = settings.duration || 60;
            document.getElementById('history-retention').value = settings.history_retention || 90;
            document.getElementById('enable-permaban').checked = settings.permaban_enabled || false;
            document.getElementById('permaban-threshold').value = settings.permaban_threshold || 10;
            
            // Show/hide permaban settings
            const permabanSettings = document.getElementById('permaban-settings');
            if (permabanSettings) {
                permabanSettings.style.display = settings.permaban_enabled ? 'block' : 'none';
            }
        }
        
        // Load monitored services
        const servicesResponse = await fetch(`${API_BASE}/monitoring/services`, fetchOptions);
        if (servicesResponse.ok) {
            const services = await servicesResponse.json();
            const servicesList = document.getElementById('monitored-services-list');
            
            if (servicesList && services.length > 0) {
                servicesList.innerHTML = services.map(service => `
                    <div class="card mb-2">
                        <div class="card-body p-2">
                            <div class="row align-items-center">
                                <div class="col-md-4">
                                    <div class="form-check">
                                        <input class="form-check-input service-toggle" type="checkbox" 
                                               id="service-${service.service_name}" 
                                               data-service="${service.service_name}"
                                               ${service.enabled ? 'checked' : ''}>
                                        <label class="form-check-label" for="service-${service.service_name}">
                                            <strong>${service.service_name}</strong>
                                        </label>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label small">Threshold</label>
                                    <input type="number" class="form-control form-control-sm service-threshold" 
                                           data-service="${service.service_name}"
                                           value="${service.threshold || 5}" min="1" max="100">
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label small">Duration (min)</label>
                                    <input type="number" class="form-control form-control-sm service-duration" 
                                           data-service="${service.service_name}"
                                           value="${service.duration_minutes || 60}" min="1" max="1440">
                                </div>
                            </div>
                        </div>
                    </div>
                `).join('');
            }
        }
    } catch (error) {
        console.error('Error loading monitoring settings:', error);
    }
}

async function saveMonitoringSettings() {
    const enabled = document.getElementById('enable-log-monitoring').checked;
    const threshold = parseInt(document.getElementById('monitor-threshold').value) || 5;
    const duration = parseInt(document.getElementById('monitor-duration').value) || 60;
    const historyRetention = parseInt(document.getElementById('history-retention').value) || 90;
    const permabanEnabled = document.getElementById('enable-permaban').checked;
    const permabanThreshold = parseInt(document.getElementById('permaban-threshold').value) || 10;
    
    // Collect service configurations
    const services = [];
    document.querySelectorAll('.service-toggle').forEach(checkbox => {
        const serviceName = checkbox.dataset.service;
        const thresholdInput = document.querySelector(`.service-threshold[data-service="${serviceName}"]`);
        const durationInput = document.querySelector(`.service-duration[data-service="${serviceName}"]`);
        
        services.push({
            service_name: serviceName,
            enabled: checkbox.checked,
            threshold: parseInt(thresholdInput?.value) || 5,
            duration_minutes: parseInt(durationInput?.value) || 60
        });
    });
    
    try {
        // Save monitoring settings
        const settingsResponse = await fetch(`${API_BASE}/monitoring/settings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                enabled: enabled,
                threshold: threshold,
                duration: duration,
                history_retention: historyRetention,
                permaban_enabled: permabanEnabled,
                permaban_threshold: permabanThreshold
            }),
            credentials: 'include'
        });
        
        // Save service configurations
        const servicesResponse = await fetch(`${API_BASE}/monitoring/services`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ services: services }),
            credentials: 'include'
        });
        
        if (settingsResponse.ok && servicesResponse.ok) {
            showAlert('Monitoring settings saved. Restart the server for changes to take effect.', 'success');
            // Optionally trigger history pruning
            if (historyRetention > 0) {
                fetch(`${API_BASE}/monitoring/prune-history`, {
                    method: 'POST',
                    credentials: 'include'
                }).catch(() => {}); // Silent fail
            }
        } else {
            const error = await settingsResponse.json().catch(() => ({ error: 'Unknown error' }));
            showAlert(error.error || 'Error saving monitoring settings', 'danger');
        }
    } catch (error) {
        console.error('Error saving monitoring settings:', error);
        showAlert('Error saving monitoring settings', 'danger');
    }
}

// Setup permaban toggle
document.addEventListener('DOMContentLoaded', function() {
    const enablePermabanCheckbox = document.getElementById('enable-permaban');
    const permabanSettings = document.getElementById('permaban-settings');
    
    if (enablePermabanCheckbox && permabanSettings) {
        enablePermabanCheckbox.addEventListener('change', function() {
            permabanSettings.style.display = this.checked ? 'block' : 'none';
        });
    }
});

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
            } else {
                // Not authenticated - show login modal if local auth is available
                if (data.local_auth_available && !data.oidc_available) {
                    showLoginModal();
                } else if (data.oidc_available) {
                    // OIDC will handle redirect
                    console.log('OIDC authentication required');
                } else {
                    // No auth available - this shouldn't happen but allow access
                    console.log('No authentication available');
                    isAuthenticated = true;
                }
            }
        } else if (response.status === 401 || response.status === 403) {
            // Check what auth is available
            try {
                const data = await response.json();
                if (data.local_auth_available && !data.oidc_available) {
                    showLoginModal();
                } else if (data.oidc_available) {
                    // OIDC will handle redirect
                    console.log('OIDC authentication required');
                }
            } catch (e) {
                // If we can't parse response, show login modal as fallback
                showLoginModal();
            }
        }
    } catch (error) {
        console.error('Error checking authentication:', error);
        // On error, show login modal if we can't determine auth status
        showLoginModal();
    }
}

function showLoginModal() {
    const loginModal = new bootstrap.Modal(document.getElementById('loginModal'));
    loginModal.show();
}

async function performLogin() {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    const errorDiv = document.getElementById('login-error');
    
    if (!username || !password) {
        errorDiv.textContent = 'Username and password are required';
        errorDiv.style.display = 'block';
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
            credentials: 'include'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            // Login successful
            errorDiv.style.display = 'none';
            bootstrap.Modal.getInstance(document.getElementById('loginModal')).hide();
            isAuthenticated = true;
            currentUser = result.user;
            updateUserInterface();
            showAlert('Login successful', 'success');
            // Reload page data
            refreshStats();
        } else {
            // Login failed
            errorDiv.textContent = result.error || 'Login failed';
            errorDiv.style.display = 'block';
            // Clear password field
            document.getElementById('login-password').value = '';
        }
    } catch (error) {
        console.error('Error during login:', error);
        errorDiv.textContent = 'Error connecting to server';
        errorDiv.style.display = 'block';
    }
}

// Allow Enter key to submit login form
document.addEventListener('DOMContentLoaded', function() {
    const loginModal = document.getElementById('loginModal');
    if (loginModal) {
        loginModal.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && e.target.id === 'login-password') {
                performLogin();
            }
        });
    }
    
    // Load public settings (theme, system name, login banner)
    loadPublicSettings();
    
    // Setup proxy settings toggle
    const enableProxyCheckbox = document.getElementById('enable-proxy');
    const proxySettingsGroup = document.getElementById('proxy-settings-group');
    if (enableProxyCheckbox && proxySettingsGroup) {
        enableProxyCheckbox.addEventListener('change', function() {
            proxySettingsGroup.style.display = this.checked ? 'block' : 'none';
        });
    }
});

// Load public settings (theme, system name, login banner)
async function loadPublicSettings() {
    try {
        const response = await fetch(`${API_BASE}/settings/public`);
        if (response.ok) {
            const settings = await response.json();
            
            // Apply theme
            document.body.className = document.body.className.replace(/dark-theme|btheme/g, '').trim();
            if (settings.theme && settings.theme !== 'default') {
                document.body.classList.add(settings.theme === 'dark' ? 'dark-theme' : 'btheme');
            }
            
            // Update system name
            const sidebarName = document.getElementById('sidebar-system-name');
            if (sidebarName) {
                sidebarName.textContent = settings.system_name || 'bWall';
            }
            
            // Update page title
            const pageTitle = document.getElementById('page-title');
            if (pageTitle) {
                pageTitle.textContent = `${settings.system_name || 'bWall'} - Firewall Management Dashboard | bunit.net`;
            }
            
            // Update login banner
            const loginBannerDisplay = document.getElementById('login-banner-display');
            if (loginBannerDisplay && settings.login_banner) {
                loginBannerDisplay.textContent = settings.login_banner;
                loginBannerDisplay.style.display = 'block';
            }
        }
    } catch (error) {
        console.error('Error loading public settings:', error);
    }
}

// Appearance Settings Functions
async function loadAppearanceSettings() {
    try {
        const response = await fetch(`${API_BASE}/settings/appearance`, fetchOptions);
        if (response.ok) {
            const settings = await response.json();
            
            document.getElementById('app-theme').value = settings.theme || 'default';
            document.getElementById('system-name').value = settings.system_name || 'bWall';
            document.getElementById('login-banner').value = settings.login_banner || '';
        }
    } catch (error) {
        console.error('Error loading appearance settings:', error);
    }
}

async function saveAppearanceSettings() {
    const theme = document.getElementById('app-theme').value;
    const systemName = document.getElementById('system-name').value.trim();
    const loginBanner = document.getElementById('login-banner').value.trim();
    
    try {
        const response = await fetch(`${API_BASE}/settings/appearance`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                theme: theme,
                system_name: systemName,
                login_banner: loginBanner
            }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert('Appearance settings saved successfully', 'success');
            // Reload public settings to apply changes
            loadPublicSettings();
        } else {
            showAlert(result.error || 'Error saving appearance settings', 'danger');
        }
    } catch (error) {
        console.error('Error saving appearance settings:', error);
        showAlert('Error saving appearance settings', 'danger');
    }
}

function loadBannerTemplate() {
    const template = `WARNING: This is a private computer system. Unauthorized access is strictly prohibited and may be subject to criminal prosecution. All activities on this system are monitored and logged. By accessing this system, you consent to monitoring.`;
    document.getElementById('login-banner').value = template;
}

// Proxy Settings Functions
async function loadProxySettings() {
    try {
        const response = await fetch(`${API_BASE}/settings/proxy`, fetchOptions);
        if (response.ok) {
            const settings = await response.json();
            
            document.getElementById('enable-proxy').checked = settings.enabled || false;
            document.getElementById('proxy-servers').value = settings.servers || '';
            document.getElementById('proxy-username').value = settings.username || '';
            document.getElementById('proxy-password').value = '';
            document.getElementById('no-proxy').value = settings.no_proxy || 'localhost,127.0.0.1,*.local';
            
            // Show/hide proxy settings group
            const proxySettingsGroup = document.getElementById('proxy-settings-group');
            if (proxySettingsGroup) {
                proxySettingsGroup.style.display = settings.enabled ? 'block' : 'none';
            }
        }
    } catch (error) {
        console.error('Error loading proxy settings:', error);
    }
}

async function saveProxySettings() {
    const enabled = document.getElementById('enable-proxy').checked;
    const servers = document.getElementById('proxy-servers').value.trim();
    const username = document.getElementById('proxy-username').value.trim();
    const password = document.getElementById('proxy-password').value.trim();
    const noProxy = document.getElementById('no-proxy').value.trim();
    
    if (enabled && !servers) {
        showAlert('Proxy servers are required when proxy is enabled', 'warning');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/settings/proxy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                enabled: enabled,
                servers: servers,
                username: username,
                password: password || null, // Only send if provided
                no_proxy: noProxy
            }),
            credentials: 'include'
        });
        
        const result = await response.json();
        if (response.ok) {
            showAlert('Proxy settings saved successfully', 'success');
            // Clear password field
            document.getElementById('proxy-password').value = '';
        } else {
            showAlert(result.error || 'Error saving proxy settings', 'danger');
        }
    } catch (error) {
        console.error('Error saving proxy settings:', error);
        showAlert('Error saving proxy settings', 'danger');
    }
}

function updateUserInterface() {
    const userInfoBar = document.getElementById('user-info-bar');
    const userName = document.getElementById('user-name');
    
    if (currentUser) {
        // Display user information (supports both OIDC and local auth)
        const displayName = currentUser.name || 
                          currentUser.preferred_username || 
                          currentUser.full_name ||
                          currentUser.username ||
                          currentUser.email || 
                          'User';
        userName.textContent = displayName;
        if (userInfoBar) {
            userInfoBar.style.display = 'flex';
        }
    } else {
        if (userInfoBar) {
            userInfoBar.style.display = 'none';
        }
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
            case 'crowdsource':
                console.log('Loading crowdsource lists data...');
                loadCrowdsourceLists();
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

async function loadActivityLog(page = null) {
    try {
        if (page !== null) {
            activityPagination.page = page;
        }
        
        const params = new URLSearchParams({
            page: activityPagination.page,
            per_page: activityPagination.per_page
        });
        
        const response = await fetch(`${API_BASE}/activity?${params}`, fetchOptions);
        const data = await response.json();
        
        const tbody = document.getElementById('activity-log');
        
        if (data.error) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger">Error: ${data.error}</td></tr>`;
            return;
        }
        
        const activities = data.entries || [];
        activityPagination = {
            page: data.page || 1,
            per_page: data.per_page || 50,
            total: data.total || 0,
            pages: data.pages || 0
        };
        
        if (activities.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No recent activity</td></tr>';
            // Activity log pagination would go here if we add it to the UI
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

// Pagination rendering function
function renderPagination(containerId, pagination, loadFunction) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    if (pagination.pages <= 1) {
        container.innerHTML = `<div class="text-muted text-center">Showing ${pagination.total} entries</div>`;
        return;
    }
    
    const { page, pages, total, per_page } = pagination;
    const start = (page - 1) * per_page + 1;
    const end = Math.min(page * per_page, total);
    
    let paginationHTML = `
        <div class="d-flex justify-content-between align-items-center">
            <div class="text-muted">
                Showing ${start} to ${end} of ${total} entries
            </div>
            <nav>
                <ul class="pagination pagination-sm mb-0">
    `;
    
    // Previous button
    if (page > 1) {
        paginationHTML += `
            <li class="page-item">
                <a class="page-link" href="#" onclick="${loadFunction}(${page - 1}); return false;">Previous</a>
            </li>
        `;
    } else {
        paginationHTML += `
            <li class="page-item disabled">
                <span class="page-link">Previous</span>
            </li>
        `;
    }
    
    // Page numbers (show up to 7 pages around current)
    const maxPagesToShow = 7;
    let startPage = Math.max(1, page - Math.floor(maxPagesToShow / 2));
    let endPage = Math.min(pages, startPage + maxPagesToShow - 1);
    
    if (endPage - startPage < maxPagesToShow - 1) {
        startPage = Math.max(1, endPage - maxPagesToShow + 1);
    }
    
    if (startPage > 1) {
        paginationHTML += `
            <li class="page-item">
                <a class="page-link" href="#" onclick="${loadFunction}(1); return false;">1</a>
            </li>
        `;
        if (startPage > 2) {
            paginationHTML += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
        }
    }
    
    for (let i = startPage; i <= endPage; i++) {
        if (i === page) {
            paginationHTML += `
                <li class="page-item active">
                    <span class="page-link">${i}</span>
                </li>
            `;
        } else {
            paginationHTML += `
                <li class="page-item">
                    <a class="page-link" href="#" onclick="${loadFunction}(${i}); return false;">${i}</a>
                </li>
            `;
        }
    }
    
    if (endPage < pages) {
        if (endPage < pages - 1) {
            paginationHTML += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
        }
        paginationHTML += `
            <li class="page-item">
                <a class="page-link" href="#" onclick="${loadFunction}(${pages}); return false;">${pages}</a>
            </li>
        `;
    }
    
    // Next button
    if (page < pages) {
        paginationHTML += `
            <li class="page-item">
                <a class="page-link" href="#" onclick="${loadFunction}(${page + 1}); return false;">Next</a>
            </li>
        `;
    } else {
        paginationHTML += `
            <li class="page-item disabled">
                <span class="page-link">Next</span>
            </li>
        `;
    }
    
    paginationHTML += `
                </ul>
            </nav>
        </div>
    `;
    
    container.innerHTML = paginationHTML;
}

// Whitelist Functions
async function loadWhitelist(page = null) {
    try {
        if (page !== null) {
            whitelistPagination.page = page;
        }
        
        const search = document.getElementById('whitelist-search')?.value.trim() || '';
        
        const params = new URLSearchParams({
            page: whitelistPagination.page,
            per_page: whitelistPagination.per_page
        });
        
        if (search) {
            params.append('search', search);
        }
        
        const response = await fetch(`${API_BASE}/whitelist?${params}`, fetchOptions);
        const data = await response.json();
        
        const tbody = document.getElementById('whitelist-table');
        
        if (data.error) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger">Error: ${data.error}</td></tr>`;
            return;
        }
        
        const entries = data.entries || [];
        whitelistPagination = {
            page: data.page || 1,
            per_page: data.per_page || 50,
            total: data.total || 0,
            pages: data.pages || 0
        };
        
        if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No whitelist entries found</td></tr>';
            renderPagination('whitelist-pagination', whitelistPagination, 'loadWhitelist');
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
        
        // Render pagination
        renderPagination('whitelist-pagination', whitelistPagination, 'loadWhitelist');
        
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

// Pagination state
let blacklistPagination = { page: 1, per_page: 50, total: 0, pages: 0 };
let whitelistPagination = { page: 1, per_page: 50, total: 0, pages: 0 };
let activityPagination = { page: 1, per_page: 50, total: 0, pages: 0 };

// Debounce search function
let searchTimeout;
function debounceSearch(type) {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
        if (type === 'blacklist') {
            blacklistPagination.page = 1; // Reset to first page
            loadBlacklist();
        } else if (type === 'whitelist') {
            whitelistPagination.page = 1;
            loadWhitelist();
        }
    }, 500);
}

// Blacklist Functions
async function loadBlacklist(page = null) {
    try {
        if (page !== null) {
            blacklistPagination.page = page;
        }
        
        const sourceFilter = document.getElementById('blacklist-source-filter')?.value || '';
        const search = document.getElementById('blacklist-search')?.value.trim() || '';
        
        const params = new URLSearchParams({
            page: blacklistPagination.page,
            per_page: blacklistPagination.per_page
        });
        
        if (sourceFilter) {
            params.append('source', sourceFilter);
        }
        if (search) {
            params.append('search', search);
        }
        
        const response = await fetch(`${API_BASE}/blacklist?${params}`, fetchOptions);
        const data = await response.json();
        
        const tbody = document.getElementById('blacklist-table');
        
        if (data.error) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Error: ${data.error}</td></tr>`;
            return;
        }
        
        const entries = data.entries || [];
        blacklistPagination = {
            page: data.page || 1,
            per_page: data.per_page || 50,
            total: data.total || 0,
            pages: data.pages || 0
        };
        
        if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No blacklist entries found</td></tr>';
            renderPagination('blacklist-pagination', blacklistPagination, 'loadBlacklist');
            return;
        }
        
        // Map source to badge
        const sourceBadges = {
            'auto-monitoring': '<span class="badge bg-warning">Active Monitoring</span>',
            'crowdsource': '<span class="badge bg-info">Crowdsource</span>',
            'manual': '<span class="badge bg-secondary">Manual</span>',
            'permaban': '<span class="badge bg-danger">Permanent Ban</span>',
            'unknown': '<span class="badge bg-dark">Unknown</span>'
        };
        
        tbody.innerHTML = entries.map(entry => {
            const source = entry.source || 'unknown';
            return `
                <tr id="blacklist-row-${entry.id}">
                    <td>${entry.id}</td>
                    <td><code>${entry.ip_address}</code></td>
                    <td>${entry.description || '-'}</td>
                    <td>${sourceBadges[source] || sourceBadges['unknown']}</td>
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
            `;
        }).join('');
        
        // Render pagination
        renderPagination('blacklist-pagination', blacklistPagination, 'loadBlacklist');
        
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
let expandedChains = new Set();

async function loadRules() {
    try {
        const container = document.getElementById('rules-chains-container');
        container.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-hourglass-split fs-1 d-block mb-2"></i>Loading chains...</div>';
        
        const response = await fetch(`${API_BASE}/rules`, fetchOptions);
        const data = await response.json();
        
        if (data.error) {
            container.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
            return;
        }
        
        const chains = data.chains || [];
        
        if (chains.length === 0) {
            container.innerHTML = '<div class="alert alert-warning">No chains found</div>';
            return;
        }
        
        // Sort chains: bWall chains first, then standard chains
        const bwallChains = chains.filter(c => c.name.startsWith('BWALL_'));
        const standardChains = chains.filter(c => !c.name.startsWith('BWALL_'));
        const sortedChains = [...bwallChains, ...standardChains];
        
        container.innerHTML = sortedChains.map(chain => {
            const isExpanded = expandedChains.has(chain.name);
            const chainBadgeClass = chain.name.startsWith('BWALL_') ? 'bg-primary' : 
                                   ['INPUT', 'FORWARD', 'OUTPUT'].includes(chain.name) ? 'bg-success' : 'bg-secondary';
            
            // Store chain data for later use
            if (!window.chainsData) window.chainsData = {};
            window.chainsData[chain.name] = chain;
            
            return `
                <div class="card mb-3 chain-card" data-chain="${chain.name}">
                    <div class="card-header d-flex justify-content-between align-items-center" 
                         style="cursor: pointer;" 
                         onclick="toggleChain('${chain.name}')">
                        <div class="d-flex align-items-center">
                            <i class="bi bi-chevron-${isExpanded ? 'down' : 'right'} me-2"></i>
                            <span class="badge ${chainBadgeClass} me-2">${chain.name}</span>
                            <span class="text-muted">${chain.rule_count} rule${chain.rule_count !== 1 ? 's' : ''}</span>
                        </div>
                        <button class="btn btn-sm btn-outline-secondary" onclick="event.stopPropagation(); loadChainRules('${chain.name}', true)" title="Refresh chain">
                            <i class="bi bi-arrow-clockwise"></i>
                        </button>
                    </div>
                    <div class="card-body chain-rules" id="chain-${chain.name}" style="display: ${isExpanded ? 'block' : 'none'};">
                        ${isExpanded ? renderChainRules(chain.rules) : '<div class="text-muted text-center py-2">Click to expand</div>'}
                    </div>
                </div>
            `;
        }).join('');
        
    } catch (error) {
        console.error('Error loading rules:', error);
        document.getElementById('rules-chains-container').innerHTML = 
            '<div class="alert alert-danger">Error loading rules: ' + error.message + '</div>';
    }
}

function toggleChain(chainName) {
    const chainCard = document.querySelector(`[data-chain="${chainName}"]`);
    const rulesDiv = document.getElementById(`chain-${chainName}`);
    const chevron = chainCard.querySelector('.bi-chevron-right, .bi-chevron-down');
    
    if (expandedChains.has(chainName)) {
        expandedChains.delete(chainName);
        rulesDiv.style.display = 'none';
        if (chevron) {
            chevron.classList.remove('bi-chevron-down');
            chevron.classList.add('bi-chevron-right');
        }
        rulesDiv.innerHTML = '<div class="text-muted text-center py-2">Click to expand</div>';
    } else {
        expandedChains.add(chainName);
        rulesDiv.style.display = 'block';
        if (chevron) {
            chevron.classList.remove('bi-chevron-right');
            chevron.classList.add('bi-chevron-down');
        }
        
        // Use cached rules if available, otherwise load from API
        if (window.chainsData && window.chainsData[chainName] && window.chainsData[chainName].rules) {
            rulesDiv.innerHTML = renderChainRules(window.chainsData[chainName].rules);
        } else {
            loadChainRules(chainName, false);
        }
    }
}

async function loadChainRules(chainName, forceRefresh = false) {
    const rulesDiv = document.getElementById(`chain-${chainName}`);
    if (!rulesDiv) return;
    
    // Use cached data if available and not forcing refresh
    if (!forceRefresh && window.chainsData && window.chainsData[chainName] && window.chainsData[chainName].rules) {
        rulesDiv.innerHTML = renderChainRules(window.chainsData[chainName].rules);
        return;
    }
    
    rulesDiv.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-hourglass-split me-2"></i>Loading rules...</div>';
    
    try {
        const response = await fetch(`${API_BASE}/rules/chain/${chainName}`, fetchOptions);
        const data = await response.json();
        
        if (data.error) {
            rulesDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
            return;
        }
        
        const rules = data.rules || [];
        
        // Update cached data
        if (window.chainsData && window.chainsData[chainName]) {
            window.chainsData[chainName].rules = rules;
            window.chainsData[chainName].rule_count = rules.length;
        }
        
        rulesDiv.innerHTML = renderChainRules(rules);
    } catch (error) {
        console.error('Error loading chain rules:', error);
        rulesDiv.innerHTML = `<div class="alert alert-danger">Error loading rules: ${error.message}</div>`;
    }
}

function renderChainRules(rules) {
    if (rules.length === 0) {
        return '<div class="text-muted text-center py-3">No rules in this chain</div>';
    }
    
    return `
        <div class="table-responsive">
            <table class="table table-sm table-hover mb-0">
                <thead>
                    <tr>
                        <th style="width: 50px;">#</th>
                        <th style="width: 80px;">Packets</th>
                        <th style="width: 80px;">Bytes</th>
                        <th style="width: 100px;">Target</th>
                        <th style="width: 80px;">Protocol</th>
                        <th style="width: 80px;">Opt</th>
                        <th style="width: 100px;">In</th>
                        <th style="width: 100px;">Out</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Options</th>
                    </tr>
                </thead>
                <tbody>
                    ${rules.map(rule => `
                        <tr>
                            <td><code>${rule.num || '-'}</code></td>
                            <td><small>${rule.pkts || '-'}</small></td>
                            <td><small>${rule.bytes || '-'}</small></td>
                            <td><span class="badge bg-${rule.target === 'ACCEPT' ? 'success' : rule.target === 'DROP' || rule.target === 'REJECT' ? 'danger' : 'secondary'}">${rule.target || '-'}</span></td>
                            <td><small>${rule.protocol || '-'}</small></td>
                            <td><small>${rule.opt || '-'}</small></td>
                            <td><small>${rule.in || '-'}</small></td>
                            <td><small>${rule.out || '-'}</small></td>
                            <td><code class="text-break">${rule.source || '-'}</code></td>
                            <td><code class="text-break">${rule.destination || '-'}</code></td>
                            <td><small class="text-muted">${rule.options || '-'}</small></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
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


