// bWall Web Installer JavaScript
// Auto-detect API base URL (works with 0.0.0.0 and localhost)
const API_BASE = window.location.origin + '/api/installer';

let currentStep = 1;
let installationData = {};

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    checkPrerequisites();
});

// Step Navigation
function nextStep(step) {
    if (step > currentStep) {
        // Validate current step before proceeding
        if (!validateCurrentStep()) {
            return;
        }
    }
    
    // Hide current step
    document.querySelector(`#step-${currentStep}`).classList.remove('active');
    document.querySelector(`#step-${currentStep}-indicator`).classList.remove('active');
    
    // Show new step
    currentStep = step;
    document.querySelector(`#step-${currentStep}`).classList.add('active');
    document.querySelector(`#step-${currentStep}-indicator`).classList.add('active');
    
    // Mark previous steps as completed
    for (let i = 1; i < currentStep; i++) {
        document.querySelector(`#step-${i}-indicator`).classList.add('completed');
    }
}

function prevStep() {
    if (currentStep > 1) {
        nextStep(currentStep - 1);
    }
}

function validateCurrentStep() {
    if (currentStep === 2) {
        const form = document.getElementById('db-form');
        if (!form.checkValidity()) {
            form.reportValidity();
            return false;
        }
    }
    return true;
}

// Step 1: Check Prerequisites
async function checkPrerequisites() {
    const resultsDiv = document.getElementById('prereq-results');
    resultsDiv.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>';
    
    try {
        const response = await fetch(`${API_BASE}/prerequisites`);
        const data = await response.json();
        
        let html = '';
        let allOk = true;
        
        data.prerequisites.forEach(prereq => {
            const statusClass = prereq.status === 'ok' ? 'success' : 
                               prereq.status === 'warning' ? 'warning' : 'error';
            const icon = prereq.status === 'ok' ? 'check-circle-fill' : 
                        prereq.status === 'warning' ? 'exclamation-triangle-fill' : 'x-circle-fill';
            
            if (prereq.status !== 'ok') allOk = false;
            
            html += `
                <div class="prereq-item ${statusClass}">
                    <i class="bi bi-${icon} me-3 fs-5"></i>
                    <div class="flex-grow-1">
                        <strong>${prereq.name}</strong>
                        ${prereq.version ? `<br><small>${prereq.version}</small>` : ''}
                        ${prereq.message ? `<br><small>${prereq.message}</small>` : ''}
                    </div>
                </div>
            `;
        });
        
        resultsDiv.innerHTML = html;
        
        // Enable next button if all prerequisites are OK
        document.getElementById('btn-step-1-next').disabled = !allOk;
        
        if (allOk) {
            addLog('All prerequisites are satisfied', 'success');
        } else {
            addLog('Some prerequisites need attention', 'warning');
        }
    } catch (error) {
        console.error('Error checking prerequisites:', error);
        resultsDiv.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle me-2"></i>
                Error checking prerequisites: ${error.message}
            </div>
        `;
    }
}

// Step 2: Database Configuration
async function testDatabase() {
    const alertDiv = document.getElementById('db-status-alert');
    const messageSpan = document.getElementById('db-status-message');
    
    alertDiv.style.display = 'block';
    alertDiv.className = 'alert alert-info';
    messageSpan.textContent = 'Testing database connection...';
    
    const dbData = {
        host: document.getElementById('db-host').value,
        root_user: document.getElementById('db-root-user').value,
        root_password: document.getElementById('db-root-password').value,
        name: document.getElementById('db-name').value,
        user: document.getElementById('db-user').value,
        password: document.getElementById('db-password').value,
        create_db: document.getElementById('create-db').checked
    };
    
    try {
        const response = await fetch(`${API_BASE}/test-database`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(dbData)
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            alertDiv.className = 'alert alert-success';
            messageSpan.innerHTML = '<i class="bi bi-check-circle me-2"></i>' + result.message;
            document.getElementById('btn-step-2-next').disabled = false;
            installationData.database = dbData;
        } else {
            alertDiv.className = 'alert alert-danger';
            messageSpan.innerHTML = '<i class="bi bi-x-circle me-2"></i>' + (result.error || 'Database connection failed');
            document.getElementById('btn-step-2-next').disabled = true;
        }
    } catch (error) {
        alertDiv.className = 'alert alert-danger';
        messageSpan.innerHTML = '<i class="bi bi-x-circle me-2"></i>Error: ' + error.message;
        document.getElementById('btn-step-2-next').disabled = true;
    }
}

// Step 3: OIDC Configuration
function toggleOidcForm() {
    const enabled = document.getElementById('enable-oidc').checked;
    const form = document.getElementById('oidc-form');
    form.style.display = enabled ? 'block' : 'none';
    
    if (!enabled) {
        installationData.oidc = null;
    }
}

// Step 4: Installation
async function startInstallation() {
    const btnInstall = document.getElementById('btn-install');
    const btnPrev = document.getElementById('btn-step-4-prev');
    const progressBar = document.getElementById('install-progress');
    const statusDiv = document.getElementById('install-status');
    const logDiv = document.getElementById('install-log');
    
    // Disable buttons
    btnInstall.disabled = true;
    btnPrev.disabled = true;
    
    // Collect installation data
    installationData.database = {
        host: document.getElementById('db-host').value,
        root_user: document.getElementById('db-root-user').value,
        root_password: document.getElementById('db-root-password').value,
        name: document.getElementById('db-name').value,
        user: document.getElementById('db-user').value,
        password: document.getElementById('db-password').value,
        create_db: document.getElementById('create-db').checked
    };
    
    if (document.getElementById('enable-oidc').checked) {
        installationData.oidc = {
            issuer: document.getElementById('oidc-issuer').value,
            client_id: document.getElementById('oidc-client-id').value,
            client_secret: document.getElementById('oidc-client-secret').value,
            redirect_uri: document.getElementById('oidc-redirect-uri').value,
            post_logout_uri: document.getElementById('oidc-post-logout-uri').value
        };
    } else {
        installationData.oidc = null;
    }
    
    // Clear log
    logDiv.innerHTML = '<div class="log-entry log-info">Starting installation...</div>';
    
    // Update progress
    function updateProgress(percent, status) {
        progressBar.style.width = percent + '%';
        progressBar.textContent = percent + '%';
        if (status) {
            statusDiv.textContent = status;
        }
    }
    
    function addInstallLog(message, type = 'info') {
        const entry = document.createElement('div');
        entry.className = `log-entry log-${type}`;
        entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        logDiv.appendChild(entry);
        logDiv.scrollTop = logDiv.scrollHeight;
    }
    
    try {
        updateProgress(10, 'Installing Python packages...');
        addInstallLog('Installing Python requirements...', 'info');
        
        const response = await fetch(`${API_BASE}/install`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(installationData)
        });
        
        if (!response.ok) {
            throw new Error('Installation failed');
        }
        
        // Stream progress updates
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            const chunk = decoder.decode(value);
            const lines = chunk.split('\n').filter(line => line.trim());
            
            for (const line of lines) {
                try {
                    const data = JSON.parse(line);
                    
                    if (data.progress !== undefined) {
                        updateProgress(data.progress, data.status || '');
                    }
                    
                    if (data.log) {
                        addInstallLog(data.log.message, data.log.type || 'info');
                    }
                    
                    if (data.complete) {
                        updateProgress(100, 'Installation complete!');
                        addInstallLog('Installation completed successfully!', 'success');
                        btnInstall.style.display = 'none';
                        document.getElementById('btn-step-4-next').style.display = 'inline-block';
                        break;
                    }
                    
                    if (data.error) {
                        addInstallLog('Error: ' + data.error, 'error');
                        updateProgress(0, 'Installation failed');
                        btnInstall.disabled = false;
                        btnPrev.disabled = false;
                        throw new Error(data.error);
                    }
                } catch (e) {
                    // Not JSON, treat as plain log
                    if (line.trim()) {
                        addInstallLog(line, 'info');
                    }
                }
            }
        }
    } catch (error) {
        console.error('Installation error:', error);
        addInstallLog('Installation failed: ' + error.message, 'error');
        updateProgress(0, 'Installation failed');
        btnInstall.disabled = false;
        btnPrev.disabled = false;
    }
}

// Utility functions
function addLog(message, type = 'info') {
    console.log(`[${type.toUpperCase()}] ${message}`);
}

