// Crowd VPN Web Interface JavaScript

// Global variables
let isLoading = false;

// Utility functions
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.remove()" class="notification-close">&times;</button>
        </div>
    `;
    
    // Add styles if not already present
    if (!document.querySelector('#notification-styles')) {
        const styles = document.createElement('style');
        styles.id = 'notification-styles';
        styles.textContent = `
            .notification {
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 1000;
                padding: 15px 20px;
                border-radius: 8px;
                color: white;
                font-weight: 600;
                animation: slideIn 0.3s ease;
                max-width: 400px;
            }
            .notification-info { background: #3182ce; }
            .notification-success { background: #38a169; }
            .notification-error { background: #e53e3e; }
            .notification-warning { background: #d69e2e; }
            .notification-content {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 10px;
            }
            .notification-close {
                background: none;
                border: none;
                color: white;
                font-size: 1.5rem;
                cursor: pointer;
                padding: 0;
                width: 20px;
                height: 20px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
        `;
        document.head.appendChild(styles);
    }
    
    // Add to document
    document.body.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

function setLoading(element, loading) {
    if (loading) {
        element.disabled = true;
        element.innerHTML = '<span class="loading"></span> ' + element.textContent;
        isLoading = true;
    } else {
        element.disabled = false;
        element.innerHTML = element.innerHTML.replace('<span class="loading"></span> ', '');
        isLoading = false;
    }
}

// Node control functions
function showStartForm() {
    if (isLoading) return;
    
    const form = document.getElementById('start-form');
    if (form) {
        form.style.display = 'block';
    }
}

function hideStartForm() {
    const form = document.getElementById('start-form');
    if (form) {
        form.style.display = 'none';
    }
}

async function startNode() {
    if (isLoading) return;
    
    const startButton = document.querySelector('#start-form button[onclick="startNode()"]');
    setLoading(startButton, true);
    
    try {
        // Get form data
        const formData = new FormData();
        formData.append('port', document.getElementById('port').value);
        formData.append('node_type', document.getElementById('node_type').value);
        formData.append('bootstrap', document.getElementById('bootstrap').value);
        formData.append('routing', document.getElementById('routing').value);
        
        // Send request
        const response = await fetch('/start_node', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
            showNotification('VPN Node started successfully!', 'success');
            hideStartForm();
            // Refresh the page to update UI
            setTimeout(() => window.location.reload(), 1000);
        } else {
            showNotification(`Failed to start node: ${result.error}`, 'error');
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
        console.error('Error starting node:', error);
    } finally {
        setLoading(startButton, false);
    }
}

async function stopNode() {
    if (isLoading) return;
    
    const stopButton = document.getElementById('stop-btn');
    setLoading(stopButton, true);
    
    try {
        const response = await fetch('/stop_node', {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (result.success) {
            showNotification('VPN Node stopped successfully!', 'success');
            // Refresh the page to update UI
            setTimeout(() => window.location.reload(), 1000);
        } else {
            showNotification(`Failed to stop node: ${result.error}`, 'error');
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
        console.error('Error stopping node:', error);
    } finally {
        setLoading(stopButton, false);
    }
}

// Format bytes function
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Update status with formatted data
function updateStatusFormatted(status) {
    // Update basic fields
    const fields = ['connected-peers', 'known-peers', 'active-routes'];
    fields.forEach(field => {
        const element = document.getElementById(field);
        if (element && status[field.replace('-', '_')] !== undefined) {
            element.textContent = status[field.replace('-', '_')];
        }
    });
    
    // Update byte fields with formatting
    const byteFields = {
        'bytes-sent': 'bytes_sent',
        'bytes-received': 'bytes_received'
    };
    
    Object.entries(byteFields).forEach(([elementId, statusKey]) => {
        const element = document.getElementById(elementId);
        if (element && status[statusKey] !== undefined) {
            element.textContent = formatBytes(status[statusKey]);
        }
    });
    
    // Update status indicator
    const indicator = document.querySelector('.status-indicator');
    const statusText = document.querySelector('.status-card p');
    
    if (indicator && statusText) {
        if (status.running) {
            indicator.className = 'status-indicator running';
            statusText.textContent = 'Running';
        } else {
            indicator.className = 'status-indicator stopped';
            statusText.textContent = 'Stopped';
        }
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', function(event) {
    // Escape key to close forms/modals
    if (event.key === 'Escape') {
        hideStartForm();
    }
    
    // Ctrl+R to refresh status (prevent default page reload)
    if (event.ctrlKey && event.key === 'r') {
        event.preventDefault();
        fetch('/api/status')
            .then(response => response.json())
            .then(status => updateStatusFormatted(status))
            .catch(error => {
                console.error('Error fetching status:', error);
                showNotification('Failed to refresh status', 'error');
            });
    }
});

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    // Add click outside to close form
    document.addEventListener('click', function(event) {
        const startForm = document.getElementById('start-form');
        const startButton = document.getElementById('start-btn');
        
        if (startForm && 
            startForm.style.display === 'block' && 
            !startForm.contains(event.target) && 
            event.target !== startButton) {
            hideStartForm();
        }
    });
    
    // Prevent form submission on Enter (use buttons instead)
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            event.preventDefault();
        });
    });
    
    console.log('Crowd VPN Web Interface initialized');
});

