// Frontend JavaScript for Secure Split-Secret Password Recovery System

const API_BASE = '/api';

// Theme Management
class ThemeManager {
    constructor() {
        this.themes = ['light', 'dark', 'colorblind'];
        this.currentTheme = this.loadTheme();
        this.init();
    }

    init() {
        // Apply saved theme
        this.setTheme(this.currentTheme);
        
        // Add event listeners to theme buttons
        document.querySelectorAll('.theme-btn').forEach(button => {
            button.addEventListener('click', () => {
                const theme = button.dataset.theme;
                this.setTheme(theme);
            });
        });
    }

    setTheme(theme) {
        if (!this.themes.includes(theme)) return;
        
        // Update data attribute on body
        document.body.setAttribute('data-theme', theme);
        
        // Update button states
        document.querySelectorAll('.theme-btn').forEach(btn => {
            btn.classList.remove('active');
            if (btn.dataset.theme === theme) {
                btn.classList.add('active');
            }
        });
        
        // Save to localStorage
        this.saveTheme(theme);
        this.currentTheme = theme;
    }

    loadTheme() {
        const saved = localStorage.getItem('theme');
        if (saved && this.themes.includes(saved)) {
            return saved;
        }
        // Check system preference
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            return 'dark';
        }
        return 'light';
    }

    saveTheme(theme) {
        localStorage.setItem('theme', theme);
    }

    getCurrentTheme() {
        return this.currentTheme;
    }
}

// Initialize theme manager
const themeManager = new ThemeManager();

// Initialize Share Manager display
displayStoredShares();
updateStatistics();

// Add event listeners for search and filters
document.getElementById('search-input').addEventListener('input', displayStoredShares);
document.getElementById('category-filter').addEventListener('change', displayStoredShares);
document.getElementById('sort-filter').addEventListener('change', displayStoredShares);

// Tab switching
document.querySelectorAll('.tab-button').forEach(button => {
    button.addEventListener('click', () => {
        const tabName = button.dataset.tab;
        
        // Update buttons
        document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        
        // Update content
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        document.getElementById(`${tabName}-tab`).classList.add('active');
        
        // Clear previous results
        clearResults();
    });
});

// Split Secret Form
document.getElementById('split-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearError();
    
    const secret = document.getElementById('secret-input').value;
    const n = parseInt(document.getElementById('n-input').value);
    const k = parseInt(document.getElementById('k-input').value);
    const userId = document.getElementById('user-id-input').value || 'anonymous';
    
    // Validate
    if (k > n) {
        showError('Threshold (k) cannot be greater than total shares (n)');
        return;
    }
    
    if (k < 2 || n < 2) {
        showError('Both k and n must be at least 2');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/split`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                secret,
                n,
                k,
                user_id: userId
            })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            showError(data.error || 'Failed to split secret');
            return;
        }
        
        // Display results
        displaySplitResults(data);
        
    } catch (error) {
        showError('Network error: ' + error.message);
    }
});

// Reconstruct Secret Form
document.getElementById('reconstruct-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearError();
    
    const secretId = document.getElementById('secret-id-reconstruct').value;
    const masterKey = document.getElementById('master-key-reconstruct').value;
    const sharesInput = document.getElementById('shares-input').value;
    
    let shares;
    try {
        shares = JSON.parse(sharesInput);
    } catch (error) {
        showError('Invalid JSON format for shares');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/reconstruct`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                secret_id: secretId,
                master_key: masterKey,
                shares: shares
            })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            showError(data.error || 'Failed to reconstruct secret');
            return;
        }
        
        // Display results
        displayReconstructResults(data);
        
    } catch (error) {
        showError('Network error: ' + error.message);
    }
});

// Share Manager Form
document.getElementById('import-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearError();
    
    const name = document.getElementById('import-name').value;
    const category = document.getElementById('import-category').value;
    const sharesInput = document.getElementById('import-shares').value;
    const notes = document.getElementById('import-notes').value;
    
    let shares;
    try {
        shares = JSON.parse(sharesInput);
    } catch (error) {
        showError('Invalid JSON format for shares');
        return;
    }
    
    // Import shares to local storage
    importShareSet(name, shares, notes, category);
    
    // Clear form
    document.getElementById('import-form').reset();
    
    // Show success message
    showError('Share set imported successfully');
    setTimeout(() => clearError(), 3000);
});

// Display Functions
function displaySplitResults(data) {
    document.getElementById('secret-id-display').textContent = data.secret_id;
    document.getElementById('master-key-display').textContent = data.master_key;
    
    // Display shares
    const sharesList = document.getElementById('shares-list');
    sharesList.innerHTML = '';
    
    data.shares.forEach(share => {
        const shareItem = document.createElement('div');
        shareItem.className = 'share-item';
        shareItem.innerHTML = `
            <h5>Share ${share.share_id}</h5>
            <code>${share.encrypted_share}</code>
        `;
        sharesList.appendChild(shareItem);
    });
    
    // Store data for download
    window.splitData = data;
    
    document.getElementById('split-result').style.display = 'block';
    document.getElementById('split-result').scrollIntoView({ behavior: 'smooth' });
}

function displayReconstructResults(data) {
    document.getElementById('reconstructed-secret').textContent = data.secret;
    document.getElementById('shares-used-info').textContent = 
        `Used ${data.shares_used} share(s) to reconstruct the secret.`;
    
    window.reconstructedSecret = data.secret;
    
    document.getElementById('reconstruct-result').style.display = 'block';
    document.getElementById('reconstruct-result').scrollIntoView({ behavior: 'smooth' });
}

// Share Manager Functions
function importShareSet(name, shares, notes, category) {
    const shareSets = getStoredShareSets();
    const shareSet = {
        id: Date.now().toString(),
        name: name,
        shares: shares,
        notes: notes,
        category: category || 'other',
        createdAt: new Date().toISOString(),
        shareCount: Array.isArray(shares) ? shares.length : Object.keys(shares).length
    };
    
    shareSets.push(shareSet);
    localStorage.setItem('shareSets', JSON.stringify(shareSets));
    
    updateStatistics();
    displayStoredShares();
}

function getStoredShareSets() {
    const stored = localStorage.getItem('shareSets');
    return stored ? JSON.parse(stored) : [];
}

function deleteShareSet(id) {
    if (confirm('Are you sure you want to delete this share set?')) {
        const shareSets = getStoredShareSets();
        const filtered = shareSets.filter(set => set.id !== id);
        localStorage.setItem('shareSets', JSON.stringify(filtered));
        updateStatistics();
        displayStoredShares();
    }
}

function exportShareSet(id) {
    const shareSets = getStoredShareSets();
    const shareSet = shareSets.find(set => set.id === id);
    
    if (shareSet) {
        const dataStr = JSON.stringify(shareSet.shares, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${shareSet.name.replace(/[^a-z0-9]/gi, '_')}_shares.json`;
        link.click();
        URL.revokeObjectURL(url);
    }
}

function loadShareSetForReconstruction(id) {
    const shareSets = getStoredShareSets();
    const shareSet = shareSets.find(set => set.id === id);
    
    if (shareSet) {
        // Switch to reconstruct tab
        document.querySelector('[data-tab="reconstruct"]').click();
        
        // Fill in the shares
        document.getElementById('shares-input').value = JSON.stringify(shareSet.shares, null, 2);
        
        // Scroll to form
        document.getElementById('reconstruct-form').scrollIntoView({ behavior: 'smooth' });
    }
}

function displayStoredShares() {
    const shareSets = getStoredShareSets();
    const container = document.getElementById('shares-list');
    
    // Apply filters
    let filteredSets = filterAndSortShares(shareSets);
    
    if (filteredSets.length === 0) {
        container.innerHTML = '<p class="no-shares">No share sets found. Try adjusting your filters or import your first set above!</p>';
        return;
    }
    
    container.innerHTML = filteredSets.map(shareSet => {
        const date = new Date(shareSet.createdAt).toLocaleDateString();
        return `
            <div class="share-set-item" data-id="${shareSet.id}">
                <input type="checkbox" class="share-set-checkbox" data-id="${shareSet.id}" onchange="toggleShareSelection('${shareSet.id}')">
                <div class="share-set-content">
                    <div class="share-set-header">
                        <div class="share-set-title">${shareSet.name}</div>
                        <div class="share-set-date">${date}</div>
                    </div>
                    <div class="share-set-meta">
                        <span class="share-count">${shareSet.shareCount} shares</span>
                        <span class="category-badge">${shareSet.category}</span>
                        <span>ID: ${shareSet.id}</span>
                    </div>
                    ${shareSet.notes ? `<div class="share-set-details"><strong>Notes:</strong> ${shareSet.notes}</div>` : ''}
                    <div class="share-set-actions">
                        <button class="btn btn-small" onclick="loadShareSetForReconstruction('${shareSet.id}')">Use for Reconstruction</button>
                        <button class="btn btn-small btn-secondary" onclick="exportShareSet('${shareSet.id}')">Export</button>
                        <button class="btn btn-small btn-secondary" onclick="deleteShareSet('${shareSet.id}')">Delete</button>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// Search, Filter, and Statistics Functions
function filterAndSortShares(shareSets) {
    const searchTerm = document.getElementById('search-input').value.toLowerCase();
    const categoryFilter = document.getElementById('category-filter').value;
    const sortFilter = document.getElementById('sort-filter').value;
    
    let filtered = shareSets.filter(shareSet => {
        const matchesSearch = !searchTerm || 
            shareSet.name.toLowerCase().includes(searchTerm) || 
            (shareSet.notes && shareSet.notes.toLowerCase().includes(searchTerm));
        
        const matchesCategory = !categoryFilter || shareSet.category === categoryFilter;
        
        return matchesSearch && matchesCategory;
    });
    
    // Sort
    filtered.sort((a, b) => {
        switch (sortFilter) {
            case 'newest':
                return new Date(b.createdAt) - new Date(a.createdAt);
            case 'oldest':
                return new Date(a.createdAt) - new Date(b.createdAt);
            case 'name':
                return a.name.localeCompare(b.name);
            case 'shares':
                return b.shareCount - a.shareCount;
            default:
                return 0;
        }
    });
    
    return filtered;
}

function updateStatistics() {
    const shareSets = getStoredShareSets();
    const totalShareSets = shareSets.length;
    const totalShares = shareSets.reduce((sum, set) => sum + set.shareCount, 0);
    
    // Calculate sets added this week
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
    const recentSets = shareSets.filter(set => new Date(set.createdAt) > oneWeekAgo).length;
    
    // Calculate unique categories
    const categories = new Set(shareSets.map(set => set.category));
    const categoriesCount = categories.size;
    
    // Update DOM
    document.getElementById('total-share-sets').textContent = totalShareSets;
    document.getElementById('total-shares').textContent = totalShares;
    document.getElementById('recent-sets').textContent = recentSets;
    document.getElementById('categories-count').textContent = categoriesCount;
}

// Batch Operations Functions
function toggleShareSelection(id) {
    const checkbox = document.querySelector(`.share-set-checkbox[data-id="${id}"]`);
    const shareItem = document.querySelector(`.share-set-item[data-id="${id}"]`);
    
    if (checkbox.checked) {
        shareItem.classList.add('selected');
    } else {
        shareItem.classList.remove('selected');
    }
}

function selectAllShares() {
    const checkboxes = document.querySelectorAll('.share-set-checkbox');
    checkboxes.forEach(checkbox => {
        checkbox.checked = true;
        const shareItem = document.querySelector(`.share-set-item[data-id="${checkbox.dataset.id}"]`);
        shareItem.classList.add('selected');
    });
}

function deselectAllShares() {
    const checkboxes = document.querySelectorAll('.share-set-checkbox');
    checkboxes.forEach(checkbox => {
        checkbox.checked = false;
        const shareItem = document.querySelector(`.share-set-item[data-id="${checkbox.dataset.id}"]`);
        shareItem.classList.remove('selected');
    });
}

function getSelectedShareIds() {
    const checkboxes = document.querySelectorAll('.share-set-checkbox:checked');
    return Array.from(checkboxes).map(cb => cb.dataset.id);
}

function exportSelected() {
    const selectedIds = getSelectedShareIds();
    if (selectedIds.length === 0) {
        showError('Please select at least one share set to export');
        return;
    }
    
    const shareSets = getStoredShareSets();
    const selectedSets = shareSets.filter(set => selectedIds.includes(set.id));
    
    const exportData = {
        exported_at: new Date().toISOString(),
        share_sets: selectedSets
    };
    
    const dataStr = JSON.stringify(exportData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `selected_share_sets_${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
}

function deleteSelected() {
    const selectedIds = getSelectedShareIds();
    if (selectedIds.length === 0) {
        showError('Please select at least one share set to delete');
        return;
    }
    
    if (confirm(`Are you sure you want to delete ${selectedIds.length} share set(s)?`)) {
        const shareSets = getStoredShareSets();
        const filtered = shareSets.filter(set => !selectedIds.includes(set.id));
        localStorage.setItem('shareSets', JSON.stringify(filtered));
        updateStatistics();
        displayStoredShares();
    }
}

function exportAllShares() {
    const shareSets = getStoredShareSets();
    if (shareSets.length === 0) {
        showError('No share sets to export');
        return;
    }
    
    const exportData = {
        exported_at: new Date().toISOString(),
        total_share_sets: shareSets.length,
        share_sets: shareSets
    };
    
    const dataStr = JSON.stringify(exportData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `all_share_sets_${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
}

// Utility Functions
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    if (input.type === 'password') {
        input.type = 'text';
    } else {
        input.type = 'password';
    }
}

function showError(message) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    errorDiv.scrollIntoView({ behavior: 'smooth' });
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        errorDiv.style.display = 'none';
    }, 5000);
}

function clearError() {
    document.getElementById('error-message').style.display = 'none';
}

function clearResults() {
    document.querySelectorAll('.result-container').forEach(el => {
        el.style.display = 'none';
    });
    clearError();
}

function downloadShares() {
    if (!window.splitData) return;
    
    const dataStr = JSON.stringify(window.splitData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `shares_${window.splitData.secret_id}.json`;
    link.click();
    URL.revokeObjectURL(url);
}

function copyToClipboard(type) {
    let text = '';
    
    if (type === 'split' && window.splitData) {
        text = JSON.stringify(window.splitData, null, 2);
    } else if (type === 'reconstruct' && window.reconstructedSecret) {
        text = window.reconstructedSecret;
    }
    
    if (text) {
        navigator.clipboard.writeText(text).then(() => {
            alert('Copied to clipboard!');
        }).catch(err => {
            showError('Failed to copy to clipboard');
        });
    }
}

// Auto-update k max based on n
document.getElementById('n-input').addEventListener('input', (e) => {
    const n = parseInt(e.target.value);
    const kInput = document.getElementById('k-input');
    kInput.max = n;
    if (parseInt(kInput.value) > n) {
        kInput.value = n;
    }
});


