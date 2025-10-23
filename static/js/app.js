// SpiderFoot TOC/Corruption Analyzer - JavaScript

let currentFilename = null;
let currentAnalysis = null;

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    setupUploadZone();
    setupFileInput();
});

// Setup drag-and-drop upload zone
function setupUploadZone() {
    const uploadZone = document.getElementById('uploadZone');

    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('drag-over');
    });

    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('drag-over');
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('drag-over');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileUpload(files[0]);
        }
    });
}

// Setup file input
function setupFileInput() {
    const fileInput = document.getElementById('fileInput');
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });
}

// Handle file upload
async function handleFileUpload(file) {
    if (!file.name.endsWith('.csv')) {
        showToast('Please select a CSV file', 'error');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    showLoading('Uploading and validating CSV file...');
    showProgress(0);

    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (response.ok) {
            currentFilename = result.filename;
            showProgress(100);
            hideLoading();
            displaySummary(result.summary);
            showToast('File uploaded successfully!', 'success');
        } else {
            throw new Error(result.error || 'Upload failed');
        }
    } catch (error) {
        hideLoading();
        showToast(`Error: ${error.message}`, 'error');
    }
}

// Display summary
function displaySummary(summary) {
    const statsGrid = document.getElementById('statsGrid');
    statsGrid.innerHTML = '';

    const stats = [
        { label: 'Total Records', value: summary.total_records, icon: 'fa-database' },
        { label: 'Event Types', value: summary.event_types_count, icon: 'fa-list' },
        { label: 'Modules', value: summary.modules_count, icon: 'fa-puzzle-piece' },
        { label: 'Corruption Indicators', value: summary.corruption_indicators, icon: 'fa-exclamation-triangle' },
        { label: 'TOC Indicators', value: summary.toc_indicators, icon: 'fa-shield-alt' }
    ];

    stats.forEach(stat => {
        const statCard = document.createElement('div');
        statCard.className = 'stat-card';
        statCard.innerHTML = `
            <div class="stat-label"><i class="fas ${stat.icon}"></i> ${stat.label}</div>
            <div class="stat-value">${stat.value.toLocaleString()}</div>
        `;
        statsGrid.appendChild(statCard);
    });

    document.getElementById('uploadSection').style.display = 'none';
    document.getElementById('summarySection').style.display = 'block';
}

// Analyze data
async function analyzeData() {
    if (!currentFilename) {
        showToast('No file uploaded', 'error');
        return;
    }

    showLoading('Analyzing data patterns and threats...');

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                filename: currentFilename,
                filters: {}
            })
        });

        const result = await response.json();

        if (response.ok) {
            currentAnalysis = result.analysis;
            hideLoading();
            displayAnalysis(result.analysis);
            showToast('Analysis complete!', 'success');
        } else {
            throw new Error(result.error || 'Analysis failed');
        }
    } catch (error) {
        hideLoading();
        showToast(`Error: ${error.message}`, 'error');
    }
}

// Display analysis results
function displayAnalysis(analysis) {
    document.getElementById('summarySection').style.display = 'none';
    document.getElementById('analysisSection').style.display = 'block';

    // Display threat overview
    displayThreatOverview(analysis);

    // Display tabs content
    displayEventsTab(analysis.event_distribution);
    displayModulesTab(analysis.module_activity);
    displayCorruptionTab(analysis.corruption_patterns);
    displayThreatsTab(analysis.toc_patterns);
    displayRecommendationsTab(analysis.recommendations);
}

// Display threat overview cards
function displayThreatOverview(analysis) {
    const threatOverview = document.getElementById('threatOverview');
    threatOverview.innerHTML = '';

    const threats = [
        {
            label: 'Corruption Indicators',
            count: analysis.corruption_patterns.total_indicators,
            icon: 'fa-exclamation-triangle',
            class: 'corruption'
        },
        {
            label: 'TOC Indicators',
            count: analysis.toc_patterns.total_indicators,
            icon: 'fa-shield-alt',
            class: 'toc'
        },
        {
            label: 'High-Risk Domains',
            count: analysis.risk_domains.total_risk_domains,
            icon: 'fa-globe',
            class: 'domains'
        },
        {
            label: 'Compromised Assets',
            count: analysis.compromised_assets.total_compromised,
            icon: 'fa-server',
            class: 'assets'
        }
    ];

    threats.forEach(threat => {
        const card = document.createElement('div');
        card.className = `threat-card ${threat.class}`;
        card.innerHTML = `
            <i class="fas ${threat.icon}"></i>
            <div class="threat-count">${threat.count}</div>
            <div class="threat-label">${threat.label}</div>
        `;
        threatOverview.appendChild(card);
    });
}

// Display events tab
function displayEventsTab(eventDist) {
    const tab = document.getElementById('eventsTab');
    tab.innerHTML = '<h3>Event Type Distribution</h3>';

    if (eventDist.distribution) {
        const table = document.createElement('table');
        table.className = 'data-table';
        table.innerHTML = `
            <thead>
                <tr>
                    <th>Event Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
                ${Object.entries(eventDist.distribution)
                    .sort((a, b) => b[1] - a[1])
                    .map(([type, count]) => {
                        const percent = ((count / eventDist.total_events) * 100).toFixed(1);
                        return `
                            <tr>
                                <td>${type}</td>
                                <td>${count}</td>
                                <td>${percent}%</td>
                            </tr>
                        `;
                    }).join('')}
            </tbody>
        `;
        tab.appendChild(table);
    }
}

// Display modules tab
function displayModulesTab(moduleActivity) {
    const tab = document.getElementById('modulesTab');
    tab.innerHTML = '<h3>Module Activity</h3>';

    if (moduleActivity.most_active && moduleActivity.most_active.length > 0) {
        const table = document.createElement('table');
        table.className = 'data-table';
        table.innerHTML = `
            <thead>
                <tr>
                    <th>Module</th>
                    <th>Events Generated</th>
                </tr>
            </thead>
            <tbody>
                ${moduleActivity.most_active.map(([module, count]) => `
                    <tr>
                        <td>${module}</td>
                        <td>${count}</td>
                    </tr>
                `).join('')}
            </tbody>
        `;
        tab.appendChild(table);
    }
}

// Display corruption tab
function displayCorruptionTab(corruptionPatterns) {
    const tab = document.getElementById('corruptionTab');
    tab.innerHTML = '<h3>Corruption Indicators Analysis</h3>';

    const summary = document.createElement('div');
    summary.innerHTML = `
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Indicators</div>
                <div class="stat-value">${corruptionPatterns.total_indicators}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Unique Keywords</div>
                <div class="stat-value">${corruptionPatterns.unique_keywords}</div>
            </div>
        </div>
    `;
    tab.appendChild(summary);

    if (corruptionPatterns.most_common_keywords && corruptionPatterns.most_common_keywords.length > 0) {
        const keywordsSection = document.createElement('div');
        keywordsSection.innerHTML = '<h4>Most Common Keywords</h4>';

        corruptionPatterns.most_common_keywords.forEach(([keyword, count]) => {
            const badge = document.createElement('span');
            badge.className = 'keyword-badge';
            badge.textContent = `${keyword} (${count})`;
            keywordsSection.appendChild(badge);
        });

        tab.appendChild(keywordsSection);
    }
}

// Display threats tab
function displayThreatsTab(tocPatterns) {
    const tab = document.getElementById('threatsTab');
    tab.innerHTML = '<h3>Threat of Compromise Analysis</h3>';

    const summary = document.createElement('div');
    summary.innerHTML = `
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Indicators</div>
                <div class="stat-value">${tocPatterns.total_indicators}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Unique Keywords</div>
                <div class="stat-value">${tocPatterns.unique_keywords}</div>
            </div>
        </div>
    `;
    tab.appendChild(summary);

    if (tocPatterns.most_common_keywords && tocPatterns.most_common_keywords.length > 0) {
        const keywordsSection = document.createElement('div');
        keywordsSection.innerHTML = '<h4>Most Common Keywords</h4>';

        tocPatterns.most_common_keywords.forEach(([keyword, count]) => {
            const badge = document.createElement('span');
            badge.className = 'keyword-badge';
            badge.textContent = `${keyword} (${count})`;
            keywordsSection.appendChild(badge);
        });

        tab.appendChild(keywordsSection);
    }
}

// Display recommendations tab
function displayRecommendationsTab(recommendations) {
    const tab = document.getElementById('recommendationsTab');
    tab.innerHTML = '<h3>Security Recommendations</h3>';

    if (recommendations && recommendations.length > 0) {
        recommendations.forEach(rec => {
            const item = document.createElement('div');
            item.className = 'recommendation-item';
            item.textContent = rec;
            tab.appendChild(item);
        });
    } else {
        tab.innerHTML += '<p>No specific recommendations at this time.</p>';
    }
}

// Generate report
async function generateReport() {
    if (!currentFilename) {
        showToast('No file uploaded', 'error');
        return;
    }

    const options = {
        generate_charts: document.getElementById('generateCharts').checked,
        generate_pdf: document.getElementById('generatePdf').checked
    };

    showLoading('Generating reports... This may take a moment.');

    try {
        const response = await fetch('/generate_report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                filename: currentFilename,
                options: options
            })
        });

        const result = await response.json();

        if (response.ok) {
            hideLoading();
            displayDownloads(result.report_id, result.files);
            showToast('Reports generated successfully!', 'success');
        } else {
            throw new Error(result.error || 'Report generation failed');
        }
    } catch (error) {
        hideLoading();
        showToast(`Error: ${error.message}`, 'error');
    }
}

// Display downloads
function displayDownloads(reportId, files) {
    const downloadsList = document.getElementById('downloadsList');
    downloadsList.innerHTML = '';

    const fileTypes = {
        'pdf': { icon: 'fa-file-pdf', label: 'PDF Report', color: '#f56565' },
        'json': { icon: 'fa-file-code', label: 'JSON Data', color: '#4299e1' },
        'charts': { icon: 'fa-chart-bar', label: 'Charts', color: '#48bb78' }
    };

    Object.entries(files).forEach(([type, value]) => {
        if (type.endsWith('_error')) return;

        const fileInfo = fileTypes[type] || { icon: 'fa-file', label: type, color: '#667eea' };

        if (Array.isArray(value)) {
            // Multiple files (charts)
            value.forEach(filename => {
                addDownloadItem(downloadsList, reportId, filename, fileInfo);
            });
        } else {
            // Single file
            addDownloadItem(downloadsList, reportId, value, fileInfo);
        }
    });

    document.getElementById('downloadsSection').style.display = 'block';
    document.getElementById('downloadsSection').scrollIntoView({ behavior: 'smooth' });
}

// Add download item
function addDownloadItem(container, reportId, filename, fileInfo) {
    const item = document.createElement('div');
    item.className = 'download-item';
    item.innerHTML = `
        <div class="download-info">
            <i class="fas ${fileInfo.icon}" style="color: ${fileInfo.color}"></i>
            <div>
                <div style="font-weight: 600;">${filename}</div>
                <div style="font-size: 0.9rem; color: var(--text-secondary);">${fileInfo.label}</div>
            </div>
        </div>
        <a href="/download/${reportId}/${filename}" class="btn btn-primary" download>
            <i class="fas fa-download"></i> Download
        </a>
    `;
    container.appendChild(item);
}

// Tab switching
function showTab(tabName) {
    // Hide all tab panes
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active');
    });

    // Remove active class from all buttons
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected tab
    document.getElementById(`${tabName}Tab`).classList.add('active');

    // Add active class to clicked button
    event.target.closest('.tab-button').classList.add('active');
}

// Reset app
function resetApp() {
    currentFilename = null;
    currentAnalysis = null;

    document.getElementById('summarySection').style.display = 'none';
    document.getElementById('analysisSection').style.display = 'none';
    document.getElementById('downloadsSection').style.display = 'none';
    document.getElementById('uploadSection').style.display = 'block';
    document.getElementById('fileInput').value = '';
}

// Show loading overlay
function showLoading(text = 'Processing...') {
    document.getElementById('loadingText').textContent = text;
    document.getElementById('loadingOverlay').style.display = 'flex';
}

// Hide loading overlay
function hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

// Show progress
function showProgress(percent) {
    document.getElementById('uploadProgress').style.display = 'block';
    document.getElementById('progressFill').style.width = percent + '%';
    document.getElementById('progressText').textContent = `Uploading... ${percent}%`;
}

// Show toast notification
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icons = {
        'success': 'fa-check-circle',
        'error': 'fa-exclamation-circle',
        'info': 'fa-info-circle'
    };

    toast.innerHTML = `
        <i class="fas ${icons[type] || icons.info}"></i>
        <span>${message}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 5000);
}
