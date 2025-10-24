// SpiderFoot TOC/Corruption Analyzer - JavaScript

const RECORD_RENDER_LIMIT = 1000;
const TEXT_PREVIEW_EXTENSIONS = new Set(['json', 'txt', 'md', 'markdown', 'csv', 'log']);
const MEDIA_PREVIEW_EXTENSIONS = new Set(['png', 'jpg', 'jpeg', 'gif', 'svg']);
const PDF_PREVIEW_EXTENSIONS = new Set(['pdf']);

let currentFilename = null;
let currentAnalysis = null;
let currentAiReport = null;
let currentWebResearch = null;

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    setupUploadZone();
    setupFileInput();
    setupPreviewModal();
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

function setupPreviewModal() {
    const modal = document.getElementById('previewModal');
    if (!modal) {
        return;
    }

    modal.addEventListener('click', (event) => {
        if (event.target.classList.contains('preview-modal__overlay')) {
            closePreviewModal();
        }
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && modal.classList.contains('active')) {
            closePreviewModal();
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
            currentAnalysis = null;
            currentAiReport = null;
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
        const displayValue = Number.isFinite(stat.value) ? Number(stat.value).toLocaleString() : '0';
        statCard.innerHTML = `
            <div class="stat-label"><i class="fas ${stat.icon}"></i> ${stat.label}</div>
            <div class="stat-value">${displayValue}</div>
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
    displayPivotsTab(analysis.pivots_and_leads || []);
    displayRecommendationsTab(analysis.recommendations);
}

// Display threat overview cards
function displayThreatOverview(analysis) {
    const threatOverview = document.getElementById('threatOverview');
    const threatDetails = document.getElementById('threatDetails');
    threatOverview.innerHTML = '';

    const corruption = analysis.corruption_patterns || {};
    const toc = analysis.toc_patterns || {};
    const riskDomains = analysis.risk_domains || {};
    const compromisedAssets = analysis.compromised_assets || {};

    const threats = [
        {
            label: 'Corruption Indicators',
            count: Number(corruption.total_indicators || 0),
            icon: 'fa-exclamation-triangle',
            class: 'corruption'
        },
        {
            label: 'TOC Indicators',
            count: Number(toc.total_indicators || 0),
            icon: 'fa-shield-alt',
            class: 'toc'
        },
        {
            label: 'High-Risk Domains',
            count: Number(riskDomains.total_risk_domains || 0),
            icon: 'fa-globe',
            class: 'domains'
        },
        {
            label: 'Compromised Assets',
            count: Number(compromisedAssets.total_compromised || 0),
            icon: 'fa-server',
            class: 'assets'
        }
    ];

    const chooseThreat = (category, cardEl) => {
        setActiveThreatCard(cardEl);
        renderThreatDetails(category, analysis);
    };

    const firstActionable = threats.find(threat => threat.count > 0) || threats[0];
    let defaultCard = null;

    threats.forEach(threat => {
        const card = document.createElement('div');
        card.className = `threat-card ${threat.class}`;
        card.setAttribute('role', 'button');
        card.setAttribute('tabindex', '0');
        card.setAttribute('aria-pressed', 'false');
        card.dataset.threatKey = threat.class;
        card.innerHTML = `
            <i class="fas ${threat.icon}"></i>
            <div class="threat-count">${threat.count}</div>
            <div class="threat-label">${threat.label}</div>
        `;

        card.addEventListener('click', () => chooseThreat(threat.class, card));
        card.addEventListener('keydown', (evt) => {
            if (evt.key === 'Enter' || evt.key === ' ') {
                evt.preventDefault();
                chooseThreat(threat.class, card);
            }
        });

        if (threat === firstActionable) {
            defaultCard = card;
        }

        threatOverview.appendChild(card);
    });

    if (defaultCard) {
        chooseThreat(defaultCard.dataset.threatKey, defaultCard);
    } else if (threatDetails) {
        threatDetails.innerHTML = '<p>Select a category above to view detailed findings.</p>';
    }
}

function setActiveThreatCard(card) {
    document.querySelectorAll('#threatOverview .threat-card').forEach((el) => {
        el.classList.remove('active');
        el.setAttribute('aria-pressed', 'false');
    });
    if (card) {
        card.classList.add('active');
        card.setAttribute('aria-pressed', 'true');
    }
}

function renderThreatDetails(category, analysis) {
    const threatDetails = document.getElementById('threatDetails');
    if (!threatDetails) {
        return;
    }

    threatDetails.classList.add('detail-panel');
    threatDetails.innerHTML = '';

    const heading = document.createElement('h3');
    heading.className = 'detail-heading';
    threatDetails.appendChild(heading);

    const summary = document.createElement('p');
    summary.className = 'detail-summary';
    threatDetails.appendChild(summary);

    if (category === 'corruption') {
        const corruption = analysis.corruption_patterns || {};
        heading.textContent = 'Corruption Indicators';
        summary.textContent = `Total indicators detected: ${Number(corruption.total_indicators || 0).toLocaleString()}`;

        renderKeywordBadges(threatDetails, corruption.most_common_keywords, 'Most Common Keywords');
        renderRecordTable(
            threatDetails,
            corruption.events || [],
            'Corruption Indicator Events',
            'No corruption indicators were detected in this dataset.'
        );
        return;
    }

    if (category === 'toc') {
        const toc = analysis.toc_patterns || {};
        heading.textContent = 'Threat of Compromise Indicators';
        summary.textContent = `Total indicators detected: ${Number(toc.total_indicators || 0).toLocaleString()}`;

        renderKeywordBadges(threatDetails, toc.most_common_keywords, 'Frequently Observed Keywords');
        renderRecordTable(
            threatDetails,
            toc.events || [],
            'Threat of Compromise Events',
            'No threat-of-compromise signals were found.'
        );
        return;
    }

    if (category === 'domains') {
        const domains = analysis.risk_domains || {};
        const details = Object.entries(domains.domain_details || {});

        heading.textContent = 'High-Risk Domains';
        summary.textContent = `Total domains flagged: ${Number(domains.total_risk_domains || 0).toLocaleString()}`;

        if (details.length > 0) {
            const domainSection = document.createElement('div');
            domainSection.className = 'detail-section';
            const domainHeading = document.createElement('h4');
            domainHeading.textContent = 'Domains by Frequency';
            domainSection.appendChild(domainHeading);

            const tableRows = details
                .sort((a, b) => (b[1].occurrences || 0) - (a[1].occurrences || 0))
                .slice(0, RECORD_RENDER_LIMIT)
                .map(([domain, info]) => {
                    const reasons = Object.entries(info.reasons || {})
                        .sort((a, b) => b[1] - a[1]);
                    const topReason = reasons.length > 0 ? reasons[0][0] : 'Multiple signals';
                    const modules = Array.isArray(info.modules) ? info.modules : [];
                    return `
                        <tr>
                            <td>${escapeHtml(domain)}</td>
                            <td>${Number(info.occurrences || 0).toLocaleString()}</td>
                            <td>${escapeHtml(topReason)}</td>
                            <td>${escapeHtml(modules.join(', ') || 'n/a')}</td>
                        </tr>
                    `;
                })
                .join('');

            const table = document.createElement('table');
            table.className = 'data-table record-table';
            table.innerHTML = `
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Hits</th>
                        <th>Primary Reason</th>
                        <th>Modules</th>
                    </tr>
                </thead>
                <tbody>
                    ${tableRows}
                </tbody>
            `;

            domainSection.appendChild(table);

            if (details.length > RECORD_RENDER_LIMIT) {
                const note = document.createElement('p');
                note.className = 'record-count-note';
                note.textContent = `Showing top ${RECORD_RENDER_LIMIT.toLocaleString()} of ${details.length.toLocaleString()} domains.`;
                domainSection.appendChild(note);
            }

            threatDetails.appendChild(domainSection);
        } else {
            const empty = document.createElement('p');
            empty.className = 'empty-state';
            empty.textContent = 'No high-risk domains were flagged in this analysis.';
            threatDetails.appendChild(empty);
        }

        renderRecordTable(
            threatDetails,
            domains.records || [],
            'Domain Risk Evidence',
            'No supporting domain events captured.'
        );
        return;
    }

    if (category === 'assets') {
        const assets = analysis.compromised_assets || {};
        const assetDetails = Object.entries(assets.asset_details || {});

        heading.textContent = 'Compromised Assets';
        summary.textContent = `Total assets flagged: ${Number(assets.total_compromised || 0).toLocaleString()}`;

        if (assetDetails.length > 0) {
            const assetSection = document.createElement('div');
            assetSection.className = 'detail-section';
            const assetHeading = document.createElement('h4');
            assetHeading.textContent = 'Assets by Severity';
            assetSection.appendChild(assetHeading);

            const tableRows = assetDetails
                .sort((a, b) => (b[1].occurrences || 0) - (a[1].occurrences || 0))
                .slice(0, RECORD_RENDER_LIMIT)
                .map(([label, info]) => {
                    const modules = Array.isArray(info.modules) ? info.modules : [];
                    const sources = Array.isArray(info.sources) ? info.sources : [];
                    return `
                        <tr>
                            <td>${escapeHtml(label)}</td>
                            <td>${escapeHtml(info.type || 'Unknown')}</td>
                            <td>${Number(info.occurrences || 0).toLocaleString()}</td>
                            <td>${escapeHtml(modules.join(', ') || 'n/a')}</td>
                            <td>${escapeHtml(sources.join(', ') || 'n/a')}</td>
                        </tr>
                    `;
                })
                .join('');

            const table = document.createElement('table');
            table.className = 'data-table record-table';
            table.innerHTML = `
                <thead>
                    <tr>
                        <th>Asset</th>
                        <th>Type</th>
                        <th>Hits</th>
                        <th>Modules</th>
                        <th>Sources</th>
                    </tr>
                </thead>
                <tbody>${tableRows}</tbody>
            `;

            assetSection.appendChild(table);

            if (assetDetails.length > RECORD_RENDER_LIMIT) {
                const note = document.createElement('p');
                note.className = 'record-count-note';
                note.textContent = `Showing top ${RECORD_RENDER_LIMIT.toLocaleString()} of ${assetDetails.length.toLocaleString()} assets.`;
                assetSection.appendChild(note);
            }

            threatDetails.appendChild(assetSection);
        } else {
            const empty = document.createElement('p');
            empty.className = 'empty-state';
            empty.textContent = 'No compromised assets were detected.';
            threatDetails.appendChild(empty);
        }

        renderRecordTable(
            threatDetails,
            assets.records || [],
            'Asset Intelligence Events',
            'No supporting asset telemetry was recorded.'
        );
        return;
    }

    heading.textContent = 'Threat Overview';
    summary.textContent = 'Select a card above to inspect supporting evidence.';
}

function renderKeywordBadges(container, keywords, title) {
    if (!Array.isArray(keywords) || keywords.length === 0) {
        return;
    }

    const section = document.createElement('div');
    section.className = 'detail-section';

    const heading = document.createElement('h4');
    heading.textContent = title;
    section.appendChild(heading);

    const wrapper = document.createElement('div');
    wrapper.className = 'keyword-badge-wrapper';

    keywords.forEach(([keyword, count]) => {
        const badge = document.createElement('span');
        badge.className = 'keyword-badge';
        badge.textContent = `${keyword} (${count})`;
        wrapper.appendChild(badge);
    });

    section.appendChild(wrapper);
    container.appendChild(section);
}

function renderRecordTable(container, records, title, emptyMessage) {
    const section = document.createElement('div');
    section.className = 'detail-section';

    const heading = document.createElement('h4');
    heading.textContent = title;
    section.appendChild(heading);

    if (!Array.isArray(records) || records.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'empty-state';
        empty.textContent = emptyMessage;
        section.appendChild(empty);
        container.appendChild(section);
        return;
    }

    const limit = Math.min(records.length, RECORD_RENDER_LIMIT);
    const rows = records.slice(0, limit).map((record) => {
        const eventType = record.type || record.Type || 'Unknown';
        const module = record.module || record.Module || 'Unknown';
        const source = record.source || record.Source || '';
        const dataField = record.data || record.Data || '';
        const timestamp = record.timestamp || record.Time || record.Timestamp || '';

        return `
            <tr>
                <td>${escapeHtml(eventType)}</td>
                <td>${escapeHtml(module)}</td>
                <td>${escapeHtml(truncateText(source, 120))}</td>
                <td>${escapeHtml(truncateText(dataField, 200))}</td>
                <td>${escapeHtml(timestamp)}</td>
            </tr>
        `;
    }).join('');

    const table = document.createElement('table');
    table.className = 'data-table record-table';
    table.innerHTML = `
        <thead>
            <tr>
                <th>Type</th>
                <th>Module</th>
                <th>Source</th>
                <th>Data</th>
                <th>Timestamp</th>
            </tr>
        </thead>
        <tbody>${rows}</tbody>
    `;

    section.appendChild(table);

    const note = document.createElement('p');
    note.className = 'record-count-note';
    if (records.length > limit) {
        note.textContent = `Showing first ${limit.toLocaleString()} of ${records.length.toLocaleString()} records.`;
    } else {
        const label = records.length === 1 ? 'record' : 'records';
        note.textContent = `Showing ${records.length.toLocaleString()} ${label}.`;
    }
    section.appendChild(note);

    container.appendChild(section);
}

function truncateText(value, maxLength) {
    if (typeof value !== 'string') {
        value = value == null ? '' : String(value);
    }
    if (!maxLength || value.length <= maxLength) {
        return value;
    }
    return `${value.slice(0, maxLength - 1)}…`;
}

function escapeHtml(value) {
    if (value == null) {
        return '';
    }
    return String(value).replace(/[&<>"']/g, (char) => {
        switch (char) {
            case '&':
                return '&amp;';
            case '<':
                return '&lt;';
            case '>':
                return '&gt;';
            case '"':
                return '&quot;';
            case '\'':
                return '&#39;';
            default:
                return char;
        }
    });
}

// Display events tab
function displayEventsTab(eventDist) {
    const tab = document.getElementById('eventsTab');
    tab.innerHTML = '<h3>Event Type Distribution</h3>';

    if (!eventDist || !eventDist.distribution) {
        tab.innerHTML += '<p>No event data available.</p>';
        return;
    }

    const recordsByType = eventDist.records_by_type || {};
    const totalEvents = eventDist.total_events || 0;

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
                    const percent = totalEvents ? ((count / totalEvents) * 100).toFixed(1) : '0.0';
                    return `
                        <tr data-event-type="${escapeHtml(type)}">
                            <td>${escapeHtml(type)}</td>
                            <td>${Number(count).toLocaleString()}</td>
                            <td>${percent}%</td>
                        </tr>
                    `;
                }).join('')}
        </tbody>
    `;
    tab.appendChild(table);

    const detailContainer = document.createElement('div');
    detailContainer.className = 'detail-panel';
    detailContainer.innerHTML = '<p class="empty-state">Select an event type to view sample records.</p>';
    tab.appendChild(detailContainer);

    Array.from(table.querySelectorAll('tbody tr')).forEach((row) => {
        const eventType = row.dataset.eventType;
        row.classList.add('clickable');
        row.addEventListener('click', () => {
            const records = recordsByType[eventType] || [];
            detailContainer.innerHTML = '';
            renderRecordTable(
                detailContainer,
                records,
                `${eventType} Records`,
                `No detailed records persisted for ${eventType}.`
            );
        });
    });
}

// Display modules tab
function displayModulesTab(moduleActivity) {
    const tab = document.getElementById('modulesTab');
    tab.innerHTML = '<h3>Module Activity</h3>';

    if (!moduleActivity || !Array.isArray(moduleActivity.most_active) || moduleActivity.most_active.length === 0) {
        tab.innerHTML += '<p>No module activity captured.</p>';
        return;
    }

    const recordsByModule = moduleActivity.records_by_module || {};

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
            ${moduleActivity.most_active
                .map(([module, count]) => `
                    <tr data-module-name="${escapeHtml(module)}">
                        <td>${escapeHtml(module)}</td>
                        <td>${Number(count).toLocaleString()}</td>
                    </tr>
                `)
                .join('')}
        </tbody>
    `;
    tab.appendChild(table);

    const detailContainer = document.createElement('div');
    detailContainer.className = 'detail-panel';
    detailContainer.innerHTML = '<p class="empty-state">Select a module to inspect its emitted records.</p>';
    tab.appendChild(detailContainer);

    Array.from(table.querySelectorAll('tbody tr')).forEach((row) => {
        const moduleName = row.dataset.moduleName;
        row.classList.add('clickable');
        row.addEventListener('click', () => {
            const records = recordsByModule[moduleName] || [];
            detailContainer.innerHTML = '';
            renderRecordTable(
                detailContainer,
                records,
                `${moduleName} Output`,
                `No records were captured for ${moduleName}.`
            );
        });
    });
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

    renderRecordTable(
        tab,
        corruptionPatterns.events || [],
        'Corruption Indicator Records',
        'No corruption indicator events were identified.'
    );
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

    renderRecordTable(
        tab,
        tocPatterns.events || [],
        'Threat of Compromise Records',
        'No threat of compromise events were captured.'
    );
}

// Display recommendations tab
function displayRecommendationsTab(recommendations) {
    const tab = document.getElementById('recommendationsTab');
    tab.innerHTML = '<h3>Security Recommendations</h3>';

    const primaryRecommendations = Array.isArray(recommendations) ? recommendations : [];
    const aiRecommendations = currentAiReport && Array.isArray(currentAiReport.recommendations)
        ? currentAiReport.recommendations
        : [];

    if (primaryRecommendations.length > 0) {
        primaryRecommendations.forEach((rec) => {
            const item = document.createElement('div');
            item.className = 'recommendation-item';
            item.textContent = rec;
            tab.appendChild(item);
        });
    }

    if (aiRecommendations.length > 0) {
        const divider = document.createElement('h4');
        divider.textContent = 'AI-Generated Strategic Recommendations';
        tab.appendChild(divider);

        aiRecommendations.forEach((rec) => {
            const item = document.createElement('div');
            item.className = 'recommendation-item';
            item.textContent = rec;
            tab.appendChild(item);
        });
    }

    if (primaryRecommendations.length === 0 && aiRecommendations.length === 0) {
        tab.innerHTML += '<p>No specific recommendations at this time.</p>';
    }
}

function createPivotCard(pivot, originLabel = null) {
    const card = document.createElement('div');
    card.className = 'pivot-card';

    const header = document.createElement('div');
    header.className = 'pivot-header';

    const category = document.createElement('span');
    category.className = 'pivot-category';
    category.textContent = pivot.category || originLabel || 'Lead';
    header.appendChild(category);

    const confidence = document.createElement('span');
    const confidenceValue = (pivot.confidence || 'unknown').toLowerCase();
    confidence.className = `pivot-confidence ${confidenceValue}`;
    confidence.textContent = pivot.confidence || 'Unknown';
    header.appendChild(confidence);

    card.appendChild(header);

    if (originLabel) {
        const origin = document.createElement('span');
        origin.className = 'pivot-origin';
        origin.textContent = originLabel;
        card.appendChild(origin);
    }

    const title = document.createElement('h4');
    title.textContent = pivot.title || pivot.indicator || 'Investigative Lead';
    card.appendChild(title);

    if (pivot.summary) {
        const summary = document.createElement('p');
        summary.className = 'pivot-summary';
        summary.textContent = pivot.summary;
        card.appendChild(summary);
    }

    if (pivot.rationale) {
        const rationale = document.createElement('p');
        rationale.className = 'pivot-rationale';
        const emphasis = document.createElement('strong');
        emphasis.textContent = 'Why it matters:';
        rationale.appendChild(emphasis);
        rationale.append(` ${pivot.rationale}`);
        card.appendChild(rationale);
    }

    const recommendation = pivot.recommended_actions || pivot.recommended_action;
    if (recommendation) {
        const actions = document.createElement('p');
        actions.className = 'pivot-actions';
        const emphasis = document.createElement('strong');
        emphasis.textContent = 'Next Steps:';
        actions.appendChild(emphasis);
        actions.append(` ${recommendation}`);
        card.appendChild(actions);
    }

    const evidence = pivot.supporting_evidence || [];
    if (Array.isArray(evidence) && evidence.length > 0) {
        const evidenceEl = document.createElement('p');
        evidenceEl.className = 'pivot-evidence';
        const emphasis = document.createElement('strong');
        emphasis.textContent = 'Supporting Evidence:';
        evidenceEl.appendChild(emphasis);
        evidenceEl.append(` ${evidence.slice(0, 5).join('; ')}`);
        card.appendChild(evidenceEl);
    }

    if (pivot.metrics && Object.keys(pivot.metrics).length > 0) {
        const metrics = document.createElement('p');
        metrics.className = 'pivot-metrics';
        const emphasis = document.createElement('strong');
        emphasis.textContent = 'Metrics:';
        metrics.appendChild(emphasis);
        const metricText = Object.entries(pivot.metrics)
            .map(([key, value]) => `${key}: ${value}`)
            .join(' • ');
        metrics.append(` ${metricText}`);
        card.appendChild(metrics);
    }

    return card;
}

function displayPivotsTab(pivots) {
    const tab = document.getElementById('pivotsTab');
    tab.innerHTML = '<h3>Investigative Pivots & Leads</h3>';

    let hasContent = false;

    if (Array.isArray(pivots) && pivots.length > 0) {
        const sectionHeading = document.createElement('h4');
        sectionHeading.textContent = 'Analytical Surface Leads';
        tab.appendChild(sectionHeading);

        pivots.forEach((pivot) => {
            tab.appendChild(createPivotCard(pivot, 'Analysis Engine'));
        });
        hasContent = true;
    }

    const aiPivots = currentAiReport && Array.isArray(currentAiReport.pivots_and_leads)
        ? currentAiReport.pivots_and_leads
        : [];

    if (aiPivots.length > 0) {
        const sectionHeading = document.createElement('h4');
        sectionHeading.textContent = 'AI-Identified Strategic Leads';
        tab.appendChild(sectionHeading);

        aiPivots.forEach((pivot) => {
            tab.appendChild(createPivotCard(pivot, 'AI Narrative'));
        });
        hasContent = true;
    }

    if (!hasContent) {
        tab.innerHTML += '<p>No pivots or investigative leads identified yet.</p>';
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
        generate_pdf: document.getElementById('generatePdf').checked,
        enable_web_research: document.getElementById('enableWebResearch').checked
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

        if (!response.ok) {
            throw new Error(result.error || 'Report generation failed');
        }

        hideLoading();

        currentAiReport = result.ai_report || null;
        currentWebResearch = result.web_research || null;

        if (currentAnalysis) {
            displayPivotsTab(currentAnalysis.pivots_and_leads || []);
            displayRecommendationsTab(currentAnalysis.recommendations || []);
        }

        if (currentAiReport) {
            showToast('AI narrative generated. Markdown download available.', 'info');
        }

        if (currentWebResearch && Array.isArray(currentWebResearch.queries) && currentWebResearch.queries.length > 0) {
            const providerLabel = currentWebResearch.provider ? ` via ${currentWebResearch.provider}` : '';
            showToast(`Web research enrichment available${providerLabel}.`, 'info');
        }

        displayDownloads(result.report_id, result.files);
        showToast('Reports generated successfully!', 'success');
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
        'pdf_intelligence': { icon: 'fa-file-pdf', label: 'Intelligence Report PDF', color: '#f56565' },
        'pdf_narrative': { icon: 'fa-file-pdf', label: 'Narrative Exposé PDF', color: '#ed8936' },
    'json': { icon: 'fa-file-code', label: 'JSON Data', color: '#4299e1' },
    'web_research': { icon: 'fa-search', label: 'Web Research Summary', color: '#805ad5' },
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

    const info = document.createElement('div');
    info.className = 'download-info';

    const safeFilename = escapeHtml(filename);
    const safeLabel = escapeHtml(fileInfo.label);
    info.innerHTML = `
        <i class="fas ${fileInfo.icon}" style="color: ${fileInfo.color}"></i>
        <div>
            <div style="font-weight: 600;">${safeFilename}</div>
            <div style="font-size: 0.9rem; color: var(--text-secondary);">${safeLabel}</div>
        </div>
    `;

    const actions = document.createElement('div');
    actions.className = 'download-actions';

    const encodedReportId = encodeURIComponent(reportId);
    const encodedFilename = encodeURIComponent(filename);
    const downloadLink = document.createElement('a');
    downloadLink.href = `/download/${encodedReportId}/${encodedFilename}`;
    downloadLink.className = 'btn btn-primary btn-sm';
    downloadLink.setAttribute('download', '');
    downloadLink.innerHTML = '<i class="fas fa-download"></i> Download';
    actions.appendChild(downloadLink);

    const extension = (filename.split('.').pop() || '').toLowerCase();
    const isTextPreview = TEXT_PREVIEW_EXTENSIONS.has(extension);
    const isMediaPreview = MEDIA_PREVIEW_EXTENSIONS.has(extension);
    const isPdfPreview = PDF_PREVIEW_EXTENSIONS.has(extension);

    if (isTextPreview || isMediaPreview || isPdfPreview) {
        const viewButton = document.createElement('button');
        viewButton.type = 'button';
        viewButton.className = 'btn btn-secondary btn-sm';
        viewButton.innerHTML = '<i class="fas fa-eye"></i> View';
        viewButton.addEventListener('click', () => {
            if (isTextPreview) {
                previewTextFile(reportId, filename);
            } else if (isPdfPreview) {
                previewPdfFile(reportId, filename);
            } else {
                previewImageFile(reportId, filename);
            }
        });
        actions.appendChild(viewButton);
    }

    item.appendChild(info);
    item.appendChild(actions);
    container.appendChild(item);
}

// Tab switching
function showTab(tabName, evt) {
    // Hide all tab panes
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active');
    });

    // Remove active class from all buttons
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected tab
    const activePane = document.getElementById(`${tabName}Tab`);
    if (activePane) {
        activePane.classList.add('active');
    }

    // Add active class to clicked button
    if (evt && evt.target) {
        const button = evt.target.closest('.tab-button');
        if (button) {
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
        }
    }
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

function previewTextFile(reportId, filename) {
    const encodedReportId = encodeURIComponent(reportId);
    const encodedFilename = encodeURIComponent(filename);
    showPreviewModal(filename);
    setPreviewBody('<p class="preview-loading"><i class="fas fa-spinner fa-spin"></i> Loading preview…</p>');

    fetch(`/preview/${encodedReportId}/${encodedFilename}`)
        .then(async (response) => {
            const data = await response.json().catch(() => ({ error: 'Invalid preview response.' }));
            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Unable to load preview');
            }

            const container = document.createElement('div');
            container.className = 'preview-text-wrapper';

            const pre = document.createElement('pre');
            pre.className = 'preview-text';
            pre.textContent = data.content || '';
            container.appendChild(pre);

            if (data.truncated) {
                const note = document.createElement('p');
                note.className = 'preview-note';
                note.textContent = 'Preview truncated. Download the file to view full contents.';
                container.appendChild(note);
            }

            setPreviewBody(container);
        })
        .catch((error) => {
            closePreviewModal();
            showToast(`Preview unavailable: ${error.message}`, 'error');
        });
}

function previewImageFile(reportId, filename) {
    const encodedReportId = encodeURIComponent(reportId);
    const encodedFilename = encodeURIComponent(filename);
    const url = `/preview/${encodedReportId}/${encodedFilename}`;

    showPreviewModal(filename);

    const img = document.createElement('img');
    img.className = 'preview-image';
    img.src = url;
    img.alt = filename;
    img.loading = 'lazy';
    img.addEventListener('error', () => {
        setPreviewBody('<p class="preview-error">Unable to render image preview. Please download the file instead.</p>');
    });

    setPreviewBody(img);
}

function previewPdfFile(reportId, filename) {
    const encodedReportId = encodeURIComponent(reportId);
    const encodedFilename = encodeURIComponent(filename);
    const url = `/preview/${encodedReportId}/${encodedFilename}`;

    showPreviewModal(filename);

    const wrapper = document.createElement('div');
    wrapper.className = 'preview-pdf-wrapper';

    const frame = document.createElement('iframe');
    frame.className = 'preview-frame';
    frame.src = url;
    frame.title = filename;
    frame.setAttribute('loading', 'lazy');
    wrapper.appendChild(frame);

    const fallback = document.createElement('p');
    fallback.className = 'preview-note';
    fallback.innerHTML = `If the PDF does not display, <a href="/download/${encodedReportId}/${encodedFilename}" target="_blank" rel="noopener">download it directly</a>.`;
    wrapper.appendChild(fallback);

    setPreviewBody(wrapper);
}

function showPreviewModal(title) {
    const modal = document.getElementById('previewModal');
    if (!modal) {
        return;
    }

    document.getElementById('previewTitle').textContent = title;
    setPreviewBody('');
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
}

function setPreviewBody(content) {
    const body = document.getElementById('previewBody');
    if (!body) {
        return;
    }

    body.innerHTML = '';
    if (typeof content === 'string') {
        body.innerHTML = content;
    } else if (content instanceof Node) {
        body.appendChild(content);
    }
}

function closePreviewModal() {
    const modal = document.getElementById('previewModal');
    if (!modal) {
        return;
    }

    modal.classList.remove('active');
    modal.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');

    const body = document.getElementById('previewBody');
    if (body) {
        body.innerHTML = '';
    }
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
