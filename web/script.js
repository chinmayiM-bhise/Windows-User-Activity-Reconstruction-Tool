/**
 * AegisDFIR Enterprise Forensic Interface Controller
 * Provides Multi-Pane Master-Detail Navigation, Chart.js Visualizations,
 * Live Triage Polling, Session Timeline, and DFIR Reporting.
 */

document.addEventListener('DOMContentLoaded', () => {
    // --- STATE MANAGEMENT ---
    let allArtifacts = [];
    let allCorrelations = [];
    let activeCategory = 'all';
    let searchQuery = '';
    let sortColumn = 'id';
    let sortDirection = 'desc';
    let currentPage = 1;
    let pageSize = 100;
    let selectedArtifactId = null;

    // Charts instances
    let timelineChartInstance = null;
    let categoryDonutInstance = null;
    let topAppsChartInstance = null;

    // --- DOM REFERENCES ---
    const navTabs = document.querySelectorAll('.nav-tab');
    const viewPanels = document.querySelectorAll('.view-panel');
    const statusToast = document.getElementById('statusToast');
    const evidenceTableBody = document.querySelector('#evidenceTable tbody');
    const recordCountDisplay = document.getElementById('recordCountDisplay');
    const filterSearchInput = document.getElementById('filterSearchInput');
    const clearSearchBtn = document.getElementById('clearSearchBtn');
    const pageSizeSelect = document.getElementById('pageSizeSelect');
    const prevPageBtn = document.getElementById('prevPageBtn');
    const nextPageBtn = document.getElementById('nextPageBtn');
    const pageIndicator = document.getElementById('pageIndicator');
    const themeToggle = document.getElementById('theme-toggle');

    // Action Controls
    const liveTriageBtn = document.getElementById('liveTriageBtn');
    const presetSelect = document.getElementById('presetSelect');
    const targetPathInput = document.getElementById('targetPathInput');
    const targetScanBtn = document.getElementById('targetScanBtn');
    const refreshBtn = document.getElementById('refreshBtn');
    const exportPdfBtn = document.getElementById('exportPdfBtn');
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    const exportJsonBtn = document.getElementById('exportJsonBtn');
    const clearDbBtn = document.getElementById('clearDbBtn');

    // Telemetry Elements
    const headerStatusText = document.getElementById('headerStatusText');
    const headerDbSha256 = document.getElementById('headerDbSha256');
    const treeTotalBadge = document.getElementById('treeTotalBadge');

    // Inspector Elements
    const inspectorHeaderTitle = document.getElementById('inspectorHeaderTitle');
    const insType = document.getElementById('insType');
    const insTime = document.getElementById('insTime');
    const insName = document.getElementById('insName');
    const insPath = document.getElementById('insPath');
    const insExtra = document.getElementById('insExtra');
    const insThreatContent = document.getElementById('insThreatContent');
    const insJsonBox = document.getElementById('insJsonBox');
    const inspectTabs = document.querySelectorAll('.inspect-tab');
    const inspectTabContents = document.querySelectorAll('.inspect-tab-content');

    // Modal Elements
    const pdfModal = document.getElementById('pdfModal');
    const closePdfModal = document.getElementById('closePdfModal');
    const pdfConfigForm = document.getElementById('pdfConfigForm');

    // Timeline Elements
    const timelineFeedContainer = document.getElementById('timelineFeedContainer');
    const btnTimelineAll = document.getElementById('btnTimelineAll');
    const btnTimelineAnomaliesOnly = document.getElementById('btnTimelineAnomaliesOnly');
    const corrSearchInput = document.getElementById('corrSearchInput');
    const btnExportCorrPdf = document.getElementById('btnExportCorrPdf');

    // Catalog Container
    const catalogGridContainer = document.getElementById('catalogGridContainer');

    // --- TOAST HELPER ---
    function showToast(message, isError = false) {
        statusToast.textContent = message;
        statusToast.style.display = 'block';
        statusToast.style.borderColor = isError ? 'var(--accent-red)' : 'var(--accent-cyan)';
        statusToast.style.color = isError ? 'var(--accent-red)' : 'var(--accent-cyan)';
        setTimeout(() => {
            statusToast.style.display = 'none';
        }, 5000);
    }

    // --- NAVIGATION VIEW SWITCHER ---
    navTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            navTabs.forEach(t => t.classList.remove('active'));
            viewPanels.forEach(p => p.classList.remove('active'));

            tab.classList.add('active');
            const targetView = tab.getAttribute('data-view');
            const panel = document.getElementById(targetView);
            if (panel) panel.classList.add('active');

            if (targetView === 'analytics-view') {
                renderVisualAnalytics();
            } else if (targetView === 'timeline-view') {
                fetchAndRenderTimeline();
            } else if (targetView === 'catalog-view') {
                renderCatalogView();
            }
        });
    });

    // --- BADGE CLASS HELPER ---
    function getBadgeClass(type) {
        const t = (type || '').toLowerCase();
        if (t.includes('prefetch')) return 'badge-prefetch';
        if (t.includes('browser') || t.includes('url')) return 'badge-browser';
        if (t.includes('powershell')) return 'badge-powershell';
        if (t.includes('usb')) return 'badge-usb';
        if (t.includes('recycle')) return 'badge-recycle';
        if (t.includes('event') || t.includes('logon')) return 'badge-event';
        if (t.includes('shellbag')) return 'badge-shellbag';
        if (t.includes('userassist')) return 'badge-userassist';
        if (t.includes('bam')) return 'badge-bam';
        if (t.includes('startup')) return 'badge-startup';
        if (t.includes('jumplist')) return 'badge-jumplist';
        return 'badge-other';
    }

    // --- TREE NODE FILTERING ---
    function filterByCategory(art, category) {
        if (category === 'all') return true;
        const t = (art.artifact_type || '').toLowerCase();
        const extra = (art.extra || '').toLowerCase();

        if (category === 'threats') {
            return extra.includes('threat_tag') || extra.includes('critical') || extra.includes('tampering') || extra.includes('1102');
        }
        if (category === 'prefetch') return t.includes('prefetch');
        if (category === 'userassist') return t.includes('userassist');
        if (category === 'bam') return t.includes('bam');
        if (category === 'startup') return t.includes('startup');
        if (category === 'lnk') return t.includes('lnk');
        if (category === 'shellbag') return t.includes('shellbag');
        if (category === 'jumplist') return t.includes('jumplist');
        if (category === 'recycle') return t.includes('recycle');
        if (category === 'browser') return t.includes('browser_url');
        if (category === 'download') return t.includes('browser_download');
        if (category === 'powershell') return t.includes('powershell');
        if (category === 'usb') return t.includes('usb');
        if (category === 'event') return t.includes('event') || t.includes('logon');
        return true;
    }

    document.querySelectorAll('.tree-node').forEach(node => {
        node.addEventListener('click', () => {
            document.querySelectorAll('.tree-node').forEach(n => n.classList.remove('active'));
            node.classList.add('active');
            activeCategory = node.getAttribute('data-category');
            currentPage = 1;
            renderEvidenceTable();
        });
    });

    // --- UPDATE SIDEBAR BADGE COUNTS ---
    function updateSidebarBadges() {
        const counts = {
            all: allArtifacts.length,
            threats: 0,
            prefetch: 0,
            userassist: 0,
            bam: 0,
            startup: 0,
            lnk: 0,
            shellbag: 0,
            jumplist: 0,
            recycle: 0,
            browser: 0,
            download: 0,
            powershell: 0,
            usb: 0,
            event: 0
        };

        allArtifacts.forEach(art => {
            const t = (art.artifact_type || '').toLowerCase();
            const extra = (art.extra || '').toLowerCase();

            if (extra.includes('threat_tag') || extra.includes('critical') || extra.includes('tampering') || extra.includes('1102')) counts.threats++;
            if (t.includes('prefetch')) counts.prefetch++;
            if (t.includes('userassist')) counts.userassist++;
            if (t.includes('bam')) counts.bam++;
            if (t.includes('startup')) counts.startup++;
            if (t.includes('lnk')) counts.lnk++;
            if (t.includes('shellbag')) counts.shellbag++;
            if (t.includes('jumplist')) counts.jumplist++;
            if (t.includes('recycle')) counts.recycle++;
            if (t.includes('browser_url')) counts.browser++;
            if (t.includes('browser_download')) counts.download++;
            if (t.includes('powershell')) counts.powershell++;
            if (t.includes('usb')) counts.usb++;
            if (t.includes('event') || t.includes('logon')) counts.event++;
        });

        treeTotalBadge.textContent = counts.all.toLocaleString();
        document.getElementById('badge-all').textContent = counts.all;
        document.getElementById('badge-threats').textContent = counts.threats;
        document.getElementById('badge-prefetch').textContent = counts.prefetch;
        document.getElementById('badge-userassist').textContent = counts.userassist;
        document.getElementById('badge-bam').textContent = counts.bam;
        document.getElementById('badge-startup').textContent = counts.startup;
        document.getElementById('badge-lnk').textContent = counts.lnk;
        document.getElementById('badge-shellbag').textContent = counts.shellbag;
        document.getElementById('badge-jumplist').textContent = counts.jumplist;
        document.getElementById('badge-recycle').textContent = counts.recycle;
        document.getElementById('badge-browser').textContent = counts.browser;
        document.getElementById('badge-download').textContent = counts.download;
        document.getElementById('badge-powershell').textContent = counts.powershell;
        document.getElementById('badge-usb').textContent = counts.usb;
        document.getElementById('badge-event').textContent = counts.event;
    }

    // --- RENDER MASTER EVIDENCE TABLE ---
    function renderEvidenceTable() {
        let filtered = allArtifacts.filter(art => filterByCategory(art, activeCategory));

        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            filtered = filtered.filter(art =>
                (art.name && art.name.toLowerCase().includes(q)) ||
                (art.path && art.path.toLowerCase().includes(q)) ||
                (art.artifact_type && art.artifact_type.toLowerCase().includes(q)) ||
                (art.extra && art.extra.toLowerCase().includes(q)) ||
                (art.timestamp && art.timestamp.toLowerCase().includes(q))
            );
        }

        // Sorting
        filtered.sort((a, b) => {
            let valA = a[sortColumn] || '';
            let valB = b[sortColumn] || '';
            if (typeof valA === 'string') valA = valA.toLowerCase();
            if (typeof valB === 'string') valB = valB.toLowerCase();

            if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
            if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
            return 0;
        });

        // Pagination
        const totalItems = filtered.length;
        const totalPages = pageSize === 'all' ? 1 : Math.max(1, Math.ceil(totalItems / parseInt(pageSize)));
        if (currentPage > totalPages) currentPage = totalPages;

        let pageItems = filtered;
        if (pageSize !== 'all') {
            const startIdx = (currentPage - 1) * parseInt(pageSize);
            pageItems = filtered.slice(startIdx, startIdx + parseInt(pageSize));
        }

        recordCountDisplay.textContent = `Showing ${pageItems.length} of ${totalItems} filtered items (${allArtifacts.length} total)`;
        pageIndicator.textContent = `Page ${currentPage} of ${totalPages}`;
        prevPageBtn.disabled = (currentPage <= 1);
        nextPageBtn.disabled = (currentPage >= totalPages);

        evidenceTableBody.innerHTML = '';

        if (pageItems.length === 0) {
            evidenceTableBody.innerHTML = `
                <tr>
                    <td colspan="6" style="text-align: center; padding: 48px; color: var(--text-muted);">
                        No evidence items found matching the selected tree node and search query.
                    </td>
                </tr>
            `;
            return;
        }

        const fragment = document.createDocumentFragment();
        pageItems.forEach(art => {
            const tr = document.createElement('tr');
            if (selectedArtifactId === art.id) tr.classList.add('selected');

            const extraStr = art.extra || '';
            const isAnomaly = extraStr.includes('threat_tag') || extraStr.includes('CRITICAL') || extraStr.includes('TAMPERING') || extraStr.includes('1102');
            const threatBadge = isAnomaly ? `<span class="threat-flag">🚨 Threat Detected</span>` : '<span style="color: var(--text-muted); font-size: 0.72rem;">Normal</span>';

            tr.innerHTML = `
                <td class="mono" style="color: var(--text-muted);">${art.id || '-'}</td>
                <td><span class="badge ${getBadgeClass(art.artifact_type)}">${art.artifact_type || 'Unknown'}</span></td>
                <td title="${art.name || ''}"><strong>${escapeHtml(art.name || 'Unnamed')}</strong></td>
                <td title="${art.path || ''}" class="mono">${escapeHtml(art.path || '-')}</td>
                <td class="mono" style="color: var(--accent-blue);">${art.timestamp || art.last_access || '-'}</td>
                <td>${threatBadge}</td>
            `;

            tr.addEventListener('click', () => {
                document.querySelectorAll('#evidenceTable tbody tr').forEach(r => r.classList.remove('selected'));
                tr.classList.add('selected');
                selectedArtifactId = art.id;
                populateDockedInspector(art);
            });

            fragment.appendChild(tr);
        });

        evidenceTableBody.appendChild(fragment);

        // Auto select first item if none selected
        if (pageItems.length > 0 && selectedArtifactId === null) {
            selectedArtifactId = pageItems[0].id;
            populateDockedInspector(pageItems[0]);
        }
    }

    function escapeHtml(str) {
        return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // --- DOCKED EVIDENCE DETAIL INSPECTOR ---
    function populateDockedInspector(art) {
        inspectorHeaderTitle.textContent = `[ID ${art.id}] ${art.name || art.artifact_type}`;
        insType.innerHTML = `<span class="badge ${getBadgeClass(art.artifact_type)}">${art.artifact_type}</span>`;
        insTime.textContent = art.timestamp || art.last_access || 'N/A';
        insName.textContent = art.name || 'N/A';
        insPath.textContent = art.path || 'N/A';
        insExtra.textContent = art.extra || 'None';

        // Threat context tab
        const extraStr = (art.extra || '');
        let threatHtml = '';
        if (extraStr.includes('threat_tag') || extraStr.includes('CRITICAL') || extraStr.includes('TAMPERING')) {
            threatHtml = `
                <div style="color: var(--accent-red); font-weight: bold; margin-bottom: 6px;">🚨 SUSPICIOUS THREAT INDICATOR IDENTIFIED</div>
                <div style="font-family: var(--font-mono); font-size: 0.76rem; background: rgba(239, 68, 68, 0.1); padding: 8px; border-radius: 4px; border: 1px solid var(--accent-red);">
                    ${escapeHtml(extraStr)}
                </div>
            `;
        } else {
            threatHtml = `<p style="color: var(--text-muted);">No automated anomaly flags triggered for this event.</p>`;
        }
        insThreatContent.innerHTML = threatHtml;

        // JSON Viewer tab
        let rawObj = {};
        try {
            if (art.details) {
                rawObj = typeof art.details === 'string' ? JSON.parse(art.details) : art.details;
            } else {
                rawObj = art;
            }
        } catch (e) {
            rawObj = art;
        }
        insJsonBox.textContent = JSON.stringify(rawObj, null, 2);
    }

    // Inspector Tab Switching
    inspectTabs.forEach(t => {
        t.addEventListener('click', () => {
            inspectTabs.forEach(x => x.classList.remove('active'));
            inspectTabContents.forEach(c => c.classList.remove('active'));
            t.classList.add('active');
            const target = document.getElementById(t.getAttribute('data-tab'));
            if (target) target.classList.add('active');
        });
    });

    // Table Header Sorting
    document.querySelectorAll('#evidenceTable th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const col = th.getAttribute('data-sort');
            if (sortColumn === col) {
                sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortColumn = col;
                sortDirection = 'desc';
            }
            renderEvidenceTable();
        });
    });

    // Search and Pagination Events
    filterSearchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value.trim();
        currentPage = 1;
        renderEvidenceTable();
    });

    clearSearchBtn.addEventListener('click', () => {
        filterSearchInput.value = '';
        searchQuery = '';
        currentPage = 1;
        renderEvidenceTable();
    });

    pageSizeSelect.addEventListener('change', (e) => {
        pageSize = e.target.value;
        currentPage = 1;
        renderEvidenceTable();
    });

    prevPageBtn.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            renderEvidenceTable();
        }
    });

    nextPageBtn.addEventListener('click', () => {
        currentPage++;
        renderEvidenceTable();
    });

    // --- FETCH DATA FROM REST API ---
    async function loadArtifactsData() {
        try {
            const [artRes, statsRes] = await Promise.all([
                fetch('/api/artifacts'),
                fetch('/api/stats')
            ]);

            if (artRes.ok) {
                allArtifacts = await artRes.json();
                updateSidebarBadges();
                renderEvidenceTable();
            }

            if (statsRes.ok) {
                const stats = await statsRes.json();
                headerStatusText.textContent = `Indexed ${stats.total_artifacts.toLocaleString()} Artifacts (${stats.anomalies_detected} Threat Flags)`;
                headerDbSha256.textContent = stats.db_sha256 ? `${stats.db_sha256.substring(0, 16)}...` : 'N/A';
                headerDbSha256.title = stats.db_sha256 || '';

                // Analytics View Cards
                document.getElementById('anTotalCount').textContent = stats.total_artifacts.toLocaleString();
                document.getElementById('anAnomalyCount').textContent = stats.anomalies_detected.toLocaleString();
                document.getElementById('anExeCount').textContent = stats.unique_executables.toLocaleString();
            }
        } catch (err) {
            showToast('Failed to load telemetry from backend.', true);
        }
    }

    // Background Task Polling
    function pollBackgroundTask(taskId, label) {
        showToast(`${label} active in background...`);
        const pollTimer = setInterval(async () => {
            try {
                const res = await fetch(`/api/task_status/${taskId}`);
                if (res.ok) {
                    const task = await res.json();
                    if (task.status === 'completed') {
                        clearInterval(pollTimer);
                        showToast(task.message || `${label} completed successfully!`);
                        loadArtifactsData();
                    } else if (task.status === 'failed') {
                        clearInterval(pollTimer);
                        showToast(`Execution error: ${task.message}`, true);
                    }
                }
            } catch (e) {
                clearInterval(pollTimer);
            }
        }, 1200);
    }

    // 1-Click Live Triage
    liveTriageBtn.addEventListener('click', async () => {
        showToast('Acquiring live Windows artifacts...');
        try {
            const res = await fetch('/api/live_triage', { method: 'POST' });
            const data = await res.json();
            if (res.status === 202 && data.task_id) {
                pollBackgroundTask(data.task_id, '1-Click Live Triage');
            } else {
                showToast(data.message || 'Error triggering triage.', true);
            }
        } catch (err) {
            showToast(`Request failed: ${err.message}`, true);
        }
    });

    // Preset Category Selection
    presetSelect.addEventListener('change', async () => {
        const val = presetSelect.value;
        if (!val) return;
        showToast(`Processing preset category '${presetSelect.options[presetSelect.selectedIndex].text}'...`);
        try {
            const res = await fetch('/api/parse_preset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ preset_id: val })
            });
            const data = await res.json();
            if (res.status === 202 && data.task_id) {
                pollBackgroundTask(data.task_id, 'Preset Triage');
            } else {
                showToast(data.message || 'Error starting preset.', true);
            }
        } catch (err) {
            showToast(`Request failed: ${err.message}`, true);
        }
        presetSelect.value = '';
    });

    // Target Auto-Scanning
    targetScanBtn.addEventListener('click', async () => {
        const p = targetPathInput.value.trim();
        if (!p) return showToast('Please enter a target path or drive letter.', true);

        showToast(`Scanning target '${p}'...`);
        try {
            const res = await fetch('/api/parse_target', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ folder_path: p })
            });
            const data = await res.json();
            if (res.status === 202 && data.task_id) {
                pollBackgroundTask(data.task_id, 'Target Triage Scan');
            } else {
                showToast(data.message || 'Scan error.', true);
            }
        } catch (err) {
            showToast(`Request failed: ${err.message}`, true);
        }
    });

    refreshBtn.addEventListener('click', () => {
        showToast('Refreshing forensic evidence...');
        loadArtifactsData();
    });

    // Clear Database
    clearDbBtn.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to completely erase the forensic evidence database?')) return;
        showToast('Clearing evidence database...');
        try {
            const res = await fetch('/api/clear_db', { method: 'POST' });
            const data = await res.json();
            showToast(data.message);
            loadArtifactsData();
        } catch (err) {
            showToast(`Error: ${err.message}`, true);
        }
    });

    // Export CSV & JSON
    exportCsvBtn.addEventListener('click', () => {
        showToast('Exporting standardized CSV...');
        window.location.href = '/api/export_csv';
    });

    exportJsonBtn.addEventListener('click', () => {
        showToast('Exporting DFIR JSON Timeline...');
        window.location.href = '/api/export_json';
    });

    // PDF Modal
    exportPdfBtn.addEventListener('click', () => pdfModal.style.display = 'flex');
    closePdfModal.addEventListener('click', () => pdfModal.style.display = 'none');

    pdfConfigForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        pdfModal.style.display = 'none';
        showToast('Generating executive forensic PDF audit report with charts...');

        const formData = new FormData(pdfConfigForm);
        const payload = Object.fromEntries(formData.entries());

        try {
            const response = await fetch('/api/export_pdf', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `AegisDFIR_Audit_Report_${Date.now()}.pdf`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
                showToast('Forensic audit PDF successfully exported.');
            } else {
                const err = await response.json();
                showToast(`PDF generation error: ${err.message}`, true);
            }
        } catch (err) {
            showToast(`Export failed: ${err.message}`, true);
        }
    });

    window.addEventListener('click', (e) => {
        if (e.target === pdfModal) pdfModal.style.display = 'none';
    });

    // --- VIEW 2: VISUAL ANALYTICS (CHART.JS) ---
    function renderVisualAnalytics() {
        if (typeof Chart === 'undefined') return;

        // 1. Activity Histogram over Time
        const timeBuckets = {};
        allArtifacts.forEach(art => {
            const t = art.timestamp || art.last_access;
            if (t && t.length >= 10) {
                const day = t.substring(0, 10);
                timeBuckets[day] = (timeBuckets[day] || 0) + 1;
            }
        });

        const sortedDays = Object.keys(timeBuckets).sort();
        const dayCounts = sortedDays.map(d => timeBuckets[d]);

        const ctxTimeline = document.getElementById('timelineChartCanvas').getContext('2d');
        if (timelineChartInstance) timelineChartInstance.destroy();

        timelineChartInstance = new Chart(ctxTimeline, {
            type: 'bar',
            data: {
                labels: sortedDays.length ? sortedDays : ['No Timestamped Data'],
                datasets: [{
                    label: 'Events Recorded',
                    data: dayCounts.length ? dayCounts : [0],
                    backgroundColor: 'rgba(0, 229, 255, 0.45)',
                    borderColor: '#00E5FF',
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94A3B8', font: { size: 10 } } },
                    y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94A3B8', font: { size: 10 } } }
                }
            }
        });

        // 2. Category Donut
        const catCounts = {};
        allArtifacts.forEach(art => {
            const t = art.artifact_type || 'Unknown';
            catCounts[t] = (catCounts[t] || 0) + 1;
        });

        const sortedCats = Object.entries(catCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
        const ctxDonut = document.getElementById('categoryDonutCanvas').getContext('2d');
        if (categoryDonutInstance) categoryDonutInstance.destroy();

        categoryDonutInstance = new Chart(ctxDonut, {
            type: 'doughnut',
            data: {
                labels: sortedCats.map(c => c[0]),
                datasets: [{
                    data: sortedCats.map(c => c[1]),
                    backgroundColor: ['#22C55E', '#38BDF8', '#F97316', '#A855F7', '#EF4444', '#EAB308', '#06B6D4', '#EC4899']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'right', labels: { color: '#94A3B8', font: { size: 10 } } } }
            }
        });

        // 3. Top Executed Binaries
        const appCounts = {};
        allArtifacts.forEach(art => {
            const t = (art.artifact_type || '').toLowerCase();
            if (t.includes('prefetch') || t.includes('userassist') || t.includes('bam')) {
                const name = art.name || 'Unknown';
                appCounts[name] = (appCounts[name] || 0) + 1;
            }
        });

        const topApps = Object.entries(appCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
        const ctxApps = document.getElementById('topAppsCanvas').getContext('2d');
        if (topAppsChartInstance) topAppsChartInstance.destroy();

        topAppsChartInstance = new Chart(ctxApps, {
            type: 'bar',
            data: {
                labels: topApps.map(a => a[0]),
                datasets: [{
                    label: 'Executions',
                    data: topApps.map(a => a[1]),
                    backgroundColor: 'rgba(34, 197, 94, 0.5)',
                    borderColor: '#22C55E',
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94A3B8' } },
                    y: { grid: { display: false }, ticks: { color: '#F0F4FC', font: { size: 10 } } }
                }
            }
        });
    }

    // --- VIEW 3: RECONSTRUCTED SESSION TIMELINE ---
    let timelineShowAnomaliesOnly = false;
    let timelineSearchQuery = '';

    async function fetchAndRenderTimeline() {
        try {
            const res = await fetch('/api/correlations');
            if (res.ok) {
                allCorrelations = await res.json();
                renderTimelineFeed();
            }
        } catch (e) {
            timelineFeedContainer.innerHTML = '<p class="text-danger">Failed to load timeline events.</p>';
        }
    }

    function renderTimelineFeed() {
        let filtered = allCorrelations.filter(c => {
            if (timelineShowAnomaliesOnly && !c.anomaly) return false;
            if (timelineSearchQuery) {
                const q = timelineSearchQuery.toLowerCase();
                return (
                    (c.detail && c.detail.toLowerCase().includes(q)) ||
                    (c.artifact_type && c.artifact_type.toLowerCase().includes(q)) ||
                    (c.anomaly && c.anomaly.toLowerCase().includes(q)) ||
                    (c.mitre && c.mitre.toLowerCase().includes(q))
                );
            }
            return true;
        });

        timelineFeedContainer.innerHTML = '';
        if (filtered.length === 0) {
            timelineFeedContainer.innerHTML = '<p style="text-align: center; color: var(--text-muted); padding: 40px;">No timeline events found.</p>';
            return;
        }

        const fragment = document.createDocumentFragment();
        filtered.forEach(item => {
            const card = document.createElement('div');
            card.className = `session-card ${item.anomaly ? 'anomaly-session' : ''}`;

            let mitreHtml = '';
            if (item.mitre) {
                const tags = item.mitre.replace(/[\[\]]/g, '').split(' ').filter(Boolean);
                tags.forEach(t => {
                    mitreHtml += `<span class="mitre-chip">${escapeHtml(t)}</span>`;
                });
            }

            card.innerHTML = `
                <div class="session-card-header">
                    <span class="session-badge">SESSION ${item.session || 1}</span>
                    <span class="badge ${getBadgeClass(item.artifact_type)}">${item.artifact_type || 'Event'}</span>
                    <span class="session-time">${item.timestamp || '-'}</span>
                </div>
                <div class="session-detail-text">${escapeHtml(item.detail || '')}</div>
                ${item.anomaly ? `<div style="color: var(--accent-red); font-weight: bold; font-size: 0.75rem;">🚨 ${escapeHtml(item.anomaly)}</div>` : ''}
                ${mitreHtml ? `<div class="session-mitre-row">${mitreHtml}</div>` : ''}
            `;
            fragment.appendChild(card);
        });

        timelineFeedContainer.appendChild(fragment);
    }

    btnTimelineAll.addEventListener('click', () => {
        btnTimelineAll.classList.add('active');
        btnTimelineAnomaliesOnly.classList.remove('active');
        timelineShowAnomaliesOnly = false;
        renderTimelineFeed();
    });

    btnTimelineAnomaliesOnly.addEventListener('click', () => {
        btnTimelineAnomaliesOnly.classList.add('active');
        btnTimelineAll.classList.remove('active');
        timelineShowAnomaliesOnly = true;
        renderTimelineFeed();
    });

    corrSearchInput.addEventListener('input', (e) => {
        timelineSearchQuery = e.target.value.trim();
        renderTimelineFeed();
    });

    btnExportCorrPdf.addEventListener('click', async () => {
        showToast('Exporting correlation timeline PDF report...');
        try {
            const res = await fetch('/api/export_correlation_pdf', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ caseNumber: 'CORR-TIMELINE-REPORT' })
            });
            if (res.ok) {
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `AegisDFIR_Correlation_Timeline_${Date.now()}.pdf`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
                showToast('Correlation PDF downloaded.');
            }
        } catch (e) {
            showToast('Failed to export correlation PDF.', true);
        }
    });

    // --- VIEW 4: CATALOG VIEW ---
    async function renderCatalogView() {
        try {
            const res = await fetch('/api/presets');
            if (res.ok) {
                const data = await res.json();
                catalogGridContainer.innerHTML = '';
                (data.catalog || []).forEach(cat => {
                    const card = document.createElement('div');
                    card.className = 'cat-item-card';
                    const liveP = (cat.live_paths && cat.live_paths[0]) ? cat.live_paths[0] : 'Auto-detected';
                    card.innerHTML = `
                        <div class="cat-header">
                            <span class="cat-title">${cat.name}</span>
                            <span class="badge ${getBadgeClass(cat.id)}">${cat.category}</span>
                        </div>
                        <p class="cat-desc">${cat.description}</p>
                        <div class="cat-path">Location: ${liveP}</div>
                    `;
                    card.addEventListener('click', () => {
                        if (!liveP.startsWith('REGISTRY:')) {
                            targetPathInput.value = liveP;
                        }
                        // Switch to grid view
                        document.querySelector('.nav-tab[data-view="grid-view"]').click();
                        showToast(`Loaded path for '${cat.name}'. Click 'Auto-Scan Target' to extract.`);
                    });
                    catalogGridContainer.appendChild(card);
                });
            }
        } catch (e) {}
    }

    // --- THEME SWITCHER ---
    function applyTheme(theme) {
        document.body.setAttribute('data-theme', theme);
        localStorage.setItem('dfir_theme_pref', theme);
        themeToggle.checked = (theme === 'dark');
    }

    themeToggle.addEventListener('change', () => {
        applyTheme(themeToggle.checked ? 'dark' : 'light');
        if (timelineChartInstance) renderVisualAnalytics();
    });

    const savedTheme = localStorage.getItem('dfir_theme_pref') || 'dark';
    applyTheme(savedTheme);

    // Initial Load
    loadArtifactsData();
});
