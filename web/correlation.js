/**
 * AegisDFIR Correlation & Timeline Controller
 */

document.addEventListener('DOMContentLoaded', () => {
    let allCorrelations = [];
    let showAnomaliesOnly = false;
    let searchQuery = '';

    const correlationsTableBody = document.querySelector('#correlationsTable tbody');
    const correlationCount = document.getElementById('correlationCount');
    const timelineSearchInput = document.getElementById('timelineSearchInput');
    const filterAllSessions = document.getElementById('filterAllSessions');
    const filterAnomaliesOnly = document.getElementById('filterAnomaliesOnly');
    const refreshCorrBtn = document.getElementById('refreshCorrBtn');
    const exportCorrelationPdfBtn = document.getElementById('exportCorrelationPdfBtn');
    const pdfReportModal = document.getElementById('pdfReportModal');
    const closePdfBtn = document.getElementById('closePdfBtn');
    const pdfReportForm = document.getElementById('pdfReportForm');
    const statusSection = document.getElementById('statusSection');
    const themeToggle = document.getElementById('theme-toggle');

    function showStatus(message, isError = false) {
        statusSection.textContent = message;
        statusSection.style.display = 'block';
        statusSection.style.borderColor = isError ? 'var(--accent-red)' : 'var(--accent-cyan)';
        statusSection.style.color = isError ? 'var(--accent-red)' : 'var(--accent-cyan)';
        setTimeout(() => { statusSection.style.display = 'none'; }, 5000);
    }

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
        return 'badge-other';
    }

    function renderTable() {
        const filtered = allCorrelations.filter(c => {
            if (showAnomaliesOnly && !c.anomaly) return false;
            if (!searchQuery) return true;
            const q = searchQuery.toLowerCase();
            return (
                (c.detail && c.detail.toLowerCase().includes(q)) ||
                (c.artifact_type && c.artifact_type.toLowerCase().includes(q)) ||
                (c.anomaly && c.anomaly.toLowerCase().includes(q)) ||
                (c.mitre && c.mitre.toLowerCase().includes(q)) ||
                (c.timestamp && c.timestamp.toLowerCase().includes(q))
            );
        });

        correlationCount.textContent = `Displaying ${filtered.length} of ${allCorrelations.length} correlated events`;
        correlationsTableBody.innerHTML = '';

        if (filtered.length === 0) {
            correlationsTableBody.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align: center; padding: 36px; color: var(--text-muted);">
                        No correlation records matched your filter criteria.
                    </td>
                </tr>
            `;
            return;
        }

        const fragment = document.createDocumentFragment();
        filtered.forEach(item => {
            const tr = document.createElement('tr');
            const typeBadge = `<span class="badge ${getBadgeClass(item.artifact_type)}">${item.artifact_type || 'Unknown'}</span>`;
            const sessionBadge = `<span class="mono-text" style="color: var(--accent-purple); font-weight: bold;">S-${item.session || '1'}</span>`;

            let indicatorsHtml = '';
            if (item.anomaly) {
                indicatorsHtml += `<span class="anomaly-pill">${item.anomaly}</span> `;
            }
            if (item.mitre) {
                indicatorsHtml += `<span class="mono-text" style="color: var(--accent-cyan); font-size: 0.72rem;">${item.mitre}</span>`;
            }
            if (!indicatorsHtml) {
                indicatorsHtml = '<span style="color: var(--text-muted); font-size: 0.72rem;">Standard Event</span>';
            }

            tr.innerHTML = `
                <td class="mono-text">${item.timestamp || '-'}</td>
                <td>${sessionBadge}</td>
                <td>${typeBadge}</td>
                <td title="${item.detail || ''}">${item.detail || '-'}</td>
                <td>${indicatorsHtml}</td>
            `;
            fragment.appendChild(tr);
        });

        correlationsTableBody.appendChild(fragment);
    }

    async function fetchCorrelations() {
        try {
            const res = await fetch('/api/correlations');
            if (res.ok) {
                allCorrelations = await res.json();
                renderTable();
            } else {
                showStatus('Failed to load correlations.', true);
            }
        } catch (err) {
            showStatus(`Error: ${err.message}`, true);
        }
    }

    // Filter Buttons
    filterAllSessions.addEventListener('click', () => {
        filterAllSessions.classList.add('active');
        filterAnomaliesOnly.classList.remove('active');
        showAnomaliesOnly = false;
        renderTable();
    });

    filterAnomaliesOnly.addEventListener('click', () => {
        filterAnomaliesOnly.classList.add('active');
        filterAllSessions.classList.remove('active');
        showAnomaliesOnly = true;
        renderTable();
    });

    timelineSearchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value.trim();
        renderTable();
    });

    refreshCorrBtn.addEventListener('click', () => {
        showStatus('Re-analyzing timeline sessions...');
        fetchCorrelations();
    });

    // PDF Export Modal
    exportCorrelationPdfBtn.addEventListener('click', () => {
        pdfReportModal.style.display = 'flex';
    });
    closePdfBtn.addEventListener('click', () => {
        pdfReportModal.style.display = 'none';
    });

    pdfReportForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        pdfReportModal.style.display = 'none';
        showStatus('Generating correlation PDF report with timeline charts...');

        const formData = new FormData(pdfReportForm);
        const payload = Object.fromEntries(formData.entries());

        try {
            const res = await fetch('/api/export_correlation_pdf', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `AegisDFIR_Correlation_Report_${Date.now()}.pdf`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
                showStatus('Correlation report downloaded successfully.');
            } else {
                const err = await res.json();
                showStatus(`Export error: ${err.message}`, true);
            }
        } catch (err) {
            showStatus(`Export error: ${err.message}`, true);
        }
    });

    window.addEventListener('click', (e) => {
        if (e.target === pdfReportModal) pdfReportModal.style.display = 'none';
    });

    // Theme Switch
    function setTheme(theme) {
        document.body.setAttribute('data-theme', theme);
        localStorage.setItem('dfir_theme', theme);
        themeToggle.checked = (theme === 'dark');
    }

    themeToggle.addEventListener('change', () => {
        setTheme(themeToggle.checked ? 'dark' : 'light');
    });

    const savedTheme = localStorage.getItem('dfir_theme') || 'dark';
    setTheme(savedTheme);

    fetchCorrelations();
});