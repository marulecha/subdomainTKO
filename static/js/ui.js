document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const elements = {
        input: document.getElementById('subdomain-input'),
        btnStart: document.getElementById('btn-start'),
        btnStop: document.getElementById('btn-stop'),
        btnClear: document.getElementById('btn-clear'),
        domainCount: document.getElementById('domain-count'),
        tbody: document.getElementById('results-body'),
        statSafe: document.getElementById('stat-safe'),
        statVuln: document.getElementById('stat-vuln'),
        statErr: document.getElementById('stat-err'),
        modal: document.getElementById('remediation-modal'),
        modalClose: document.querySelector('.close-btn'),
        modalTitle: document.getElementById('modal-title'),
        modalBody: document.getElementById('modal-body')
    };

    // --- Helper for preventing DOM XSS ---
    function escapeHTML(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    let isScanning = false;
    let domainsToScan = [];
    let stats = { safe: 0, vuln: 0, err: 0 };

    // Update domain count on input
    elements.input.addEventListener('input', () => {
        const text = elements.input.value.trim();
        const lines = text ? text.split('\n').filter(line => line.trim() !== '') : [];
        elements.domainCount.textContent = lines.length;
    });

    // Handle Start Scan
    elements.btnStart.addEventListener('click', async () => {
        const text = elements.input.value.trim();
        domainsToScan = text ? text.split('\n').filter(line => line.trim() !== '') : [];

        if (domainsToScan.length === 0) return;

        // Reset state
        isScanning = true;
        stats = { safe: 0, vuln: 0, err: 0 };
        updateStatsUI();
        elements.tbody.innerHTML = '';

        // Toggle UI buttons
        elements.btnStart.classList.add('hidden');
        elements.btnStop.classList.remove('hidden');
        elements.input.disabled = true;

        // Scan Loop
        for (const domain of domainsToScan) {
            if (!isScanning) break;

            // Add loading row
            // Create a safe, unique row ID (encode to base64 to avoid invalid characters as ID)
            const rowId = `domain-${btoa(encodeURIComponent(domain)).replace(/[^a-zA-Z0-9]/g, '')}`;
            addLoadingRow(domain, rowId);

            // Perform actual check
            const result = await checkSubdomain(domain);

            // Update row with results
            updateRow(rowId, domain, result);
            updateStatsUI();
        }

        // Finish Scanning
        stopScan();
    });

    // Handle Stop Scan
    elements.btnStop.addEventListener('click', stopScan);

    // Handle Clear
    elements.btnClear.addEventListener('click', () => {
        elements.input.value = '';
        elements.domainCount.textContent = '0';
        elements.tbody.innerHTML = '<tr class="empty-state"><td colspan="5">Ready to scan. Paste subdomains on the left.</td></tr>';
        stats = { safe: 0, vuln: 0, err: 0 };
        updateStatsUI();
    });

    // Function to stop the scan
    function stopScan() {
        isScanning = false;
        elements.btnStart.classList.remove('hidden');
        elements.btnStop.classList.add('hidden');
        elements.input.disabled = false;
    }

    // Function to update stats counter
    function updateStatsUI() {
        elements.statSafe.textContent = stats.safe;
        elements.statVuln.textContent = stats.vuln;
        elements.statErr.textContent = stats.err;
    }

    // Add a row in "Scanning..." state
    function addLoadingRow(domain, id) {
        const tr = document.createElement('tr');
        tr.id = id;
        tr.innerHTML = `
            <td><span class="status scanning"><i class="fa-solid fa-spinner fa-spin"></i> Scanning</span></td>
            <td><strong>${escapeHTML(domain)}</strong></td>
            <td class="text-muted">...</td>
            <td class="text-muted">-</td>
            <td>-</td>
        `;
        elements.tbody.prepend(tr);
    }

    // Update row with final result
    function updateRow(id, domain, result) {
        const tr = document.getElementById(id);
        if (!tr) return;

        let statusIcon, statusClass, actionHtml = '-';

        if (result.status === 'vulnerable') {
            stats.vuln++;
            statusClass = 'vulnerable';
            statusIcon = '<i class="fa-solid fa-skull"></i> VULNERABLE';
            actionHtml = `<button class="action-btn" onclick="openRemediationModal('${result.signature.name}')">Info</button>`;
        } else if (result.status === 'error') {
            stats.err++;
            statusClass = 'error';
            statusIcon = '<i class="fa-solid fa-circle-exclamation"></i> ERROR';
        } else {
            stats.safe++;
            statusClass = 'safe';
            statusIcon = '<i class="fa-solid fa-check-circle"></i> SAFE';
        }

        const providerDisplay = result.status === 'vulnerable' ? `<span class="provider">${escapeHTML(result.provider)}</span>` : '-';
        const displayMessage = escapeHTML(result.message || result.type);

        tr.innerHTML = `
            <td><span class="status ${statusClass}">${statusIcon}</span></td>
            <td><strong>${escapeHTML(domain)}</strong></td>
            <td class="text-xs font-mono break-all">${displayMessage}</td>
            <td>${providerDisplay}</td>
            <td>${actionHtml}</td>
        `;
    }

    // --- Modal Logic ---

    // Explicitly make the handler global so inline onclick="" can see it
    window.openRemediationModal = function (providerName) {
        // Find the signature details
        const sig = signatures.find(s => s.name === providerName);
        if (!sig) return;

        elements.modalTitle.textContent = `Vulnerability: ${sig.name} Takeover`;
        elements.modalBody.innerHTML = `
            <div class="remediation-block">
                <h3><i class="fa-solid fa-triangle-exclamation"></i> How it works</h3>
                <p>${sig.description}</p>
            </div>
            <div class="remediation-block" style="border-left-color: var(--success); margin-top:1rem;">
                <h3 style="color: var(--success);"><i class="fa-solid fa-wrench"></i> Remediation</h3>
                <p>${sig.remediation}</p>
                <a href="${sig.link}" target="_blank">Official Documentation <i class="fa-solid fa-external-link-alt"></i></a>
            </div>
        `;
        elements.modal.classList.add('active');
    };

    // Close modal handlers
    elements.modalClose.addEventListener('click', () => {
        elements.modal.classList.remove('active');
    });

    window.addEventListener('click', (event) => {
        if (event.target === elements.modal) {
            elements.modal.classList.remove('active');
        }
    });

});
