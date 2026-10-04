document.addEventListener('DOMContentLoaded', () => {
    const $ = id => document.getElementById(id);
    const elements = {
        input: $('subdomain-input'),
        gutter: $('gutter'),
        dropzone: $('dropzone'),
        fileInput: $('file-input'),
        btnStart: $('btn-start'),
        btnStop: $('btn-stop'),
        btnClear: $('btn-clear'),
        btnExample: $('btn-example'),
        btnCopy: $('btn-copy'),
        btnCsv: $('btn-export-csv'),
        btnJson: $('btn-export-json'),
        parseSummary: $('parse-summary'),
        settingsPreview: $('settings-preview'),
        concurrency: $('opt-concurrency'),
        concurrencyValue: $('opt-concurrency-value'),
        scanState: $('scan-state'),
        scanStateText: $('scan-state-text'),
        intro: $('intro'),
        resultsView: $('results-view'),
        progressBar: $('progress-bar'),
        progressLabel: $('progress-label'),
        progressEta: $('progress-eta'),
        filters: $('filters'),
        activeFilter: $('active-filter'),
        search: $('search-input'),
        tbody: $('results-body'),
        emptyState: $('empty-state'),
        dialog: $('details-dialog'),
        dialogContent: $('dialog-content'),
        drawerPos: $('drawer-pos'),
        btnPrev: $('btn-prev'),
        btnNext: $('btn-next'),
        toast: $('toast'),
        disclaimer: $('disclaimer')
    };

    // rank orders the default sort: running lookups first, then by severity.
    const STATUS = {
        scanning: { label: 'Scanning', icon: 'fa-circle-notch fa-spin', rank: -1 },
        vulnerable: { label: 'Vulnerable', icon: 'fa-skull', rank: 0 },
        review: { label: 'Review', icon: 'fa-magnifying-glass', rank: 1 },
        error: { label: 'Error', icon: 'fa-circle-exclamation', rank: 2 },
        safe: { label: 'Safe', icon: 'fa-check', rank: 3 },
        none: { label: 'No record', icon: 'fa-ban', rank: 4 }
    };

    const EXAMPLE = [
        '# Replace with hosts you may test',
        'www.github.com',
        'docs.github.com',
        'test.s3.amazonaws.com',
        'nonexistent-subdomain.example.com',
        'https://blog.cloudflare.com/',
        '*.example.org'
    ].join('\n');

    const state = {
        results: [],          // in scan order
        byDomain: new Map(),
        filter: 'all',
        query: '',
        sort: { key: 'status', dir: 1 },
        controller: null,
        resolver: 'cloudflare',
        startedAt: 0,
        finishedAt: 0,
        total: 0,
        done: 0
    };

    // --- Helpers ---

    function escapeHTML(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Escape a hostname and allow line breaks after dots, so narrow screens wrap at label boundaries.
    function breakableHost(host) {
        return escapeHTML(host).replace(/\./g, '.<wbr>');
    }

    // Show the leftmost label brighter than the parent domain.
    function hostHTML(host) {
        const dot = host.indexOf('.');
        if (dot === -1 || host.split('.').length < 3) return `<span class="host-sub">${breakableHost(host)}</span>`;
        return `<span class="host-sub">${escapeHTML(host.slice(0, dot + 1))}<wbr></span><span class="host-root">${breakableHost(host.slice(dot + 1))}</span>`;
    }

    function store(key, value) {
        try { localStorage.setItem(`subtko:${key}`, value); } catch { /* storage unavailable */ }
    }

    function recall(key) {
        try { return localStorage.getItem(`subtko:${key}`); } catch { return null; }
    }

    let toastTimer;
    function toast(message, icon = 'fa-circle-check') {
        elements.toast.innerHTML = `<i class="fa-solid ${icon}" aria-hidden="true"></i> ${escapeHTML(message)}`;
        elements.toast.classList.add('visible');
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => elements.toast.classList.remove('visible'), 2600);
    }

    function formatDuration(ms) {
        if (ms < 1000) return 'under 1s';
        const s = Math.round(ms / 1000);
        return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
    }

    function plural(n, word) {
        return `${n} ${word}${n === 1 ? '' : 's'}`;
    }

    function download(filename, content, type) {
        const url = URL.createObjectURL(new Blob([content], { type }));
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function isTyping(target) {
        return target.closest('input, textarea, select, [contenteditable]');
    }

    // --- Settings, disclaimer, static content ---

    const isMac = /Mac|iPhone|iPad/.test(navigator.platform);
    $('shortcut-hint').textContent = isMac ? '⌘ ↵' : 'Ctrl ↵';
    $('sig-count').textContent = signatures.length;
    $('provider-cloud').innerHTML = signatures
        .map(s => `<span class="provider-chip ${s.status}">${escapeHTML(s.name)}</span>`)
        .join('');

    const resolverRadios = document.querySelectorAll('input[name="resolver"]');
    const savedResolver = recall('resolver');
    if (RESOLVERS[savedResolver]) state.resolver = savedResolver;
    resolverRadios.forEach(radio => {
        radio.checked = radio.value === state.resolver;
        radio.addEventListener('change', () => {
            state.resolver = radio.value;
            store('resolver', radio.value);
            refreshSettingsPreview();
        });
    });

    const savedConcurrency = Number(recall('concurrency'));
    if (savedConcurrency >= 1 && savedConcurrency <= 20) elements.concurrency.value = savedConcurrency;

    function refreshSettingsPreview() {
        elements.concurrencyValue.textContent = elements.concurrency.value;
        elements.settingsPreview.textContent = `${RESOLVERS[state.resolver].label} · ${elements.concurrency.value} parallel`;
    }

    elements.concurrency.addEventListener('input', () => {
        store('concurrency', elements.concurrency.value);
        refreshSettingsPreview();
    });
    refreshSettingsPreview();

    if (recall('disclaimer-dismissed') === '1') elements.disclaimer.classList.add('hidden');
    $('btn-dismiss-disclaimer').addEventListener('click', () => {
        elements.disclaimer.classList.add('hidden');
        store('disclaimer-dismissed', '1');
    });

    // --- Editor: line gutter and parse summary ---

    const GUTTER_LIMIT = 20000;

    function refreshEditor() {
        const text = elements.input.value;
        const { targets, invalid, duplicates } = parseTargets(text);

        // Gutter: mark each line as host, comment, duplicate or invalid.
        const seen = new Set();
        const lines = text.split('\n');
        const marks = [];
        for (let i = 0; i < Math.min(lines.length, GUTTER_LIMIT); i++) {
            const raw = lines[i];
            const body = raw.replace(/#.*$/, '').trim();
            let cls = '';
            let title = '';
            if (!body) {
                cls = raw.trim() ? 'comment' : 'blank';
            } else {
                const hosts = body.split(/[\s,;]+/).filter(Boolean).map(normalizeHost);
                if (hosts.some(h => !h)) {
                    cls = 'bad';
                    title = 'Not a valid hostname';
                } else if (hosts.every(h => seen.has(h))) {
                    cls = 'dup';
                    title = 'Duplicate';
                }
                hosts.forEach(h => h && seen.add(h));
            }
            marks.push(`<span class="${cls}"${title ? ` title="${title}"` : ''}>${i + 1}</span>`);
        }
        elements.gutter.innerHTML = marks.join('');
        elements.gutter.scrollTop = elements.input.scrollTop;

        elements.btnStart.disabled = targets.length === 0 || !!state.controller;
        elements.btnStart.querySelector('span').textContent = targets.length
            ? `Scan ${plural(targets.length, 'host')}`
            : 'Start scan';

        if (!text.trim()) {
            elements.parseSummary.innerHTML = '<span class="muted">Paste, type, or drop a .txt file</span>';
            return;
        }
        const parts = [`<span class="ok"><i class="dot"></i>${plural(targets.length, 'host')}</span>`];
        if (duplicates) parts.push(`<span class="dup"><i class="dot"></i>${duplicates} duplicate${duplicates === 1 ? '' : 's'}</span>`);
        if (invalid.length) parts.push(`<span class="bad" title="${escapeHTML(invalid.join(', '))}"><i class="dot"></i>${invalid.length} invalid</span>`);
        elements.parseSummary.innerHTML = parts.join('');
    }

    function loadExample() {
        elements.input.value = EXAMPLE;
        refreshEditor();
        elements.input.focus();
        toast('Example targets loaded', 'fa-wand-magic-sparkles');
    }

    elements.input.addEventListener('input', refreshEditor);
    elements.input.addEventListener('scroll', () => { elements.gutter.scrollTop = elements.input.scrollTop; });
    elements.btnExample.addEventListener('click', loadExample);

    elements.input.addEventListener('keydown', event => {
        if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
            event.preventDefault();
            if (!elements.btnStart.disabled) startScan();
        }
    });

    async function appendFile(file) {
        if (!file) return;
        if (file.size > 5 * 1024 * 1024) {
            toast('File is larger than 5 MB', 'fa-circle-exclamation');
            return;
        }
        const text = await file.text();
        const current = elements.input.value.trim();
        elements.input.value = current ? `${current}\n${text}` : text;
        refreshEditor();
        toast(`Imported ${file.name}`, 'fa-file-import');
    }

    elements.fileInput.addEventListener('change', () => {
        appendFile(elements.fileInput.files[0]);
        elements.fileInput.value = '';
    });

    ['dragenter', 'dragover'].forEach(type => elements.dropzone.addEventListener(type, event => {
        if (!event.dataTransfer.types.includes('Files') || elements.input.disabled) return;
        event.preventDefault();
        elements.dropzone.classList.add('dragging');
    }));
    ['dragleave', 'drop'].forEach(type => elements.dropzone.addEventListener(type, () => {
        elements.dropzone.classList.remove('dragging');
    }));
    elements.dropzone.addEventListener('drop', event => {
        if (!event.dataTransfer.files.length || elements.input.disabled) return;
        event.preventDefault();
        appendFile(event.dataTransfer.files[0]);
    });

    elements.btnClear.addEventListener('click', () => {
        if (state.controller) return;
        elements.input.value = '';
        state.results = [];
        state.byDomain.clear();
        state.total = 0;
        state.done = 0;
        elements.tbody.replaceChildren();
        resetFilters();
        refreshEditor();
        setScanState('idle');
        elements.input.focus();
    });

    // --- Scanning ---

    function setScanState(mode, text) {
        elements.scanState.className = `scan-state ${mode}`;
        elements.scanStateText.textContent = text || 'Ready';
    }

    async function startScan() {
        const { targets } = parseTargets(elements.input.value);
        if (!targets.length || state.controller) return;

        const controller = new AbortController();
        const resolver = state.resolver;
        const limit = Number(elements.concurrency.value);

        state.controller = controller;
        state.results = [];
        state.byDomain.clear();
        state.total = targets.length;
        state.done = 0;
        state.startedAt = performance.now();
        elements.tbody.replaceChildren();

        setScanningUI(true);
        render();
        // On stacked layouts the results sit below the editor, so bring them into view.
        if (window.matchMedia('(max-width: 900px)').matches) {
            document.querySelector('.results-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        let next = 0;
        async function worker() {
            while (next < targets.length && !controller.signal.aborted) {
                const domain = targets[next++];
                const entry = { domain, status: 'scanning', chain: [], addresses: [], resolver };
                state.results.push(entry);
                state.byDomain.set(domain, entry);
                scheduleRender();

                try {
                    Object.assign(entry, await checkSubdomain(domain, { resolver, signal: controller.signal }));
                } catch (err) {
                    if (err.name === 'AbortError') {
                        state.results.splice(state.results.indexOf(entry), 1);
                        state.byDomain.delete(domain);
                        entry.row?.remove();
                        break;
                    }
                    Object.assign(entry, { status: 'error', message: err.message });
                }
                state.done++;
                scheduleRender();
            }
        }

        await Promise.all(Array.from({ length: Math.min(limit, targets.length) }, worker));

        const stopped = controller.signal.aborted;
        state.controller = null;
        state.finishedAt = performance.now();
        setScanningUI(false);
        render();

        const counts = countByStatus();
        const elapsed = formatDuration(state.finishedAt - state.startedAt);
        if (stopped) {
            setScanState('idle', `Stopped at ${state.done} of ${state.total}`);
            toast('Scan stopped', 'fa-circle-stop');
        } else if (counts.vulnerable) {
            setScanState('alert', `${counts.vulnerable} vulnerable`);
            toast(`Found ${counts.vulnerable} vulnerable, ${counts.review} to review`, 'fa-skull');
            elements.filters.querySelector('.vulnerable').classList.add('flash');
        } else {
            setScanState('done', `Done in ${elapsed}`);
            toast(counts.review ? `Done. ${counts.review} to review` : 'Done. Nothing vulnerable found', 'fa-circle-check');
        }
        if (counts.vulnerable && document.hidden) document.title = `(${counts.vulnerable}) SubdomainTKO`;
    }

    function setScanningUI(scanning) {
        elements.btnStart.classList.toggle('hidden', scanning);
        elements.btnStop.classList.toggle('hidden', !scanning);
        elements.input.disabled = scanning;
        elements.btnClear.disabled = scanning;
        elements.concurrency.disabled = scanning;
        resolverRadios.forEach(r => { r.disabled = scanning; });
        elements.filters.querySelectorAll('.flash').forEach(el => el.classList.remove('flash'));
        if (scanning) {
            setScanState('scanning', 'Scanning');
            elements.btnStop.focus();
        } else {
            refreshEditor();
            elements.btnStart.focus();
        }
    }

    elements.btnStart.addEventListener('click', startScan);
    elements.btnStop.addEventListener('click', () => state.controller?.abort());
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) document.title = 'SubdomainTKO | Subdomain Takeover Scanner';
    });

    // --- Rendering ---

    let renderQueued = false;
    function scheduleRender() {
        if (renderQueued) return;
        renderQueued = true;
        requestAnimationFrame(() => {
            renderQueued = false;
            render();
        });
    }

    function countByStatus() {
        const counts = { scanning: 0, vulnerable: 0, review: 0, safe: 0, none: 0, error: 0 };
        state.results.forEach(r => { counts[r.status]++; });
        return counts;
    }

    function matchesQuery(r, q) {
        if (!q) return true;
        return r.domain.includes(q)
            || r.chain.some(c => c.includes(q))
            || (r.signature && r.signature.name.toLowerCase().includes(q));
    }

    function visibleResults() {
        const rows = state.results.filter(r =>
            (state.filter === 'all' || r.status === state.filter) && matchesQuery(r, state.query));
        const order = new Map(state.results.map((r, i) => [r, i]));
        const { key, dir } = state.sort;
        if (key === 'status') {
            rows.sort((a, b) => (STATUS[a.status].rank - STATUS[b.status].rank) * dir || order.get(a) - order.get(b));
        } else if (key === 'domain') {
            rows.sort((a, b) => a.domain.localeCompare(b.domain) * dir);
        }
        return rows;
    }

    function dnsSummary(r) {
        if (r.status === 'scanning') return '<span class="skeleton"></span>';
        const last = r.chain.length ? r.chain[r.chain.length - 1] : null;
        if (last) {
            const hops = r.chain.length > 1 ? `<span class="hops" title="${escapeHTML(r.chain.join(' → '))}">${r.chain.length} hops</span>` : '';
            const tail = r.dangling ? '<span class="tag nx">NXDOMAIN</span>' : '';
            return `<span class="rtype">CNAME</span><span class="mono">${breakableHost(last)}</span>${hops}${tail}`;
        }
        if (r.addresses.length) {
            const more = r.addresses.length > 1 ? `<span class="hops">+${r.addresses.length - 1}</span>` : '';
            return `<span class="rtype">A</span><span class="mono">${escapeHTML(r.addresses[0])}</span>${more}`;
        }
        return `<span class="muted mono">${escapeHTML(r.rcode || '')}</span>`;
    }

    function rowHTML(r) {
        const s = STATUS[r.status];
        const provider = r.signature
            ? `<span class="provider">${escapeHTML(r.signature.name)}</span>`
            : '<span class="muted">-</span>';
        return `
            <td><span class="status ${r.status}"><i class="fa-solid ${s.icon}" aria-hidden="true"></i> ${s.label}</span></td>
            <td class="domain-cell mono">${hostHTML(r.domain)}</td>
            <td class="dns-cell">${dnsSummary(r)}</td>
            <td>${provider}</td>
            <td class="chevron">${r.status === 'scanning' ? '' : '<i class="fa-solid fa-arrow-right" aria-hidden="true"></i>'}</td>`;
    }

    // Rows are kept per result and patched in place, so finished rows animate once.
    function syncRow(r) {
        if (!r.row) {
            r.row = document.createElement('tr');
            r.row.dataset.domain = r.domain;
        }
        if (r.rowStatus === r.status) return;
        const wasScanning = r.rowStatus === 'scanning';
        r.rowStatus = r.status;
        r.row.className = `row ${r.status}${wasScanning ? ' fresh' : ''}`;
        r.row.innerHTML = rowHTML(r);
        if (r.status === 'scanning') {
            r.row.removeAttribute('tabindex');
            r.row.removeAttribute('aria-label');
        } else {
            r.row.tabIndex = 0;
            r.row.setAttribute('aria-label', `${r.domain}, ${STATUS[r.status].label}. Open details.`);
        }
    }

    let rendered = [];
    function render() {
        const hasResults = state.results.length > 0 || !!state.controller;
        elements.intro.classList.toggle('hidden', hasResults);
        elements.resultsView.classList.toggle('hidden', !hasResults);
        if (!hasResults) return;

        rendered = visibleResults();
        rendered.forEach(syncRow);
        const rows = rendered.map(r => r.row);
        const current = elements.tbody.children;
        const same = rows.length === current.length && rows.every((row, i) => current[i] === row);
        if (!same) elements.tbody.replaceChildren(...rows);

        // Empty state for filters and search
        const showEmpty = rendered.length === 0 && state.results.length > 0;
        elements.emptyState.classList.toggle('hidden', !showEmpty);
        if (showEmpty) {
            elements.emptyState.innerHTML = `
                <i class="fa-solid fa-filter-circle-xmark" aria-hidden="true"></i>
                <h3>No matching results</h3>
                <p>Nothing matches ${state.filter !== 'all' ? `the ${STATUS[state.filter].label} filter` : 'this view'}${state.query ? ` and "${escapeHTML(state.query)}"` : ''}.</p>
                <button type="button" class="btn ghost small" id="btn-reset-filters">Show all results</button>`;
            $('btn-reset-filters').addEventListener('click', resetFilters);
        }

        // Stat cards and distribution bar
        const counts = countByStatus();
        elements.filters.querySelectorAll('[data-count]').forEach(el => {
            el.textContent = counts[el.dataset.count];
            el.classList.toggle('zero', counts[el.dataset.count] === 0);
        });
        elements.progressBar.querySelectorAll('[data-seg]').forEach(seg => {
            const share = state.total ? (counts[seg.dataset.seg] / state.total) * 100 : 0;
            seg.style.width = `${share}%`;
        });

        const pct = state.total ? Math.round((state.done / state.total) * 100) : 0;
        elements.progressBar.setAttribute('aria-valuenow', pct);
        elements.progressBar.classList.toggle('running', !!state.controller);
        elements.progressLabel.textContent = `${state.done} of ${plural(state.total, 'host')} scanned`;
        if (state.controller) {
            const elapsed = performance.now() - state.startedAt;
            const eta = state.done ? (elapsed / state.done) * (state.total - state.done) : 0;
            elements.progressEta.textContent = state.done ? `about ${formatDuration(eta)} left` : 'starting';
            setScanState('scanning', `Scanning ${pct}%`);
        } else if (state.finishedAt) {
            elements.progressEta.textContent = `took ${formatDuration(state.finishedAt - state.startedAt)} via ${RESOLVERS[state.results[0]?.resolver || state.resolver].label}`;
        }

        const finished = state.results.some(r => r.status !== 'scanning');
        elements.btnCsv.disabled = !finished;
        elements.btnJson.disabled = !finished;
        elements.btnCopy.disabled = !(counts.vulnerable + counts.review);

        if (elements.dialog.open) refreshDrawerNav();
    }

    // --- Filters, search, sort ---

    function setFilter(filter) {
        state.filter = filter;
        elements.filters.querySelectorAll('.stat-card').forEach(card => {
            const active = card.dataset.filter === filter;
            card.classList.toggle('active', active);
            card.setAttribute('aria-pressed', active);
        });
        elements.filters.classList.toggle('filtered', filter !== 'all');
        elements.activeFilter.classList.toggle('hidden', filter === 'all');
        if (filter !== 'all') {
            elements.activeFilter.innerHTML = `<span class="status ${filter}">${STATUS[filter].label}</span>
                <button type="button" class="icon-btn small" aria-label="Clear filter"><i class="fa-solid fa-xmark" aria-hidden="true"></i></button>`;
            elements.activeFilter.querySelector('button').addEventListener('click', () => setFilter('all'));
        }
        render();
    }

    function resetFilters() {
        elements.search.value = '';
        state.query = '';
        setFilter('all');
    }

    elements.filters.addEventListener('click', event => {
        const card = event.target.closest('.stat-card');
        if (card) setFilter(state.filter === card.dataset.filter ? 'all' : card.dataset.filter);
    });

    elements.search.addEventListener('input', () => {
        state.query = elements.search.value.trim().toLowerCase();
        render();
    });

    elements.search.addEventListener('keydown', event => {
        if (event.key === 'Escape' && elements.search.value) {
            event.stopPropagation();
            elements.search.value = '';
            state.query = '';
            render();
        }
    });

    function refreshSortHeaders() {
        document.querySelectorAll('.sort-btn').forEach(b => {
            const th = b.closest('th');
            const icon = b.querySelector('i');
            const active = b.dataset.sort === state.sort.key;
            th.setAttribute('aria-sort', active ? (state.sort.dir === 1 ? 'ascending' : 'descending') : 'none');
            icon.className = `fa-solid ${active ? (state.sort.dir === 1 ? 'fa-sort-up' : 'fa-sort-down') : 'fa-sort'}`;
        });
    }

    document.querySelectorAll('.sort-btn').forEach(btn => btn.addEventListener('click', () => {
        const key = btn.dataset.sort;
        state.sort = state.sort.key === key ? { key, dir: -state.sort.dir } : { key, dir: 1 };
        refreshSortHeaders();
        render();
    }));

    // --- Details drawer ---

    let drawerDomain = null;

    function chainHTML(r) {
        const hops = [`<li><span class="hop-type">Host</span><span class="mono">${breakableHost(r.domain)}</span></li>`];
        r.chain.forEach(c => {
            const hit = c === r.matchedHost ? ' <span class="tag match">matched</span>' : '';
            hops.push(`<li><span class="hop-type">CNAME</span><span class="mono">${breakableHost(c)}${hit}</span></li>`);
        });
        if (r.addresses.length) {
            const shown = r.addresses.slice(0, 3).map(escapeHTML).join('<br>');
            const rest = r.addresses.slice(3);
            const more = rest.length
                ? `<details class="more"><summary>${rest.length} more</summary>${rest.map(escapeHTML).join('<br>')}</details>`
                : '';
            hops.push(`<li class="end-ok"><span class="hop-type">A</span><span class="mono">${shown}${more}</span></li>`);
        } else if (r.rcode) {
            hops.push(`<li class="${r.rcode === 'NOERROR' ? '' : 'end-bad'}"><span class="hop-type">Result</span><span class="mono">${escapeHTML(r.rcode)}</span></li>`);
        }
        return `<ol class="chain">${hops.join('')}</ol>`;
    }

    function detailsHTML(r) {
        const s = STATUS[r.status];
        const sig = r.signature;
        const safeDomain = escapeHTML(r.domain);
        const sections = [];

        sections.push(`
            <section>
                <h3>Resolution path</h3>
                ${chainHTML(r)}
            </section>`);

        if (sig) {
            const edge = sig.status === 'edge'
                ? '<p class="note"><i class="fa-solid fa-circle-info" aria-hidden="true"></i> Only exploitable in some setups. Confirm before reporting.</p>'
                : '';
            sections.push(`
                <section class="block danger">
                    <h3><i class="fa-solid fa-crosshairs" aria-hidden="true"></i> ${escapeHTML(sig.name)}</h3>
                    <p>${escapeHTML(sig.description)}</p>
                    ${edge}
                </section>`);

            if (sig.fingerprint && !r.dangling) {
                sections.push(`
                    <section class="block">
                        <h3><i class="fa-solid fa-fingerprint" aria-hidden="true"></i> Confirm by hand</h3>
                        <p>Browsers cannot read another site's response. Open the host and look for this text:</p>
                        <code class="fingerprint">${escapeHTML(sig.fingerprint)}</code>
                        <div class="link-row">
                            <a class="btn ghost small" href="https://${safeDomain}" target="_blank" rel="noopener noreferrer">Open over HTTPS <i class="fa-solid fa-arrow-up-right-from-square" aria-hidden="true"></i></a>
                            <a class="btn ghost small" href="http://${safeDomain}" target="_blank" rel="noopener noreferrer">Open over HTTP <i class="fa-solid fa-arrow-up-right-from-square" aria-hidden="true"></i></a>
                        </div>
                    </section>`);
            }

            if (sig.claim) {
                sections.push(`
                    <section class="block">
                        <h3><i class="fa-solid fa-flag" aria-hidden="true"></i> Proof of concept</h3>
                        <p>${escapeHTML(sig.claim)}</p>
                    </section>`);
            }
        }

        if (r.status === 'vulnerable' || r.status === 'review') {
            const fix = sig
                ? `Delete the DNS record for <span class="mono">${safeDomain}</span>, or recreate the ${escapeHTML(sig.name)} resource under your own account.`
                : `Delete the DNS record for <span class="mono">${safeDomain}</span>, or point it at a host you control.`;
            const docs = sig?.docs
                ? `<a href="${escapeHTML(sig.docs)}" target="_blank" rel="noopener noreferrer">${escapeHTML(sig.name)} documentation <i class="fa-solid fa-arrow-up-right-from-square" aria-hidden="true"></i></a>`
                : '';
            sections.push(`
                <section class="block success">
                    <h3><i class="fa-solid fa-wrench" aria-hidden="true"></i> Remediation</h3>
                    <p>${fix}</p>
                    ${docs}
                </section>`);
        }

        sections.push(`
            <section>
                <h3>Query</h3>
                <dl class="facts">
                    <dt>Response</dt><dd class="mono">${escapeHTML(r.rcode || '-')}</dd>
                    <dt>Resolver</dt><dd>${escapeHTML(RESOLVERS[r.resolver]?.label || '-')}</dd>
                    <dt>Time</dt><dd>${r.ms ? `${Math.round(r.ms)} ms` : '-'}</dd>
                </dl>
            </section>`);

        return `
            <header class="drawer-header ${r.status}">
                <span class="status ${r.status} large"><i class="fa-solid ${s.icon}" aria-hidden="true"></i> ${s.label}</span>
                <h2 id="dialog-title" class="mono">${breakableHost(r.domain)}</h2>
                <p>${escapeHTML(r.message)}</p>
                <div class="link-row">
                    <button type="button" class="btn ghost small" data-copy="${safeDomain}"><i class="fa-regular fa-copy" aria-hidden="true"></i> Copy host</button>
                    ${r.chain.length ? `<button type="button" class="btn ghost small" data-copy="${escapeHTML(r.chain.join('\n'))}"><i class="fa-solid fa-link" aria-hidden="true"></i> Copy CNAME chain</button>` : ''}
                </div>
            </header>
            ${sections.join('')}`;
    }

    function finishedRendered() {
        return rendered.filter(r => r.status !== 'scanning');
    }

    function refreshDrawerNav() {
        const list = finishedRendered();
        const i = list.findIndex(r => r.domain === drawerDomain);
        elements.drawerPos.textContent = i === -1 ? '' : `${i + 1} of ${list.length}`;
        elements.btnPrev.disabled = i <= 0;
        elements.btnNext.disabled = i === -1 || i >= list.length - 1;
    }

    function openDetails(r) {
        if (!r || r.status === 'scanning') return;
        drawerDomain = r.domain;
        elements.dialogContent.innerHTML = detailsHTML(r);
        elements.dialogContent.scrollTop = 0;
        state.results.forEach(x => x.row?.classList.toggle('selected', x === r));
        refreshDrawerNav();
        if (!elements.dialog.open) elements.dialog.showModal();
    }

    function stepDetails(delta) {
        const list = finishedRendered();
        const i = list.findIndex(r => r.domain === drawerDomain);
        const target = list[i + delta];
        if (target) {
            openDetails(target);
            target.row?.scrollIntoView({ block: 'nearest' });
        }
    }

    elements.btnPrev.addEventListener('click', () => stepDetails(-1));
    elements.btnNext.addEventListener('click', () => stepDetails(1));

    elements.dialogContent.addEventListener('click', event => {
        const btn = event.target.closest('[data-copy]');
        if (btn) copyText(btn.dataset.copy, 'Copied to clipboard');
    });

    elements.dialog.addEventListener('keydown', event => {
        if (event.key === 'j' || event.key === 'ArrowDown') { event.preventDefault(); stepDetails(1); }
        if (event.key === 'k' || event.key === 'ArrowUp') { event.preventDefault(); stepDetails(-1); }
    });

    elements.dialog.addEventListener('close', () => {
        const row = state.byDomain.get(drawerDomain)?.row;
        state.results.forEach(x => x.row?.classList.remove('selected'));
        row?.focus();
    });

    // The drawer fills its own box, so a click that targets the dialog element is on the backdrop.
    elements.dialog.addEventListener('click', event => {
        if (event.target === elements.dialog) elements.dialog.close();
    });

    elements.tbody.addEventListener('click', event => {
        const row = event.target.closest('tr[data-domain]');
        if (row) openDetails(state.byDomain.get(row.dataset.domain));
    });

    elements.tbody.addEventListener('keydown', event => {
        const row = event.target.closest('tr[data-domain]');
        if (!row) return;
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            openDetails(state.byDomain.get(row.dataset.domain));
        } else if (['ArrowDown', 'ArrowUp', 'j', 'k'].includes(event.key)) {
            event.preventDefault();
            const down = event.key === 'ArrowDown' || event.key === 'j';
            (down ? row.nextElementSibling : row.previousElementSibling)?.focus();
        }
    });

    document.addEventListener('keydown', event => {
        if (event.key === '/' && !isTyping(event.target) && !elements.dialog.open && !elements.resultsView.classList.contains('hidden')) {
            event.preventDefault();
            elements.search.focus();
        }
    });

    // --- Export ---

    async function copyText(text, message) {
        try {
            await navigator.clipboard.writeText(text);
            toast(message, 'fa-copy');
        } catch {
            toast('Clipboard is not available', 'fa-circle-exclamation');
        }
    }

    function finishedResults() {
        return state.results.filter(r => r.status !== 'scanning');
    }

    elements.btnCopy.addEventListener('click', () => {
        const hosts = state.results.filter(r => r.status === 'vulnerable' || r.status === 'review').map(r => r.domain);
        copyText(hosts.join('\n'), `Copied ${plural(hosts.length, 'host')}`);
    });

    function stamp() {
        return new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    }

    elements.btnCsv.addEventListener('click', () => {
        const cell = v => {
            const s = String(v ?? '');
            return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
        };
        const header = ['domain', 'status', 'provider', 'cname_chain', 'a_records', 'rcode', 'message'];
        const lines = finishedResults().map(r => [
            r.domain, r.status, r.signature?.name, r.chain.join(' > '), r.addresses.join(' '), r.rcode, r.message
        ].map(cell).join(','));
        download(`subtko-${stamp()}.csv`, [header.join(','), ...lines].join('\n'), 'text/csv');
        toast('CSV downloaded', 'fa-download');
    });

    elements.btnJson.addEventListener('click', () => {
        const data = finishedResults().map(r => ({
            domain: r.domain,
            status: r.status,
            provider: r.signature?.name || null,
            cname_chain: r.chain,
            a_records: r.addresses,
            rcode: r.rcode,
            message: r.message
        }));
        download(`subtko-${stamp()}.json`, JSON.stringify(data, null, 2), 'application/json');
        toast('JSON downloaded', 'fa-download');
    });

    refreshEditor();
    render();
});
