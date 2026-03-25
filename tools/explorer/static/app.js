/* ── Materios Explorer SPA ──────────────────────────────────────────── */

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function truncHash(h, n = 8) {
    if (!h) return 'N/A';
    h = String(h);
    if (h.length <= n * 2 + 2) return h;
    return h.slice(0, n + 2) + '..' + h.slice(-n);
}

function timeAgo(ms) {
    if (!ms) return '';
    const secs = Math.floor((Date.now() - ms) / 1000);
    if (secs < 0) return 'just now';
    if (secs < 60) return secs + 's ago';
    const mins = Math.floor(secs / 60);
    if (mins < 60) return mins + 'm ago';
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + 'h ago';
    const days = Math.floor(hrs / 24);
    return days + 'd ago';
}

function formatNumber(n) {
    if (n == null) return '0';
    return Number(n).toLocaleString();
}

function formatBalance(raw, decimals = 12) {
    if (!raw && raw !== 0) return '0';
    const n = BigInt(raw);
    const d = BigInt(10 ** decimals);
    const whole = n / d;
    const frac = n % d;
    const fracStr = frac.toString().padStart(decimals, '0').slice(0, 4);
    return whole.toLocaleString() + '.' + fracStr;
}

function statusBadge(status) {
    switch (status) {
        case 'anchored': return '<span class="badge badge-anchored">Anchored</span>';
        case 'certified': return '<span class="badge badge-certified">Certified</span>';
        case 'awaiting_cert': return '<span class="badge badge-awaiting">Awaiting Cert</span>';
        case 'stale': return '<span class="badge badge-stale">Stale</span>';
        case 'submitted': return '<span class="badge badge-submitted">Submitted</span>';
        case 'failed': return '<span class="badge badge-fail">Failed</span>';
        default: return '<span class="badge badge-submitted">Submitted</span>';
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Brief feedback could be added here
    });
}

async function apiFetch(path) {
    const res = await fetch('api/' + path);
    const text = await res.text();
    try {
        return JSON.parse(text);
    } catch {
        throw new Error('HTTP ' + res.status);
    }
}

function hashLink(hash) {
    return `<a href="#/receipt/${hash}" class="truncated mono">${truncHash(hash, 10)}</a>`;
}

function blockLink(num) {
    return `<a href="#/block/${num}">#${num}</a>`;
}

function addrLink(addr) {
    if (!addr) return 'N/A';
    return `<a href="#/account/${addr}" class="truncated">${truncHash(addr, 8)}</a>`;
}

function fieldRow(label, value, isHash = false) {
    const cls = isHash ? 'mono' : '';
    const copyBtn = isHash && value && value !== 'N/A'
        ? ` <button class="copy-btn" onclick="copyToClipboard('${value}')" title="Copy">&#x2398;</button>`
        : '';
    return `<div class="field-row"><div class="field-label">${label}</div><div class="field-value ${cls}">${value || 'N/A'}${copyBtn}</div></div>`;
}

// Only show loading placeholder when app has no real content yet.
// Keeps old content visible during fetches and auto-refreshes.
function showLoadingIfEmpty(msg) {
    const app = document.getElementById('app');
    if (!app.innerHTML.trim() || app.querySelector('.loading')) {
        app.innerHTML = '<div class="loading">' + msg + '</div>';
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

const routes = [
    { pattern: /^\/$/,                       handler: renderDashboard },
    { pattern: /^\/blocks$/,                 handler: renderBlocksList },
    { pattern: /^\/block\/(.+)$/,            handler: (m) => renderBlockDetail(m[1]) },
    { pattern: /^\/receipts$/,               handler: renderReceiptsList },
    { pattern: /^\/receipt\/(.+)$/,          handler: (m) => renderReceiptDetail(m[1]) },
    { pattern: /^\/verify\/(.+)$/,           handler: (m) => renderVerification(m[1]) },
    { pattern: /^\/anchors$/,                handler: renderAnchorsList },
    { pattern: /^\/anchor\/(.+)$/,           handler: (m) => renderAnchorDetail(m[1]) },
    { pattern: /^\/account\/(.+)$/,          handler: (m) => renderAccountDetail(m[1]) },
    { pattern: /^\/committee$/,              handler: renderCommitteeHealth },
];

let committeeRefreshInterval = null;

function router() {
    const hash = (location.hash.slice(1) || '/').split('?')[0];
    const app = document.getElementById('app');

    // Clear committee auto-refresh when navigating away
    if (committeeRefreshInterval) {
        clearInterval(committeeRefreshInterval);
        committeeRefreshInterval = null;
    }

    // Update active nav link
    document.querySelectorAll('.nav-link').forEach(el => {
        const route = el.getAttribute('data-route');
        el.classList.toggle('active', hash === route || (route !== '/' && hash.startsWith(route)));
    });

    for (const r of routes) {
        const m = hash.match(r.pattern);
        if (m) {
            r.handler(m);
            // Set up auto-refresh for committee page
            if (hash === '/committee') {
                committeeRefreshInterval = setInterval(renderCommitteeHealth, 15000);
            }
            return;
        }
    }

    app.innerHTML = '<div class="error-msg">Page not found</div>';
}

window.addEventListener('hashchange', router);
window.addEventListener('DOMContentLoaded', () => {
    router();
    loadFooterInfo();
    // Set up search
    document.getElementById('global-search').addEventListener('keydown', e => {
        if (e.key === 'Enter') doSearch();
    });
});

function getPage() {
    const params = new URLSearchParams(location.hash.split('?')[1] || '');
    return parseInt(params.get('page') || '1', 10);
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

async function doSearch() {
    const q = document.getElementById('global-search').value.trim();
    if (!q) return;

    try {
        const result = await apiFetch('search?q=' + encodeURIComponent(q));
        if (result.type === 'block') location.hash = '#/block/' + result.id;
        else if (result.type === 'receipt') location.hash = '#/receipt/' + result.id;
        else if (result.type === 'anchor') location.hash = '#/anchor/' + result.id;
        else if (result.type === 'account') location.hash = '#/account/' + result.id;
        else {
            const app = document.getElementById('app');
            app.innerHTML = '<div class="error-msg">No results found for: ' + q + '</div>';
        }
    } catch (e) {
        document.getElementById('app').innerHTML = '<div class="error-msg">Search error: ' + e.message + '</div>';
    }
}

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

let refreshTimer = null;

function loadFooterInfo() {
    apiFetch('chain-info').then(info => {
        if (info.error) {
            document.getElementById('footer-chain-info').textContent = 'Disconnected';
            return;
        }
        document.getElementById('footer-chain-info').textContent =
            `Block #${formatNumber(info.best_block)} | ${formatNumber(info.receipt_count)} transactions | Committee: ${info.committee?.size || 0}/${info.committee?.threshold || 0}`;
    }).catch(() => {
        document.getElementById('footer-chain-info').textContent = 'Disconnected';
    });
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

async function renderDashboard() {
    const app = document.getElementById('app');
    showLoadingIfEmpty('Loading dashboard...');

    try {
        const [info, recentData, certifiedData, failedData] = await Promise.all([
            apiFetch('chain-info'),
            apiFetch('receipts?limit=10'),
            apiFetch('receipts/recent-certified?limit=10'),
            apiFetch('receipts/recent-failed?limit=5').catch(() => ({ failures: [], total: 0 })),
        ]);

        if (info.error && !app.querySelector('.stats-grid')) {
            app.innerHTML = '<div class="error-msg">' + info.error + '</div>';
            return;
        }
        if (info.error) return; // keep existing content on refresh errors

        const motra = info.motra || {};
        const stats = info.receipt_stats || {};
        const anchoredCount = stats.anchored || 0;
        const failedCount = stats.failed || 0;
        const failures = failedData.failures || [];

        // Build the failed submissions section (only shown if there are failures)
        let failedSection = '';
        if (failures.length > 0) {
            failedSection = `
                <div class="failed-feed">
                    <div class="card failed-card">
                        <div class="card-header">
                            <span class="card-title failed-title">Recent Failed Submissions</span>
                            <span class="card-action failed-count">${failedCount} total</span>
                        </div>
                        <div class="card-body">
                            ${renderFailedTable(failures, true)}
                        </div>
                    </div>
                </div>
            `;
        }

        app.innerHTML = `
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Best Block</div>
                    <div class="stat-value accent">${formatNumber(info.best_block)}</div>
                    <div class="stat-sub">Finalized: #${formatNumber(info.finalized_block || info.best_block)}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Receipts</div>
                    <div class="stat-value">${formatNumber(info.receipt_count)}</div>
                    <div class="stat-sub">${anchoredCount} anchored${failedCount ? ', ' + failedCount + ' failed' : ''}</div>
                </div>
                <div class="stat-card clickable" onclick="location.hash='#/committee'">
                    <div class="stat-label">Committee</div>
                    <div class="stat-value">${info.committee?.size || 0} / ${info.committee?.threshold || 0}</div>
                    <div class="stat-sub">Attestation threshold &middot; <a href="#/committee" style="color:var(--accent)">Health</a></div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">MOTRA Burned</div>
                    <div class="stat-value">${formatBalance(motra.total_burned || 0)}</div>
                    <div class="stat-sub">Total issued: ${formatBalance(motra.total_issued || 0)}</div>
                </div>
            </div>

            <div class="dashboard-grid">
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Recent Activity</span>
                        <a href="#/receipts" class="card-action">View All</a>
                    </div>
                    <div class="card-body">
                        ${renderReceiptsTable(recentData.receipts || [], true)}
                        <div class="card-note">Pending receipts may be from load tests or missing blob provisioning.</div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Recently Verified</span>
                        <a href="#/receipts?status=certified" class="card-action">View All</a>
                    </div>
                    <div class="card-body">
                        ${renderReceiptsTable(certifiedData.receipts || [], true)}
                    </div>
                </div>
            </div>

            ${failedSection}
        `;

        // Auto-refresh dashboard
        clearInterval(refreshTimer);
        refreshTimer = setInterval(() => {
            if ((location.hash.slice(1) || '/') === '/') renderDashboard();
            else clearInterval(refreshTimer);
        }, 30000);

    } catch (e) {
        // Only show error if there's no existing dashboard content
        if (!app.querySelector('.stats-grid')) {
            app.innerHTML = '<div class="error-msg">Failed to load dashboard: ' + e.message + '</div>';
        }
    }
}

function renderBlocksTable(blocks, compact = false) {
    if (!blocks.length) return '<div class="loading">No blocks found</div>';
    return `<table class="data-table">
        <thead><tr>
            <th>Block</th>
            <th>Hash</th>
            ${compact ? '' : '<th>Parent</th>'}
            <th class="right">Txns</th>
            <th class="right">Events</th>
            <th class="right">Time</th>
        </tr></thead>
        <tbody>
        ${blocks.map(b => `<tr>
            <td>${blockLink(b.number)}</td>
            <td class="mono truncated">${truncHash(b.hash, 8)}</td>
            ${compact ? '' : `<td class="mono truncated">${truncHash(b.parent_hash, 8)}</td>`}
            <td class="right">${b.extrinsics_count || 0}</td>
            <td class="right">${b.events_count || 0}</td>
            <td class="right time-ago">${timeAgo(b.timestamp)}</td>
        </tr>`).join('')}
        </tbody>
    </table>`;
}

function renderReceiptsTable(receipts, compact = false) {
    if (!receipts.length) return '<div class="loading">No transactions found</div>';
    return `<table class="data-table">
        <thead><tr>
            <th>Receipt ID</th>
            <th>Status</th>
            <th>Submitter</th>
            <th class="right">Age</th>
        </tr></thead>
        <tbody>
        ${receipts.map(r => `<tr>
            <td>${hashLink(r.receipt_id)}</td>
            <td>${statusBadge(r.status)}</td>
            <td>${addrLink(r.submitter)}</td>
            <td class="right time-ago">${timeAgo(r.timestamp)}</td>
        </tr>`).join('')}
        </tbody>
    </table>`;
}

function renderFailedTable(failures, compact = false) {
    if (!failures.length) return '<div class="loading">No failed submissions found</div>';
    return `<table class="data-table">
        <thead><tr>
            <th>Block</th>
            <th>Method</th>
            <th>Account</th>
            <th>Error</th>
            <th class="right">Age</th>
        </tr></thead>
        <tbody>
        ${failures.map(f => `<tr class="failed-row">
            <td>${f.block_number ? blockLink(f.block_number) : 'N/A'}</td>
            <td><span class="badge badge-fail">${f.extrinsic_method || 'unknown'}</span></td>
            <td>${addrLink(f.account)}</td>
            <td class="failed-error" title="${(f.error || '').replace(/"/g, '&quot;')}">${truncError(f.error || 'ExtrinsicFailed')}</td>
            <td class="right time-ago">${timeAgo(f.timestamp)}</td>
        </tr>`).join('')}
        </tbody>
    </table>`;
}

function truncError(err) {
    if (!err) return 'Unknown';
    if (err.length <= 50) return err;
    return err.slice(0, 47) + '...';
}

// ---------------------------------------------------------------------------
// Blocks List
// ---------------------------------------------------------------------------

async function renderBlocksList() {
    const app = document.getElementById('app');
    const page = getPage();
    showLoadingIfEmpty('Loading blocks...');

    try {
        const data = await apiFetch(`blocks?page=${page}&limit=20`);
        app.innerHTML = `
            <div class="section-title">Blocks</div>
            <div class="card">
                <div class="card-body">
                    ${renderBlocksTable(data.blocks || [])}
                </div>
            </div>
            ${renderPagination(page, data.best_block ? Math.ceil(data.best_block / 20) : 1, '#/blocks')}
        `;
    } catch (e) {
        if (!app.querySelector('.section-title')) {
            app.innerHTML = '<div class="error-msg">Failed to load blocks: ' + e.message + '</div>';
        }
    }
}

// ---------------------------------------------------------------------------
// Block Detail
// ---------------------------------------------------------------------------

async function renderBlockDetail(id) {
    const app = document.getElementById('app');
    showLoadingIfEmpty('Loading block...');

    try {
        const block = await apiFetch('block/' + id);
        if (block.error) {
            app.innerHTML = '<div class="error-msg">' + block.error + '</div>';
            return;
        }

        const extrinsics = block.extrinsics || [];
        const events = block.events || [];

        app.innerHTML = `
            <div class="breadcrumb"><a href="#/blocks">Blocks</a> / Block #${block.number}</div>
            <div class="section-title">Block #${formatNumber(block.number)}</div>

            <div class="card">
                <div class="card-header"><span class="card-title">Block Details</span></div>
                <div class="card-body">
                    <div class="field-grid">
                        ${fieldRow('Block Number', formatNumber(block.number))}
                        ${fieldRow('Block Hash', block.hash, true)}
                        ${fieldRow('Parent Hash', block.parent_hash, true)}
                        ${fieldRow('State Root', block.state_root, true)}
                        ${fieldRow('Extrinsics Root', block.extrinsics_root, true)}
                        ${fieldRow('Timestamp', block.timestamp ? new Date(block.timestamp).toISOString() : 'N/A')}
                        ${fieldRow('Extrinsics', extrinsics.length)}
                        ${fieldRow('Events', events.length)}
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header"><span class="card-title">Extrinsics (${extrinsics.length})</span></div>
                <div class="card-body">
                    <table class="data-table">
                        <thead><tr><th>#</th><th>Module</th><th>Call</th><th>Signer</th><th>Result</th></tr></thead>
                        <tbody>
                        ${extrinsics.map((ex, i) => `<tr>
                            <td>${i}</td>
                            <td><span class="badge badge-info">${ex.module || '?'}</span></td>
                            <td>${ex.call || '?'}</td>
                            <td>${ex.signer ? addrLink(ex.signer) : '<span class="text-dim">unsigned</span>'}</td>
                            <td>${ex.success ? '<span class="badge badge-success">OK</span>' : '<span class="badge badge-fail">FAIL</span>'}</td>
                        </tr>`).join('')}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <div class="card-header"><span class="card-title">Events (${events.length})</span></div>
                <div class="card-body">
                    <table class="data-table">
                        <thead><tr><th>#</th><th>Module</th><th>Event</th><th>Details</th></tr></thead>
                        <tbody>
                        ${events.map((ev, i) => `<tr>
                            <td>${i}</td>
                            <td><span class="badge badge-info">${ev.module || '?'}</span></td>
                            <td>${ev.event || '?'}</td>
                            <td class="mono" style="font-size:11px">${formatEventAttrs(ev.attributes)}</td>
                        </tr>`).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    } catch (e) {
        if (!app.querySelector('.field-grid')) {
            app.innerHTML = '<div class="error-msg">Failed to load block: ' + e.message + '</div>';
        }
    }
}

function formatEventAttrs(attrs) {
    if (!attrs || typeof attrs !== 'object') return '';
    return Object.entries(attrs).map(([k, v]) => {
        const vs = String(v);
        if (vs.startsWith('0x') && vs.length === 66) {
            return `${k}: <a href="#/receipt/${vs}">${truncHash(vs, 6)}</a>`;
        }
        if (vs.length > 30) return `${k}: ${truncHash(vs, 10)}`;
        return `${k}: ${vs}`;
    }).join(' | ');
}

// ---------------------------------------------------------------------------
// Receipts List
// ---------------------------------------------------------------------------

async function renderReceiptsList() {
    const app = document.getElementById('app');
    const page = getPage();
    const params = new URLSearchParams(location.hash.split('?')[1] || '');
    const statusFilter = params.get('status') || '';
    showLoadingIfEmpty('Loading receipts...');

    try {
        const isFailed = statusFilter === 'failed';
        let contentHtml = '';
        let totalCount = 0;

        if (isFailed) {
            // Fetch failed submissions from the dedicated endpoint
            const failedData = await apiFetch('receipts/recent-failed?limit=50');
            const failures = failedData.failures || [];
            totalCount = failures.length;
            contentHtml = renderFailedTable(failures);
        } else {
            let url = `receipts?page=${page}&limit=20`;
            if (statusFilter) url += `&status=${statusFilter}`;
            const data = await apiFetch(url);
            totalCount = data.total || 0;
            contentHtml = renderReceiptsTable(data.receipts || []);
        }

        const totalPages = isFailed ? 1 : Math.max(1, Math.ceil(totalCount / 20));
        const baseHash = statusFilter ? `#/receipts?status=${statusFilter}` : '#/receipts';
        app.innerHTML = `
            <div class="section-title">Transactions</div>
            <div class="filter-bar">
                <button class="filter-btn${!statusFilter ? ' active' : ''}" onclick="location.hash='#/receipts'">All</button>
                <button class="filter-btn${statusFilter === 'anchored' ? ' active' : ''}" onclick="location.hash='#/receipts?status=anchored'">Anchored</button>
                <button class="filter-btn${statusFilter === 'certified' ? ' active' : ''}" onclick="location.hash='#/receipts?status=certified'">Certified</button>
                <button class="filter-btn${statusFilter === 'pending' ? ' active' : ''}" onclick="location.hash='#/receipts?status=pending'">Pending</button>
                <button class="filter-btn${statusFilter === 'stale' ? ' active' : ''}" onclick="location.hash='#/receipts?status=stale'">Stale</button>
                <button class="filter-btn filter-btn-failed${statusFilter === 'failed' ? ' active' : ''}" onclick="location.hash='#/receipts?status=failed'">Failed</button>
            </div>
            <div class="card${isFailed ? ' failed-card' : ''}">
                <div class="card-header">
                    <span class="card-title">${formatNumber(totalCount)} total</span>
                </div>
                <div class="card-body">
                    ${contentHtml}
                </div>
            </div>
            ${isFailed ? '' : renderPagination(page, totalPages, baseHash)}
        `;
    } catch (e) {
        if (!app.querySelector('.filter-bar')) {
            app.innerHTML = '<div class="error-msg">Failed to load receipts: ' + e.message + '</div>';
        }
    }
}

// ---------------------------------------------------------------------------
// Receipt Detail
// ---------------------------------------------------------------------------

async function renderReceiptDetail(id) {
    const app = document.getElementById('app');
    showLoadingIfEmpty('Loading receipt...');

    try {
        const receipt = await apiFetch('receipt/' + encodeURIComponent(id));
        if (receipt.error) {
            // Check if there's failure info attached
            if (receipt.failure) {
                const f = receipt.failure;
                app.innerHTML = `
                    <div class="breadcrumb"><a href="#/receipts">Transactions</a> / Receipt</div>
                    <div class="result-banner failed">SUBMISSION FAILED</div>
                    <div class="card failed-card">
                        <div class="card-header"><span class="card-title failed-title">Failed Submission Details</span></div>
                        <div class="card-body">
                            <div class="field-grid">
                                ${fieldRow('Receipt ID', id, true)}
                                ${fieldRow('Status', '<span class="badge badge-fail">Failed</span>')}
                                ${fieldRow('Block', f.block_number ? `<a href="#/block/${f.block_number}">#${f.block_number}</a>` : 'N/A')}
                                ${fieldRow('Extrinsic Index', f.extrinsic_index != null ? String(f.extrinsic_index) : 'N/A')}
                                ${fieldRow('Method', f.extrinsic_method || 'unknown')}
                                ${fieldRow('Account', f.account ? `<a href="#/account/${f.account}">${f.account}</a>` : 'N/A')}
                                ${fieldRow('Error', f.error || 'ExtrinsicFailed')}
                                ${f.error_module ? fieldRow('Error Module', f.error_module) : ''}
                                ${f.error_name ? fieldRow('Error Name', f.error_name) : ''}
                                ${fieldRow('Time', f.timestamp ? new Date(f.timestamp).toISOString() : 'N/A')}
                            </div>
                        </div>
                    </div>
                `;
                return;
            }
            app.innerHTML = '<div class="error-msg">' + receipt.error + '</div>';
            return;
        }

        let bannerClass, bannerText;
        switch (receipt.status) {
            case 'anchored': bannerClass = 'verified'; bannerText = 'ANCHORED'; break;
            case 'certified': bannerClass = 'verified'; bannerText = 'CERTIFIED'; break;
            case 'awaiting_cert': bannerClass = 'partial'; bannerText = 'AWAITING CERTIFICATION'; break;
            case 'stale': bannerClass = 'failed'; bannerText = 'STALE'; break;
            default: bannerClass = 'partial'; bannerText = 'SUBMITTED'; break;
        }

        app.innerHTML = `
            <div class="breadcrumb"><a href="#/receipts">Transactions</a> / Receipt</div>

            <div class="result-banner ${bannerClass}">${bannerText}</div>

            <div class="card">
                <div class="card-header"><span class="card-title">Receipt Details</span></div>
                <div class="card-body">
                    <div class="field-grid">
                        ${fieldRow('Receipt ID', receipt.receipt_id, true)}
                        ${fieldRow('Status', statusBadge(receipt.status))}
                        ${fieldRow('Submitter', `<a href="#/account/${receipt.submitter}">${receipt.submitter}</a>`)}
                        ${fieldRow('Content Hash', receipt.content_hash, true)}
                        ${fieldRow('Base Root SHA256', receipt.base_root_sha256, true)}
                        ${fieldRow('Availability Cert', receipt.availability_cert_hash, true)}
                        ${fieldRow('Schema Hash', receipt.schema_hash, true)}
                        ${fieldRow('Storage Locator', receipt.storage_locator_hash, true)}
                        ${fieldRow('Base Manifest', receipt.base_manifest_hash, true)}
                        ${fieldRow('Safety Manifest', receipt.safety_manifest_hash, true)}
                        ${fieldRow('Monitor Config', receipt.monitor_config_hash, true)}
                        ${fieldRow('Attestation Evidence', receipt.attestation_evidence_hash, true)}
                        ${fieldRow('Created', receipt.created_at_millis ? new Date(receipt.created_at_millis).toISOString() : 'N/A')}
                    </div>
                </div>
            </div>

            <div style="text-align:center">
                <button class="verify-btn" onclick="location.hash='#/verify/${receipt.receipt_id}'">Verify Chain of Custody</button>
            </div>
        `;
    } catch (e) {
        if (!app.querySelector('.field-grid')) {
            app.innerHTML = '<div class="error-msg">Failed to load receipt: ' + e.message + '</div>';
        }
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

async function renderVerification(id) {
    const app = document.getElementById('app');
    showLoadingIfEmpty('Running verification (may take up to 25s)...');

    try {
        const [receipt, report] = await Promise.all([
            apiFetch('receipt/' + encodeURIComponent(id)).catch(() => ({ error: 'Receipt fetch failed' })),
            apiFetch('verify/' + encodeURIComponent(id)),
        ]);

        if (report.error) {
            app.innerHTML = `
                <div class="breadcrumb"><a href="#/receipt/${id}">Receipt</a> / Verify</div>
                <div class="error-msg">${report.error}</div>
            `;
            return;
        }

        // Result banner
        let bannerClass = 'failed', bannerText = 'NOT VERIFIED';
        if (report.result === 'FULLY_VERIFIED') { bannerClass = 'verified'; bannerText = 'FULLY VERIFIED'; }
        else if (report.result === 'PARTIALLY_VERIFIED') { bannerClass = 'partial'; bannerText = 'PARTIALLY VERIFIED'; }

        // Chain of custody
        const stages = [
            { label: 'Receipt', step: 1 },
            { label: 'Cert', step: 2 },
            { label: 'Leaf', step: 3 },
            { label: 'Merkle', step: 5 },
            { label: 'Anchor', step: 4 },
        ];
        const cocHtml = stages.map((s, i) => {
            const step = (report.steps || []).find(st => st.step === s.step);
            const cls = step ? (step.passed ? 'pass' : (step.warnings && step.warnings.length ? 'pending' : 'fail')) : 'idle';
            const arrow = i < stages.length - 1 ? '<span class="coc-arrow">&rarr;</span>' : '';
            return `<div class="coc-step ${cls}">${s.label}</div>${arrow}`;
        }).join('');

        // Steps list
        const stepsHtml = (report.steps || []).map(s => {
            const badge = s.passed ? 'pass' : (s.warnings && s.warnings.length > 0 ? 'warn' : 'fail');
            const badgeText = s.passed ? 'PASS' : (s.warnings && s.warnings.length > 0 ? 'WARN' : 'FAIL');
            let detail = '';
            if (s.details && Object.keys(s.details).length > 0) {
                const important = ['error', 'cert_hash', 'leaf_hash', 'match_type', 'event_block', 'chain'];
                detail = important
                    .filter(k => s.details[k] !== undefined)
                    .map(k => `${k}: ${s.details[k]}`)
                    .join(' | ');
            }
            const warnings = (s.warnings || []).map(w => `<div class="step-detail" style="color:var(--yellow)">${w}</div>`).join('');
            return `<li>
                <span class="step-badge ${badge}">${badgeText}</span>
                <div>
                    <div class="step-title">[${s.step}/7] ${s.title}</div>
                    ${detail ? `<div class="step-detail">${detail}</div>` : ''}
                    ${warnings}
                </div>
            </li>`;
        }).join('');

        // Anchor card
        let anchorHtml = '';
        if (report.anchor) {
            anchorHtml = `
                <div class="card">
                    <div class="card-header"><span class="card-title">Checkpoint Anchor</span></div>
                    <div class="card-body">
                        <div class="field-grid">
                            ${fieldRow('Anchor ID', report.anchor.anchor_id, true)}
                            ${fieldRow('Root Hash', report.anchor.root_hash, true)}
                            ${fieldRow('Manifest Hash', report.anchor.manifest_hash, true)}
                            ${fieldRow('Block', report.anchor.block_num ? blockLink(report.anchor.block_num) : 'N/A')}
                            ${fieldRow('Match Type', report.anchor.match_type)}
                        </div>
                    </div>
                </div>
            `;
        }

        app.innerHTML = `
            <div class="breadcrumb"><a href="#/receipt/${id}">Receipt</a> / Verification</div>

            <div class="result-banner ${bannerClass}">${bannerText}</div>

            <div class="chain-of-custody">${cocHtml}</div>

            ${!receipt.error ? `
            <div class="card">
                <div class="card-header"><span class="card-title">Receipt Details</span></div>
                <div class="card-body">
                    <div class="field-grid">
                        ${fieldRow('Receipt ID', receipt.receipt_id, true)}
                        ${fieldRow('Status', statusBadge(receipt.status))}
                        ${fieldRow('Submitter', receipt.submitter ? addrLink(receipt.submitter) : 'N/A')}
                        ${fieldRow('Content Hash', receipt.content_hash, true)}
                        ${fieldRow('Cert Hash', receipt.availability_cert_hash, true)}
                        ${fieldRow('Created', receipt.created_at_millis ? new Date(receipt.created_at_millis).toISOString() : 'N/A')}
                    </div>
                </div>
            </div>
            ` : ''}

            <div class="card">
                <div class="card-header"><span class="card-title">Verification Steps</span></div>
                <div class="card-body">
                    <ul class="step-list">${stepsHtml}</ul>
                </div>
            </div>

            ${anchorHtml}
        `;
    } catch (e) {
        app.innerHTML = '<div class="error-msg">Verification error: ' + e.message + '</div>';
    }
}

// ---------------------------------------------------------------------------
// Anchors List
// ---------------------------------------------------------------------------

async function renderAnchorsList() {
    const app = document.getElementById('app');
    const page = getPage();
    showLoadingIfEmpty('Loading anchors...');

    try {
        const data = await apiFetch(`anchors?page=${page}&limit=20`);
        const totalPages = Math.max(1, Math.ceil((data.total || 0) / 20));
        app.innerHTML = `
            <div class="section-title">Checkpoint Anchors</div>
            <div class="card">
                <div class="card-header">
                    <span class="card-title">${formatNumber(data.total || 0)} total</span>
                </div>
                <div class="card-body">
                    ${renderAnchorsTable(data.anchors || [])}
                </div>
            </div>
            ${renderPagination(page, totalPages, '#/anchors')}
        `;
    } catch (e) {
        if (!app.querySelector('.section-title')) {
            app.innerHTML = '<div class="error-msg">Failed to load anchors: ' + e.message + '</div>';
        }
    }
}

function renderAnchorsTable(anchors) {
    if (!anchors.length) return '<div class="loading">No anchors found</div>';
    return `<table class="data-table">
        <thead><tr>
            <th>Anchor ID</th>
            <th>Root Hash</th>
            <th>Submitter</th>
            <th>Block</th>
            <th class="right">Time</th>
        </tr></thead>
        <tbody>
        ${anchors.map(a => `<tr>
            <td><a href="#/anchor/${a.anchor_id}" class="truncated mono">${truncHash(a.anchor_id, 10)}</a></td>
            <td class="mono truncated">${truncHash(a.root_hash || a.content_hash || '', 8)}</td>
            <td>${addrLink(a.submitter)}</td>
            <td>${a.block_num ? blockLink(a.block_num) : 'N/A'}</td>
            <td class="right time-ago">${timeAgo(a.timestamp)}</td>
        </tr>`).join('')}
        </tbody>
    </table>`;
}

// ---------------------------------------------------------------------------
// Anchor Detail
// ---------------------------------------------------------------------------

async function renderAnchorDetail(id) {
    const app = document.getElementById('app');
    showLoadingIfEmpty('Loading anchor...');

    try {
        const anchor = await apiFetch('anchor/' + encodeURIComponent(id));
        if (anchor.error) {
            app.innerHTML = '<div class="error-msg">' + anchor.error + '</div>';
            return;
        }

        app.innerHTML = `
            <div class="breadcrumb"><a href="#/anchors">Anchors</a> / Anchor</div>
            <div class="section-title">Checkpoint Anchor</div>

            <div class="card">
                <div class="card-header"><span class="card-title">Anchor Details</span></div>
                <div class="card-body">
                    <div class="field-grid">
                        ${fieldRow('Anchor ID', anchor.anchor_id, true)}
                        ${fieldRow('Content Hash', anchor.content_hash, true)}
                        ${fieldRow('Root Hash', anchor.root_hash, true)}
                        ${fieldRow('Manifest Hash', anchor.manifest_hash, true)}
                        ${fieldRow('Submitter', anchor.submitter ? `<a href="#/account/${anchor.submitter}">${anchor.submitter}</a>` : 'N/A')}
                        ${fieldRow('Created', anchor.created_at_millis ? new Date(anchor.created_at_millis).toISOString() : 'N/A')}
                    </div>
                </div>
            </div>
        `;
    } catch (e) {
        if (!app.querySelector('.field-grid')) {
            app.innerHTML = '<div class="error-msg">Failed to load anchor: ' + e.message + '</div>';
        }
    }
}

// ---------------------------------------------------------------------------
// Account Detail
// ---------------------------------------------------------------------------

async function renderAccountDetail(addr) {
    const app = document.getElementById('app');
    showLoadingIfEmpty('Loading account...');

    try {
        const account = await apiFetch('account/' + encodeURIComponent(addr));
        if (account.error) {
            app.innerHTML = '<div class="error-msg">' + account.error + '</div>';
            return;
        }

        const receipts = account.receipts_submitted || [];

        app.innerHTML = `
            <div class="breadcrumb">Account</div>
            <div class="section-title" style="word-break:break-all;font-size:14px">${account.address}
                ${account.is_committee_member ? ' <span class="badge badge-committee">Committee</span>' : ''}
                <button class="copy-btn" onclick="copyToClipboard('${account.address}')" title="Copy">&#x2398;</button>
            </div>

            <div class="balance-cards">
                <div class="stat-card">
                    <div class="stat-label">MATRA Balance</div>
                    <div class="stat-value">${formatBalance(account.matra_balance || 0)}</div>
                    <div class="stat-sub">Native token</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">MOTRA Balance</div>
                    <div class="stat-value">${formatBalance(account.motra_balance || 0)}</div>
                    <div class="stat-sub">Capacity token</div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-title">Submitted Transactions (${receipts.length})</span>
                </div>
                <div class="card-body">
                    ${receipts.length ? renderReceiptsTable(receipts) : '<div class="loading">No transactions found for this account</div>'}
                </div>
            </div>
        `;
    } catch (e) {
        if (!app.querySelector('.balance-cards')) {
            app.innerHTML = '<div class="error-msg">Failed to load account: ' + e.message + '</div>';
        }
    }
}

// ---------------------------------------------------------------------------
// Committee Health
// ---------------------------------------------------------------------------

async function renderCommitteeHealth() {
    const app = document.getElementById('app');
    showLoadingIfEmpty('Loading committee health...');

    try {
        const data = await apiFetch('committee/health');
        if (data.error) {
            app.innerHTML = `<div class="card"><div class="card-body-padded"><span class="text-dim">Error: ${data.error}</span></div></div>`;
            return;
        }

        // Threshold banner
        let bannerClass = 'green';
        let bannerText = '';
        if (data.online > data.threshold) {
            bannerClass = 'green';
            bannerText = `${data.online}/${data.total} online — threshold met`;
        } else if (data.online === data.threshold) {
            bannerClass = 'yellow';
            bannerText = `${data.online}/${data.total} online — one failure from losing quorum`;
        } else {
            bannerClass = 'red';
            bannerText = `${data.online}/${data.total} online — BELOW THRESHOLD (need ${data.threshold})`;
        }

        const bannerIcon = bannerClass === 'green' ? '\u25CF' : bannerClass === 'yellow' ? '\u25D0' : '\u25CB';

        // Member table
        let rows = '';
        for (const m of data.members) {
            const badge = committeeStatusBadge(m.status);
            const verifiedIcon = m.verified ? '\u2713' : (m.status === 'no_heartbeat' ? '\u2014' : '\u26A0');
            const verifiedClass = m.verified ? 'verified-yes' : (m.status === 'no_heartbeat' ? 'verified-na' : 'verified-no');
            const ageSecs = m.age_secs != null ? m.age_secs + 's' : '\u2014';
            const connIcon = m.substrate_connected ? '\u25CF' : '\u25CB';
            const connClass = m.substrate_connected ? 'conn-yes' : 'conn-no';

            rows += `<tr>
                <td>${addrLink(m.address)}</td>
                <td>${m.label || '\u2014'}</td>
                <td>${badge}</td>
                <td class="${verifiedClass}">${verifiedIcon}</td>
                <td>${ageSecs}</td>
                <td>${m.best_block || '\u2014'}</td>
                <td>${m.finality_gap ?? '\u2014'}</td>
                <td>${m.certs_submitted || 0}</td>
                <td>${m.version || '\u2014'}</td>
                <td class="${connClass}">${connIcon}</td>
            </tr>`;
        }

        app.innerHTML = `
            <h2 class="section-title">Committee Health</h2>
            <div class="committee-banner ${bannerClass}">
                <span class="banner-icon">${bannerIcon}</span>
                ${bannerText}
                <span class="banner-detail">Threshold: ${data.threshold}-of-${data.total}</span>
            </div>
            <div class="card" style="margin-top: 16px; overflow-x: auto;">
                <div class="card-body">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Address</th>
                                <th>Label</th>
                                <th>Status</th>
                                <th>Verified</th>
                                <th>Last HB</th>
                                <th>Best Block</th>
                                <th>Fin. Gap</th>
                                <th>Certs</th>
                                <th>Version</th>
                                <th>RPC</th>
                            </tr>
                        </thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>
            </div>
        `;
    } catch (e) {
        if (!app.querySelector('.committee-banner')) {
            app.innerHTML = `<div class="card"><div class="card-body-padded"><span class="text-dim">Failed to load: ${e.message}</span></div></div>`;
        }
    }
}

function committeeStatusBadge(status) {
    switch (status) {
        case 'online': return '<span class="badge badge-online">Online</span>';
        case 'degraded': return '<span class="badge badge-degraded">Degraded</span>';
        case 'offline': return '<span class="badge badge-offline">Offline</span>';
        case 'no_heartbeat': return '<span class="badge badge-no-hb">No Heartbeat</span>';
        default: return '<span class="badge">' + status + '</span>';
    }
}

function formatUptime(secs) {
    if (secs < 3600) return Math.floor(secs / 60) + 'm';
    if (secs < 86400) return Math.floor(secs / 3600) + 'h';
    return Math.floor(secs / 86400) + 'd';
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

function renderPagination(current, totalPages, baseHash) {
    if (totalPages <= 1) return '';
    const prev = current > 1 ? `<button class="page-btn" onclick="location.hash='${baseHash}?page=${current - 1}'">&laquo; Prev</button>` : '<button class="page-btn" disabled>&laquo; Prev</button>';
    const next = current < totalPages ? `<button class="page-btn" onclick="location.hash='${baseHash}?page=${current + 1}'">Next &raquo;</button>` : '<button class="page-btn" disabled>Next &raquo;</button>';
    return `<div class="pagination">${prev}<span class="page-info">Page ${current} of ${totalPages}</span>${next}</div>`;
}
