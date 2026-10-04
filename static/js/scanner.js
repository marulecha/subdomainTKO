// DNS-over-HTTPS resolvers. Both return the same JSON format and allow CORS,
// so the scanner works from any static host (GitHub Pages, file://, etc.).
const RESOLVERS = {
    cloudflare: { label: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
    google: { label: 'Google', url: 'https://dns.google/resolve' }
};

const RCODES = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };
const QUERY_TIMEOUT_MS = 8000;
const MAX_ATTEMPTS = 3;

// Turn pasted text into a deduplicated list of hostnames.
// Accepts URLs, wildcards, ports, trailing dots and comma or space separated lists.
function parseTargets(text) {
    const seen = new Set();
    const targets = [];
    const invalid = [];
    let duplicates = 0;

    for (const rawLine of text.split('\n')) {
        const line = rawLine.replace(/#.*$/, '').trim();
        if (!line) continue;

        for (const token of line.split(/[\s,;]+/)) {
            if (!token) continue;
            const host = normalizeHost(token);
            if (!host) {
                invalid.push(token);
            } else if (seen.has(host)) {
                duplicates++;
            } else {
                seen.add(host);
                targets.push(host);
            }
        }
    }

    return { targets, invalid, duplicates };
}

// Reduce a URL, wildcard or host:port to a bare lowercase hostname. Returns null if invalid.
function normalizeHost(token) {
    let host = token.trim().toLowerCase();
    host = host.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');  // scheme
    host = host.replace(/^[^@/]*@/, '');                  // credentials
    host = host.split(/[/?#]/)[0];                        // path, query, fragment
    host = host.replace(/:\d+$/, '');                     // port
    host = host.replace(/^\*\./, '');                     // wildcard
    host = host.replace(/\.+$/, '');                      // trailing dot

    if (host.length > 253 || !host.includes('.')) return null;
    const label = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;
    return host.split('.').every(part => label.test(part)) ? host : null;
}

function stripDot(name) {
    return String(name).toLowerCase().replace(/\.$/, '');
}

function matchesSuffix(host, pattern) {
    if (pattern instanceof RegExp) return pattern.test(host);
    return host === pattern || host.endsWith('.' + pattern);
}

function findSignature(hosts) {
    for (const host of hosts) {
        const sig = signatures.find(s => s.match.some(p => matchesSuffix(host, p)));
        if (sig) return { sig, host };
    }
    return null;
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// One DoH JSON query with a timeout and retries on network errors, 429 and 5xx.
async function dohQuery(name, type, resolverKey, signal) {
    const resolver = RESOLVERS[resolverKey] || RESOLVERS.cloudflare;
    const url = `${resolver.url}?name=${encodeURIComponent(name)}&type=${type}`;
    let lastError;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        if (signal?.aborted) throw new DOMException('Scan stopped', 'AbortError');

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), QUERY_TIMEOUT_MS);
        const onAbort = () => controller.abort();
        signal?.addEventListener('abort', onAbort);

        try {
            const res = await fetch(url, {
                headers: { accept: 'application/dns-json' },
                signal: controller.signal
            });
            if (res.ok) return await res.json();
            lastError = new Error(`Resolver returned HTTP ${res.status}`);
            if (res.status !== 429 && res.status < 500) break;
        } catch (err) {
            if (signal?.aborted) throw new DOMException('Scan stopped', 'AbortError');
            lastError = err.name === 'AbortError' ? new Error('Resolver timed out') : new Error('Network error reaching resolver');
        } finally {
            clearTimeout(timer);
            signal?.removeEventListener('abort', onAbort);
        }

        await sleep(400 * 2 ** (attempt - 1));
    }

    throw lastError;
}

// Resolve a subdomain and classify it.
// status: 'vulnerable' | 'review' | 'safe' | 'none' | 'error'
async function checkSubdomain(domain, { resolver = 'cloudflare', signal } = {}) {
    const started = performance.now();
    const base = { domain, chain: [], addresses: [], rcode: null, signature: null, matchedHost: null };

    let data;
    try {
        data = await dohQuery(domain, 'A', resolver, signal);
    } catch (err) {
        if (err.name === 'AbortError') throw err;
        return { ...base, status: 'error', message: err.message, ms: performance.now() - started };
    }

    const answers = data.Answer || [];
    const chain = answers.filter(r => r.type === 5).map(r => stripDot(r.data));
    const addresses = answers.filter(r => r.type === 1).map(r => r.data);
    const rcode = RCODES[data.Status] || `RCODE ${data.Status}`;
    const dangling = chain.length > 0 && data.Status === 3;
    const match = findSignature(chain);
    const result = {
        ...base,
        chain,
        addresses,
        rcode,
        dangling,
        signature: match?.sig || null,
        matchedHost: match?.host || null,
        ms: performance.now() - started
    };

    if (data.Status === 2 || data.Status === 5) {
        return { ...result, status: 'error', message: `${rcode}. The authoritative nameservers did not answer. Check for a stale NS delegation.` };
    }

    if (chain.length === 0 && data.Status === 3) {
        return { ...result, status: 'none', message: 'No DNS record exists for this name.' };
    }

    if (match) {
        const { sig } = match;
        if (dangling) {
            return {
                ...result,
                status: sig.status === 'vulnerable' ? 'vulnerable' : 'review',
                message: `CNAME target ${chain[chain.length - 1]} does not resolve on ${sig.name}.`
            };
        }
        if (sig.nxdomainOnly) {
            return { ...result, status: 'safe', message: `Points to ${sig.name} and the resource exists.` };
        }
        if (sig.fingerprint) {
            return { ...result, status: 'review', message: `Points to ${sig.name}. Open the host and look for the unclaimed-resource message.` };
        }
        return { ...result, status: 'safe', message: `Points to ${sig.name}.` };
    }

    if (dangling) {
        return { ...result, status: 'review', message: `Dangling CNAME. ${chain[chain.length - 1]} does not resolve. Check whether its domain can be registered.` };
    }

    if (chain.length === 0 && addresses.length === 0) {
        return { ...result, status: 'safe', message: 'Name exists but has no A record.' };
    }

    return { ...result, status: 'safe', message: chain.length ? 'CNAME chain resolves to a live host.' : 'Resolves directly to an A record.' };
}
