// Use Cloudflare DoH (DNS over HTTPS)
const DOH_API = 'https://cloudflare-dns.com/dns-query';

async function checkSubdomain(subdomain) {
    try {
        // Query DNS CNAME and A records
        const cnameRecord = await queryDNS(subdomain, 'CNAME');
        const aRecord = await queryDNS(subdomain, 'A');

        // Clean up the trailing dot from DNS records
        const cnameValue = cnameRecord ? cnameRecord.replace(/\.$/, '') : null;

        if (!cnameValue && !aRecord) {
            return { status: 'safe', type: 'No Record', message: 'Domain does not resolve' };
        }

        if (cnameValue) {
            // Check against our signatures database
            for (const sig of signatures) {
                // If any of the vulnerable CNAMEs are a substring of the target's CNAME
                if (sig.cname.some(provider_cname => cnameValue.includes(provider_cname))) {

                    // We found a match in the CNAME. 
                    // To avoid CORS issues strictly from the browser (since we can't GET random domains easily),
                    // we flag it based on the CNAME signature alone for this client-side tool.
                    return {
                        status: 'vulnerable',
                        type: 'CNAME Match',
                        message: cnameValue,
                        provider: sig.name,
                        signature: sig
                    };
                }
            }
            // Resolves but doesn't match our specific vulnerable providers
            return { status: 'safe', type: 'Resolves (CNAME)', message: cnameValue };
        }

        // Resolves directly to an IP (A record)
        return { status: 'safe', type: 'Resolves (A)', message: aRecord };

    } catch (error) {
        console.error("DNS check failed:", error);
        return { status: 'error', type: 'DNS Error', message: error.message };
    }
}

async function queryDNS(domain, type) {
    try {
        const response = await fetch(`${DOH_API}?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`, {
            headers: {
                'Accept': 'application/dns-json'
            }
        });
        const data = await response.json();

        // Return the first valid answer
        if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
            return data.Answer[0].data;
        }
        return null;
    } catch (e) {
        throw new Error("DoH Request Failed");
    }
}
