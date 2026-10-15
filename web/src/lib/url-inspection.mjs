const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'ow.ly', 'cutt.ly', 'rb.gy', 'rebrand.ly', 'tiny.cc']);
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function isPrivateIpv4(host) {
  if (!IPV4.test(host)) return false;
  const octets = host.split('.').map(Number);
  if (octets.some(value => value < 0 || value > 255)) return false;
  return octets[0] === 10 || octets[0] === 127 || octets[0] === 0 ||
    (octets[0] === 169 && octets[1] === 254) ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168);
}

/** Inspect a URL as untrusted text; this helper never performs network requests. */
export function inspectUrl(input) {
  if (typeof input !== 'string' || !input.trim()) return { ok: false, error: 'Enter a URL to inspect.' };
  const raw = input.trim();
  if (raw.length > 4096) return { ok: false, error: 'URL text must be 4,096 characters or fewer.' };

  let candidate = raw;
  if (!/^https?:\/\//i.test(candidate)) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(candidate) && !/^[a-z0-9.-]+:\d{1,5}(?:\/|$)/i.test(candidate)) {
      return { ok: false, error: 'Only HTTP and HTTPS URLs can be inspected. Other schemes are not opened or executed.' };
    }
    candidate = 'https://' + candidate;
  }

  let parsed;
  try { parsed = new URL(candidate); }
  catch { return { ok: false, error: 'That text could not be parsed as a URL. Check the hostname and try again.' }; }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, error: 'Only HTTP and HTTPS URLs can be inspected. Other schemes are not opened or executed.' };
  }
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!hostname || hostname.includes(' ')) return { ok: false, error: 'A valid hostname is required.' };

  const findings = [];
  const add = (severity, title, detail) => findings.push({ severity, title, detail });
  if (parsed.username || parsed.password) add('high', 'Credentials embedded in URL', 'The URL contains a username or password before the hostname. Do not share it; credentials are omitted from this result.');
  if (parsed.protocol !== 'https:') add('medium', 'HTTP without transport encryption', 'The URL uses HTTP. HTTPS alone does not prove a site is trustworthy.');
  if (parsed.port && !((parsed.protocol === 'http:' && parsed.port === '80') || (parsed.protocol === 'https:' && parsed.port === '443'))) {
    add('medium', 'Non-standard port', 'The destination specifies a non-default port. Verify that this is expected for the service.');
  }
  if (SHORTENERS.has(hostname)) add('low', 'URL-shortening service', 'The final destination is obscured until the link is resolved in a controlled environment.');
  if (hostname.startsWith('xn--') || hostname.split('.').some(label => label.startsWith('xn--'))) {
    add('medium', 'Internationalized domain label', 'The hostname contains an encoded internationalized label. Check the intended spelling carefully for lookalike characters.');
  }
  const isIp = IPV4.test(hostname) || hostname.includes(':');
  if (isIp) add('low', 'IP-address destination', 'The hostname is an IP address rather than a conventional domain. This is not malicious by itself.');
  if (isPrivateIpv4(hostname) || hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '::1' || hostname === '0:0:0:0:0:0:0:1') {
    add('info', 'Local or private-network address', 'This appears to target a local/private address. SATARK does not connect to it.');
  }
  const labels = hostname.split('.').filter(Boolean);
  if (labels.length >= 5) add('low', 'Deeply nested hostname', 'The hostname has many subdomain labels. Confirm the registered domain rather than trusting a familiar-looking subdomain.');
  if (hostname.endsWith('.')) add('low', 'Trailing dot in hostname', 'The hostname has a trailing dot; normalize it before comparing it with an allowlist.');
  if (parsed.pathname.length > 160 || parsed.search.length > 240) add('info', 'Long URL components', 'The path or query is unusually long. This is a review cue, not proof of maliciousness.');
  if (/%(?:0[0-9a-f]|1[0-9a-f]|7f)/i.test(parsed.pathname + parsed.search)) add('low', 'Encoded control characters', 'The URL contains percent-encoded control characters that may complicate inspection or logging.');

  return {
    ok: true,
    normalized: parsed.protocol + '//' + parsed.host + parsed.pathname,
    hostname: parsed.hostname,
    protocol: parsed.protocol.slice(0, -1).toUpperCase(),
    path: parsed.pathname || '/',
    queryParameterNames: [...new Set([...parsed.searchParams.keys()])].slice(0, 30),
    hasFragment: Boolean(parsed.hash),
    findings,
    summary: findings.length
      ? findings.length + ' review cue(s) found. These are heuristics, not a reputation check or a safety verdict.'
      : 'No configured URL-format cues were found. This is not a safety verdict.',
    notice: 'Local-only inspection. SATARK did not visit this URL, resolve DNS, follow redirects, or query threat-intelligence services. Query values and embedded credentials are not included in the result.',
  };
}
