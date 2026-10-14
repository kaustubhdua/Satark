import cache from '../data/local-ioc-cache.json' with { type: 'json' };

const MAX_AGE_HOURS_DEFAULT = 72;

function normalizeUrl(value) {
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) return null;
    parsed.username = '';
    parsed.password = '';
    parsed.hash = '';
    parsed.hostname = parsed.hostname.toLowerCase();
    return parsed.origin + parsed.pathname + parsed.search;
  } catch {
    return null;
  }
}

function isFresh(source, now) {
  const lastSync = Date.parse(source?.last_successful_sync || '');
  const maxAgeHours = Number(source?.max_age_hours ?? MAX_AGE_HOURS_DEFAULT);
  if (!Number.isFinite(lastSync) || !Number.isFinite(maxAgeHours) || maxAgeHours <= 0) return false;
  return now - lastSync >= 0 && now - lastSync <= maxAgeHours * 60 * 60 * 1000;
}

/**
 * Read-only, offline IOC lookup. Analysis never fetches feeds or visits indicators.
 * The checked-in manifest is intentionally empty until an operator imports a
 * feed whose license permits the intended use.
 */
export function lookupLocalIocs(input, now = Date.now(), data = cache) {
  if (!data || data.schema_version !== 1 || !Array.isArray(data.sources) || !Array.isArray(data.indicators)) {
    return { status: 'unavailable', matches: [], freshSources: 0, staleSources: 0 };
  }
  if (data.sources.length === 0 || data.indicators.length === 0) {
    return { status: 'not_configured', matches: [], freshSources: 0, staleSources: 0 };
  }

  const sources = new Map(data.sources.map(source => [source.id, source]));
  const freshIds = new Set();
  let staleSources = 0;
  for (const source of data.sources) {
    if (isFresh(source, now)) freshIds.add(source.id);
    else staleSources += 1;
  }
  const freshSources = freshIds.size;
  if (!freshSources) return { status: 'stale', matches: [], freshSources, staleSources };

  const candidates = new Set();
  const urlPattern = /https?:\/\/[^\s<>"']{1,2048}/gi;
  for (const match of input.matchAll(urlPattern)) {
    const raw = match[0].replace(/[.,);!?\]]+$/g, '');
    const normalized = normalizeUrl(raw);
    if (normalized) candidates.add(normalized);
  }

  const matches = [];
  for (const indicator of data.indicators) {
    if (!freshIds.has(indicator.source_id) || typeof indicator.value !== 'string') continue;
    const source = sources.get(indicator.source_id);
    if (!source) continue;
    let matched = false;
    if (indicator.type === 'url') {
      const normalized = normalizeUrl(indicator.value);
      matched = normalized !== null && candidates.has(normalized);
    } else if (indicator.type === 'domain') {
      const domain = indicator.value.toLowerCase().replace(/\.$/, '');
      for (const candidate of candidates) {
        try {
          if (new URL(candidate).hostname.toLowerCase() === domain) matched = true;
        } catch { /* ignored */ }
      }
    }
    if (matched) {
      let hostname = 'matched indicator';
      try { hostname = new URL(indicator.value.includes('://') ? indicator.value : 'https://' + indicator.value).hostname; } catch { /* redacted fallback */ }
      matches.push({
        type: indicator.type,
        evidence: hostname.slice(0, 253),
        source: String(source.name || source.id).slice(0, 120),
        source_id: source.id,
        source_url: String(source.url || '').slice(0, 500),
        source_license: String(source.license || 'unspecified').slice(0, 240),
        source_version: String(source.version || 'unspecified').slice(0, 80),
        last_successful_sync: source.last_successful_sync,
      });
      if (matches.length >= 10) break;
    }
  }

  return {
    status: matches.length ? 'match' : 'no_match',
    matches,
    freshSources,
    staleSources,
  };
}
