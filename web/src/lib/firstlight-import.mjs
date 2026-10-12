const MAX_CSV_RECORDS = 10_000;

/** Parse bounded RFC-4180-style CSV for the synthetic FIRSTLIGHT workspace. */
export function parseCsv(text) {
  if (typeof text !== 'string') throw new Error('CSV input must be text.');
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  let closedQuote = false;

  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else { quoted = false; closedQuote = true; }
      } else field += char;
      continue;
    }
    if (closedQuote && char !== ',' && char !== '\r' && char !== '\n') {
      throw new Error('Unexpected character after a quoted CSV field.');
    }
    if (char === '"' && field.length === 0 && !closedQuote) quoted = true;
    else if (char === ',') { row.push(field); field = ''; closedQuote = false; }
    else if (char === '\n' || char === '\r') {
      if (char === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = ''; closedQuote = false;
      if (row.some(cell => cell.trim() !== '')) rows.push(row);
      row = [];
      if (rows.length > MAX_CSV_RECORDS + 1) throw new Error('Import exceeds 10,000 event records.');
    } else {
      if (char === '"') throw new Error('Unexpected quote in an unquoted CSV field.');
      field += char;
    }
  }
  if (quoted) throw new Error('CSV contains an unclosed quoted field.');
  if (field.length || row.length || closedQuote) {
    row.push(field);
    if (row.some(cell => cell.trim() !== '')) rows.push(row);
  }
  if (rows.length < 2) throw new Error('CSV needs a header and at least one event row.');

  const headers = rows[0].map((value, index) =>
    (index === 0 ? value.replace(/^\uFEFF/, '') : value).trim().toLowerCase()
  );
  if (headers.some(header => !header)) throw new Error('CSV headers cannot be empty.');
  if (new Set(headers).size !== headers.length) throw new Error('CSV contains duplicate column headers.');
  if (!headers.some(header => ['id', 'timestamp', 'time', 'source', 'kind', 'summary', 'message', 'description', 'evidence_id'].includes(header))) {
    throw new Error('CSV header must include event fields such as timestamp, source, kind, or summary.');
  }
  const records = rows.slice(1);
  if (records.length > MAX_CSV_RECORDS) throw new Error('Import exceeds 10,000 event records.');
  if (records.some(record => record.length > headers.length)) {
    throw new Error('CSV has rows with more columns than its header.');
  }
  const events = records.map((columns, index) => {
    const record = {};
    headers.forEach((header, columnIndex) => { record[header] = (columns[columnIndex] || '').trim(); });
    return {
      id: record.id || record.evidence_id || 'IMP-' + String(index + 1).padStart(3, '0'),
      timestamp: record.timestamp || record.time || new Date().toISOString(),
      source: record.source || 'Imported source',
      kind: record.kind || 'observation',
      summary: record.summary || record.message || record.description || 'Imported event',
    };
  });
  const ids = new Set();
  for (const event of events) {
    if (ids.has(event.id)) throw new Error('CSV contains duplicate evidence IDs.');
    ids.add(event.id);
  }
  return events;
}
