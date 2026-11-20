import SiteHeader from '../site-header';

const capabilities = [
  { id: 'text', number: '01', title: 'Text & message triage', status: 'Available · production needs a shared rate limiter', detail: 'The Next.js API runs deterministic local checks and can optionally use a self-hosted Ollama model. Production deployments fail closed until shared rate limiting is configured.', href: '/investigate', action: 'Open investigation' },
  { id: 'url', number: '02', title: 'URL inspection', status: 'Available · local format review, destination never fetched', detail: 'Review URL structure in the browser: hostname, scheme, path, query keys and format-based cues. The destination is not visited, so reputation and page content are not assessed.', href: '/url', action: 'Open URL inspector' },
  { id: 'image', number: '03', title: 'Image metadata & integrity', status: 'Available · local inspection', detail: 'Inspect supported metadata and calculate a local SHA-256 fingerprint. This is not a deepfake verdict or a visual threat scan.', href: '/image-review', action: 'Open image review' },
  { id: 'qr', number: '04', title: 'QR-code investigation', status: 'Available · cross-browser local decoding; destination checks limited', detail: 'Decode QR payloads locally with the browser BarcodeDetector and bundled jsQR fallback. HTTP/HTTPS destination text can be submitted to SATARK analysis when you choose; the destination is never fetched or opened automatically.', href: '/qr', action: 'Open QR decoder' },
  { id: 'pdf', number: '05', title: 'PDF & text document review', status: 'Available · bounded local extraction and heuristics', detail: 'Extract selectable PDF text (up to 50 pages/15 MiB) and TXT, Markdown, CSV or LOG text (up to 2 MiB), fingerprint the source and review transparent local patterns. OCR for scanned PDFs, encrypted PDFs and Office files are not supported.', href: '/pdf-review', action: 'Open document review' },
  { id: 'video', number: '06', title: 'Video frame sampling', status: 'Available · browser-local sampling', detail: 'Read MP4/WebM metadata and sample up to six representative frames from clips up to 50 MiB/120 seconds. The workflow does not analyze audio, detect all edits or certify authenticity.', href: '/media-review', action: 'Open media review' },
  { id: 'intel', number: '07', title: 'Threat intelligence', status: 'Partial · local IOC cache requires approved feed data', detail: 'No match must never mean safe. A useful result needs source provenance, version, freshness and distinct unavailable/no-match/match states.', href: '/investigate', action: 'View analysis' },
  { id: 'firstlight', number: '08', title: 'FIRSTLIGHT incident command', status: 'Training available · persistence needs end-to-end verification', detail: 'Review synthetic evidence, findings, event timelines and simulated response decisions. Simulation controls do not execute real containment actions.', href: '/firstlight', action: 'Open FIRSTLIGHT' },
  { id: 'cases', number: '09', title: 'Persistent case workspace', status: 'Implemented · requires the self-hosted SATARK API and database', detail: 'Create cases, filter and search within the selected tenant, update status/severity, and open a saved case in FIRSTLIGHT. End-to-end persistence remains subject to verified schema, tenant isolation, and production configuration.', href: '/cases', action: 'Open case workspace' },
  { id: 'reports', number: '10', title: 'Reports & saved cases', status: 'Partial · authenticated journey requires acceptance tests', detail: 'Local TXT/JSON export and persistent-report code exist. Full PDF export and end-to-end case reconciliation are not yet established.', href: '/reports', action: 'Open reports' },
  { id: 'learn', number: '11', title: 'Security learning', status: 'Available · educational only', detail: 'Academy lessons, a 100-level Scam Challenge of practice scenarios, and a Classroom session summary that stores counts only. Educational only; scenarios are practice material, not real incidents.', href: '/learn', action: 'Open learning' },
];

export default function ToolsPage() {
  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <div className="eyebrow">Capability directory</div>
        <h1>Every tool, with its real status.</h1>
        <p className="lead">Each entry states what you can open today, what runs locally in your browser, and what depends on a configured backend. Statuses describe implementation, not independent verification of every deployment.</p>
        <div className="workspace-grid capability-grid">
          {capabilities.map((item) => (
            <article className="workspace-card" id={item.id} key={item.id}>
              <h2>{item.title}</h2>
              <p className="status-line"><strong>{item.status}</strong></p>
              <p>{item.detail}</p>
              <a className="btn btn-secondary" href={item.href}>{item.action} <span aria-hidden="true">↗</span></a>
            </article>
          ))}
        </div>
        <section className="panel" aria-labelledby="migration-heading">
          <div className="eyebrow">Engineering reference</div>
          <h2 id="migration-heading">Security-tool parity matrix</h2>
          <p>The feature-by-feature matrix lists implementation boundaries, required security controls, dependencies and acceptance tests for each workflow.</p>
          <a className="btn btn-primary" href="https://github.com/kaustubhdua/Satark/blob/main/docs/SECURITY_TOOL_PARITY_MATRIX.md">Read the security-tool parity matrix <span aria-hidden="true">↗</span></a>
        </section>
      </div>
    </main>
  );
}
