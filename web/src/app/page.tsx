'use client';

import SiteHeader from './site-header';
import dynamic from 'next/dynamic';
import { useEffect, useRef, useState } from 'react';

// Defer the health/status module until its below-the-fold section is near view.
const ServiceReadiness = dynamic(() => import('../components/service-readiness'), { ssr: false });
import IntegrityLedger from '../components/ui/integrity-ledger';
import {
  ArrowRight, ArrowUpRight, ScanSearch, ShieldCheck, FileText, BookOpen, LockKeyhole, ScanLine, Eye, ShieldAlert,
  Fingerprint, ListFilter, Radar, Clock3, SearchCheck, Route, UserCheck, Image as ImageIcon, Film, FolderKanban, ChevronRight, Terminal,
} from 'lucide-react';

// The order reflects the shared FIRSTLIGHT engine's deterministic investigation stages.
const stages = [
  { icon: Fingerprint, name: 'Evidence integrity', text: 'Checks every SHA-256 seal' },
  { icon: ListFilter, name: 'Evidence triage', text: 'Sorts what to look at first' },
  { icon: Radar, name: 'Detection & correlation', text: 'Links signals to evidence' },
  { icon: Clock3, name: 'Timeline', text: 'Rebuilds the order of events' },
  { icon: SearchCheck, name: 'Verification & gaps', text: 'Says what is still unknown' },
  { icon: Route, name: 'Response planning', text: 'Proposes next actions' },
];

const bento = [
  { icon: ScanSearch, title: 'Investigate a message or link', text: 'Paste a suspicious message or URL. See the signals behind the score, without SATARK opening the link.', href: '/investigate', cta: 'Start investigating', cls: 'span-3 wide-m', dots: true },
  { icon: ShieldCheck, title: 'FIRSTLIGHT incident command', text: 'Reconstruct an account-compromise case from sealed evidence, then review each proposed response before it is recorded.', href: '/firstlight', cta: 'Open FIRSTLIGHT', cls: 'span-3 wide-m', dots: true },
  { icon: ScanLine, title: 'Decode a QR code', text: 'Read the destination as text before your phone opens it.', href: '/qr', cta: 'Decode a QR code', cls: 'span-2' },
  { icon: FileText, title: 'Review a document', text: 'Extract PDF or text locally and flag pressure and payment cues.', href: '/pdf-review', cta: 'Review a document', cls: 'span-2' },
  { icon: ImageIcon, title: 'Inspect an image', text: 'Read metadata markers and fingerprint the file in your browser.', href: '/image-review', cta: 'Inspect an image', cls: 'span-2' },
  { icon: Film, title: 'Sample video frames', text: 'Pull six representative frames from a clip for a closer look. No deepfake verdicts.', href: '/media-review', cta: 'Sample a video', cls: 'span-3 wide-m' },
  { icon: FolderKanban, title: 'Cases and reports', text: 'Keep investigations, evidence and report snapshots in your team workspace once it is connected.', href: '/cases', cta: 'Open cases', cls: 'span-3 wide-m' },
  { icon: Terminal, title: 'Native endpoint sensor', text: 'Collect bounded Linux authentication signals and file-integrity changes with SATARK-authored tooling.', href: '/native-sensor', cta: 'Explore native sensor', cls: 'span-3 wide-m' },
];

const tools: Array<[string, string, string, string]> = [
  ['Text & message triage', 'Spot pressure tactics, impersonation cues and risky requests.', '/investigate', 'Open analysis'],
  ['URL review', 'Review a URL as text without automatically visiting it.', '/url', 'Open URL inspector'],
  ['Image metadata & integrity', 'Inspect supported metadata markers and calculate a SHA-256 fingerprint locally. Not an authenticity verdict.', '/image-review', 'Open image review'],
  ['QR-code investigation', 'Decode QR payloads locally with the native browser API and bundled fallback decoder. Destinations are never fetched automatically.', '/qr', 'Open QR decoder'],
  ['PDF & text document review', 'Extract supported PDF and plain-text content locally, calculate a source fingerprint and inspect explainable text cues.', '/pdf-review', 'Open document review'],
  ['Video frame sampling', 'Inspect MP4/WebM metadata and sample up to six frames within bounded size/duration limits. No deepfake verdict.', '/media-review', 'Open media review'],
  ['Threat-intelligence status', 'The local indicator cache needs an approved, provenance-tracked feed. No match does not mean safe.', '/tools#intel', 'View status'],
  ['Persistent case workspace', 'Create and track tenant-scoped investigation cases when the workspace backend is configured.', '/cases', 'Open cases'],
  ['Reports & saved exports', 'Review local TXT/JSON exports and persistent report snapshots where the workspace database is configured.', '/reports', 'Open reports'],
  ['Native Linux endpoint sensor', 'Review the first-party local auth-log and file-integrity collector, operator commands and evidence limitations.', '/native-sensor', 'Explore sensor'],
  ['Academy & scam challenge', 'Practice recognizing social-engineering patterns with educational examples.', '/learn', 'Open learning'],
];

const principles = [
  { icon: Eye, title: 'Uncertainty stays visible', text: 'Signals are triage guidance, not a verdict.' },
  { icon: LockKeyhole, title: 'Privacy-aware by default', text: 'Submitted URLs are not automatically visited.' },
  { icon: UserCheck, title: 'Human control over response decisions', text: 'Review and approval workflows are available; this deployment does not claim live containment.' },
];

export default function Home() {
  const readinessRef = useRef<HTMLDivElement | null>(null);
  const [readinessVisible, setReadinessVisible] = useState(false);

  useEffect(() => {
    const target = readinessRef.current;
    if (!target) return;
    if (!('IntersectionObserver' in window)) {
      setReadinessVisible(true);
      return;
    }
    const observer = new IntersectionObserver(entries => {
      if (entries.some(entry => entry.isIntersecting)) {
        setReadinessVisible(true);
        observer.disconnect();
      }
    }, { rootMargin: '240px 0px' });
    observer.observe(target);
    return () => observer.disconnect();
  }, []);

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container" id="main-content" tabIndex={-1}>
        <section className="sentinel-hero" aria-labelledby="hero-title">
          <div className="dot-pattern" aria-hidden="true" />
          <div className="sentinel-hero-copy">
            <a className="shiny-pill sentinel-kicker" href="/firstlight"><b>New</b><span className="shiny-text">FIRSTLIGHT evidence-led investigation</span><ChevronRight size={14} aria-hidden="true" /></a>
            <h1 id="hero-title">Every second matters. Every piece of evidence counts.</h1>
            <p className="sentinel-lede">Check suspicious messages, links and files with signals you can read. When it is more than a phishing email, FIRSTLIGHT helps reconstruct an incident from evidence. Live containment is not enabled by default.</p>
            <div className="sentinel-hero-actions">
              <a className="sentinel-primary" href="/investigate"><ScanSearch size={16} aria-hidden="true" /> Start an investigation</a>
              <a className="sentinel-secondary" href="/firstlight">Open FIRSTLIGHT</a>
            </div>
            <div className="sentinel-trust-line">
              <span><LockKeyhole size={14} aria-hidden="true" /> Links are never opened for you</span>
              <span><UserCheck size={14} aria-hidden="true" /> Human control over response decisions</span>
            </div>
            <p className="field-note sentinel-privacy-note">Local deterministic checks by default. No third-party AI key is required. Optional self-hosted Ollama analysis is only used when configured.</p>
          </div>
          <IntegrityLedger />
        </section>

        <section className="home-section" aria-labelledby="pipeline-title">
          <div className="sentinel-section-heading">
            <div><div className="sentinel-overline">How FIRSTLIGHT works</div><h2 id="pipeline-title">Six investigation stages, one decision for you.</h2></div>
            <p>Each stage has a defined purpose and hands structured results to the next. Findings remain tied to evidence; this is a staged deterministic workflow, not six independent AI agents.</p>
          </div>
          <div className="pipeline-card">
            <div className="dot-pattern" aria-hidden="true" />
            <ol className="pipeline" aria-label="FIRSTLIGHT investigation stages">
              {stages.map(({ icon: Icon, name, text }) => (
                <li className="pipeline-node" key={name}>
                  <span className="pipeline-icon"><Icon size={20} strokeWidth={1.7} aria-hidden="true" /></span>
                  <strong>{name}</strong><small>{text}</small>
                </li>
              ))}
              <li className="pipeline-node is-human">
                <span className="pipeline-icon"><UserCheck size={20} strokeWidth={1.7} aria-hidden="true" /></span>
                <strong>You approve</strong><small>Nothing runs on its own</small>
              </li>
            </ol>
            <p className="pipeline-caption">Records that change after they are sealed are quarantined before any finding is drawn, and response actions stay simulations until you approve them.</p>
          </div>
        </section>

        <section className="sentinel-workflows" aria-labelledby="workflow-title">
          <div className="sentinel-section-heading">
            <div><div className="sentinel-overline">Your workspace</div><h2 id="workflow-title">Choose the right starting point.</h2></div>
            <p>Each tool explains what it can check, what it cannot prove, and what to verify next.</p>
          </div>
          <div className="bento">
            {bento.map(({ icon: Icon, title, text, href, cta, cls, dots }) => (
              <a className={'bento-card ' + cls} href={href} key={title}>
                {dots && <div className="dot-pattern" aria-hidden="true" />}
                <span className="bento-icon"><Icon size={18} strokeWidth={1.7} aria-hidden="true" /></span>
                <h3>{title}</h3>
                <p>{text}</p>
                <span className="bento-cta">{cta} <ArrowRight size={14} aria-hidden="true" /></span>
              </a>
            ))}
          </div>
        </section>

        <section className="home-tools" aria-labelledby="capability-title">
          <div className="sentinel-section-heading">
            <div><div className="sentinel-overline">Capability map</div><h2 id="capability-title">Know what is available, and what is not.</h2></div>
            <p>A missing signal never proves content is safe. Each tool states its limits.</p>
          </div>
          <details className="tools-disclosure">
            <summary><span><strong>Browse the full capability map</strong><small>Every tool, its current status and its boundaries</small></span><span className="disclosure-icon" aria-hidden="true">＋</span></summary>
            <div className="tool-grid">
              {tools.map(([title, description, href, action]) => <article className="tool-card" key={title}>
                <h3>{title}</h3><p>{description}</p><a className="text-link" href={href}>{action}</a>
              </article>)}
            </div>
            <div className="tool-boundary"><span aria-hidden="true">i</span><p><strong>Important boundary:</strong> SATARK does not visit submitted URLs or execute uploaded files. Image metadata cannot prove authenticity. Persistent cases and evidence require a configured database and verified tenant access.</p></div>
          </details>
        </section>

        <section className="sentinel-method" aria-labelledby="method-title">
          <div className="method-intro"><div className="sentinel-overline">The SATARK standard</div><h2 id="method-title">Confidence comes from verification.</h2><p>Security tools should help you think clearly, not make decisions for you.</p><a href="/tools" className="method-link">Explore all capabilities <ArrowUpRight size={15} aria-hidden="true" /></a></div>
          <div className="method-principles">
            {principles.map(({ icon: Icon, title, text }) => <article key={title} className="principle-row"><span className="principle-icon"><Icon size={18} aria-hidden="true" /></span><div><h3>{title}</h3><p>{text}</p></div></article>)}
          </div>
        </section>

        <section className="sentinel-boundary" aria-label="Capability status">
          <div className="boundary-icon"><ShieldAlert size={18} aria-hidden="true" /></div>
          <div><strong>Built for careful triage, not false certainty.</strong><p>OCR for scanned PDFs, audio analysis and deepfake detection are not supported. QR destinations and submitted URLs are never visited automatically, and persistent case history depends on a configured workspace database. A missing signal never proves that content is safe.</p></div>
          <a href="/tools">Capability status <ArrowUpRight size={15} aria-hidden="true" /></a>
        </section>

        <div ref={readinessRef} style={{ marginTop: 24, minHeight: 76 }}>
          {readinessVisible
            ? <ServiceReadiness />
            : <div className="readiness-banner readiness-lazy-placeholder" role="status" aria-live="polite"><span className="readiness-dot" aria-hidden="true" /><div className="readiness-body"><strong>Service status loads on approach</strong><small>The configuration snapshot is deferred until this section is near the viewport.</small></div></div>}
        </div>

        <section className="sentinel-learning-strip">
          <div className="learning-mark"><BookOpen size={20} aria-hidden="true" /></div><div><div className="sentinel-overline">Build your instincts</div><h2>Practice spotting the pressure.</h2><p>Learn the patterns behind urgency, impersonation and social engineering in a safe environment.</p></div><a href="/learn" className="sentinel-secondary">Open the academy</a>
        </section>
      </div>
    </main>
  );
}
