'use client';

import SiteHeader from './site-header';
import { Radar, SplitFlapText } from '../components/react-bits';
import ServiceReadiness from '../components/service-readiness';

const tools = [
  ['01', 'Text & message triage', 'Spot pressure tactics, impersonation cues and risky requests.', '/investigate', 'OPEN ANALYSIS'],
  ['02', 'URL review', 'Review a URL as text without automatically visiting it.', '/investigate', 'OPEN ANALYSIS'],
  ['03', 'Image metadata & integrity', 'Inspect supported metadata markers and calculate a SHA-256 fingerprint locally. Not a deepfake verdict.', '/image-review', 'OPEN IMAGE REVIEW'],
  ['04', 'QR-code investigation', 'QR payload analysis is not yet ported to this web workspace.', '', 'NOT YET PORTED'],
  ['05', 'PDF & document review', 'A sandboxed local document pipeline is not yet available here.', '', 'NOT YET PORTED'],
  ['06', 'Video & media signals', 'Video processing and provenance checks are not yet migrated.', '', 'NOT YET PORTED'],
  ['07', 'Persistent history & exports', 'Review reports here; durable case history requires a configured workspace database.', '/reports', 'OPEN REPORTS'],
  ['08', 'Academy & scam challenge', 'Practice recognizing social-engineering patterns with educational examples.', '/learn', 'OPEN LEARNING'],
];

export default function Home() {
  return (
    <main className="shell home-overview">
      <SiteHeader status />
      <div className="container" id="main-content" tabIndex={-1}>
        <ServiceReadiness />
        <section className="hero home-hero">
          <div>
            <div className="eyebrow">✳ DIGITAL THREAT INVESTIGATION</div>
            <h1>Pause the panic.<br /><span>Find the signal.</span></h1>
            <div className="hero-signal" aria-label="Security workspace principles">
              <SplitFlapText words={['EVIDENCE FIRST', 'VERIFY THEN ACT', 'HUMAN REVIEW']} fontSize={24} padTo={15} tileColor="#111827" textColor="#c9f36b" gap={3} cycleDelay={3600} />
            </div>
            <p className="lead">A focused workspace for investigating suspicious digital content. Start with one task, follow the evidence, and keep uncertainty visible.</p>
            <div className="actions">
              <a className="btn btn-primary" href="/investigate">Start an investigation <span aria-hidden="true">↗</span></a>
              <a className="btn btn-secondary" href="/firstlight">Open FIRSTLIGHT <span aria-hidden="true">→</span></a>
            </div>
            <p className="home-privacy-note">Local deterministic checks by default · No third-party AI key is required · Human review always</p>
          </div>
          <div className="signal-card home-signal-card">
            <div className="radar-preview"><Radar color="#c9f36b" mode="sweep" speed={0.8} trail={0.3} scale={0.86} ringCount={5} spokeCount={12} targets={5} clutter={0.3} mouseInteraction={false} grain={0.01} /></div>
            <div className="card-head"><span>WORKSPACE PREVIEW</span><span className="pill">ILLUSTRATIVE</span></div>
            <div className="score-row"><div className="score">3</div><div className="score-meta"><strong>Evidence review stages</strong><span>Illustration only · not live telemetry</span></div></div>
            <div className="evidence-list">
              {[
                ['↗', 'Collect context', 'Record the source and time'],
                ['⌁', 'Review evidence', 'Separate facts from hypotheses'],
                ['◷', 'Choose next steps', 'Verify before taking action']
              ].map(item => <div className="evidence" key={item[1]}><div className="evidence-icon" aria-hidden="true">{item[0]}</div><div className="evidence-copy"><strong>{item[1]}</strong><small>{item[2]}</small></div><span className="check">GUIDE</span></div>)}
            </div>
          </div>
        </section>

        <section className="home-workspaces" aria-labelledby="workspace-heading">
          <div className="section-title">
            <div><div className="eyebrow">CHOOSE A WORKFLOW</div><h2 id="workspace-heading">Your next step, clearly laid out.</h2></div>
            <p>Each destination has a distinct purpose. Advanced capabilities stay out of your way until you need them.</p>
          </div>
          <div className="workspace-grid home-workspace-grid">
            <article className="workspace-card"><div className="workspace-icon" aria-hidden="true">⌕</div><h3>Investigate content</h3><p>Analyze a suspicious URL or message with deterministic local rules and optional self-hosted AI.</p><a className="text-link" href="/investigate">Open investigation <span aria-hidden="true">→</span></a></article>
            <article className="workspace-card"><div className="workspace-icon" aria-hidden="true">✳</div><h3>FIRSTLIGHT case lab</h3><p>Walk through an incident, evidence ledger, timeline, findings and response decisions.</p><a className="text-link" href="/firstlight">Open FIRSTLIGHT <span aria-hidden="true">→</span></a></article>
            <article className="workspace-card"><div className="workspace-icon" aria-hidden="true">◎</div><h3>Image review</h3><p>Inspect supported image metadata markers and a local file fingerprint. No authenticity verdicts.</p><a className="text-link" href="/image-review">Review an image <span aria-hidden="true">→</span></a></article>
            <article className="workspace-card"><div className="workspace-icon" aria-hidden="true">▤</div><h3>Reports & learning</h3><p>Review and export analysis notes or practice spotting common social-engineering patterns.</p><div className="actions home-card-actions"><a className="text-link" href="/reports">Open reports →</a><a className="text-link" href="/learn">Practice safely →</a></div></article>
          </div>
        </section>

        <section className="tools-section home-tools">
          <div className="section-title"><div><div className="eyebrow">CAPABILITY MAP</div><h2>Know what is live—and what is not.</h2></div><p>Unported features are labelled plainly instead of pretending to work.</p></div>
          <details className="tools-disclosure">
            <summary><span><strong>Browse all eight capabilities</strong><small>Available tools, current boundaries and migration status</small></span><span className="disclosure-icon" aria-hidden="true">＋</span></summary>
            <div className="tool-grid">
              {tools.map(([number, title, description, href, action]) => <article className="tool-card" key={number}>
                <div className="tool-card-top"><span>{number}</span><span className="tool-arrow" aria-hidden="true">↗</span></div>
                <h3>{title}</h3><p>{description}</p>
                {href ? <a className="text-link" href={href}>{action} →</a> : <span className="text-link" aria-disabled="true">{action}</span>}
              </article>)}
            </div>
            <div className="tool-boundary"><span aria-hidden="true">i</span><p><strong>Important boundary:</strong> a missing indicator is not proof that content is safe. The app does not visit submitted URLs or execute uploaded files. Image metadata hints cannot prove authenticity. Persistent cases and evidence require a configured database and verified tenant access.</p></div>
          </details>
        </section>
      </div>
      <footer className="footer"><span>SATARK · Evidence-led digital security</span><span>Local-first triage · Human review required</span></footer>
    </main>
  );
}
