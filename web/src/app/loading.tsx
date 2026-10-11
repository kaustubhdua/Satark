export default function Loading() {
  return (
    <main className="loading-screen loading-screen-v2" role="status" aria-live="polite" aria-label="Loading SATARK workspace">
      <div className="loading-grid" aria-hidden="true" />
      <div className="loading-orbit loading-orbit-one" aria-hidden="true" />
      <div className="loading-orbit loading-orbit-two" aria-hidden="true" />
      <section className="loading-console">
        <div className="loading-console-top"><span><i className="loader-live-dot" /> SECURE SESSION</span><span className="loading-top-right">SATARK / FIRSTLIGHT</span></div>
        <div className="loader-mark loader-mark-v2" aria-hidden="true"><span>S</span><i /></div>
        <div className="loader-eyebrow">SATARK SENTINEL <span aria-hidden="true">/</span> INCIDENT RESPONSE</div>
        <h1>Bringing the signal<br /><em>into focus.</em></h1>
        <p>Preparing your investigation workspace, evidence tools, and review controls.</p>
        <div className="loader-progress-meta"><span>INITIALIZING WORKSPACE</span><span className="loader-status-word">PLEASE WAIT</span></div>
        <div className="loader-track loader-track-v2" aria-hidden="true"><span /></div>
        <div className="loader-stages" aria-hidden="true"><span><i /> Interface</span><span><i /> Evidence</span><span><i /> Review tools</span></div>
        <div className="loader-foot">EVIDENCE FIRST <span aria-hidden="true">·</span> HUMAN REVIEW ALWAYS</div>
      </section>
    </main>
  );
}
