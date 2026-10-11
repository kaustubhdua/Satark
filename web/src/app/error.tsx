'use client';

export default function Error({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return <main className="loading-screen"><div className="loader-mark">S<span>.</span></div><div className="loader-eyebrow">WORKSPACE INTERRUPTION</div><h1>This view needs another try.</h1><p>Your work may not have been saved. Retry this view or return to the workspace.</p><div className="actions"><button className="btn btn-primary" onClick={() => reset()}>Retry view ↻</button><a className="btn btn-secondary" href="/">Back to SATARK →</a></div></main>;
}