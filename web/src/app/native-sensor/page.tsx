import SiteHeader from '../site-header';

const steps = [
  { title: 'Collect local authentication signals', text: 'Read a bounded portion of an operator-selected Linux auth log. The sensor classifies failed and successful logins, privilege use and session changes.' },
  { title: 'Watch important files', text: 'Create a bounded file manifest for paths you explicitly select. Later scans identify additions, modifications and missing files.' },
  { title: 'Preserve traceable observations', text: 'Each event records its source, SHA-256 digest and stable identifier. A local JSONL hash chain detects ordinary journal edits.' },
  { title: 'Verify before investigating', text: 'Check the journal chain and use the records as evidence for a human-led investigation. These observations are signals, not a verdict.' },
];

const commands = [
  { label: 'Collect authentication events', command: 'python satark_native_sensor.py auth-log --path /var/log/auth.log --journal ./state/native-events.jsonl' },
  { label: 'Scan explicitly selected paths', command: 'python satark_native_sensor.py file-scan --paths /etc/ssh /etc/sudoers.d --state ./state/file-manifest.json --journal ./state/native-events.jsonl' },
  { label: 'Verify the journal', command: 'python satark_native_sensor.py verify-journal --journal ./state/native-events.jsonl' },
  { label: 'Run the sensor tests', command: 'python -m unittest -v tests.test_satark_native_sensor' },
];

export default function NativeSensorPage() {
  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <div className="eyebrow">Endpoint sensor</div>
        <h1>Collect your own endpoint signals. Keep the evidence traceable.</h1>
        <p className="lead">SATARK’s first-party Linux sensor is a standard-library Python collector for local authentication logs and file-integrity snapshots. It runs on your machine, needs no Wazuh, and has no network access, AI key or automatic remediation.</p>
        <div className="actions">
          <a className="btn btn-primary" href="https://github.com/kaustubhdua/Satark/blob/main/satark_native_sensor.py">View sensor source <span aria-hidden="true">↗</span></a>
          <a className="btn btn-secondary" href="https://github.com/kaustubhdua/Satark/blob/main/docs/NATIVE_ENDPOINT_SENSOR.md">Read operator guide <span aria-hidden="true">↗</span></a>
        </div>

        <section className="panel" aria-labelledby="pipeline-title">
          <h2 id="pipeline-title">How the sensor works</h2>
          <p>A small, auditable collection path with explicit limits.</p>
          <ol className="sensor-steps">
            {steps.map((step) => <li key={step.title}><h3>{step.title}</h3><p>{step.text}</p></li>)}
          </ol>
        </section>

        <section className="panel" aria-labelledby="commands-title">
          <h2 id="commands-title">Operator commands</h2>
          <p>Run from a local checkout with Python 3.12 or later.</p>
          <div className="sensor-commands">
            {commands.map(item => <div key={item.label}><h3>{item.label}</h3><pre><code>{item.command}</code></pre></div>)}
          </div>
        </section>

        <div className="workspace-grid">
          <section className="workspace-card" aria-labelledby="safety-title">
            <h2 id="safety-title">Safety boundaries</h2>
            <ul><li>Reads only local paths the operator selects; symlinks and non-regular files are skipped.</li><li>Bounded log, file and scan sizes reduce accidental resource exhaustion.</li><li>Does not execute commands, contact providers, elevate privileges or isolate hosts.</li><li>Use least privilege and protect the journal and manifest.</li></ul>
          </section>
          <section className="workspace-card" aria-labelledby="limits-title">
            <h2 id="limits-title">Limitations</h2>
            <ul><li>This is a pull-based Linux sensor, not a resident daemon or a full EDR.</li><li>A local hash chain can be recomputed by a privileged attacker who rewrites the whole journal; external anchoring is needed for stronger assurance.</li><li>Local unit tests do not prove live host coverage or production readiness.</li><li>Central ingestion and automated response remain separate acceptance gates.</li></ul>
          </section>
        </div>

        <section className="panel" aria-labelledby="next-title">
          <h2 id="next-title">Next: investigate what it found</h2>
          <p>Import the journal as evidence in FIRSTLIGHT. Treat sensor events as signals that need context, not as a verdict.</p>
          <a className="btn btn-secondary" href="/firstlight">Open FIRSTLIGHT <span aria-hidden="true">→</span></a>
        </section>
      </div>
    </main>
  );
}
