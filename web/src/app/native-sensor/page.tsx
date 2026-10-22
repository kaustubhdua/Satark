import Link from 'next/link';
import { ArrowLeft, ArrowRight, FileSearch, Fingerprint, LockKeyhole, Terminal, ShieldAlert } from 'lucide-react';
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
    <main className="min-h-screen bg-zinc-950 text-zinc-100">
      <SiteHeader />
      <div id="main-content" tabIndex={-1} className="mx-auto max-w-6xl px-5 pb-20 pt-10 sm:px-8">
        <Link href="/" className="inline-flex items-center gap-2 text-sm text-zinc-400 transition hover:text-white"><ArrowLeft size={16} /> Back to SATARK</Link>
        <section className="mt-8 overflow-hidden rounded-3xl border border-emerald-400/20 bg-gradient-to-br from-emerald-950/60 via-zinc-900 to-zinc-950 p-6 sm:p-10">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-emerald-300"><Fingerprint size={16} /> SATARK native telemetry</div>
          <h1 className="mt-5 max-w-3xl text-3xl font-semibold tracking-tight sm:text-5xl">Collect your own endpoint signals. Keep the evidence traceable.</h1>
          <p className="mt-5 max-w-2xl text-base leading-7 text-zinc-300">SATARK’s first-party Linux sensor is a standard-library Python collector for local authentication logs and file-integrity snapshots. It is inspired by established SIEM/EDR architecture patterns without requiring Wazuh as a runtime dependency.</p>
          <div className="mt-7 flex flex-wrap gap-3">
            <a href="https://github.com/kaustubhdua/Satark/blob/main/satark_native_sensor.py" className="inline-flex items-center gap-2 rounded-xl bg-emerald-300 px-4 py-3 text-sm font-semibold text-zinc-950 hover:bg-emerald-200">View sensor source <ArrowRight size={16} /></a>
            <a href="https://github.com/kaustubhdua/Satark/blob/main/docs/NATIVE_ENDPOINT_SENSOR.md" className="inline-flex items-center gap-2 rounded-xl border border-white/15 px-4 py-3 text-sm font-semibold text-zinc-100 hover:bg-white/5">Read operator guide</a>
          </div>
          <div className="mt-6 flex flex-wrap gap-2 text-xs text-zinc-300">
            <span className="rounded-full border border-white/10 px-3 py-1.5">No third-party AI key</span>
            <span className="rounded-full border border-white/10 px-3 py-1.5">No network calls</span>
            <span className="rounded-full border border-white/10 px-3 py-1.5">No automatic remediation</span>
          </div>
        </section>

        <section className="mt-12" aria-labelledby="pipeline-title">
          <div className="mb-5 flex items-center gap-3"><span className="rounded-xl bg-emerald-400/10 p-3 text-emerald-300"><FileSearch size={22} /></span><div><h2 id="pipeline-title" className="text-xl font-semibold">How the sensor works</h2><p className="mt-1 text-sm text-zinc-400">A small, auditable collection path with explicit limits.</p></div></div>
          <div className="grid gap-4 sm:grid-cols-2">
            {steps.map((step, index) => <article key={step.title} className="rounded-2xl border border-white/10 bg-zinc-900/70 p-5"><div className="text-xs font-semibold tracking-widest text-emerald-300">STEP 0{index + 1}</div><h3 className="mt-3 font-semibold">{step.title}</h3><p className="mt-2 text-sm leading-6 text-zinc-400">{step.text}</p></article>)}
          </div>
        </section>

        <section className="mt-12" aria-labelledby="commands-title">
          <div className="mb-5 flex items-center gap-3"><span className="rounded-xl bg-sky-400/10 p-3 text-sky-300"><Terminal size={22} /></span><div><h2 id="commands-title" className="text-xl font-semibold">Operator commands</h2><p className="mt-1 text-sm text-zinc-400">Run from a local checkout with Python 3.12 or later.</p></div></div>
          <div className="space-y-3">
            {commands.map(item => <div key={item.label} className="rounded-2xl border border-white/10 bg-black/30 p-4"><div className="mb-2 text-sm font-medium text-zinc-300">{item.label}</div><pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-lg bg-zinc-900 p-3 text-xs leading-6 text-emerald-200"><code>{item.command}</code></pre></div>)}
          </div>
        </section>

        <section className="mt-12 grid gap-4 md:grid-cols-2">
          <article className="rounded-2xl border border-white/10 bg-zinc-900/60 p-5"><div className="flex items-center gap-2 font-semibold"><LockKeyhole size={18} className="text-emerald-300" /> Safety boundaries</div><ul className="mt-3 list-disc space-y-2 pl-5 text-sm leading-6 text-zinc-400"><li>Reads only local paths the operator selects; symlinks and non-regular files are skipped.</li><li>Bounded log, file and scan sizes reduce accidental resource exhaustion.</li><li>Does not execute commands, contact providers, elevate privileges or isolate hosts.</li><li>Use least privilege and protect the journal and manifest.</li></ul></article>
          <article className="rounded-2xl border border-amber-300/20 bg-amber-950/20 p-5"><div className="flex items-center gap-2 font-semibold text-amber-200"><ShieldAlert size={18} /> Important limitations</div><ul className="mt-3 list-disc space-y-2 pl-5 text-sm leading-6 text-zinc-300"><li>This is a pull-based Linux sensor, not a resident daemon or a full EDR.</li><li>A local hash chain can be recomputed by a privileged attacker who rewrites the whole journal; external anchoring is needed for stronger assurance.</li><li>Local unit tests do not prove live host coverage or production readiness.</li><li>Central ingestion and automated response remain separate acceptance gates.</li></ul></article>
        </section>

        <div className="mt-10 flex flex-col gap-3 rounded-2xl border border-white/10 bg-zinc-900/50 p-5 sm:flex-row sm:items-center sm:justify-between"><div><div className="font-semibold">Continue to incident investigation</div><p className="mt-1 text-sm text-zinc-400">Use evidence-backed workflows; treat sensor events as signals that need context.</p></div><Link href="/firstlight" className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl border border-emerald-300/30 px-4 py-3 text-sm font-semibold text-emerald-200 hover:bg-emerald-300/10">Open FIRSTLIGHT <ArrowRight size={16} /></Link></div>
        <p className="mt-6 text-center text-xs text-zinc-600">SATARK-native implementation · Open source · Evidence and provider claims remain independently verifiable</p>
      </div>
    </main>
  );
}
