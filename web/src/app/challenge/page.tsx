'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import SiteHeader from '../site-header';
import LearnTabs from '../learn-tabs';
import ranksData from '../../data/learning/ranks.json';
import {
  LEVELS, MAX_POINTS, QUESTIONS_PER_LEVEL, STORAGE_KEY, canStartLevel, computePoints, emptyProgress, finishLevel,
  normalizeProgress, rankForLevel, tierForLevel,
} from '../../lib/scam-challenge.mjs';
import type { FinishOutcome, Progress, Rank } from '../../lib/scam-challenge.mjs';
import './challenge.css';

type Question = { id: string; category: string; question: string; options: string[]; answer: number; explanation: string };
type View = 'dashboard' | 'map' | 'play' | 'results';
type Run = { level: number; questions: Question[]; index: number; correct: number; points: number; times: number[]; picked: number | null };

const ranks = ranksData as Rank[];
const fmt = (value: number) => value.toLocaleString('en-US');

async function loadLevel(level: number): Promise<Question[]> {
  const tier = tierForLevel(level);
  const module = await import(`../../data/learning/scam-challenge-tier-${tier}.json`);
  const questions = (module.default as { levels: Record<string, Question[]> }).levels[String(level)];
  if (!questions || questions.length !== QUESTIONS_PER_LEVEL) throw new Error('Level data is unavailable.');
  return questions;
}

export default function ChallengePage() {
  const [progress, setProgress] = useState<Progress>(emptyProgress);
  const [hydrated, setHydrated] = useState(false);
  const [storageOk, setStorageOk] = useState(true);
  const [view, setView] = useState<View>('dashboard');
  const [run, setRun] = useState<Run | null>(null);
  const [outcome, setOutcome] = useState<FinishOutcome | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [elapsed, setElapsed] = useState(0);
  const [confirmReset, setConfirmReset] = useState(false);
  const startedAt = useRef(0);
  const nextRef = useRef<HTMLButtonElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    try {
      setProgress(normalizeProgress(JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? 'null')));
    } catch {
      setStorageOk(false);
    }
    setHydrated(true);
  }, []);

  const persist = useCallback((next: Progress) => {
    setProgress(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      setStorageOk(true);
    } catch {
      setStorageOk(false);
    }
  }, []);

  // Live "points available" meter. Hidden from assistive tech; the real score is announced on answer.
  const answered = run?.picked != null;
  useEffect(() => {
    if (view !== 'play' || !run || answered) return;
    const id = window.setInterval(() => setElapsed((performance.now() - startedAt.current) / 1000), 250);
    return () => window.clearInterval(id);
  }, [view, run, answered]);

  useEffect(() => { if (answered) nextRef.current?.focus(); }, [answered]);
  useEffect(() => { headingRef.current?.focus({ preventScroll: true }); }, [view]);

  const start = useCallback(async (level: number) => {
    if (!canStartLevel(progress, level)) return;
    setLoading(true); setError('');
    try {
      const questions = await loadLevel(level);
      startedAt.current = performance.now();
      setElapsed(0);
      setRun({ level, questions, index: 0, correct: 0, points: 0, times: [], picked: null });
      setView('play');
    } catch {
      setError('Could not load that level. Check your connection and try again.');
    } finally {
      setLoading(false);
    }
  }, [progress]);

  const pick = useCallback((choice: number) => {
    setRun((current) => {
      if (!current || current.picked != null) return current;
      const seconds = (performance.now() - startedAt.current) / 1000;
      const right = choice === current.questions[current.index].answer;
      return {
        ...current, picked: choice, correct: current.correct + (right ? 1 : 0),
        points: current.points + computePoints(right, seconds), times: [...current.times, seconds],
      };
    });
  }, []);

  const advance = useCallback(() => {
    if (!run || run.picked == null) return;
    if (run.index + 1 < run.questions.length) {
      startedAt.current = performance.now();
      setElapsed(0);
      setRun({ ...run, index: run.index + 1, picked: null });
      return;
    }
    const result = finishLevel(progress, ranks, run.level, { correct: run.correct, times: run.times, points: run.points });
    persist(result.progress);
    setOutcome(result);
    setView('results');
  }, [run, progress, persist]);

  // Keyboard: 1-4 answer, Enter/Space continues (buttons keep their native behaviour).
  useEffect(() => {
    if (view !== 'play') return;
    const onKey = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      if (/^[1-4]$/.test(event.key) && run && run.picked == null) pick(Number(event.key) - 1);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [view, run, pick]);

  const rank = rankForLevel(progress.highestUnlocked, ranks);
  const frontier = progress.highestUnlocked;
  const rankDone = Array.from({ length: rank.hi - rank.lo + 1 }, (_, i) => rank.lo + i).filter((level) => progress.completed.includes(level)).length;
  const hasStarted = progress.completed.length > 0;

  const resetProgress = () => {
    persist(emptyProgress());
    setConfirmReset(false); setRun(null); setOutcome(null); setView('dashboard');
  };

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage sc-page" id="main-content" tabIndex={-1}>
        <LearnTabs current="/challenge" />
        {!hydrated ? <p className="lead" role="status">Loading your progress…</p> : (<>
          {view === 'dashboard' && (<>
            <div className="eyebrow">Scam Challenge</div>
            <h1 ref={headingRef} tabIndex={-1}>{hasStarted ? 'Welcome back, agent.' : 'Spot the scam. Climb the ranks.'}</h1>
            <p className="lead">{LEVELS} levels, {QUESTIONS_PER_LEVEL} scenarios each. Faster correct answers earn more points. Every scenario is written for training and is not a real message or incident.</p>
            <section className="sc-rank-card" aria-label="Your current rank" style={{ ['--rank' as string]: rank.color }}>
              <div className="sc-rank-badge" aria-hidden="true">{rank.roman}</div>
              <div>
                <div className="sc-rank-label">Current rank</div>
                <div className="sc-rank-name">{rank.name}</div>
                <div className="sc-rank-sub">Levels {rank.lo} to {rank.hi} · {rankDone} of 10 cleared in this rank</div>
              </div>
            </section>
            <dl className="sc-stats">
              <div><dt>Total score</dt><dd>{fmt(progress.totalScore)}</dd></div>
              <div><dt>Levels cleared</dt><dd>{progress.completed.length} / {LEVELS}</dd></div>
              <div><dt>Perfect levels</dt><dd>{progress.perfect.length}</dd></div>
              <div><dt>Frontier level</dt><dd>{frontier}</dd></div>
            </dl>
            <div className="button-row">
              <button type="button" className="btn btn-primary" onClick={() => start(frontier)} disabled={loading}>
                {loading ? 'Loading…' : hasStarted ? `Continue: level ${frontier}` : 'Start level 1'}
              </button>
              <button type="button" className="btn btn-secondary" onClick={() => setView('map')}>Level map</button>
            </div>
            {error && <p className="error-message" role="alert">{error}</p>}
            <section className="sc-howto" aria-labelledby="howto-title">
              <h2 id="howto-title">How it works</h2>
              <ul>
                <li>Answer with the mouse, touch, or the <kbd>1</kbd> to <kbd>4</kbd> keys.</li>
                <li>Score at least {QUESTIONS_PER_LEVEL / 2} of {QUESTIONS_PER_LEVEL} to pass. Only your frontier level unlocks the next one.</li>
                <li>A rank&apos;s last level opens the next rank only after you have scored a perfect {QUESTIONS_PER_LEVEL}/{QUESTIONS_PER_LEVEL} on every level in that rank at least once.</li>
                <li>Correct answers earn up to {fmt(MAX_POINTS)} points, falling as you take longer, to a floor of {fmt(Math.trunc(MAX_POINTS * 0.08))}.</li>
              </ul>
            </section>
            <p className="hint sc-storage" role={storageOk ? undefined : 'alert'}>
              {storageOk ? 'Progress is saved in this browser only. It is a practice aid, not a record or a credential.' : 'Your browser is blocking local storage, so progress will not be saved after you leave this page.'}
            </p>
            {hasStarted && (confirmReset
              ? <div className="sc-confirm" role="group" aria-label="Confirm reset">
                  <span>Erase all Scam Challenge progress in this browser?</span>
                  <button type="button" className="btn btn-secondary" onClick={resetProgress}>Yes, erase it</button>
                  <button type="button" className="btn btn-ghost" onClick={() => setConfirmReset(false)}>Keep my progress</button>
                </div>
              : <button type="button" className="btn btn-ghost sc-reset" onClick={() => setConfirmReset(true)}>Reset progress</button>)}
          </>)}

          {view === 'map' && (<>
            <div className="eyebrow">Level map</div>
            <h1 ref={headingRef} tabIndex={-1}>Choose a level</h1>
            <div className="button-row"><button type="button" className="btn btn-secondary" onClick={() => setView('dashboard')}>Back to dashboard</button></div>
            {error && <p className="error-message" role="alert">{error}</p>}
            {ranks.map((r) => (
              <section className="sc-rank-group" key={r.roman} aria-labelledby={`rank-${r.roman}`} style={{ ['--rank' as string]: r.color }}>
                <h2 id={`rank-${r.roman}`}><span className="sc-rank-pip" aria-hidden="true">{r.roman}</span>{r.name}<span className="sc-rank-range">Levels {r.lo} to {r.hi}</span></h2>
                <ol className="sc-levels">
                  {Array.from({ length: r.hi - r.lo + 1 }, (_, i) => r.lo + i).map((level) => {
                    const unlocked = canStartLevel(progress, level);
                    const done = progress.completed.includes(level);
                    const perfect = progress.perfect.includes(level);
                    const best = progress.scores[level];
                    const state = !unlocked ? 'locked' : perfect ? 'perfect' : done ? 'cleared' : level === frontier ? 'current' : 'open';
                    const label = `Level ${level}, ${state === 'perfect' ? 'perfect' : state === 'cleared' ? 'cleared' : state === 'current' ? 'next up' : state === 'locked' ? 'locked' : 'open'}${best ? `, best score ${fmt(best)}` : ''}`;
                    return (
                      <li key={level}>
                        <button type="button" className={`sc-level is-${state}`} disabled={!unlocked || loading} aria-label={label} onClick={() => start(level)}>
                          <span className="sc-level-num">{level}</span>
                          <span className="sc-level-mark" aria-hidden="true">{state === 'locked' ? 'LOCK' : state === 'perfect' ? '★' : state === 'cleared' ? '✓' : state === 'current' ? '▶' : ''}</span>
                        </button>
                      </li>
                    );
                  })}
                </ol>
              </section>
            ))}
          </>)}

          {view === 'play' && run && (() => {
            const q = run.questions[run.index];
            const right = run.picked === q.answer;
            const available = computePoints(true, elapsed);
            const r = rankForLevel(run.level, ranks);
            return (<>
              <div className="sc-hud" role="group" aria-label="Level status">
                <div><span>Level</span><strong>{String(run.level).padStart(2, '0')}</strong></div>
                <div><span>Question</span><strong>{run.index + 1}/{QUESTIONS_PER_LEVEL}</strong></div>
                <div><span>Score</span><strong>{fmt(run.points)}</strong></div>
                <div><span>Correct</span><strong>{run.correct}/{run.index + (answered ? 1 : 0)}</strong></div>
                <div><span>Rank</span><strong>{r.roman}</strong></div>
              </div>
              {!answered && (
                <div className="sc-timer" aria-hidden="true">
                  <span>Points now</span>
                  <span className="sc-timer-track"><span style={{ width: `${(available / MAX_POINTS) * 100}%` }} /></span>
                  <strong>{fmt(available)}</strong>
                </div>
              )}
              <section className="sc-question" aria-labelledby="sc-q">
                <div className="sc-qcat">{q.category} · practice scenario</div>
                <h1 id="sc-q" ref={headingRef} tabIndex={-1}>{q.question}</h1>
                <div className="sc-options" role="group" aria-label="Answer choices">
                  {q.options.map((option, index) => {
                    const state = !answered ? '' : index === q.answer ? 'is-right' : index === run.picked ? 'is-wrong' : 'is-dim';
                    return (
                      <button type="button" key={option} className={`sc-option ${state}`} disabled={answered} onClick={() => pick(index)}>
                        <span className="sc-key" aria-hidden="true">{index + 1}</span>
                        <span className="sc-option-text">{option}</span>
                        {answered && index === q.answer && <span className="sc-verdict">Correct answer</span>}
                        {answered && index === run.picked && index !== q.answer && <span className="sc-verdict">Your answer</span>}
                      </button>
                    );
                  })}
                </div>
              </section>
              {answered && (
                <section className={`sc-feedback ${right ? 'is-right' : 'is-wrong'}`} role="status" aria-live="polite">
                  <strong>{right ? `Correct! +${fmt(computePoints(true, run.times[run.times.length - 1]))} points` : 'Not quite. No points for this one.'}</strong>
                  <p>{q.explanation}</p>
                </section>
              )}
              <div className="button-row">
                {answered
                  ? <button type="button" ref={nextRef} className="btn btn-primary" onClick={advance}>{run.index + 1 < run.questions.length ? 'Next question' : 'Finish level'}</button>
                  : <span className="hint">Press 1 to 4 to answer.</span>}
                <button type="button" className="btn btn-ghost" onClick={() => { setRun(null); setView('map'); }}>Exit level</button>
              </div>
            </>);
          })()}

          {view === 'results' && outcome && (() => {
            const { result, rankUp, blockedByRank } = outcome;
            const next = result.level + 1;
            const nextOpen = next <= LEVELS && canStartLevel(progress, next);
            return (<>
              <div className="eyebrow">Level {result.level} results</div>
              <h1 ref={headingRef} tabIndex={-1}>{result.isLegend ? 'SATARK Legend. Level 100 cleared.' : result.passed ? 'Level cleared.' : 'Not this time.'}</h1>
              <dl className="sc-stats">
                <div><dt>Score</dt><dd>{fmt(result.score)}</dd></div>
                <div><dt>Correct</dt><dd>{result.correct} / {QUESTIONS_PER_LEVEL}</dd></div>
                <div><dt>Average time</dt><dd>{result.avgTime.toFixed(1)}s</dd></div>
                <div><dt>Best on this level</dt><dd>{fmt(progress.scores[result.level] ?? 0)}</dd></div>
              </dl>
              {!result.passed && <p className="notice-panel" role="status">You need at least {QUESTIONS_PER_LEVEL / 2} correct to pass. Read the explanations and try again; your best score is kept.</p>}
              {rankUp && <div className="sc-rankup" role="status" style={{ ['--rank' as string]: rankUp.color }}>
                <span className="sc-rankup-label">Rank up</span>
                <span className="sc-rank-badge" aria-hidden="true">{rankUp.roman}</span>
                <strong>Rank {rankUp.roman}: {rankUp.name}</strong>
                <span>New rank unlocked. Level {rankUp.lo} is open.</span>
              </div>}
              {blockedByRank && <p className="notice-panel" role="status">
                You passed, but the next rank stays locked until every level in <strong>{blockedByRank.rank.name}</strong> has been aced at least once. Still needed: level{blockedByRank.missing.length === 1 ? '' : 's'} {blockedByRank.missing.join(', ')}.
              </p>}
              <div className="button-row">
                {nextOpen && result.passed && <button type="button" className="btn btn-primary" onClick={() => start(next)} disabled={loading}>Next: level {next}</button>}
                <button type="button" className="btn btn-secondary" onClick={() => start(result.level)} disabled={loading}>Replay level {result.level}</button>
                <button type="button" className="btn btn-ghost" onClick={() => setView('map')}>Level map</button>
                <button type="button" className="btn btn-ghost" onClick={() => setView('dashboard')}>Dashboard</button>
              </div>
              {error && <p className="error-message" role="alert">{error}</p>}
            </>);
          })()}
        </>)}
      </div>
    </main>
  );
}
