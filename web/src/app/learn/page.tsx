'use client';

import SiteHeader from '../site-header';
import { useState } from 'react';

const questions = [
  { q: 'A message says your account will be blocked in 10 minutes unless you log in through its link. What is the safest next step?', options: ['Click quickly before it expires', 'Open the official app/site independently and check for alerts', 'Reply with your OTP to verify identity'], correct: 1, why: 'Urgency and an unsolicited link are warning signs. Verify through a trusted channel you open independently.' },
  { q: 'A message claims you won a prize but must pay a processing fee first. What should you do?', options: ['Pay a small fee to test it', 'Share bank details so the prize can be sent', 'Treat it as suspicious and verify the claim independently'], correct: 2, why: 'Advance-fee prize claims are a common scam pattern. Do not send money or sensitive details to claim an unsolicited prize.' },
  { q: 'An AI scanner labels a message “low risk”. Does that prove it is safe?', options: ['Yes, the model checked everything', 'No. Review evidence and verify the sender independently', 'Only if the message has a logo'], correct: 1, why: 'AI outputs can be wrong and may lack context. A risk label is a triage signal, not proof.' },
];

export default function LearnPage() {
  const [answers, setAnswers] = useState<Record<number, number>>({});
  const [checked, setChecked] = useState(false);
  const answeredCount = Object.keys(answers).length;
  const correctCount = questions.filter((question, index) => answers[index] === question.correct).length;

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <div className="eyebrow">SECURITY AWARENESS / PRACTICE</div>
        <h1>Pause. Verify. Then act.</h1>
        <p className="lead">Practice spotting common social-engineering patterns. This short quiz is educational and does not certify a message as safe or malicious.</p>
        <div className="quiz-progress" aria-live="polite">
          <span><strong>{answeredCount} of {questions.length}</strong> answered</span>
          <span className="quiz-progress-track" aria-hidden="true"><span style={{ width: `${(answeredCount / questions.length) * 100}%` }} /></span>
        </div>
        {questions.map((question, index) => (
          <section className="form-panel quiz-card" key={question.q} aria-labelledby={`question-${index}`}>
            <div className="quiz-question-label">QUESTION {String(index + 1).padStart(2, '0')} / {String(questions.length).padStart(2, '0')}</div>
            <h2 id={`question-${index}`}>{question.q}</h2>
            <fieldset className="quiz-options">
              <legend className="sr-only">Choose one answer</legend>
              {question.options.map((option, optionIndex) => (
                <label className={`quiz-option ${checked && answers[index] === optionIndex ? (optionIndex === question.correct ? 'is-correct' : 'is-incorrect') : ''} ${checked && optionIndex === question.correct ? 'shows-correct' : ''}`} key={option}>
                  <input type="radio" name={`q${index}`} checked={answers[index] === optionIndex}
                    onChange={() => { setAnswers(previous => ({ ...previous, [index]: optionIndex })); setChecked(false); }} />
                  <span>{option}</span>
                  {checked && optionIndex === question.correct && <span className="answer-marker" aria-label="Correct answer">✓</span>}
                </label>
              ))}
            </fieldset>
            {checked && <div className="notice-panel quiz-explanation">
              <strong>{answers[index] === undefined ? 'Not answered' : answers[index] === question.correct ? 'Correct answer' : 'Review this answer'}</strong>
              <p>{question.why}</p>
            </div>}
          </section>
        ))}
        {checked && <section className="quiz-score" aria-live="polite">
          <span className="eyebrow">YOUR RESULT</span>
          <h2>{correctCount} / {questions.length} correct</h2>
          <p>{answeredCount < questions.length ? `You answered ${answeredCount} of ${questions.length}. Unanswered questions are not counted as correct.` : correctCount === questions.length ? 'Great work. Keep verifying claims through trusted channels.' : 'Review the explanations above, then try again to reinforce the safest response.'}</p>
        </section>}
        <div className="button-row quiz-actions">
          <button className="btn btn-primary" type="button" onClick={() => setChecked(true)} disabled={answeredCount === 0}>Check answers</button>
          <button className="btn btn-secondary" type="button" onClick={() => { setAnswers({}); setChecked(false); }}>Reset quiz</button>
        </div>
      </div>
    </main>
  );
}
