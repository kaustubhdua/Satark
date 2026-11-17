import Link from 'next/link';
import './learn.css';

const tabs = [
  { href: '/learn', label: 'Academy', hint: 'Lessons and quiz' },
  { href: '/challenge', label: 'Scam Challenge', hint: '100 levels' },
  { href: '/classroom', label: 'Classroom', hint: 'Session summary' },
] as const;

/** Section tabs shared by the three learning pages. */
export default function LearnTabs({ current }: Readonly<{ current: (typeof tabs)[number]['href'] }>) {
  return (
    <nav className="learn-tabs" aria-label="Learning sections">
      {tabs.map((tab) => (
        <Link key={tab.href} href={tab.href} aria-current={tab.href === current ? 'page' : undefined}
          className={'learn-tab' + (tab.href === current ? ' is-current' : '')}>
          <span className="learn-tab-label">{tab.label}</span>
          <span className="learn-tab-hint">{tab.hint}</span>
        </Link>
      ))}
    </nav>
  );
}
