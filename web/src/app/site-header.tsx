'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const links = [
  { href: '/investigate', label: 'Investigate' },
  { href: '/firstlight', label: 'FIRSTLIGHT' },
  { href: '/reports', label: 'Reports' },
  { href: '/learn', label: 'Learn' },
  { href: '/login', label: 'Workspace' },
];

export default function SiteHeader({ status = false }: { status?: boolean }) {
  const pathname = usePathname();

  return (
    <>
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <header className="topbar">
        <Link className="brand" href="/" aria-label="SATARK home">
          <span className="brand-mark" aria-hidden="true">S</span>
          <span>SATARK<span className="brand-period">.</span></span>
        </Link>
        <nav className="nav-links" aria-label="Main navigation">
          {links.map(link => {
            const active = pathname === link.href || (link.href === '/firstlight' && pathname.startsWith('/firstlight/'));
            return (
              <Link key={link.href} href={link.href} className={active ? 'active' : undefined}
                aria-current={active ? 'page' : undefined}>
                {link.label}
              </Link>
            );
          })}
        </nav>
        {status && <div className="status"><span className="status-dot" aria-hidden="true" /> SECURITY WORKSPACE</div>}
      </header>
    </>
  );
}
