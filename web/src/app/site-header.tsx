'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState } from 'react';
import { Menu, X, ShieldCheck } from 'lucide-react';

const links = [
  { href: '/investigate', label: 'Investigate' },
  { href: '/tools', label: 'Tools' },
  { href: '/firstlight', label: 'FIRSTLIGHT' },
  { href: '/learn', label: 'Academy' },
  { href: '/cases', label: 'Cases' },
  { href: '/reports', label: 'Reports' },
];

export default function SiteHeader({ status = false }: { status?: boolean }) {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <>
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <header className="topbar">
        <Link className="brand" href="/" aria-label="SATARK home" onClick={() => setMobileOpen(false)}>
          <span className="brand-mark" aria-hidden="true">S</span>
          <span>SATARK<span className="brand-period">.</span></span>
        </Link>
        <button type="button" className="mobile-nav-toggle"
          aria-label={mobileOpen ? 'Close navigation menu' : 'Open navigation menu'}
          aria-expanded={mobileOpen} aria-controls="primary-navigation"
          onClick={() => setMobileOpen(open => !open)}>
          {mobileOpen ? <X size={19} /> : <Menu size={19} />}
          <span>{mobileOpen ? 'Close' : 'Menu'}</span>
        </button>
        <nav id="primary-navigation" className={'nav-links' + (mobileOpen ? ' nav-links-open' : '')} aria-label="Main navigation">
          {links.map(link => {
            const active = pathname === link.href || (link.href === '/firstlight' && pathname.startsWith('/firstlight/'));
            return (
              <Link key={link.href} href={link.href} className={active ? 'active' : undefined}
                aria-current={active ? 'page' : undefined} onClick={() => setMobileOpen(false)}>
                {link.label}
              </Link>
            );
          })}
        </nav>
        {status && <div className="status"><span className="status-dot" aria-hidden="true" /> SECURITY WORKSPACE</div>}
        <div className="header-trust" aria-label="Security-first product"><ShieldCheck size={13} /> EVIDENCE FIRST</div>
      </header>
    </>
  );
}
