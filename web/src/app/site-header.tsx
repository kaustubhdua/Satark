'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useRef, useState, type MouseEvent } from 'react';
import { Menu, X } from 'lucide-react';
import { getActiveTenant, getSession } from '../lib/satark-auth';

const links = [
  { href: '/investigate', label: 'Investigate' },
  { href: '/tools', label: 'Tools' },
  { href: '/firstlight', label: 'FIRSTLIGHT' },
  { href: '/learn', label: 'Academy' },
  { href: '/cases', label: 'Cases' },
  { href: '/reports', label: 'Reports' },
  { href: '/native-sensor', label: 'Endpoint sensor' },
];

export default function SiteHeader() {
  const pathname = usePathname();
  const router = useRouter();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [tilting, setTilting] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  // Show the account state without a request for anonymous visitors: only
  // check the server session when this browser has previously chosen a workspace.
  const [signedIn, setSignedIn] = useState(false);
  useEffect(() => {
    let cancelled = false;
    if (!getActiveTenant()) { setSignedIn(false); return; }
    void getSession().then(session => { if (!cancelled) setSignedIn(Boolean(session)); });
    return () => { cancelled = true; };
  }, [pathname]);

  // The S mark tilts like a nudge, then settles and takes you home.
  function goHome(event: MouseEvent<HTMLAnchorElement>) {
    setMobileOpen(false);
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) return;
    event.preventDefault();
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    setTilting(false);
    requestAnimationFrame(() => setTilting(true));
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      setTilting(false);
      if (pathname === '/') window.scrollTo({ top: 0, behavior: reduce ? 'auto' : 'smooth' });
      else router.push('/');
    }, reduce ? 0 : 420);
  }
  // Tool-detail routes belong to the Tools section even though each has its own URL.
  const toolDetailRoutes = new Set(['/url', '/image-review', '/qr', '/pdf-review', '/media-review']);
  // The Scam Challenge and Classroom pages belong to the Academy section.
  const learningRoutes = new Set(['/challenge', '/classroom']);

  return (
    <>
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <header className="topbar">
        <Link className="brand" href="/" onClick={goHome}>
          <span className={'brand-mark' + (tilting ? ' is-tilting' : '')} aria-hidden="true">S</span>
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
            const active = pathname === link.href
              || (link.href === '/firstlight' && pathname.startsWith('/firstlight/'))
              || (link.href === '/tools' && toolDetailRoutes.has(pathname))
              || (link.href === '/learn' && learningRoutes.has(pathname));
            return (
              <Link key={link.href} href={link.href} className={active ? 'active' : undefined}
                aria-current={active ? 'page' : undefined} onClick={() => setMobileOpen(false)}>
                {link.label}
              </Link>
            );
          })}
          <Link href="/login" className={'nav-cta' + (pathname === '/login' ? ' active' : '')}
            aria-current={pathname === '/login' ? 'page' : undefined} onClick={() => setMobileOpen(false)}>
            {signedIn ? 'Account' : 'Sign in'}
          </Link>
        </nav>
      </header>
    </>
  );
}
