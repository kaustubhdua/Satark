import type { Metadata, Viewport } from 'next';
import { GeistSans } from 'geist/font/sans';
import { GeistMono } from 'geist/font/mono';
// Self-hosted open-source pixel fonts (SIL OFL 1.1). Served from our own origin,
// so the strict font-src 'self' policy still applies.
import '@fontsource/press-start-2p/latin-400.css';
import '@fontsource/vt323/latin-400.css';
import './globals.css';
import './design-system.css';
import './arcade.css';
import RouteExperience from './route-experience';
import SiteFooter from './site-footer';

export const metadata: Metadata = {
  title: 'SATARK — Digital Security Workspace',
  description: 'Investigate suspicious digital content with evidence-backed security checks.',
};

export const viewport: Viewport = { themeColor: '#0a0420', colorScheme: 'dark' };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={'arcade ' + GeistSans.variable + ' ' + GeistMono.variable}>
      <body><RouteExperience />{children}<SiteFooter /></body>
    </html>
  );
}
