import type { Metadata, Viewport } from 'next';
import { GeistSans } from 'geist/font/sans';
import { GeistMono } from 'geist/font/mono';
import './globals.css';
import './design-system.css';
import RouteExperience from './route-experience';
import SiteFooter from './site-footer';
import { LocalModeNotice } from './local-workspace-panel';

export const metadata: Metadata = {
  title: 'SATARK — Digital Security Workspace',
  description: 'Investigate suspicious digital content with evidence-backed security checks.',
};

export const viewport: Viewport = { themeColor: '#09090b', colorScheme: 'dark' };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={GeistSans.variable + ' ' + GeistMono.variable}>
      <body><RouteExperience /><LocalModeNotice />{children}<SiteFooter /></body>
    </html>
  );
}
