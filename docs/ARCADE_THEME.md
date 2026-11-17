# Arcade theme

The web workspace ships an arcade-cabinet skin: pixel type, neon palette, chunky press-down
buttons, CRT scanlines and a synthwave floor grid. It is a presentation layer only; no behavior,
copy, or data flow changes.

## Where it lives

| File | Role |
| --- | --- |
| `web/src/app/arcade.css` | The whole theme. Every rule is scoped under `.arcade`. |
| `web/src/app/layout.tsx` | Imports the fonts and stylesheet and sets `class="arcade"` on `<html>`. |

**Turn it off:** remove `arcade` from the `<html>` className in `layout.tsx`. The previous skin
(`design-system.css`) is untouched underneath.

## Open-source ingredients

| Ingredient | License | How it is used |
| --- | --- | --- |
| [Press Start 2P](https://fonts.google.com/specimen/Press+Start+2P) by CodeMan38 | SIL OFL 1.1 | Headings and buttons, via the `@fontsource/press-start-2p` npm package |
| [VT323](https://fonts.google.com/specimen/VT323) by Peter Hull | SIL OFL 1.1 | Labels, navigation, chips, via `@fontsource/vt323` |
| Hard-offset pixel borders, press-down keys | Technique only | Written from scratch, in the spirit of [NES.css](https://github.com/nostalgic-css/NES.css) (MIT) and 8bitcn. No code copied. |

Fonts are bundled and served from the app's own origin, so the existing `font-src 'self'`
Content-Security-Policy is unchanged and no third-party font CDN is contacted at runtime.

## Guard rails (kept on purpose)

- **Readable body copy.** Paragraphs, tables, evidence and code stay in Geist / Geist Mono. Pixel
  fonts are for headings, buttons and short labels only.
- **Accessibility.** `tests/browser-smoke.mjs` runs axe on every route at desktop and mobile
  viewports and passes with the theme on. Focus rings are a thick yellow outline.
- **Motion is optional.** The floor scroll, blinking cursor and button pulse exist only inside
  `prefers-reduced-motion: no-preference`; with reduced motion nothing animates and hover does
  not shift layout.
- **High contrast.** `prefers-contrast: more` removes the scanlines and floor grid.
- **Scanlines never block input** (`pointer-events: none`) and are hidden when printing.
- **No pretend controls.** The theme adds no fake scores, credits, lives or progress bars. The
  repository's design principle "no pretend controls" still applies: segmented bars only ever
  render real values.
- **No horizontal overflow.** Checked at 360 px on every primary route.
