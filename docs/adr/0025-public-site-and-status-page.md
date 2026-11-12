# 0025 Public website and the separately hosted status page

**Status:** Accepted (phase 9)

- **Public site** in the same Next.js app (`web/app/(site)`): home (what it
  protects against, how anycast works, a live PoP map from the public
  status), how it works (a packet's journey, platform diagram, FAQ), pricing
  (plans by features; prices are not invented), status (live per PoP),
  contact. `/` is the home page. Contact address and the status page URL come
  from the build environment (`web/.env.example`), never from code.
- **Status page** (`status-page/`): plain HTML, CSS and JavaScript, no
  build step, no dependency on the platform's hosting: put it on any static
  host or CDN on its own domain. It polls the API's public
  `GET /api/v1/status` cross-origin (the API sends CORS headers only for
  `[server] status_page_origins`, only on that endpoint, never with
  credentials). When the API cannot be reached it says so, keeps showing
  the last known state (kept in the visitor's browser), and lists incidents
  from `incidents.json`, which operators edit on the status host. Strict CSP
  (`script-src 'self'`); `connect-src *` because the API's address is
  configuration.
- **Quality:** every public page and the status page pass axe (WCAG 2.1
  A/AA) in light and dark mode, do not scroll sideways on a phone, and the
  site pages link to signup (Playwright `site.spec.ts`).
