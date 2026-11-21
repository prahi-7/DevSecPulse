# DevSecPulse

A defensive web application/API security audit dashboard built with React/Vite/Tailwind, Express, MongoDB Atlas, and JWT. Color system: plum `#29213D`, violet `#7455D9`, lavender `#EDE7FA`, warm-white `#F8F7FC`.

## Architecture

- `client/` — responsive React application, Recharts history charts, auth and report pages.
- `server/src/routes/` — authenticated API, ownership checks, input validation.
- `server/src/services/ssrf.js` — URL and DNS address policy.
- `server/src/services/httpAudit.js` — outbound HTTP(S) with pinned DNS result, redirect validation, TLS verification, timeout, size limits.
- `server/src/services/audit.js` — checks and remediation evidence.
- `server/src/services/queue.js` — bounded in-process scan concurrency.
- `server/src/models/` — Mongoose user, target, scan records.
- `server/tests/` — automated unit and API smoke tests.

## Setup

Requirements: Node 20+, npm, MongoDB Atlas cluster with network access from the backend.

```bash
npm install
npm run install:all
cp server/.env.example server/.env
cp client/.env.example client/.env
```

On Windows PowerShell use `Copy-Item server/.env.example server/.env` and similarly for client. Edit `server/.env` with your own Atlas URI and a cryptographically random JWT secret of 32+ characters. Never commit `.env`. Configure Atlas database user and IP access (prefer narrow egress allowlists). Then:

```bash
npm run dev
```

Open `http://localhost:5173`. API runs at `http://localhost:5000`. Tests: `npm test`; frontend build: `npm run build`; lint: `npm run lint`.

## API

All requests JSON. For protected routes send `Authorization: Bearer <token>`.

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/register` | `{name,email,password}` returns user and JWT |
| POST | `/api/auth/login` | `{email,password}` returns user and JWT |
| GET | `/api/auth/me` | Current authenticated user |
| GET | `/api/health` | Service health |
| GET | `/api/targets` | User-owned targets |
| POST | `/api/targets` | `{name,url}` add public target |
| DELETE | `/api/targets/:id` | Remove owned target |
| POST | `/api/targets/:id/scans` | Queue audit; returns HTTP 202 |
| GET | `/api/scans` | Most recent 100 owned scans |
| GET | `/api/scans/:id` | Owned report and status |
| GET | `/api/scans/:id/compare/:otherId` | Compare same-target completed/partial scans |

## Scoring

Start at 100. Deduct once per unique finding ID: Critical 25, High 15, Medium 8, Low 3, Informational 0. Floor at zero. Grades: A+ 95–100; A 90–94; B+ 85–89; B 80–84; C 70–79; D 60–69; F below 60. Failed scans have **no score**. Checks marked inconclusive make the scan partial. Scoring reflects only implemented checks and does not estimate total exploitability.

## Scope and security limitations

**Only scan assets you own or are authorized to assess.** The scanner makes a single bounded GET to each endpoint and follows up to four validated redirects. TLS certificate verification is never disabled. The request resolves all DNS results and rejects the hostname if *any* result is nonpublic; the actual socket uses a pinned validated address. Only ports 80 and 443 are accepted. The backend sends no user authentication credentials. Redirects are validated independently. Response bodies are discarded after a 64 KiB cap; per-request timeout is 8 seconds. A per-user active-scan restriction, global concurrency limit, and API rate limits are provided.

CORS analysis is limited to headers from the requested GET; it does not simulate preflight, Origin reflection, or credentials behavior. HTTP-to-HTTPS redirect analysis reflects the requested URL and actual redirects; an HTTPS-only target does not establish whether an HTTP endpoint redirects. Certificate hostname/trust verification occurs during the Node TLS handshake; a failure prevents a successful scan, and individual causes are not always distinguished. No port scan, exploit attempt, active penetration testing, or comprehensive vulnerability assessment is performed.

**Before public multi-tenant deployment:** replace the in-process queue with a durable job queue and worker isolation; add strong proof-of-domain-ownership or an approval workflow (this starter does not establish ownership of submitted public domains), centralized egress firewall rules, dedicated outbound proxy, DNS and IP threat intelligence, per-organization quotas, abuse monitoring, audit logging, and user-initiated scan cancellation. This starter is not suitable for arbitrary anonymous public scanning. The `CLIENT_ORIGIN` CORS setting is explicit, but CORS is not an authentication mechanism.

## Deployment

- Frontend: deploy `client/` to Vercel or Netlify, build `npm run build`, output `dist`, set `VITE_API_URL=https://YOUR-API-DOMAIN/api`.
- Backend: deploy `server/` to a Node 20+ hosting service with `npm start`; configure `MONGODB_URI`, `JWT_SECRET`, `CLIENT_ORIGIN`, and `PORT` from the provider. Enable HTTPS at the reverse proxy.
- Database: MongoDB Atlas, least-privilege credentials, network allowlist, backups, and TLS.
- Run tests and inspect security policy before enabling outbound scans on internet-facing hosting.

## Known gaps

No MFA, password reset, email verification, durable queue, scan cancellation, ownership proof, or active preflight CORS testing. Print-to-PDF uses the browser print dialog; no server-side PDF rendering is required. Authentication tokens live in session storage, which is vulnerable to XSS; a production version should prefer carefully configured httpOnly SameSite cookies with CSRF defenses. Scan history is retained when targets are removed.
