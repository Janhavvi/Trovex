# Trovex Platform

A React + Vite dashboard for visualizing security assessment findings, attack paths, role exposure, mobile risk, and evidence collection.

## Getting started

```bash
npm install
npm run dev
```

This starts the Vite frontend and the Express API for UI development:

- Frontend: http://localhost:8443/
- Backend: http://localhost:3001/api/health

## Local Monitoring Stack

The full local stack runs the dashboard/API, Postgres, n8n, a private training lab, and the private OWASP ZAP Baseline adapter. Before the first run, copy `.env.example` to `.env` and replace its placeholders with local-only random values. Never commit `.env`.

```bash
Copy-Item .env.example .env
npm run stack:up
```

Open http://localhost:3001 for the dashboard and http://localhost:5678 for n8n. On the first n8n visit, create its owner account, import `n8n/workflows/trovex-assessment.json`, and publish/activate it. The lab and scanner have no host-published ports; the scanner is pinned to the private `trovex-lab` service and runs the ZAP Baseline passive checks only.

The Overview button sends `assessment.started` to the API. The backend creates a scan record, injects its configured lab URL and authorization reference, and rejects mismatched targets, expired authorization, or a disabled kill switch. n8n validates the scope, starts the scanner, and returns the job ID. Results are written to Postgres and shown in Findings and Overview. A Render cron service triggers the same scoped workflow daily at 03:00 UTC.

The scanner accepts only jobs created by the backend, checks a generated internal callback token, and never accepts a caller-selected target. The lab is a separate private service; the public dashboard is not included in the scan scope.

Stop the local stack with `npm run stack:down`. Postgres data is kept in its named Docker volume.

## Render Deployment

`render.yaml` defines the full stack. The GitHub repository must contain the project and this Blueprint before Render can deploy it. In Render, choose **New > Blueprint** and connect the repository. Render generates the internal callback token and n8n encryption key; enter the lab authorization expiry in the Blueprint prompt. Keep all actual secrets in Render environment settings, not GitHub.

The app, lab, and scanner communicate over Render's private network. The lab and scanner are private services; the public dashboard is never used as a scan target. Postgres stores app findings and n8n workflow data in separate databases. n8n's workflow must be imported and activated once from its Render URL. Render's web services, private services, and Postgres plans in this Blueprint are paid; check current pricing before deploying.

Only OWASP ZAP Baseline is used. It crawls the isolated lab and evaluates passive rules; it does not run the active scanner. The daily monitor reuses the same backend scope guard.

## Production build

```bash
npm run build
```

## Scripts

- `npm run dev` — start the frontend and API together
- `npm run dev:frontend` — start only the Vite app
- `npm run dev:backend` — start only the Express API
- `npm run stack:up` — build and start the complete local Docker stack
- `npm run stack:down` — stop the local Docker stack
- `npm run build` — create a production build
- `npm run preview` — preview the production build locally
- `npm test` — run the backend smoke test
