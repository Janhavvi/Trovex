# Trovex

Safe. Proven. Fixed.

Trovex is an evidence-first cybersecurity assessment platform for discovering, validating, fixing, and re-testing security findings in a controlled environment. It combines a React frontend, an Express API, a Postgres-backed data layer, security workflow automation, and a private lab model for scoped assessment operations.

## Overview

The platform is designed around a security workflow:

- Target / scope definition
- Scan and validation
- Evidence capture
- Attack path analysis
- Fix and re-test
- Report generation

It includes a secure login flow, role-based access control, a production-ready dashboard, and a lab-oriented assessment model intended for controlled security testing.

## Tech stack

- Frontend: React + Vite
- API: Node.js + Express
- Database: PostgreSQL
- Workflow automation: n8n
- Container lab: Docker
- Reporting: PDF and SARIF-style report generation
- Security: hashed passwords, scoped target validation, HTTP-only sessions, and backend enforcement

## Project structure

```text
.
├── src/                 # React app
├── server/              # Backend helpers, scoring, reports, DB access
├── tests/               # API and smoke tests
├── n8n/                 # Workflow definitions
├── lab/                 # Lab-related service code
├── scanner/             # Scanner service
├── scripts/             # Utility scripts
├── docker-compose.yml   # Local stack configuration
├── Dockerfile           # App container config
├── server.js            # Express server entry point
├── package.json         # Scripts and dependencies
├── vite.config.ts      # Vite configuration
├── render.yaml          # Render deployment blueprint
├── .env.example         # Example environment config
├── README.md            # Project documentation
└── index.html           # App entry HTML
```

## Features

- Secure account creation and login
- Role-based permissions for Admin, Security Analyst, and Viewer
- Scoped authorized target mode with validation checks
- Security dashboard and workload views
- Findings and evidence tracking
- Attack path visualization
- Fix and re-test lifecycle support
- Reporting exports
- Local Docker stack for lab and automation integration

## Local development

1. Install dependencies

```bash
npm install
```

2. Start the app in development mode

```bash
npm run dev
```

This starts the frontend and backend together.

- Frontend: http://localhost:8443/
- Backend: http://localhost:3001

3. Optional: start only the frontend or backend

```bash
npm run dev:frontend
npm run dev:backend
```

## Docker / local stack

The project includes a Docker-based stack to run the platform plus supporting services.

```bash
npm run stack:up
```

To stop it:

```bash
npm run stack:down
```

The stack is intended for local workshop or demo usage and keeps lab/service components isolated from public exposure.

## Environment variables

Create a local environment file based on the project example and keep secrets out of source control.

```bash
cp .env.example .env
```

Typical variables include:

- `PORT`
- `NODE_ENV`
- `DATABASE_URL`
- `FRONTEND_URL`
- `JWT_SECRET` / `SESSION_SECRET`
- `N8N_WEBHOOK_URL`
- `N8N_AUTOMATION_KEY`
- `WEBHOOK_SECRET`
- `AUTHORIZED_LAB_URL`
- `LAB_AUTHORIZATION_REF`

Do not commit actual secret values.

## Authentication and RBAC

The application includes a backend-driven authentication flow with secure password handling and session-based access.

Supported roles include:

- Admin
- Security Analyst
- Viewer

Access is enforced on the backend, not only in the UI. Public sign-up is intended for limited user roles, while elevated administrative access must use a controlled mechanism rather than broad public registration.

## Security model

The platform includes protections around the assessment flow:

- private lab allowlist enforcement
- authorization checks for target access
- kill-switch protection for scans
- rate-limited auth attempts
- HTTP-only cookies for sessions
- security headers
- no plaintext password storage

## Testing

Run the project test suite:

```bash
npm test
```

Production build verification:

```bash
npm run build
```

## Useful scripts

```bash
npm run dev
npm run dev:frontend
npm run dev:backend
npm run stack:up
npm run stack:down
npm run build
npm run preview
npm test
```

## Deployment notes

The project is structured to support deployment to a free-tier stack such as:

- Frontend: Vercel
- Backend: Render
- Database: PostgreSQL / Neon-compatible service
- Automation: n8n
- Lab: Docker / isolated service environment

The deployment configuration is included in the repository and is intended to be adapted to the actual cloud environment. The repository should never contain live credentials or secrets.

## License

This project is provided for internal and project-based development use. Update this section if your repository uses a specific license.
