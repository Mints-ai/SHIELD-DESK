# ShieldDesk

ShieldDesk is a security operations platform for incident triage, tenant-aware dashboards, AI-assisted investigation, fleet visibility, and governance workflows. The repo currently contains a Next.js application, a Python CVE / ML service, and supporting Go and Python microservices.

## Current repo structure

```text
.
├── src/                     # Next.js app, dashboards, API routes, shared UI
├── ai-chat-desk/            # Python vulnerability intelligence / ML service
├── services/                # Additional Go / Python services
├── db/                      # SQL schema and seed data
├── shared/                  # shared contracts, schemas, events
├── gateway/                 # gateway config
├── infra/                   # Terraform and Helm configs
├── agent/                   # endpoint agent code
├── public/                  # static assets
├── tests/                   # test suite
├── package.json             # frontend dependencies and scripts
├── docker-compose.yml       # local service orchestration
├── .env.example             # sample environment variables
├── start.ps1                # quick local launch helper
├── CHECKLIST.md             # project checklist
├── BLAST_RADIUS_README.md   # architecture notes
├── WORKING_README.md        # operational notes
├── SHIELDDESK_PROJECT_GUIDE.md
├── README.md                # project overview
└── ...
```

## What is running in this repo

The application currently uses:

- Next.js 16 + React 19 + TypeScript in the root app
- PostgreSQL for the main data layer
- Python service in [ai-chat-desk](ai-chat-desk) for CVE / ML logic
- Additional microservices under [services](services)
- Ollama for local LLM support when configured

## Prerequisites

Install the following on your machine:

- Node.js 20+
- npm 10+
- Python 3.10+
- Optional: Go 1.21+
- Optional: Docker Desktop / Docker Engine
- Optional: Ollama with model `qwen3:4b`

## Quick start

### 1) Install frontend dependencies

```bash
npm install
```

### 2) Configure environment

```bash
cp .env.example .env.local
```

Then review and adjust the values in [.env.example](.env.example), especially the database and service URLs.

### 3) Start the app

#### Option A: Local full stack

The repo includes a PowerShell launcher for the main stack:

```powershell
pwsh -File ./start.ps1
```

If you are on Windows PowerShell directly:

```powershell
.\start.ps1
```

This is intended to bring up the main services together, including:

- Next.js app on http://localhost:3000
- Python AI service on http://localhost:8000
- Ollama on http://localhost:11434

#### Option B: Manual startup

Open separate terminals:

Terminal 1 — frontend:

```bash
npm run dev
```

Terminal 2 — Python CVE / ML service:

```bash
cd ai-chat-desk
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python server.py
```

Terminal 3 — local LLM:

```bash
ollama serve
```

If needed:

```bash
ollama pull qwen3:4b
```

## Docker startup

To run the stack with Docker Compose:

```bash
docker compose up --build
```

This is defined in [docker-compose.yml](docker-compose.yml) and is the quickest way to boot the main local infrastructure.

## Test suite

Run the project tests with:

```bash
npm test
```

This repository includes automated checks for security, governance, tenant behavior, and ingestion flows.

## Useful reference docs

- [CHECKLIST.md](CHECKLIST.md)
- [BLAST_RADIUS_README.md](BLAST_RADIUS_README.md)
- [WORKING_README.md](WORKING_README.md)
- [SHIELDDESK_PROJECT_GUIDE.md](SHIELDDESK_PROJECT_GUIDE.md)

## Notes

- This README was previously out of sync with the actual project state and included stale local references and outdated architecture statements.
- The content here reflects the repo as currently checked out and aligns with the actual scripts and folder structure.

## License and usage

Use this project within the constraints of your organization’s security policies and internal compliance requirements.
