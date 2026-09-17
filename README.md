# ShieldDesk AI Chat Widget 

Next.js frontend + server-side API for the ShieldDesk AI Chat Widget. The
model is a **local Ollama instance** — no cloud LLM API, no incident/CVE
data ever leaves your own infrastructure. No Firebase either — since
ShieldDesk itself doesn't have a login system yet (this widget is the
first component being built), auth is a dev-mode header backed by real
Postgres RBAC/tenant data. See "Dev-mode auth" below.

## Setup

```bash
cp .env.example .env.local   # fill in DATABASE_URL, PYTHON_AI_SERVICE_URL

# Ollama — pull a tool-calling-capable model and start serving:
ollama pull qwen3:4b
ollama serve

# stand up Postgres, then:
psql $DATABASE_URL -f db/schema.sql
psql $DATABASE_URL -f db/seed.sql

npm install
npm run dev
```

Visit http://localhost:3000/api/health to confirm both Postgres and
Ollama are reachable. The widget itself has no sign-in gate right now —
it renders immediately and identifies its (dev-mode) user via a header.
Try asking it about "today's critical incidents" or "Investigate
INC-1042" — these are real seeded rows.

To exercise the actual Python vulnerability-intelligence engine too:

```bash
pip install -r ../requirements.txt --break-system-packages
python3 ../server.py    # serves on :8000
```

## Dev-mode auth

`lib/auth/session.ts` reads an `X-ShieldDesk-User` header (a `users.id`
value) instead of verifying a real token. RBAC and tenant isolation are
still real — enforced from the matching Postgres row, not trusted from
the header — this only skips the "prove who you are" step, which nothing
exists yet to do properly. `db/seed.sql` ships three dev users to test
different roles/tenants: `dev-analyst` (user, acme-tenant), `dev-admin`
(system_admin, acme-tenant — can view cross-tenant), `dev-other` (user,
globex-tenant — used to prove tenant isolation).

Swap this for real verification once ShieldDesk has a login flow —
only the token→uid step in `session.ts` needs to change; the Postgres
lookup and every tool's RBAC check stay the same.

## How the model is scoped

Per the Scope Addendum, the model is a 4-intent router, not a general
assistant:

1. **Fetch incidents** — `getIncidents`
2. **Analyze a CVE** — `analyzeCve`
3. **Investigate an incident** — `investigateIncident`
4. **Generate a mitigation plan** — `generateMitigationPlan`

`app/api/chat/route.ts` routes deterministically first (a CVE id, an
incident code, or an "incidents" keyword skips the model entirely).
Anything else goes to the model with `tool_choice: "auto"` across all four
tools (OpenAI-compatible — this is what Ollama's `/v1/chat/completions`
endpoint accepts too) — if it doesn't call one, the request is genuinely
out of scope and gets a fixed decline message, never an answer from the
model's own general knowledge.

Note: local models — especially small ones — are less reliable at this
kind of tool-selection than a large cloud model. Worth watching once
this is running against the real `qwen3:4b` (or whatever model you pull)
rather than the mock server used to verify the wiring in this session.

## Structure

```
db/
├── schema.sql                 # designed as part of this build — see below
└── seed.sql                   # dev users + sample incidents/assets/CVE links
src/
├── app/
│   ├── api/
│   │   ├── chat/route.ts      # regex fast-path → Gemini routing → tool call → streamed answer
│   │   └── health/route.ts    # env/DB sanity check
│   └── layout.tsx             # globally-mounted <ChatWidget />
├── components/
│   ├── ai-chat/ChatWidget.tsx # floating button + panel, SSE streaming, error/retry
│   └── ui/avatar.tsx          # lightweight Avatar/AvatarFallback (no Radix)
├── lib/
│   ├── ai/ollama.ts            # server-only Ollama client (OpenAI-compatible endpoint)
│   ├── auth/session.ts        # dev-mode header → Postgres role/tenant lookup
│   ├── db/                    # PostgreSQL pool
│   ├── permissions.ts         # canAccess(role, permission) — RBAC
│   ├── tools/shieldDeskChatTools.ts  # the 4 allow-listed tools + OpenAI-format schemas
│   └── utils.ts                # cn() className helper
└── types/chat.ts
```

## Schema — designed here, not discovered

`db/schema.sql` isn't reverse-engineered from an existing ShieldDesk
platform — nothing exists yet, so this project defines it: `users`,
`incidents`, `incident_events`, `assets`, `incident_assets`, and
`incident_cves` (a many-to-many join deciding how incidents relate to
CVEs — one incident can involve several, one CVE can span incidents),
plus `chat_audit_log`. Revise freely once the real incidents/assets pages
(later phases) impose their own requirements — this is a reasonable
starting point, not a constraint handed down from elsewhere.

## Verified end-to-end (this session)

With a real local Postgres (seeded) and the real Python engine
(`server.py`, trained model already present) both running:

- Tenant isolation: `dev-analyst` (acme-tenant) sees the seeded incidents;
  `dev-other` (globex-tenant) sees none, and gets `not_found` — not a
  permissions error — when investigating an acme incident by code.
- `investigateIncident` correctly joins incident + events + assets.
- `analyzeCve` correctly calls the real `GET /api/lookup?cve=...`
  endpoint — confirmed against both a real CVE in the 10,374-row
  knowledge base and one that doesn't exist (`not_found`).
- `generateMitigationPlan` correctly reads the `incident_cves` join,
  looks up each linked CVE, and folds unresolved ones into the plan's
  note rather than failing.

Also verified, against a mock server implementing Ollama's exact
OpenAI-compatible protocol (real Ollama isn't installable in this
sandbox — see the Ollama migration notes for why): the regex fast-path
correctly skips the routing call but still uses the model for final
formatting; `tool_choice: "auto"` tool-call parsing works; genuine
decline (no tool call) is correctly treated as out-of-scope.

Not yet tested against a real model's actual judgment — only the
protocol wiring. Pull a real model and point `OLLAMA_BASE_URL` at it to
find out how qwen3:4b (or whatever you choose) actually performs at
routing.

## What's next

- **Run this against a real Ollama + model** — the one thing not yet
  tested for real, only via protocol mock.
- **Phase 6** — pass page/record context into `/api/chat` so "investigate
  this" resolves the ID without the user typing it.
- **Real auth** — once ShieldDesk has a login flow, replace the header
  check in `lib/auth/session.ts`.
- **Phase 8** — expand the audit log / test coverage beyond what's here.
