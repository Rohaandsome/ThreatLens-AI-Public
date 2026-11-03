# ThreatLens AI

AI-Powered Cyber Threat Intelligence Analysis and Secure Sharing

> **Demo video:** Coming soon — YouTube URL placeholder (no video link available yet).

## Overview

Critical infrastructure teams face a flood of unstructured threat reports and need fast, trustworthy, shareable analysis. ThreatLens AI ingests a report, produces evidence-backed findings with Meta Muse Spark 1.3, and exports or shares results in standard formats with human approval.

## Key Features

- AI analysis powered by Meta Muse Spark 1.3 via the Meta Model API
- Evidence-backed findings with confidence levels and source references
- Extracted IoCs, CVEs, and MITRE ATT&CK mappings
- STIX 2.1 bundle export for interoperable threat intel
- TLP 2.0-aware secure sharing workflow with human approval
- Local MISP event preview, plus audit log and analysis history

## Tech Stack

Meta Model API (Muse Spark 1.3) · React / TypeScript / Vite · Python / FastAPI · STIX 2.1 · PyMISP

## Quick Start

Prerequisites: Python 3.11+, Node.js 20.19+ or 22.12+ (required by Vite 8).

```bash
# 1. Install dependencies
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
cd frontend && npm install && cd ..

# 2. Configure the backend
cp backend/.env.example backend/.env
# Edit backend/.env and set MODEL_API_KEY, OPERATOR_API_KEY, ADMIN_API_KEY.
# Generate keys with: python -c "import secrets; print(secrets.token_urlsafe(32))"

# 3. Start the backend (from the backend/ directory)
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# 4. Start the frontend (in a second terminal, from the project root)
cd frontend
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.
API health check: `GET http://127.0.0.1:8000/api/health`.

## Security & Limitations

- Demo uses synthetic sample data only; no real victim or classified data.
- All sharing and export actions require explicit human approval.
- Development setup binds to loopback only (`127.0.0.1` / `localhost`).
- MISP integration is a local preview of the event payload; this demo does not publish to any external MISP instance.
- Implemented code vs. verified functionality: the sharing/export code paths are implemented and covered by automated tests, but live external sharing was not demonstrated in this environment.

## Developer

[github.com/rohaandsome](https://github.com/rohaandsome)
