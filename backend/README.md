# CodeShieldAI Backend (FastAPI)

Secure scanning orchestration + auth + reporting.

This service powers:
- OAuth login (GitHub/Google)
- repo/file ingestion
- heuristic + ML orchestration
- hybrid scoring
- report generation (JSON + PDF)
- history persistence (MongoDB Atlas)

---

## Quickstart

### Prerequisites
- Python 3.10+
- (Optional) CUDA runtime if using GPU inference
- MongoDB Atlas URI (or local MongoDB)

### Install
```bash
cd backend
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run (dev)
```bash
uvicorn app.main:app --reload --port 8000
```

---

## Environment Variables

Create `backend/.env`:

```bash
# Database
MONGODB_URI=mongodb+srv://...

# Auth
OAUTH_GITHUB_CLIENT_ID=...
OAUTH_GITHUB_CLIENT_SECRET=...
OAUTH_GOOGLE_CLIENT_ID=...
OAUTH_GOOGLE_CLIENT_SECRET=...

# Security / Sessions
JWT_SECRET=change-me
ALLOWED_ORIGINS=http://localhost:5173

# Models
MODEL_DEVICE=cuda   # cpu|cuda
DEFAULT_MODEL=graphcodebert
```

---

## API Surface (Typical)

### Auth
- `GET /auth/login/github`
- `GET /auth/login/google`
- `GET /auth/callback/{provider}`
- `POST /auth/logout`

### Scan
- `POST /scan/upload` (multipart)
- `POST /scan/repo` (JSON: repo_url + model)
- `GET /scan/{scan_id}`

### History
- `GET /history`
- `GET /history/{scan_id}`

### Export
- `GET /scan/{scan_id}/report.json`
- `GET /scan/{scan_id}/report.pdf`

> Keep the frontend and backend aligned by documenting exact schemas in `docs/api.md`.

---

## Request Lifecycle (Backend)

1. **Ingress**
   - Accept file uploads or repo URL.
2. **Ingestion & Normalization**
   - Extract/clone/fetch, filter by language, cap sizes, build file index.
3. **Heuristic Pass**
   - Run language-specific rules to produce exact line-based findings.
4. **ML Pass**
   - Chunk code → tokenize → infer with selected model.
5. **Hybrid Scoring**
   - Combine probabilities + rule severities; boost on critical hotspots.
6. **Explain & Remediate**
   - Generate developer-ready remediation guidance.
7. **Persist**
   - Store scan summary + findings in MongoDB.
8. **Respond**
   - Return JSON for UI; optionally render/export PDF.

---

## Deployment

### Hugging Face Spaces
- Hardware: CPU or GPU
- Configure Secrets:
  - MongoDB URI
  - OAuth keys
  - JWT secret
- Ensure CORS allows the Vercel domain.

---

## Operational Notes
- Rate limit scan endpoints (recommended)
- Enforce file limits & safe archive extraction
- Never execute scanned code
- Mask secrets in logs and reports
