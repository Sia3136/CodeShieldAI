# CodeShieldAI Frontend (React + Vite + TypeScript)

A professional dashboard UI for:
- initiating scans (upload / repo connect / paste URL)
- viewing KPIs and analytics charts
- exploring findings with exact line ranges
- comparing GraphCodeBERT vs CodeBERT
- exporting PDF reports
- viewing scan history

---

## Tech Stack
- React + Vite + TypeScript
- Tailwind CSS
- Framer Motion
- Charting (your chosen library)
- OAuth-aware routing / protected pages

---

## Quickstart

### Prerequisites
- Node.js 18+

### Install & Run
```bash
cd frontend
npm install
npm run dev
```

### Environment
Create `frontend/.env`:
```bash
VITE_API_BASE_URL=http://localhost:8000
```

---

## UI Modules (Suggested)
- **Landing Page** (marketing)
- **Auth** (OAuth redirect handling)
- **Dashboard**
  - KPI tiles
  - vulnerability type distribution (pie)
  - vulnerability density by file type
  - top 5 vulnerability types
  - top 10 most vulnerable files
  - last 5 days activity (line)
  - risk score distribution (columns)
  - detection confidence distribution
  - model comparison graph (GraphCodeBERT vs CodeBERT)
- **Scan**
  - upload
  - connect GitHub
  - paste repo URL
- **History**
  - prior scans and drill-down
- **Report**
  - JSON view + PDF download button

---

## Deployment (Vercel)
- Set `VITE_API_BASE_URL` to the deployed backend URL.
- Ensure OAuth callback URLs are configured for the Vercel domain.
