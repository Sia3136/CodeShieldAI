# CodeShieldAI — AI-Powered Multi‑Layer Vulnerability Detection

Secure your code with **Transformer-based semantic analysis** and **deterministic multi-language heuristics**.

CodeShieldAI is a full-stack application security scanning platform that bridges traditional static analysis and modern deep learning. It combines **fine‑tuned GraphCodeBERT / CodeBERT** with a robust **Multi‑Language Heuristic Engine** to deliver high-confidence vulnerability detection across **8+ languages**.

---

## Quick Links (Component READMEs)
- **Backend** → [backend/README.md](backend/README.md)
- **Frontend** → [frontend/README.md](frontend/README.md)
- **ML / Models** → [ml/README.md](ml/README.md)
- **Heuristic Engine / Rules** → [rules/README.md](rules/README.md)
- **Docs (Architecture / API / Ops)** → [docs/README.md](docs/README.md)

---

## Product Overview

CodeShieldAI is a hybrid vulnerability detection platform that:
- **understands intent** using transformer models (GraphCodeBERT / CodeBERT),
- **verifies critical hotspots** using deterministic rules (multi-language),
- merges both into a **hybrid risk score** with confidence and explainability.

The platform supports:
- scanning uploaded files,
- scanning public GitHub repositories (OAuth connect or paste URL),
- viewing scan history and analytics,
- downloading a professional PDF report.

---

## Key Features

- **Hybrid Detection Pipeline**
  - Transformer Logic Layer (GraphCodeBERT / CodeBERT)
  - Deterministic Heuristic Layer (8+ languages)
  - Hybrid Scoring with boost/rollback logic for critical rule hits

- **Repository Scanning**
  - zero-config scanning of public GitHub repositories
  - scan by connect or by pasting a Git repo URL

- **File Upload Scanning**
  - scan individual files or batches

- **Model Comparison**
  - compare GraphCodeBERT vs CodeBERT results and confidence

- **Remediation Intelligence**
  - exact vulnerable line ranges
  - vulnerability type & severity
  - actionable fix recommendations and safer alternatives

- **History & Analytics**
  - scan history stored in MongoDB Atlas
  - dashboard insights across trends, densities, and distributions

- **Exportable Reports**
  - JSON report for automation
  - PDF report for audit/compliance sharing

---

## Supported Languages

**Rule Engine coverage:**
- Python
- Java
- C
- JavaScript / TypeScript
- PHP
- Node.js
- C++
- SQL

**ML layer:** can generalize beyond these depending on tokenization and training distribution, but deterministic guarantees focus on the above.

---

## How It Works (Hybrid Workflow)

### 1) Transformer Logic Layer (Deep Learning)
**Models:** fine‑tuned GraphCodeBERT and CodeBERT  
**Strength:** detects complex logic flaws and data-flow issues by learning vulnerable semantics from large corpora.

### 2) Heuristic Pattern Layer (Deterministic Rules)
**Strength:** instant, deterministic detection of known high-risk hotspots (e.g., `eval`, command injection sinks, unsafe deserialization, common XXE patterns, SQLi construction patterns).

### 3) Hybrid Scoring (Boost / Rollback Logic)
If a high-severity deterministic rule matches, it can **boost** ML results to ensure critical vulnerabilities are not missed due to model uncertainty.

---

## Architecture

### System Architecture

<img width="2816" height="1536" alt="Gemini_Generated_Image_ozt9bqozt9bqozt9" src="https://github.com/user-attachments/assets/50672b7a-a92e-4cec-9c12-c5efcd325428" />

---

### ML Inference Architecture

<img width="2816" height="1536" alt="Gemini_Generated_Image_ly4dmcly4dmcly4d" src="https://github.com/user-attachments/assets/f335aba6-0ab9-4149-964e-63ae14df715a" />

---

## Dashboard & Analytics

The dashboard provides a professional security overview including:
- KPIs (risk score, total vulnerabilities, scan duration, confidence)
- vulnerability type distribution (pie chart)
- vulnerability density by file type
- top 5 vulnerability types
- top 10 most vulnerable files
- last 5 days activity (line chart)
- risk score distribution (column chart)
- detection confidence distribution
- model comparison: GraphCodeBERT vs CodeBERT
- insights derived from all charts and scan results

---

## Reports & Outputs

A scan produces:
- overall **risk score** and **severity**
- **total vulnerabilities**
- **scan duration**
- severity breakdown (**critical/high/medium/low**)
- per-file findings with:
  - vulnerability type/category
  - confidence
  - exact file and line ranges
  - remediation guidance
- export:
  - **JSON report**
  - **PDF report**

---

## Installation & Local Development (Monorepo)

> Detailed steps live in each component README. This section is intentionally short.

### Prerequisites
- Node.js 18+
- Python 3.10+
- MongoDB Atlas URI (or local MongoDB)
- GitHub + Google OAuth credentials (for auth features)

### Run (dev)
- Backend: `cd backend && uvicorn app.main:app --reload --port 8000`
- Frontend: `cd frontend && npm i && npm run dev`

---

## Dataset & Training Summary

Fine-tuning dataset: merged splits of:
- DiverseVul, Devign, ReVeal, BigVul, CrossVul, CVEfixes

Size:
- ~50k samples
- ~33k vulnerable, ~17k safe
