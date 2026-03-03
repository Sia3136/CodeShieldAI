CodeShieldAI Backend (FastAPI)
Secure scanning orchestration + auth + reporting.

This service powers:

OAuth login (GitHub/Google)
repo/file ingestion
heuristic + ML orchestration
hybrid scoring
report generation (JSON + PDF)
history persistence (MongoDB Atlas)
Quickstart
Prerequisites
Python 3.10+
(Optional) CUDA runtime if using GPU inference
MongoDB Atlas URI (or local MongoDB)
Install
cd backend
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
Run (dev)
uvicorn app.main:app --reload --port 80
