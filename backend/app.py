from contextlib import asynccontextmanager
from fastapi import FastAPI, Body, HTTPException, Query
import os
import torch
from typing import Dict, Any
from datetime import datetime, timedelta
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import certifi
from pydantic import BaseModel
import uuid
import re
from typing import Dict, Any, List, Optional
from auth import UserCreate, UserLogin, create_access_token, get_password_hash, verify_password, verify_token
from github_auth import generate_oauth_url, exchange_code_for_token as github_exchange_code, encrypt_token, decrypt_token, get_user_repositories, get_repository_branches, GitHubAuthError
from google_auth import generate_google_oauth_url, exchange_code_for_token as google_exchange_code, GoogleAuthError
from hybrid_detection import rule_based_scan, compute_weighted_risk, merge_findings
from repo_scanner import RepositoryScanner, parse_github_url, RepositoryScannerError

import json
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import numpy as np

class CodeRequest(BaseModel):
    code: str
    model: str = "GraphCodeBERT"

class RepositoryScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    file_patterns: Optional[List[str]] = None
    model: str = "GraphCodeBERT"
    access_token: Optional[str] = None

# ── Model Configuration ──
MODEL_REGISTRY = {
    "GraphCodeBERT": "models/graphcodebert",
    "CodeBERT": "models/codebert"
}
DEFAULT_MODEL = "GraphCodeBERT"

class VulnerabilityScanner:
    def __init__(self, model_display_name: str):
        self.model_name = model_display_name
        self.path = MODEL_REGISTRY[model_display_name]
        
        print(f"[ML] Loading {model_display_name} from {self.path}...")
        self.tokenizer = AutoTokenizer.from_pretrained(self.path)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.path)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        self.model.eval()
        
        # Load local config
        config_path = os.path.join(self.path, "model_config.json")
        with open(config_path, "r") as f:
            self.config = json.load(f)
        
        self.threshold = self.config.get("threshold", 0.5)
        print(f"[ML] {model_display_name} loaded (Threshold: {self.threshold})")

    def scan(self, code: str) -> Dict[str, Any]:
        inputs = self.tokenizer(
            code, 
            return_tensors="pt", 
            truncation=True, 
            max_length=self.config.get("max_length", 512),
            padding=True
        ).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)
            # Assuming binary classification: [Clean, Vulnerable]
            score = probs[0][1].item() * 100
        
        is_vulnerable = (score / 100.0) >= self.threshold
        
        return {
            "vulnerable": is_vulnerable,
            "score": round(score, 2),
            "risk_level": self.get_risk_level(score),
            "model_used": self.model_name
        }

    def get_risk_level(self, score: float) -> str:
        if score > 80: return "Critical"
        if score > 60: return "High"
        if score > 40: return "Medium"
        return "Low"

class ModelManager:
    def __init__(self):
        self._scanners = {}

    def get_scanner(self, model_name: str) -> VulnerabilityScanner:
        if model_name not in MODEL_REGISTRY:
            model_name = DEFAULT_MODEL
            
        if model_name not in self._scanners:
            self._scanners[model_name] = VulnerabilityScanner(model_name)
        return self._scanners[model_name]

    def is_loaded(self, model_name: str) -> bool:
        return model_name in self._scanners

# Initialize global manager
model_manager = ModelManager()

load_dotenv()

app = FastAPI(title="CodeShield AI Backend")
from fastapi.middleware.cors import CORSMiddleware

# Get origins from environment variable or default to localhost
FRONTEND_URL = os.getenv("FRONTEND_URL", "").strip()
allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    # Production Vercel deployment (explicit)
    "https://code-shield-ai-brown.vercel.app",
]
if FRONTEND_URL and FRONTEND_URL not in allowed_origins:
    allowed_origins.append(FRONTEND_URL)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    # Allow any Vercel preview deployments AND Hugging Face space previews
    allow_origin_regex=r"https://(.*\.vercel\.app|.*\.hf\.space)",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# ── Environment ──
load_dotenv()

# Print critical env status (sanitized)
print(f"[ENV] FRONTEND_URL: {FRONTEND_URL}")
print(f"[ENV] MONGO_URI present: {'Yes' if os.getenv('MONGO_URI') else 'No'}")
print(f"[ENV] JWT_SECRET present: {'Yes' if os.getenv('JWT_SECRET_KEY') else 'No'}")

# MongoDB connection
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/codeshield_db")
client = None
db = None
scans_collection = None
users_collection = None
github_tokens_collection = None
repository_scans_collection = None

# Email config
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "").strip()
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "").strip()
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "").strip()
ALERT_THRESHOLD = 70.0

# Globals for lazy loading
clf = None
tokenizer = None
code_model = None
device = torch.device("cpu")

def connect_to_mongodb():
    global client, db, scans_collection, users_collection, github_tokens_collection, repository_scans_collection
    try:
        # Add SSL/TLS options for MongoDB Atlas with certifi
        client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=5000,
            tlsCAFile=certifi.where()  # Use certifi for SSL certificates
        )
        client.server_info()  # force connection test
        db = client["codeshield_db"]
        scans_collection = db["scan_results"]
        users_collection = db["users"]
        github_tokens_collection = db["github_tokens"]
        repository_scans_collection = db["repository_scans"]
        print("[DB] Successfully connected to MongoDB Atlas")
        print(f"[DB] Using database: codeshield_db | collections: scan_results, users, github_tokens, repository_scans")
    except ConnectionFailure as e:
        print(f"[DB ERROR] Failed to connect to MongoDB: {str(e)}")
        print("   → Check MONGO_URI in .env and MongoDB Atlas network access")
    except Exception as e:
        print(f"[DB CRITICAL] MongoDB setup failed: {str(e)}")

# ── Helper Functions ──

def get_embedding(code: str) -> np.ndarray:
    if not isinstance(code, str) or not code.strip():
        return np.zeros(768, dtype=np.float32)
    try:
        inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512, padding=True)
        inputs = {k: v.to(device) for k, v in inputs.items()}
        with torch.no_grad():
            outputs = code_model(**inputs)
        emb = outputs.last_hidden_state.mean(dim=1).squeeze().cpu().numpy()
        return emb
    except Exception as e:
        print(f"[Embedding ERROR] {str(e)}")
        return np.zeros(768, dtype=np.float32)

def get_severity(score: float) -> str:
    if score > 80: return "Critical"
    if score > 60: return "High"
    if score > 40: return "Medium"
    return "Low"

def explain_prediction(code: str, is_vulnerable: bool, score: float) -> List[Dict[str, Any]]:
    if not is_vulnerable:
        return []

    lines = code.splitlines()
    vulnerabilities = []
    
    # Advanced pattern mapping with targeted fixes
    patterns = {
        r'pickle\.loads|pickle\.load|joblib\.load': ('CRITICAL', 'Insecure Deserialization', 
            'Picking or loading untrusted data can lead to Remote Code Execution.',
            'Use JSON or another safe serialization format. For joblib, ensure the source is trusted.'),
        r'yaml\.load\s*\(': ('HIGH', 'Insecure YAML Loading', 
            'Loading YAML without a safe loader can lead to code execution.',
            'Use yaml.safe_load() instead of yaml.load().'),
        r'os\.system\s*\(|subprocess\.call\s*\(|subprocess\.run\s*\(.*shell\s*=\s*True': ('HIGH', 'Command Injection', 
            'Direct system calls or shell=True can lead to OS command injection.',
            'Use subprocess.run with arguments as a list: subprocess.run(["ls", "-l", path])'),
        r'exec\s*\(|eval\s*\(': ('CRITICAL', 'Arbitrary Code Execution', 
            'Execution of arbitrary strings as code is extremely dangerous.',
            'Avoid dynamic code execution. Use safer alternatives like literal_eval for data.'),
        r'(SELECT|INSERT|UPDATE|DELETE).*FROM.*WHERE.*(\%|\+|\{)': ('HIGH', 'Potential SQL Injection', 
            'Using string formatting or concatenation for SQL queries is a major risk.',
            'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'),
        r'(password|api_key|secret|token|passphrase|access_token)\s*=\s*[\'\"].+[\'\"]': ('HIGH', 'Hardcoded Credential', 
            'A hardcoded secret was detected in the source code.',
            'Use environment variables: os.getenv("API_KEY") or a secret manager.'),
        r'jwt\.decode\(.*verify\s*=\s*False\)': ('CRITICAL', 'Insecure JWT Validation', 
            'JWT signature verification is disabled.',
            'Always enable signature verification: jwt.decode(token, key, algorithms=["HS256"])'),
    }

    for i, line in enumerate(lines):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith('#') or line_clean.startswith('//'):
            continue

        for pattern, (severity, vuln_type, desc, fix) in patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                vulnerabilities.append({
                    "line": i + 1,
                    "content": line_clean,
                    "severity": severity,
                    "type": vuln_type,
                    "description": desc,
                    "fix": fix
                })
                break
    
    if not vulnerabilities and (is_vulnerable or score >= 35.0):
        vulnerabilities.append({
            "line": 1,
            "content": "Overall code structure (ML Prediction)",
            "severity": get_severity(score),
            "type": "Deep Learning Risk Assessment",
            "description": f"The neural network detected Semantic Risk Patterns with {score:.1f}% confidence.",
            "fix": "Conduct a manual review. The code may be semantically similar to vulnerable codebases."
        })

    return vulnerabilities

def apply_heuristic_boost(code: str, original_score: float) -> float:
    """Boosts the score if known dangerous combinations exist."""
    lower_code = code.lower()
    boosted_score = original_score

    # Rule: Pickle + System/Subprocess = Guaranteed RCE
    if ("pickle" in lower_code or "__reduce__" in lower_code) and "os.system" in lower_code:
        boosted_score = max(boosted_score, 98.5)
    
    # Rule: f-string or concat in SQL execute
    if "execute" in lower_code and ("f\"" in lower_code or "f'" in lower_code or "+" in lower_code):
        if "select" in lower_code or "where" in lower_code:
            boosted_score = max(boosted_score, 85.0)

    # Rule: Hardcoded passwords/keys
    if any(kw in lower_code for kw in ["api_key =", "password =", "secret ="]) and len(lower_code) < 500:
        boosted_score = max(boosted_score, 75.0)

    return min(boosted_score, 100.0)

def suggest_fix(code: str) -> str:
    lower = code.lower()
    if "select" in lower and any(op in lower for op in ["+", "'", '"']):
        return "Use parameterized queries:\ncursor.execute('SELECT ... = ?', (value,))"
    if "password =" in lower:
        return "Use environment variables:\nimport os\npassword = os.getenv('DB_PASS')"
    if "pickle.load" in lower or "pickle.loads" in lower:
        return "Avoid pickle on untrusted data — use JSON instead"
    if any(x in lower for x in ["os.system", "exec(", "eval("]):
        return "Never pass user input to exec/eval/os.system"
    return "No obvious fix detected — review manually"

def send_email_alert(code: str, score: float, severity: str, highlights: str):
    if score < ALERT_THRESHOLD or not all([EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECEIVER]):
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECEIVER
        msg['Subject'] = f"CodeShield AI ALERT: {severity} Vulnerability ({score}% risk)"

        body = f"""URGENT: High-risk code detected!

Severity: {severity}
Risk Score: {score}%

Code:
{code[:500]}{"..." if len(code)>500 else ""}

Highlights:
{highlights}

Review immediately!
CodeShield AI
"""
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        print("[EMAIL] Alert sent successfully")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {str(e)}")
        return False

def save_scan_to_db(code: str, result: Dict, email_sent: bool, user_email: str = None):
    try:
        scan_doc = {
            "scan_time": datetime.utcnow().isoformat(),
            "code_snippet": code,
            "vulnerable": result["vulnerable"],
            "risk_score": result["score"],
            "severity": result["severity"],
            "highlights": result["highlights"],
            "suggested_fix": result.get("suggested_fix", ""),
            "email_sent": email_sent,
            "user_email": user_email,
        }
        insert_result = scans_collection.insert_one(scan_doc)
        print(f"[DB] Scan saved → _id: {insert_result.inserted_id} | user: {user_email or 'anonymous'}")
    except Exception as e:
        print(f"[DB ERROR] Save failed: {str(e)}")

# ── Lifespan (startup) ──
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[STARTUP] Connecting to MongoDB...")
    try:
        connect_to_mongodb()
    except Exception as e:
        print(f"[STARTUP WARNING] MongoDB connection failed but continuing: {e}")
    yield
    try:
        if client:
            client.close()
            print("[SHUTDOWN] MongoDB connection closed")
    except Exception:
        pass

app.router.lifespan_context = lifespan

@app.get("/")
def root():
    db_status = "Connected" if scans_collection is not None else "Not connected"
    return {"message": "CodeShield AI Backend", "db_status": db_status}

@app.post("/scan")
async def scan_code(request: CodeRequest, token: str = None):
    code = request.code
    selected_model = request.model # "GraphCodeBERT", "CodeBERT"

    # Resolve user email from token (if provided)
    user_email = None
    if token:
        try:
            user_email = verify_token(token)
        except:
            pass # Continue as anonymous

    code = code.strip()
    if not code:
        return {"vulnerable": False, "score": 0.0, "message": "Empty code"}

    print(f"[DEBUG] Request Model: {selected_model} | Code len: {len(code)}")

    try:
        # 1. Get appropriate scanner
        scanner = model_manager.get_scanner(selected_model)
        
        # 2. Perform ML Scan
        ml_result = scanner.scan(code)
        ml_score = ml_result["score"]
        
        # 3. Perform Rule-based Scan (Heuristics)
        rule_findings = rule_based_scan(code)
        
        # 4. Compute Final Weighted Risk
        final_score = compute_weighted_risk(rule_findings, ml_score)
        
        # Threshold: if rules find something or ML score is high
        is_vuln = final_score > 35.0 or ml_result["vulnerable"]
        severity = get_severity(final_score)

        # 5. Explanation and Fix
        # We can extract rule titles for better highlights
        rule_highlights = "\n".join([f"- {f['title']} ({f['severity']}) at line {f['line']}" for f in rule_findings[:5]])
        ml_highlights = explain_prediction(code, is_vuln, final_score)
        
        highlights = f"{ml_highlights}\n\nRule Findings:\n{rule_highlights if rule_highlights else 'No specific rules triggered.'}"
        fix = suggest_fix(code) if is_vuln else ""

        result = {
            "vulnerable": is_vuln,
            "score": final_score,
            "severity": severity,
            "highlights": highlights, # Now a list of objects
            "suggested_fix": fix,
            "model_used": ml_result["model_used"]
        }

        # Email alert if high risk
        email_sent = send_email_alert(code, final_score, severity, highlights)

        # Save to MongoDB
        if scans_collection is not None:
            save_scan_to_db(code, result, email_sent, user_email)

        return result

    except Exception as e:
        print(f"[scan ERROR] {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


# ── Repository Scanning Endpoints ──

def scan_single_file(file_info: Dict, model_name: str) -> Dict:
    """Helper function to scan a single file from repository"""
    try:
        path = file_info["absolute_path"]
        if not os.path.exists(path):
            return {"file_path": file_info["path"], "status": "error", "error": "File not found"}
            
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(1024 * 512) # Read first 512KB
        
        if not content:
            return {"file_path": file_info["path"], "status": "skipped", "reason": "File empty"}
        
        # Simple scan logic for file
        scanner = model_manager.get_scanner(model_name)
        ml_result = scanner.scan(content)
        rule_findings = rule_based_scan(content)
        final_score = compute_weighted_risk(rule_findings, ml_result["score"])
        
        is_vuln = final_score > 40.0
        
        return {
            "file_path": file_info["path"],
            "status": "scanned",
            "risk_score": final_score,
            "vulnerable": is_vuln,
            "highlights": explain_prediction(content, is_vuln, final_score),
            "suggested_fix": suggest_fix(content) if is_vuln else ""
        }
    except Exception as e:
        return {"file_path": file_info["path"], "status": "error", "error": str(e)}

@app.post("/scan/repository")
async def scan_repository(request: RepositoryScanRequest, token: Optional[str] = Query(None)):
    scan_id = str(uuid.uuid4())
    user_email = None
    if token:
        try: user_email = verify_token(token)
        except: pass

    try:
        repo_info = parse_github_url(request.repo_url)
        with RepositoryScanner() as scanner:
            clone_path = scanner.clone_repository(request.repo_url, branch=request.branch, access_token=request.access_token)
            files = scanner.get_files_by_pattern(clone_path, patterns=request.file_patterns)
            
            if not files:
                return {"scan_id": scan_id, "status": "completed", "total_files": 0}
            
            file_results = [scan_single_file(f, request.model) for f in files[:50]] # Limit to 50 files for now
            scanned = [r for r in file_results if r["status"] == "scanned"]
            vuln_count = sum(1 for r in scanned if r["vulnerable"])
            avg_risk = sum(r["risk_score"] for r in scanned) / len(scanned) if scanned else 0
            
            scan_result = {
                "scan_id": scan_id,
                "repository": repo_info["full_name"],
                "scan_time": datetime.utcnow().isoformat(),
                "total_files": len(files),
                "vulnerable_files": vuln_count,
                "overall_risk_score": round(avg_risk, 1),
                "file_results": file_results,
                "status": "completed",
                "user_email": user_email
            }
            
            if repository_scans_collection is not None:
                repository_scans_collection.insert_one(scan_result.copy())
            
            return scan_result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/scan/repository/{scan_id}")
async def get_repo_scan(scan_id: str):
    if repository_scans_collection is None: raise HTTPException(status_code=503, detail="DB Error")
    scan = repository_scans_collection.find_one({"scan_id": scan_id}, {"_id": 0})
    if not scan: raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ── Auth Endpoints ──

@app.post("/auth/register")
async def register_user(user_data: UserCreate):
    print(f"[AUTH] Attempting to register: {user_data.email}")
    if users_collection is None:
        raise HTTPException(status_code=503, detail="Database not connected")
    existing = users_collection.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_pw = get_password_hash(user_data.password)
    user_doc = {
        "email": user_data.email,
        "password": hashed_pw, # Old field name
        "password_hash": hashed_pw, # New field name (consistent with auth.py)
        "name": user_data.name or user_data.email.split('@')[0],
        "auth_provider": "email",
        "created_at": datetime.utcnow().isoformat(),
        "last_login": None,
    }
    users_collection.insert_one(user_doc)
    token = create_access_token({"sub": user_data.email}, expires_delta=timedelta(hours=24))
    return {"access_token": token, "token_type": "bearer"}


@app.post("/auth/login")
async def login_user(user_data: UserLogin):
    print(f"[AUTH] Login attempt: {user_data.email}")
    if users_collection is None:
        raise HTTPException(status_code=503, detail="Database not connected")
    user = users_collection.find_one({"email": user_data.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Check both potential password field names (password or password_hash)
    stored_pw = user.get("password") or user.get("password_hash")
    if not stored_pw or not verify_password(user_data.password, stored_pw):
        print(f"[AUTH] Password mismatch or missing for: {user_data.email}")
        raise HTTPException(status_code=401, detail="Invalid email or password")
        
    users_collection.update_one({"email": user_data.email}, {"$set": {"last_login": datetime.utcnow().isoformat()}})
    token = create_access_token({"sub": user_data.email}, expires_delta=timedelta(hours=24))
    return {"access_token": token, "token_type": "bearer"}


@app.get("/auth/me")
async def get_current_user(token: str):
    email = verify_token(token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if users_collection is None:
        raise HTTPException(status_code=503, detail="Database not connected")
    user = users_collection.find_one({"email": email}, {"_id": 0, "password": 0, "github_token": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user["created_at"] = user.get("created_at", datetime.utcnow()).isoformat()
    user["last_login"] = user.get("last_login").isoformat() if user.get("last_login") else None
    return user


@app.get("/auth/github")
async def github_auth_init():
    try:
        result = generate_oauth_url()
        return {"auth_url": result["url"], "state": result["state"]}
    except GitHubAuthError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/auth/github/callback")
async def github_auth_callback(data: dict = Body(...)):
    code = data.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code required")
    if users_collection is None:
        raise HTTPException(status_code=503, detail="Database not connected")
    try:
        token_data = github_exchange_code(code)
        user_info = token_data["user"]
        email = user_info.get("email") or f"{user_info['login']}@github.com"
        encrypted_token = encrypt_token(token_data["access_token"])
        
        # Consistent user payload
        user_payload = {
            "email": email,
            "name": user_info.get("name") or user_info["login"],
            "username": user_info["login"],
            "avatar_url": user_info.get("avatar_url"),
            "auth_provider": "github",
            "github_token": encrypted_token,
            "last_login": datetime.utcnow().isoformat(),
        }
        
        users_collection.update_one(
            {"email": email},
            {"$set": user_payload, "$setOnInsert": {"created_at": datetime.utcnow().isoformat()}},
            upsert=True,
        )
        app_token = create_access_token({"sub": email}, expires_delta=timedelta(hours=24))
        return {
            "access_token": app_token,
            "token_type": "bearer",
            "user": {
                "email": email,
                "name": user_payload["name"],
                "username": user_payload["username"],
                "avatar_url": user_payload["avatar_url"],
                "auth_provider": "github",
            },
        }
    except GitHubAuthError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/auth/github/repositories")
async def get_repos(access_token: str):
    try:
        repos = get_user_repositories(access_token)
        return {"repositories": repos}
    except GitHubAuthError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/auth/github/branches")
async def get_branches(repo_full_name: str, access_token: str):
    try:
        branches = get_repository_branches(access_token, repo_full_name)
        return {"branches": branches}
    except GitHubAuthError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/auth/github/token")
async def get_github_token(token: str):
    email = verify_token(token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if users_collection is None:
        raise HTTPException(status_code=503, detail="Database not connected")
    user = users_collection.find_one({"email": email})
    if not user or "github_token" not in user:
        raise HTTPException(status_code=404, detail="GitHub token not found for this user")
    return {"access_token": decrypt_token(user["github_token"])}


@app.get("/auth/google")
async def google_auth_init():
    try:
        result = generate_google_oauth_url()
        return {"auth_url": result["url"]}
    except GoogleAuthError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/auth/google/callback")
async def google_auth_callback(data: dict = Body(...)):
    code = data.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code required")
    if users_collection is None:
        raise HTTPException(status_code=503, detail="Database not connected")
    try:
        token_data = google_exchange_code(code)
        user_info = token_data["user"]
        email = user_info.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Email not provided by Google")
        
        user_payload = {
            "email": email,
            "name": user_info.get("name", ""),
            "avatar_url": user_info.get("picture"),
            "auth_provider": "google",
            "last_login": datetime.utcnow().isoformat(),
        }
        
        users_collection.update_one(
            {"email": email},
            {"$set": user_payload, "$setOnInsert": {"created_at": datetime.utcnow().isoformat()}},
            upsert=True,
        )
        app_token = create_access_token({"sub": email}, expires_delta=timedelta(hours=24))
        return {
            "access_token": app_token,
            "token_type": "bearer",
            "user": {
                "email": email,
                "name": user_payload["name"],
                "avatar_url": user_payload["avatar_url"],
                "auth_provider": "google",
            },
        }
    except GoogleAuthError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Analytics Endpoints ──

@app.get("/analytics/detailed")
async def get_analytics_detailed(token: str = None):
    if scans_collection is None:
        raise HTTPException(status_code=503, detail="Database not connected")
    try:
        query = {}
        if token:
            email = verify_token(token)
            if email:
                query["user_email"] = email

        scans = list(scans_collection.find(query).sort("scan_time", -1).limit(500))
        total_scans = len(scans)
        total_vulnerabilities = sum(1 for s in scans if s.get("vulnerable"))

        # Vulnerability distribution from pattern keywords in highlights string
        from collections import defaultdict
        vuln_counts = defaultdict(int)
        PATTERN_NAMES = [
            ("pickle.loads", "Insecure Deserialization"),
            ("__reduce__", "Malicious Pickle Payload"),
            ("os.system", "Command Injection"),
            ("exec(", "Arbitrary Code Execution"),
            ("eval(", "Dynamic Code Evaluation"),
            ("SELECT", "SQL Injection"),
            ("password =", "Hardcoded Credentials"),
            ("api_key =", "Hardcoded Credentials"),
        ]
        for scan in scans:
            highlights = scan.get("highlights", [])
            snippet = scan.get("code_snippet", "")
            
            # Check snippet and highlights list
            found_patterns = set()
            for pattern, name in PATTERN_NAMES:
                # Check snippet
                if pattern in snippet:
                    found_patterns.add(name)
                # Check structured highlights if it's a list
                if isinstance(highlights, list):
                    for h in highlights:
                        content = h.get("content", "")
                        if pattern in content:
                            found_patterns.add(name)
                # Fallback for old string format
                elif isinstance(highlights, str) and pattern in highlights:
                    found_patterns.add(name)
            
            for name in found_patterns:
                vuln_counts[name] += 1
        vulnerability_distribution = [
            {"name": k, "value": v}
            for k, v in sorted(vuln_counts.items(), key=lambda x: -x[1])
        ]

        # Scan timeline — last 10 days
        now = datetime.utcnow()
        timeline = {}
        for i in range(10):
            date = (now - timedelta(days=i)).strftime("%Y-%m-%d")
            timeline[date] = {"date": date, "total": 0, "vulnerable": 0, "clean": 0}
        for scan in scans:
            scan_time = scan.get("scan_time")
            if not scan_time:
                continue
            
            date = None
            if isinstance(scan_time, datetime):
                date = scan_time.strftime("%Y-%m-%d")
            elif isinstance(scan_time, str):
                try:
                    # Handle ISO string YYYY-MM-DD...
                    date = scan_time.split("T")[0]
                except:
                    continue
            
            if date and date in timeline:
                timeline[date]["total"] += 1
                if scan.get("vulnerable"):
                    timeline[date]["vulnerable"] += 1
                else:
                    timeline[date]["clean"] += 1
        scan_timeline = list(reversed(list(timeline.values())))

        # Risk distribution
        risk_dist = {"0-25 (Low)": 0, "26-50 (Medium)": 0, "51-75 (High)": 0, "76-100 (Critical)": 0}
        for scan in scans:
            score = scan.get("risk_score") or 0
            if score <= 25:
                risk_dist["0-25 (Low)"] += 1
            elif score <= 50:
                risk_dist["26-50 (Medium)"] += 1
            elif score <= 75:
                risk_dist["51-75 (High)"] += 1
            else:
                risk_dist["76-100 (Critical)"] += 1
        risk_distribution = [{"range": k, "count": v} for k, v in risk_dist.items()]

        return {
            "vulnerability_distribution": vulnerability_distribution,
            "scan_timeline": scan_timeline,
            "risk_distribution": risk_distribution,
            "top_vulnerable_files": [],
            "model_performance": [],
            "security_trend": [],
            "confidence_distribution": [],
            "total_scans": total_scans,
            "total_vulnerabilities": total_vulnerabilities,
        }
    except Exception as e:
        print(f"[Analytics ERROR] {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to compute analytics")


@app.get("/analytics/scan-history")
async def get_scan_history(limit: int = 20, token: str = None):
    if scans_collection is None:
        raise HTTPException(status_code=503, detail="Database not connected")
    try:
        query = {}
        if token:
            email = verify_token(token)
            if email:
                query["user_email"] = email

        scans = list(
            scans_collection.find(query, {"_id": 0, "email_sent": 0})
            .sort("scan_time", -1)
            .limit(limit)
        )
        total = scans_collection.count_documents(query)

        for scan in scans:
            if isinstance(scan.get("scan_time"), datetime):
                scan["scan_time"] = scan["scan_time"].isoformat()

        return {"scans": scans, "total": total}
    except Exception as e:
        print(f"[Analytics ERROR] {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch scan history")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 7860))
    uvicorn.run("app:app", host="0.0.0.0", port=port)