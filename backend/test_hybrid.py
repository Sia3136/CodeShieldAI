"""
Quick tests for hybrid_detection.py rule engine.
Run with: python test_hybrid.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from hybrid_detection import rule_based_scan, compute_weighted_risk, merge_findings, override_generic_ml_finding

PASS = "\033[92m✅ PASS\033[0m"
FAIL = "\033[91m❌ FAIL\033[0m"
results = []

def check(name, condition, detail=""):
    status = PASS if condition else FAIL
    print(f"{status} {name}" + (f" — {detail}" if detail else ""))
    results.append(condition)

# ── Test 1: Kubernetes privileged container ──────────────────────────────────
k8s_yaml = """
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: bad-container
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /var/run/docker.sock
      name: docker-sock
"""
findings = rule_based_scan(k8s_yaml, "deployment.yaml")
cwe_ids = [f["cwe_id"] for f in findings]
check("K8s: privileged=true detected as CWE-284", "CWE-284" in cwe_ids)
check("K8s: docker.sock mount detected", any("docker.sock" in f.get("title","").lower() or "docker" in f.get("title","").lower() for f in findings))
check("K8s: at least one CRITICAL finding", any(f["severity"] == "CRITICAL" for f in findings))

# ── Test 2: Terraform public exposure ────────────────────────────────────────
tf_code = """
resource "aws_security_group_rule" "allow_all" {
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_db_instance" "main" {
  publicly_accessible = true
  encrypted           = false
}
"""
findings = rule_based_scan(tf_code, "main.tf")
cwe_ids = [f["cwe_id"] for f in findings]
check("Terraform: 0.0.0.0/0 detected", "CWE-284" in cwe_ids)
check("Terraform: publicly_accessible=true detected", any("publicly" in f.get("title","").lower() for f in findings))
check("Terraform: unencrypted storage detected", "CWE-311" in cwe_ids)

# ── Test 3: C++ buffer overflow ───────────────────────────────────────────────
cpp_code = """
#include <string.h>
void process(char *input) {
    char buf[64];
    strcpy(buf, input);   // dangerous
    printf(input);        // format string
    system("ls");         // command injection
}
"""
findings = rule_based_scan(cpp_code, "main.cpp")
cwe_ids = [f["cwe_id"] for f in findings]
check("C++: strcpy detected as CWE-120", "CWE-120" in cwe_ids)
check("C++: format string detected as CWE-134", "CWE-134" in cwe_ids)
check("C++: system() detected as CWE-78", "CWE-78" in cwe_ids)

# ── Test 4: C# SQL injection ──────────────────────────────────────────────────
cs_code = """
var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + userId, conn);
var reader = cmd.ExecuteReader();
var xmlDoc = new XmlDocument();
var formatter = new BinaryFormatter();
"""
findings = rule_based_scan(cs_code, "UserService.cs")
cwe_ids = [f["cwe_id"] for f in findings]
check("C#: SQL injection detected as CWE-89", "CWE-89" in cwe_ids)
check("C#: XXE risk detected as CWE-611", "CWE-611" in cwe_ids)
check("C#: BinaryFormatter detected as CWE-502", "CWE-502" in cwe_ids)

# ── Test 5: Ruby eval + YAML.load ─────────────────────────────────────────────
ruby_code = """
def run(input)
  eval(params[:code])
  data = YAML.load(user_input)
  User.update(params)
end
"""
findings = rule_based_scan(ruby_code, "controller.rb")
cwe_ids = [f["cwe_id"] for f in findings]
check("Ruby: eval detected as CWE-94", "CWE-94" in cwe_ids)
check("Ruby: YAML.load detected as CWE-502", "CWE-502" in cwe_ids)
check("Ruby: mass assignment detected as CWE-915", "CWE-915" in cwe_ids)

# ── Test 6: Generic JWT bypass ────────────────────────────────────────────────
jwt_code = """
const decoded = jwt.verify(token, secret, { algorithms: ['none'] });
const payload = jwt.decode(token, { verify: false });
"""
findings = rule_based_scan(jwt_code, "auth.js")
cwe_ids = [f["cwe_id"] for f in findings]
check("Generic: JWT alg=none detected as CWE-347", "CWE-347" in cwe_ids)

# ── Test 7: Weighted risk score ───────────────────────────────────────────────
mock_findings = [
    {"severity": "CRITICAL", "cwe_id": "CWE-78"},
    {"severity": "CRITICAL", "cwe_id": "CWE-89"},
    {"severity": "HIGH",     "cwe_id": "CWE-312"},
    {"severity": "MEDIUM",   "cwe_id": "CWE-22"},
]
score = compute_weighted_risk(mock_findings, ml_score=50.0)
check("Weighted score > 80 for mixed CRITICAL/HIGH findings", score > 80, f"score={score}")
check("Weighted score <= 100", score <= 100, f"score={score}")

# ── Test 8: Generic ML finding override ──────────────────────────────────────
generic_finding = {
    "type": "Code Quality & Security Concerns",
    "severity": "CRITICAL",
    "description": "ML model flagged this code with 99% confidence.",
    "fix": "Review concerns.",
    "line": 1,
}
rule_f = [{"cwe_id": "CWE-78", "title": "Command Injection", "severity": "CRITICAL", "line": 5, "content": "os.system(cmd)", "description": "...", "fix": "..."}]
overridden = override_generic_ml_finding(generic_finding, rule_f)
check("Generic ML finding replaced by rule finding", overridden.get("cwe_id") == "CWE-78")

no_rule_overridden = override_generic_ml_finding(generic_finding, [])
check("Generic ML finding downgraded to LOW when no rule confirms", no_rule_overridden.get("severity") == "LOW")
check("Downgraded finding labeled 'ML Anomaly (Unconfirmed)'", no_rule_overridden.get("type") == "ML Anomaly (Unconfirmed)")

# ── Test 9: Secure code produces no findings ──────────────────────────────────
secure_code = """
const express = require('express');
const crypto = require('crypto');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
app.get('/user/:id', async (req, res) => {
  const query = "SELECT * FROM users WHERE id = ?";
  const results = await db.query(query, [userId]);
  res.json(results);
});
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}
"""
findings = rule_based_scan(secure_code, "server.js")
check("Secure code: no CRITICAL findings", not any(f["severity"] == "CRITICAL" for f in findings),
      f"found: {[f['title'] for f in findings if f['severity']=='CRITICAL']}")

# ── Summary ───────────────────────────────────────────────────────────────────
passed = sum(results)
total = len(results)
print(f"\n{'='*50}")
print(f"Results: {passed}/{total} tests passed")
if passed == total:
    print("\033[92mAll tests passed! ✅\033[0m")
else:
    print(f"\033[91m{total - passed} test(s) failed ❌\033[0m")
    sys.exit(1)
