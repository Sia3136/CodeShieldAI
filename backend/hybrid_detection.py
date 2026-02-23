"""
Hybrid Detection Engine for CodeShieldAI
=========================================
Rule-based vulnerability detection layer that wraps the ML model.
Covers: IaC (Kubernetes/Terraform/Docker), C/C++, C#, Ruby, dependency files,
        and generic patterns (JWT, secrets, path traversal, SSRF, etc.)

This module is intentionally independent of the ML model so it can be
tested and extended without touching the ML pipeline.
"""

import re
from typing import List, Dict, Any, Optional

# ---------------------------------------------------------------------------
# Severity weights for risk score calculation
# ---------------------------------------------------------------------------
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def rule_based_scan(code: str, filename: str = "snippet") -> List[Dict[str, Any]]:
    """
    Run all applicable rule engines on the given code.

    Returns a list of finding dicts:
        {
            "cwe_id":      str,   e.g. "CWE-78"
            "title":       str,   short human-readable title
            "severity":    str,   CRITICAL | HIGH | MEDIUM | LOW
            "line":        int,   1-based line number (best-effort)
            "content":     str,   the offending line / snippet
            "description": str,   explanation
            "fix":         str,   remediation advice
            "source":      str,   "rule-engine"
        }
    """
    if not code or not code.strip():
        return []

    fname_lower = filename.lower()
    findings: List[Dict[str, Any]] = []

    # --- Route by file type ---
    if _is_iac_file(fname_lower):
        findings.extend(_scan_iac(code, fname_lower))

    if _is_cpp_file(fname_lower):
        findings.extend(_scan_cpp(code))

    if _is_csharp_file(fname_lower):
        findings.extend(_scan_csharp(code))

    if _is_ruby_file(fname_lower):
        findings.extend(_scan_ruby(code))

    if _is_dependency_file(fname_lower):
        findings.extend(_scan_dependency_file(code, fname_lower))

    if _is_java_file(fname_lower):
        findings.extend(_scan_java(code))

    if _is_go_file(fname_lower):
        findings.extend(_scan_go(code))

    if _is_php_file(fname_lower):
        findings.extend(_scan_php(code))

    # Generic rules apply to ALL file types
    findings.extend(_scan_generic(code, fname_lower))

    # Deduplicate: same cwe_id + line (keep first occurrence)
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("cwe_id", ""), f.get("line", 0))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Second pass: remove findings whose title is a substring of another
    # finding on the same line (e.g. "OS Command Injection" vs "Command Injection")
    final = []
    for i, f in enumerate(unique):
        title_i = f.get("title", "").lower()
        line_i  = f.get("line", 0)
        dominated = False
        for j, g in enumerate(unique):
            if i == j:
                continue
            title_j = g.get("title", "").lower()
            line_j  = g.get("line", 0)
            # If same line and one title contains the other, keep the longer/more specific one
            if line_i == line_j and title_i != title_j:
                if title_i in title_j:          # f is a substring of g → drop f
                    dominated = True
                    break
        if not dominated:
            final.append(f)

    return final


def compute_weighted_risk(findings: List[Dict[str, Any]], ml_score: float = 0.0) -> float:
    """
    Compute a weighted risk score from confirmed findings only.
    ML Anomaly (Unconfirmed) findings are EXCLUDED from scoring.

    Formula:
        base  = (sum of severity weights / max_possible) * 100
        bonus = +15 if any CRITICAL, +8 if any HIGH (not already CRITICAL)
        ml    = ml_score contributes up to 20% when rule findings exist

    Returns a float 0–100.
    """
    # Exclude ML Anomaly observations from scoring
    real_findings = [
        f for f in findings
        if f.get("type") != "ML Anomaly (Unconfirmed)"
        and f.get("source") != "ml-anomaly"
    ]

    if not real_findings:
        # No confirmed findings — fall back to ML score (capped at 60)
        return min(ml_score, 60.0)

    total_weight = sum(SEVERITY_WEIGHTS.get(f.get("severity", "LOW"), 2) for f in real_findings)
    max_possible = len(real_findings) * SEVERITY_WEIGHTS["CRITICAL"]
    base_score = (total_weight / max_possible) * 100

    # Severity bonuses — applied after ratio so CRITICAL repos always score high
    severities = {f.get("severity", "LOW") for f in real_findings}
    if "CRITICAL" in severities:
        base_score = min(base_score + 15, 100)
    elif "HIGH" in severities:
        base_score = min(base_score + 8, 100)

    # Blend with ML score (ML gets 20% weight when rules also fired)
    blended = base_score * 0.80 + ml_score * 0.20
    return round(min(blended, 100.0), 1)


def separate_ml_observations(
    findings: List[Dict[str, Any]]
) -> tuple:
    """
    Split findings into two lists:
      - confirmed: real rule-engine or specific ML findings
      - observations: ML Anomaly (Unconfirmed) items

    Returns (confirmed, observations)
    """
    confirmed = []
    observations = []
    for f in findings:
        if (
            f.get("type") == "ML Anomaly (Unconfirmed)"
            or f.get("source") == "ml-anomaly"
        ):
            observations.append(f)
        else:
            confirmed.append(f)
    return confirmed, observations


def merge_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicates findings by CWE and Line. 
    Keeps the one with higher severity if multiple occur on the same line.
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    merged = {}
    
    for f in findings:
        key = (f.get("cwe_id"), f.get("line"))
        if key not in merged:
            merged[key] = f
        else:
            current_sev = merged[key].get("severity", "LOW")
            new_sev = f.get("severity", "LOW")
            if severity_order.get(new_sev, 3) < severity_order.get(current_sev, 3):
                merged[key] = f
                
    return list(merged.values())


def override_generic_ml_finding(
    finding: Dict[str, Any],
    rule_findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    If the ML model returned a generic 'Code Quality & Security Concerns'
    finding, either:
      - Replace it with the most severe rule-engine finding (if one exists), or
      - Downgrade it to LOW with label 'ML Anomaly (Unconfirmed)' and mark
        source='ml-anomaly' so it is excluded from scoring and counts.

    Returns the (possibly modified) finding dict.
    """
    is_generic = (
        finding.get("type") == "Code Quality & Security Concerns"
        or "ML model flagged" in finding.get("description", "")
    )
    if not is_generic:
        return finding

    if rule_findings:
        # Pick the most severe rule finding to surface instead
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        best = min(rule_findings, key=lambda f: order.index(f.get("severity", "LOW")))
        return best

    # No rule confirmation — downgrade and tag as observation only
    return {
        **finding,
        "severity": "LOW",
        "type": "ML Anomaly (Unconfirmed)",
        "source": "ml-anomaly",
        "description": (
            "The ML model flagged this code but no specific vulnerability pattern "
            "was confirmed by the rule engine. Manual review recommended."
        ),
        "fix": "Manually review the code for security issues. No automated fix available.",
    }


def merge_findings(
    ml_findings: List[Dict[str, Any]],
    rule_findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Merge ML findings and rule-engine findings.
    - Override generic ML findings using rule engine results.
    - Append rule findings that are not already represented.
    """
    merged = []

    for mf in ml_findings:
        merged.append(override_generic_ml_finding(mf, rule_findings))

    # Add rule findings not already in merged (avoid duplicates by cwe_id+line)
    existing_keys = {(f.get("cwe_id", ""), f.get("line", 0)) for f in merged}
    for rf in rule_findings:
        key = (rf.get("cwe_id", ""), rf.get("line", 0))
        if key not in existing_keys:
            merged.append(rf)
            existing_keys.add(key)

    # Sort: CRITICAL first
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    merged.sort(key=lambda f: order.get(f.get("severity", "LOW"), 3))
    return merged


# ---------------------------------------------------------------------------
# File-type helpers
# ---------------------------------------------------------------------------

def _is_iac_file(fname: str) -> bool:
    return any(fname.endswith(ext) for ext in (
        ".yaml", ".yml", ".tf", ".hcl", ".dockerfile"
    )) or "dockerfile" in fname

def _is_cpp_file(fname: str) -> bool:
    return any(fname.endswith(ext) for ext in (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"))

def _is_csharp_file(fname: str) -> bool:
    return fname.endswith(".cs")

def _is_ruby_file(fname: str) -> bool:
    return fname.endswith(".rb") or fname in ("gemfile", "rakefile")

def _is_dependency_file(fname: str) -> bool:
    base = fname.split("/")[-1].split("\\")[-1]
    return base in (
        "requirements.txt", "requirements-dev.txt", "requirements_dev.txt",
        "gemfile", "gemfile.lock", "package.json", "package-lock.json",
        "pipfile", "pipfile.lock", "poetry.lock", "cargo.toml"
    ) or base.startswith("requirements") and base.endswith(".txt")


# ---------------------------------------------------------------------------
# IaC Scanner (Kubernetes, Terraform, Docker)
# ---------------------------------------------------------------------------

def _scan_iac(code: str, fname: str) -> List[Dict[str, Any]]:
    findings = []
    lines = code.splitlines()

    # ---- Kubernetes / Docker Compose YAML ----
    if fname.endswith((".yaml", ".yml")):
        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            if re.search(r'privileged\s*:\s*true', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-284", "Kubernetes Privileged Container", "CRITICAL", i, stripped,
                    "Running a container in privileged mode gives it full access to the host kernel, "
                    "enabling container escape and full host compromise.",
                    "Set `privileged: false` and use specific capabilities via `capabilities.add` only if needed."
                ))

            if re.search(r'hostNetwork\s*:\s*true', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-653", "Host Network Namespace Sharing", "HIGH", i, stripped,
                    "Using the host network namespace bypasses network isolation, "
                    "exposing all host network interfaces to the container.",
                    "Remove `hostNetwork: true`. Use Kubernetes NetworkPolicies for controlled access."
                ))

            if re.search(r'hostPID\s*:\s*true', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-653", "Host PID Namespace Sharing", "HIGH", i, stripped,
                    "Sharing the host PID namespace allows the container to see and signal all host processes.",
                    "Remove `hostPID: true`."
                ))

            if re.search(r'hostIPC\s*:\s*true', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-653", "Host IPC Namespace Sharing", "MEDIUM", i, stripped,
                    "Sharing the host IPC namespace allows inter-process communication with host processes.",
                    "Remove `hostIPC: true`."
                ))

            if re.search(r'docker\.sock', stripped):
                findings.append(_finding(
                    "CWE-284", "Docker Socket Mount", "CRITICAL", i, stripped,
                    "Mounting the Docker socket gives the container full control over the Docker daemon, "
                    "enabling container escape and full host compromise.",
                    "Never mount /var/run/docker.sock. Use a dedicated Docker-in-Docker sidecar with restricted permissions."
                ))

            if re.search(r'runAsUser\s*:\s*0\b', stripped):
                findings.append(_finding(
                    "CWE-250", "Container Running as Root (UID 0)", "HIGH", i, stripped,
                    "Running containers as root increases the blast radius of a container escape.",
                    "Set `runAsNonRoot: true` and `runAsUser` to a non-zero UID in the securityContext."
                ))

            if re.search(r'allowPrivilegeEscalation\s*:\s*true', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-269", "Privilege Escalation Allowed", "HIGH", i, stripped,
                    "Allowing privilege escalation lets processes gain more privileges than their parent.",
                    "Set `allowPrivilegeEscalation: false` in the container securityContext."
                ))

            if re.search(r'readOnlyRootFilesystem\s*:\s*false', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-732", "Writable Root Filesystem", "MEDIUM", i, stripped,
                    "A writable root filesystem allows an attacker to modify system files after a container compromise.",
                    "Set `readOnlyRootFilesystem: true` and use volume mounts for writable paths."
                ))

            # Secrets in env vars
            if re.search(r'(password|secret|api_key|token|passwd)\s*:', stripped, re.IGNORECASE):
                if re.search(r'value\s*:\s*["\']?.+["\']?', stripped, re.IGNORECASE):
                    if not re.search(r'secretKeyRef|configMapKeyRef|valueFrom', stripped, re.IGNORECASE):
                        findings.append(_finding(
                            "CWE-312", "Hardcoded Secret in Kubernetes Manifest", "HIGH", i, stripped,
                            "Secrets stored as plain text in Kubernetes manifests are exposed in version control.",
                            "Use Kubernetes Secrets with `secretKeyRef` or an external secret manager (Vault, AWS Secrets Manager)."
                        ))

            # Wildcard RBAC verbs
            if re.search(r'verbs\s*:\s*\[.*\*.*\]', stripped):
                findings.append(_finding(
                    "CWE-269", "Overly Permissive RBAC (Wildcard Verbs)", "HIGH", i, stripped,
                    "Using wildcard verbs in RBAC grants unrestricted access to Kubernetes resources.",
                    "Restrict RBAC verbs to only what is needed (e.g., [get, list, watch])."
                ))

    # ---- Terraform HCL ----
    if fname.endswith((".tf", ".hcl")):
        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            if re.search(r'0\.0\.0\.0/0', stripped):
                findings.append(_finding(
                    "CWE-284", "Public Network Exposure (0.0.0.0/0)", "CRITICAL", i, stripped,
                    "Allowing traffic from 0.0.0.0/0 exposes the resource to the entire internet.",
                    "Restrict CIDR blocks to specific trusted IP ranges. Never use 0.0.0.0/0 for production."
                ))

            if re.search(r'acl\s*=\s*["\']public-read', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-284", "Public S3 Bucket ACL", "CRITICAL", i, stripped,
                    "Setting S3 bucket ACL to public-read exposes all bucket contents to the internet.",
                    "Use `acl = \"private\"` and configure bucket policies explicitly."
                ))

            if re.search(r'encrypted\s*=\s*false', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-311", "Unencrypted Storage Resource", "HIGH", i, stripped,
                    "Storage resources without encryption expose data at rest.",
                    "Set `encrypted = true` and specify a KMS key."
                ))

            if re.search(r'deletion_protection\s*=\s*false', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-693", "Deletion Protection Disabled", "MEDIUM", i, stripped,
                    "Disabling deletion protection allows accidental or malicious deletion of critical resources.",
                    "Set `deletion_protection = true` for production databases and critical resources."
                ))

            if re.search(r'skip_final_snapshot\s*=\s*true', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-693", "Final Snapshot Skipped on DB Deletion", "MEDIUM", i, stripped,
                    "Skipping the final snapshot means data cannot be recovered after deletion.",
                    "Set `skip_final_snapshot = false` and specify `final_snapshot_identifier`."
                ))

            if re.search(r'publicly_accessible\s*=\s*true', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-284", "Database Publicly Accessible", "CRITICAL", i, stripped,
                    "Making a database publicly accessible exposes it to internet-based attacks.",
                    "Set `publicly_accessible = false` and use VPC peering or bastion hosts for access."
                ))

            if re.search(r'(password|secret|api_key)\s*=\s*["\'].+["\']', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-312", "Hardcoded Secret in Terraform", "HIGH", i, stripped,
                    "Hardcoded secrets in Terraform files are exposed in version control and state files.",
                    "Use `var.` variables with `sensitive = true`, or reference secrets from AWS Secrets Manager / Vault."
                ))

    # ---- Dockerfile ----
    if "dockerfile" in fname or fname.endswith(".dockerfile"):
        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            if re.search(r'^USER\s+root\b', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-250", "Dockerfile Running as Root", "HIGH", i, stripped,
                    "Running the container process as root increases attack surface.",
                    "Add `USER nonroot` or create a dedicated user: `RUN useradd -r appuser && USER appuser`"
                ))

            if re.search(r'curl\s+.*\|\s*(bash|sh)', stripped):
                findings.append(_finding(
                    "CWE-494", "Curl-Pipe-Bash in Dockerfile", "CRITICAL", i, stripped,
                    "Piping curl output directly to bash executes arbitrary remote code without verification.",
                    "Download the script, verify its checksum, then execute: `curl -o script.sh URL && sha256sum -c checksums && bash script.sh`"
                ))

            if re.search(r'^ADD\s+https?://', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-494", "ADD with Remote URL (Use COPY instead)", "MEDIUM", i, stripped,
                    "Using ADD with a URL downloads files without integrity verification.",
                    "Use `RUN curl -o file URL && sha256sum -c checksums` to verify downloads."
                ))

            if re.search(r'--privileged', stripped):
                findings.append(_finding(
                    "CWE-284", "Privileged Docker Run in Dockerfile", "CRITICAL", i, stripped,
                    "Running with --privileged gives the container full host access.",
                    "Remove --privileged. Use specific capabilities with --cap-add only if necessary."
                ))

    return findings


# ---------------------------------------------------------------------------
# C/C++ Scanner
# ---------------------------------------------------------------------------

def _scan_cpp(code: str) -> List[Dict[str, Any]]:
    findings = []
    lines = code.splitlines()

    unsafe_copy = re.compile(r'\b(strcpy|strcat|gets|sprintf|scanf|vsprintf|wcscpy|wcscat)\s*\(')
    format_string = re.compile(r'\b(printf|fprintf|sprintf|syslog)\s*\(\s*[^"\']+\s*\)')
    system_call = re.compile(r'\bsystem\s*\(')

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue

        if unsafe_copy.search(line):
            func = unsafe_copy.search(line).group(1)
            findings.append(_finding(
                "CWE-120", f"Unsafe Buffer Function: {func}()", "CRITICAL", i, stripped,
                f"`{func}()` does not check buffer boundaries and can cause stack/heap buffer overflows.",
                f"Replace `{func}` with its safe counterpart: "
                f"`{'strncpy' if 'cpy' in func else 'strncat' if 'cat' in func else 'fgets' if func == 'gets' else 'snprintf'}`. "
                "Always pass the destination buffer size."
            ))

        if format_string.search(line):
            findings.append(_finding(
                "CWE-134", "Format String Vulnerability", "HIGH", i, stripped,
                "Passing a user-controlled string as the format argument allows format string attacks.",
                "Always use a literal format string: `printf(\"%s\", user_input)` instead of `printf(user_input)`."
            ))

        if system_call.search(line):
            findings.append(_finding(
                "CWE-78", "OS Command Injection via system()", "CRITICAL", i, stripped,
                "`system()` passes the command to the shell, enabling command injection if any part is user-controlled.",
                "Use `execve()` with an argument array instead of `system()`. Never pass user input to shell commands."
            ))

        if re.search(r'\bmalloc\s*\(.*\*.*\)', line) and re.search(r'\bint\b', line):
            findings.append(_finding(
                "CWE-190", "Potential Integer Overflow in malloc Size", "HIGH", i, stripped,
                "Multiplying integers to compute malloc size can overflow, leading to undersized allocation.",
                "Use `calloc(n, size)` instead of `malloc(n * size)`, or check for overflow before multiplying."
            ))

        if re.search(r'\bnull\b|\bNULL\b', line, re.IGNORECASE) and re.search(r'\*\s*\w+', line):
            if re.search(r'=\s*(null|NULL|0)\b', line, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-476", "Potential Null Pointer Dereference", "MEDIUM", i, stripped,
                    "Dereferencing a pointer that may be NULL causes undefined behavior or crashes.",
                    "Always check pointer validity before dereferencing: `if (ptr != NULL) { ... }`"
                ))

    return findings


# ---------------------------------------------------------------------------
# C# Scanner
# ---------------------------------------------------------------------------

def _scan_csharp(code: str) -> List[Dict[str, Any]]:
    findings = []
    lines = code.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # SQL Injection via string concatenation
        if re.search(r'(SqlCommand|ExecuteReader|ExecuteNonQuery|ExecuteScalar)', line):
            if re.search(r'["\']\s*\+|string\.Format|string\.Concat|\$"', line):
                if re.search(r'(SELECT|INSERT|UPDATE|DELETE|WHERE)', line, re.IGNORECASE):
                    findings.append(_finding(
                        "CWE-89", "SQL Injection via String Concatenation (C#)", "CRITICAL", i, stripped,
                        "Building SQL queries with string concatenation allows SQL injection attacks.",
                        "Use parameterized queries: `new SqlCommand(\"SELECT * FROM users WHERE id = @id\", conn)` "
                        "with `cmd.Parameters.AddWithValue(\"@id\", userId)`."
                    ))

        # XXE via XmlDocument without resolver
        if re.search(r'XmlDocument\s*\(\s*\)', line):
            findings.append(_finding(
                "CWE-611", "XXE Risk: XmlDocument Without XmlResolver=null", "HIGH", i, stripped,
                "XmlDocument by default resolves external entities, enabling XXE attacks.",
                "Set `xmlDoc.XmlResolver = null` immediately after creating the XmlDocument."
            ))

        # Insecure deserialization
        if re.search(r'BinaryFormatter\s*\(\s*\)', line):
            findings.append(_finding(
                "CWE-502", "Insecure Deserialization: BinaryFormatter", "CRITICAL", i, stripped,
                "BinaryFormatter can deserialize arbitrary types, enabling remote code execution.",
                "Use `System.Text.Json.JsonSerializer` or `XmlSerializer` instead. "
                "BinaryFormatter is disabled by default in .NET 5+ for this reason."
            ))

        # Hardcoded connection strings
        if re.search(r'(Password|pwd)\s*=\s*[^\s;{]+', line, re.IGNORECASE):
            if not re.search(r'ConfigurationManager|Environment\.GetEnvironmentVariable|appsettings', line):
                findings.append(_finding(
                    "CWE-312", "Hardcoded Database Password (C#)", "HIGH", i, stripped,
                    "Hardcoded passwords in connection strings are exposed in source control.",
                    "Use `ConfigurationManager.ConnectionStrings` or environment variables / Azure Key Vault."
                ))

        # Path traversal
        if re.search(r'(File\.Read|File\.Write|File\.Open|Path\.Combine)', line):
            if re.search(r'Request\.|HttpContext\.|\.Query\[|\.Form\[', line):
                findings.append(_finding(
                    "CWE-22", "Path Traversal via User Input (C#)", "HIGH", i, stripped,
                    "Using user-supplied input in file paths can allow directory traversal attacks.",
                    "Validate and sanitize file paths. Use `Path.GetFullPath()` and verify the result "
                    "starts with the expected base directory."
                ))

    return findings


# ---------------------------------------------------------------------------
# Ruby Scanner
# ---------------------------------------------------------------------------

def _scan_ruby(code: str) -> List[Dict[str, Any]]:
    findings = []
    lines = code.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        if re.search(r'\beval\s*[\(\s]', line):
            findings.append(_finding(
                "CWE-94", "Arbitrary Code Execution via eval() (Ruby)", "CRITICAL", i, stripped,
                "`eval()` executes arbitrary Ruby code. If user input reaches eval, it enables RCE.",
                "Remove `eval`. Use explicit method dispatch or a safe expression parser."
            ))

        if re.search(r'\bsend\s*\(', line) and re.search(r'params\[|request\.|@\w+', line):
            findings.append(_finding(
                "CWE-94", "Dynamic Method Dispatch via send() with User Input (Ruby)", "HIGH", i, stripped,
                "`send()` with user-controlled method names allows calling arbitrary methods.",
                "Use a whitelist of allowed method names before calling `send()`."
            ))

        if re.search(r'YAML\.load\s*\(', line) and not re.search(r'YAML\.safe_load', line):
            findings.append(_finding(
                "CWE-502", "Insecure YAML Deserialization (Ruby)", "CRITICAL", i, stripped,
                "`YAML.load()` can deserialize arbitrary Ruby objects, enabling RCE.",
                "Use `YAML.safe_load()` instead of `YAML.load()`."
            ))

        if re.search(r'constantize', line) and re.search(r'params\[|request\.', line):
            findings.append(_finding(
                "CWE-94", "Remote Code Execution via constantize with User Input (Ruby)", "CRITICAL", i, stripped,
                "`constantize` converts a string to a class constant. With user input, this enables RCE.",
                "Never call `constantize` on user-supplied strings. Use a whitelist of allowed class names."
            ))

        # Mass assignment
        if re.search(r'update\s*\(\s*params\b', line) or re.search(r'create\s*\(\s*params\b', line):
            findings.append(_finding(
                "CWE-915", "Mass Assignment Vulnerability (Ruby/Rails)", "HIGH", i, stripped,
                "Passing `params` directly to `update` or `create` allows attackers to set arbitrary attributes.",
                "Use Strong Parameters: `params.require(:user).permit(:name, :email)` instead of raw `params`."
            ))

        if re.search(r'`.*#\{', line) or re.search(r'system\s*\(.*#\{', line):
            findings.append(_finding(
                "CWE-78", "OS Command Injection via String Interpolation (Ruby)", "CRITICAL", i, stripped,
                "Interpolating user input into backtick or system() calls enables OS command injection.",
                "Use `Open3.capture2e` with an argument array: `Open3.capture2e('ls', user_input)`."
            ))

    return findings


# ---------------------------------------------------------------------------
# PHP Scanner
# ---------------------------------------------------------------------------

def _scan_php(code: str) -> List[Dict[str, Any]]:
    findings = []
    lines = code.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue

        # OS Command Injection
        if re.search(r'\b(shell_exec|exec|passthru|system|proc_open|popen)\s*\(', line):
            if re.search(r'\$_(GET|POST|REQUEST|COOKIE|FILES)', line):
                findings.append(_finding(
                    "CWE-78", "PHP Command Injection via Superglobals", "CRITICAL", i, stripped,
                    "Calling shell execution functions with direct superglobal input leads to total host compromise.",
                    "Never pass raw user input to execution functions. Use escapeshellarg() or avoid shell calls."
                ))
            else:
                findings.append(_finding(
                    "CWE-78", "Potential PHP Command Injection", "HIGH", i, stripped,
                    "Execution functions pass commands to the system shell.",
                    "Avoid shell execution. Use built-in PHP functions or sanitize input with escapeshellarg()."
                ))

        # Code Injection / Eval
        if re.search(r'\b(eval|assert|create_function)\s*\(', line):
            findings.append(_finding(
                "CWE-94", "PHP Code Injection (eval)", "CRITICAL", i, stripped,
                "`eval()` and similar functions execute arbitrary PHP code.",
                "Remove eval(). Use safer alternatives like dictionary lookups or JSON parser."
            ))

        # SQL Injection
        if re.search(r'\b(mysqli_query|mysql_query|PDO::query|PDO::exec)\s*\(', line):
            if re.search(r'\$_(GET|POST|REQUEST|COOKIE)', line) or ('"' in line or "'" in line and "." in line):
                findings.append(_finding(
                    "CWE-89", "PHP SQL Injection", "CRITICAL", i, stripped,
                    "Building SQL queries with string concatenation or superglobals allows SQL injection.",
                    "Use prepared statements with PDO or MySQLi."
                ))

        # File Inclusion (LFI/RFI)
        if re.search(r'\b(include|require|include_once|require_once)\s*\(', line):
            if re.search(r'\$_(GET|POST|REQUEST)', line):
                findings.append(_finding(
                    "CWE-98", "PHP Remote/Local File Inclusion", "CRITICAL", i, stripped,
                    "Using user input in include/require statements allows attackers to execute remote scripts.",
                    "Whitelist allowed files or use a fixed path. Never include user-controlled filenames."
                ))

        # Insecure File Upload
        if "move_uploaded_file" in line and not (".jpg" in line.lower() or ".png" in line.lower()):
            findings.append(_finding(
                "CWE-434", "Unrestricted File Upload Risk (PHP)", "HIGH", i, stripped,
                "Moving uploaded files without strictly whitelisting extensions allows uploading .php scripts.",
                "Verify file extension against a whitelist and scan content for PHP tags."
            ))

    return findings


# ---------------------------------------------------------------------------
# Java Scanner
# ---------------------------------------------------------------------------

def _scan_java(code: str) -> List[Dict[str, Any]]:
    findings = []
    lines = code.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # Command Injection
        if "Runtime.getRuntime().exec" in line or "ProcessBuilder" in line:
            findings.append(_finding(
                "CWE-78", "Java Command Injection", "CRITICAL", i, stripped,
                "Executing system commands with Java runtime or ProcessBuilder is dangerous if input is controlled.",
                "Avoid shell calls. Use Java APIs or pass arguments as an array to ProcessBuilder."
            ))

        # XXE
        if "DocumentBuilderFactory" in line or "XMLReaderFactory" in line:
            findings.append(_finding(
                "CWE-611", "Java XXE Risk", "HIGH", i, stripped,
                "Java XML parsers resolve external entities by default, leading to XXE.",
                "Set `factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);`"
            ))

        # Insecure Deserialization
        if "ObjectInputStream" in line and ".readObject()" in line:
            findings.append(_finding(
                "CWE-502", "Java Insecure Deserialization", "CRITICAL", i, stripped,
                "Deserializing untrusted data with ObjectInputStream enables remote code execution.",
                "Use JSON or other safe formats. Avoid native Java serialization for untrusted data."
            ))

        # SQL Injection
        if "statement.executeQuery" in line and ("+" in line or "append" in line):
            if re.search(r'SELECT|INSERT|UPDATE|DELETE', line, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-89", "Java SQL Injection", "CRITICAL", i, stripped,
                    "Building SQL queries with string concatenation is vulnerable to SQL injection.",
                    "Use PreparedStatement with placeholders (?)."
                ))

    return findings


# ---------------------------------------------------------------------------
# Go Scanner
# ---------------------------------------------------------------------------

def _scan_go(code: str) -> List[Dict[str, Any]]:
    findings = []
    lines = code.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # Command Injection
        if "exec.Command" in line or "os.StartProcess" in line:
            findings.append(_finding(
                "CWE-78", "Go Command Injection", "CRITICAL", i, stripped,
                "Executing external commands via os/exec is sensitive to input injection.",
                "Pass arguments as a slice, never concatenate strings into the command."
            ))

        # Unsafe usage
        if "unsafe.Pointer" in line or "uintptr" in line:
            findings.append(_finding(
                "CWE-242", "Go Unsafe Pointer Usage", "LOW", i, stripped,
                "Using the `unsafe` package bypasses Go's type safety and memory protection.",
                "Avoid `unsafe` unless strictly necessary for performance or FFI."
            ))

        # SQL Injection
        if ".Query(" in line or ".Exec(" in line:
            if "fmt.Sprintf" in line or '"+"' in line:
                findings.append(_finding(
                    "CWE-89", "Go SQL Injection", "CRITICAL", i, stripped,
                    "Concatenating strings for SQL queries in Go allows injection.",
                    "Use parameterized queries: `db.Query(\"SELECT... WHERE id=?\", id)`."
                ))

    return findings


# ---------------------------------------------------------------------------
# Dependency File Scanner
# ---------------------------------------------------------------------------

# Known malicious / severely vulnerable packages (illustrative list)
KNOWN_BAD_PACKAGES = {
    # npm
    "event-stream": ("CWE-506", "Known Malicious Package: event-stream", "CRITICAL",
                     "event-stream v3.3.6 contained a backdoor targeting cryptocurrency wallets.",
                     "Remove this package immediately. Use a maintained alternative."),
    "ua-parser-js": ("CWE-506", "Known Malicious Package: ua-parser-js", "CRITICAL",
                     "ua-parser-js was compromised to install cryptominers and password stealers.",
                     "Update to the latest patched version immediately."),
    "node-ipc": ("CWE-506", "Known Malicious Package: node-ipc", "CRITICAL",
                 "node-ipc v10.1.1-10.1.2 contained destructive payload targeting Russian/Belarusian IPs.",
                 "Pin to version 9.2.2 or use an alternative."),
    "colors": ("CWE-506", "Known Malicious Package: colors", "HIGH",
               "colors v1.4.1+ was intentionally broken by its author.",
               "Pin to colors@1.4.0 or use the `chalk` package."),
    # Python
    "pylibmc": ("CWE-1104", "Outdated Dependency: pylibmc", "MEDIUM",
                "pylibmc has known memory safety issues in older versions.",
                "Ensure you are using the latest version and review the changelog."),
}

def _scan_dependency_file(code: str, fname: str) -> List[Dict[str, Any]]:
    findings = []
    lines = code.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        # Check for known bad packages
        for pkg_name, (cwe, title, severity, desc, fix) in KNOWN_BAD_PACKAGES.items():
            if re.search(rf'\b{re.escape(pkg_name)}\b', stripped, re.IGNORECASE):
                findings.append(_finding(cwe, title, severity, i, stripped, desc, fix))

        # Unpinned dependencies (requirements.txt)
        if fname.endswith(".txt") and "requirements" in fname:
            if re.search(r'^[a-zA-Z]', stripped) and not re.search(r'[=<>!~]', stripped):
                findings.append(_finding(
                    "CWE-1104", "Unpinned Dependency", "LOW", i, stripped,
                    f"Package `{stripped}` has no version pin. Future updates may introduce vulnerabilities.",
                    f"Pin the version: `{stripped}==<specific_version>`. Run `pip freeze` to get current versions."
                ))

        # Wildcard versions in package.json
        if fname == "package.json":
            if re.search(r'["\']\s*\*\s*["\']', stripped):
                pkg_match = re.search(r'"([^"]+)"\s*:\s*"\s*\*\s*"', stripped)
                pkg = pkg_match.group(1) if pkg_match else "unknown"
                findings.append(_finding(
                    "CWE-1104", f"Wildcard Version for {pkg}", "MEDIUM", i, stripped,
                    f"Using `*` as the version for `{pkg}` installs any version, including ones with vulnerabilities.",
                    f"Pin to a specific version range: `\"^1.2.3\"` or `\"~1.2.3\"`."
                ))

    return findings


# ---------------------------------------------------------------------------
# Generic Scanner (applies to all file types)
# ---------------------------------------------------------------------------

def _scan_generic(code: str, fname: str) -> List[Dict[str, Any]]:
    findings = []
    lines = code.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip comment lines
        if re.match(r'^\s*(//|#|/\*|\*)', line):
            continue

        # --- JWT bypass ---
        if re.search(r'alg\s*[=:]\s*["\']?none["\']?', stripped, re.IGNORECASE):
            findings.append(_finding(
                "CWE-347", "JWT Algorithm None Bypass", "CRITICAL", i, stripped,
                "Setting JWT algorithm to 'none' disables signature verification, allowing token forgery.",
                "Always specify a strong algorithm (HS256, RS256) and reject tokens with alg=none."
            ))

        if re.search(r'verify\s*[=:]\s*[Ff]alse', stripped) and re.search(r'jwt|token|decode', stripped, re.IGNORECASE):
            findings.append(_finding(
                "CWE-347", "JWT Signature Verification Disabled", "CRITICAL", i, stripped,
                "Disabling JWT signature verification allows attackers to forge tokens.",
                "Always verify JWT signatures. Remove `verify=False` / `algorithms=['none']`."
            ))

        # --- Hardcoded secrets (improved regex) ---
        secret_pattern = re.compile(
            r'(password|passwd|api_key|apikey|secret|token|access_key|private_key|auth_token|client_secret)'
            r'\s*[=:]\s*["\']([^"\']{6,})["\']',
            re.IGNORECASE
        )
        if secret_pattern.search(stripped):
            match = secret_pattern.search(stripped)
            key_name = match.group(1)
            # Avoid flagging environment variable lookups
            if not re.search(r'(os\.getenv|os\.environ|process\.env|getenv|env\[|ENV\[|config\[|settings\.)', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-312", f"Hardcoded Secret: {key_name}", "HIGH", i, stripped,
                    f"A hardcoded `{key_name}` was detected in source code. "
                    "This exposes credentials in version control.",
                    "Use environment variables: `os.getenv('SECRET_KEY')` or a secrets manager (Vault, AWS Secrets Manager)."
                ))

        # --- Path traversal ---
        if re.search(r'\.\./|\.\.\\', stripped):
            if re.search(r'(open|read|write|include|require|import|load|file)', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-22", "Path Traversal (../ in File Operation)", "HIGH", i, stripped,
                    "Using `../` in file paths can allow attackers to access files outside the intended directory.",
                    "Resolve and validate the canonical path. Ensure it starts with the expected base directory."
                ))

        # --- SSRF ---
        if re.search(r'(fetch|requests\.get|requests\.post|urllib|http\.get|axios)\s*\(', stripped, re.IGNORECASE):
            if re.search(r'(req\.|request\.|params\[|query\[|body\.|input|user)', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-918", "Server-Side Request Forgery (SSRF)", "HIGH", i, stripped,
                    "Making HTTP requests to user-controlled URLs enables SSRF attacks, "
                    "potentially accessing internal services.",
                    "Validate and whitelist allowed URL schemes and hostnames before making requests."
                ))

        # --- Insecure random for security purposes ---
        if re.search(r'\b(Math\.random|random\.random|rand\(\))\b', stripped):
            if re.search(r'(token|session|password|key|secret|csrf|nonce|salt)', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-338", "Insecure Pseudo-Random Number Generator for Security", "HIGH", i, stripped,
                    "Using `Math.random()` or `random.random()` for security tokens is predictable.",
                    "Use a cryptographically secure RNG: `crypto.randomBytes(32)` (Node.js) or `secrets.token_hex(32)` (Python)."
                ))

        # --- Prototype pollution ---
        if re.search(r'__proto__', stripped):
            if re.search(r'(req\.|request\.|params|query|body|input)', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-1321", "Prototype Pollution via User Input", "HIGH", i, stripped,
                    "Merging user-controlled objects without sanitization can pollute Object.prototype.",
                    "Sanitize objects before merging. Use `Object.create(null)` for dictionaries "
                    "or libraries like `lodash.merge` with prototype pollution protection."
                ))

        # --- eval with user input ---
        if re.search(r'\beval\s*\(', stripped):
            if re.search(r'(req\.|request\.|params|query|body|input|user)', stripped, re.IGNORECASE):
                findings.append(_finding(
                    "CWE-94", "Code Injection via eval() with User Input", "CRITICAL", i, stripped,
                    "Passing user-controlled data to `eval()` enables arbitrary code execution.",
                    "Never use `eval()` with user input. Use a safe expression parser or JSON.parse() for data."
                ))

        # --- XXE ---
        if re.search(r'(xml\.etree|minidom|lxml|DOMParser|XMLReader|SAXParser)', stripped, re.IGNORECASE):
            if re.search(r'(parse|load|fromstring|parseString)', stripped, re.IGNORECASE):
                if not re.search(r'(resolve_entities\s*=\s*False|XMLResolver\s*=\s*null|FEATURE_EXTERNAL)', stripped):
                    findings.append(_finding(
                        "CWE-611", "XML External Entity (XXE) Risk", "HIGH", i, stripped,
                        "XML parsers that resolve external entities are vulnerable to XXE attacks.",
                        "Disable external entity resolution: set `resolve_entities=False` (lxml) or "
                        "`parser.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` (Java)."
                    ))

        # --- SQL injection (generic, all languages) ---
        if re.search(r'(execute|query|raw|cursor\.execute)\s*\(', stripped, re.IGNORECASE):
            if re.search(r'(f["\']|["\']\s*\+|\.format\s*\(|%\s*\(|string\.Format)', stripped):
                if re.search(r'(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)', stripped, re.IGNORECASE):
                    findings.append(_finding(
                        "CWE-89", "SQL Injection via String Formatting", "CRITICAL", i, stripped,
                        "Building SQL queries with string formatting or concatenation allows SQL injection.",
                        "Use parameterized queries / prepared statements. Never interpolate user input into SQL."
                    ))

        # --- Insecure deserialization ---
        if re.search(r'(pickle\.loads?|pickle\.load|joblib\.load|marshal\.loads?)', stripped):
            findings.append(_finding(
                "CWE-502", "Insecure Deserialization (pickle/marshal)", "CRITICAL", i, stripped,
                "Deserializing untrusted data with pickle or marshal enables arbitrary code execution.",
                "Use JSON or another safe format for untrusted data. If pickle is required, "
                "use HMAC signing to verify data integrity before deserializing."
            ))

        # --- Shell injection ---
        if re.search(r'\bos\.system\s*\(', stripped):
            findings.append(_finding(
                "CWE-78", "OS Command Injection via os.system()", "CRITICAL", i, stripped,
                "`os.system()` passes the command to the shell, enabling injection if user input is involved.",
                "Use `subprocess.run(['cmd', arg1, arg2], check=True)` with arguments as a list."
            ))

        if re.search(r'subprocess\.(call|run|Popen)\s*\(', stripped):
            if re.search(r'shell\s*=\s*True', stripped):
                findings.append(_finding(
                    "CWE-78", "Command Injection via subprocess shell=True", "HIGH", i, stripped,
                    "Using `shell=True` passes the command to the shell interpreter, enabling injection.",
                    "Use `shell=False` (default) and pass arguments as a list: `subprocess.run(['ls', path])`."
                ))

    return findings


# ---------------------------------------------------------------------------
# Language Detectors
# ---------------------------------------------------------------------------

def _is_iac_file(fname: str) -> bool:
    return fname.endswith((".yaml", ".yml", ".tf", ".hcl", "dockerfile")) or "dockerfile" in fname

def _is_cpp_file(fname: str) -> bool:
    return fname.endswith((".c", ".cpp", ".h", ".hpp", ".cc", ".cxx"))

def _is_csharp_file(fname: str) -> bool:
    return fname.endswith((".cs", ".aspx", ".cshtml"))

def _is_ruby_file(fname: str) -> bool:
    return fname.endswith((".rb", ".erb", ".rake", "gemfile"))

def _is_java_file(fname: str) -> bool:
    return fname.endswith((".java", ".jsp", ".jar"))

def _is_go_file(fname: str) -> bool:
    return fname.endswith(".go")

def _is_php_file(fname: str) -> bool:
    return fname.endswith(".php")

def _is_dependency_file(fname: str) -> bool:
    return fname in ["requirements.txt", "package.json", "gemfile", "go.mod", "pom.xml"]


def _finding(
    cwe_id: str,
    title: str,
    severity: str,
    line: int,
    content: str,
    description: str,
    fix: str
) -> Dict[str, Any]:
    return {
        "cwe_id": cwe_id,
        "title": title,
        "type": title,          # alias for frontend compatibility
        "severity": severity,
        "line": line,
        "content": content[:200],  # truncate very long lines
        "description": description,
        "fix": fix,
        "source": "rule-engine",
    }
