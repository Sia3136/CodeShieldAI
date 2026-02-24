# CodeShieldAI Rules Engine (Heuristic Pattern Layer)

Deterministic, multi-language hotspot detection.

This engine provides:
- language-aware rule packs (Python/Java/Go/JS/TS/PHP/Ruby/C++/C#)
- exact finding locations (file + line ranges)
- severity mapping (Critical/High/Medium/Low)
- CWE-like categorization (recommended)
- rule metadata for explainability and boosting logic

---

## What the Rules Engine Detects (Examples)
- command injection sinks (`os.system`, `exec`, `Runtime.exec`, etc.)
- code injection (`eval`, dynamic require/import, reflection misuse)
- SQL injection construction patterns (string concatenation into queries)
- XXE patterns in XML parsers
- insecure deserialization
- hardcoded secrets patterns
- weak crypto usage (legacy hashes, insecure modes)

> Keep rule naming consistent (e.g., `PY-OS-CMD-001`) and version rules for reproducibility.

---

## Output Format (Recommended)
Each rule hit should include:
- `rule_id`, `title`, `language`
- `severity` (Critical/High/Medium/Low)
- `confidence` = 1.0 (deterministic match)
- `file_path`, `start_line`, `end_line`
- `snippet` (optional)
- `message` (what matched and why)

---

## Integration with Hybrid Scorer
Rules can **boost** ML output when:
- severity is high/critical
- rule is a known exploit sink
- rule match is close to user-controlled input patterns

Example policy:
- if `rule_severity >= High` then `final_score = max(final_score, boosted_score)`
- if `Critical` then ensure severity >= Critical regardless of ML uncertainty
