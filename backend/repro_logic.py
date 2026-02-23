import sys
import os
# Mocking imports that might be heavy or missing if we just want to test logic flow
# But we need real logic for heuristic boost.
# Let's try to import app logic.

sys.path.append(os.path.join(os.getcwd(), 'Code-a-thon_VIT'))

# We will copy the critical logic here to debug it in isolation avoid depending on DB/Models for the heuristic part first.

def get_severity(score: float) -> str:
    if score > 80: return "Critical"
    if score > 60: return "High"
    if score > 40: return "Medium"
    return "Low"

def apply_heuristic_boost(code: str, original_score: float) -> float:
    """Boosts the score if known dangerous combinations exist."""
    lower_code = code.lower()
    boosted_score = original_score

    # Rule: Pickle + System/Subprocess = Guaranteed RCE
    if ("pickle" in lower_code or "__reduce__" in lower_code) and "os.system" in lower_code:
        print("DEBUG: heuristic hit - pickle + os.system")
        boosted_score = max(boosted_score, 98.5)
    
    # Rule: f-string or concat in SQL execute
    if "execute" in lower_code and ("f\"" in lower_code or "f'" in lower_code or "+" in lower_code):
        if "select" in lower_code or "where" in lower_code:
            boosted_score = max(boosted_score, 85.0)

    # Rule: Hardcoded passwords/keys
    if any(kw in lower_code for kw in ["api_key =", "password =", "secret ="]) and len(lower_code) < 500:
        boosted_score = max(boosted_score, 75.0)

    return min(boosted_score, 100.0)

user_code = """import os
import pickle
import base64

class Malicious:
    def _reduce_(self):
        return (os.system, ("rm -rf /",)) # Command to wipe the server

print(base64.b64encode(pickle.dumps(Malicious()))"""

print(f"Code to scan:\n{user_code}")
print("-" * 20)

lower_code = user_code.lower()
print(f"'os.system' in lower: {'os.system' in lower_code}")
print(f"'pickle' in lower: {'pickle' in lower_code}")
print(f"'__reduce__' in lower: {'__reduce__' in lower_code}")

score = apply_heuristic_boost(user_code, 0.0)
print(f"Score: {score}")
