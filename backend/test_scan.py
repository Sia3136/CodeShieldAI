import requests
import json

# Test the scan endpoint
url = "http://localhost:8000/scan"
payload = {
    "code": "import os\npassword = 'hardcoded123'\nquery = f'SELECT * FROM users WHERE id={user_id}'",
    "model": "GraphCodeBERT"
}

print("Testing /scan endpoint...")
print(f"URL: {url}")
print(f"Payload: {json.dumps(payload, indent=2)}")
print("-" * 60)

try:
    response = requests.post(url, json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")
