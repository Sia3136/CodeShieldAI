import requests
import sys

# Payload from user (corrected parens)
payload = """import os
import pickle
import base64

class Malicious:
    def _reduce_(self):
        return (os.system, ("rm -rf /",)) # Command to wipe the server

print(base64.b64encode(pickle.dumps(Malicious())))"""

try:
    print("Sending request to http://127.0.0.1:8000/scan...")
    response = requests.post("http://127.0.0.1:8000/scan", json={"code": payload})
    
    if response.status_code == 200:
        data = response.json()
        print("Response Code:", response.status_code)
        print("Response Body:", data)
        
        if data['score'] > 90:
            print("SUCCESS: Live server detected the vulnerability.")
        else:
            print("FAILURE: Live server returned low score.")
    else:
        print(f"Error: {response.status_code} - {response.text}")

except Exception as e:
    print(f"Connection failed: {e}")
    print("Make sure uvicorn is running on port 8000.")
