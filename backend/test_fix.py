import asyncio
import sys
import os
from unittest.mock import MagicMock, patch

# Add current dir to path
sys.path.append(os.getcwd())

# Mock fastAPI and other deps if needed, but we try to import app
# We need to mock torch etc if they are not present, but they should be present in venv
# The user env has them.

from app import scan_code, CodeRequest, apply_heuristic_boost

async def test_rce_detection_with_ml_failure():
    print("Testing RCE detection when ML fails...")
    
    # RCE Payload
    payload = """import os
import pickle
import base64

class Malicious:
    def _reduce_(self):
        return (os.system, ("rm -rf /",)) # Command to wipe the server

print(base64.b64encode(pickle.dumps(Malicious()))"""

    req = CodeRequest(code=payload)

    # Patch get_embedding to fail (return zeros)
    with patch('app.get_embedding') as mock_emb:
        # Simulate embedding failure (zeros)
        import numpy as np
        mock_emb.return_value = np.zeros(768)
        
        # We also need to patch lazy_load_models to return True so it attempts ML
        with patch('app.lazy_load_models') as mock_load:
            mock_load.return_value = True
            
            # Run scan
            result = await scan_code(req)
            
            print("Result:", result)
            
            if result['score'] > 90 and result['vulnerable']:
                print("SUCCESS: Detected RCE despite embedding failure!")
            else:
                print("FAILURE: Did not detect RCE.")

if __name__ == "__main__":
    asyncio.run(test_rce_detection_with_ml_failure())
