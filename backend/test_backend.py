"""
Fetch data from CodeShield AI Backend API
"""
import requests
import json
from datetime import datetime

API_BASE_URL = "http://127.0.0.1:8001"

def test_server_status():
    """Check if backend server is running"""
    try:
        response = requests.get(f"{API_BASE_URL}/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Server is running: {data['message']}")
            print(f"   DB Status: {data.get('db_status', 'Unknown')}")
            return True
        else:
            print(f"❌ Server returned status code: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Is it running?")
        print(f"   Expected URL: {API_BASE_URL}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def scan_code(code_snippet):
    """Send code to backend for vulnerability scanning"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/scan",
            data=code_snippet,
            headers={"Content-Type": "text/plain"},
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            print("\n" + "="*60)
            print("📊 SCAN RESULT")
            print("="*60)
            print(f"Vulnerable: {result.get('vulnerable', 'Unknown')}")
            print(f"Risk Score: {result.get('score', 0)}%")
            print(f"Severity: {result.get('severity', 'Unknown')}")
            print(f"\nHighlights:\n{result.get('highlights', 'N/A')}")
            if result.get('suggested_fix'):
                print(f"\n💡 Suggested Fix:\n{result['suggested_fix']}")
            print("="*60)
            return result
        else:
            print(f"❌ Scan failed with status code: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
    except Exception as e:
        print(f"❌ Scan error: {e}")
        return None

def test_multiple_scans():
    """Test scanning multiple code samples"""
    test_codes = [
        {
            "name": "SQL Injection Vulnerability",
            "code": "query = 'SELECT * FROM users WHERE name = ' + user_input"
        },
        {
            "name": "Eval Vulnerability",
            "code": "eval(user_data)"
        },
        {
            "name": "Safe Code",
            "code": "import os\napi_key = os.getenv('API_KEY')"
        },
        {
            "name": "Hardcoded Password",
            "code": "password = 'admin123'"
        }
    ]
    
    results = []
    for test in test_codes:
        print(f"\n🔍 Testing: {test['name']}")
        print(f"Code: {test['code']}")
        result = scan_code(test['code'])
        if result:
            results.append({
                "name": test['name'],
                "result": result
            })
        print("\n" + "-"*60)
    
    return results

def save_results_to_file(results, filename="scan_results.json"):
    """Save scan results to JSON file"""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n✅ Results saved to {filename}")
    except Exception as e:
        print(f"❌ Failed to save results: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("CodeShield AI Backend Integration Test")
    print("=" * 60)
    
    # Test server status
    if not test_server_status():
        print("\n⚠️  Please start the backend server first:")
        print("   cd Code-a-thon_VIT")
        print('   uvicorn app:app --reload')
        exit(1)
    
    print("\n" + "=" * 60)
    print("Running vulnerability scans...")
    print("=" * 60)
    
    # Test multiple scans
    results = test_multiple_scans()
    
    # Save results
    if results:
        save_results_to_file(results)
    
    print("\n✅ Integration test completed!")
    print(f"   Scans performed: {len(results)}")
    print(f"   Check your MongoDB for saved scans!")
