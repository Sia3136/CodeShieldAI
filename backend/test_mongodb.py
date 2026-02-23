"""
Test MongoDB connection and inject sample scan data
"""
from pymongo import MongoClient
from datetime import datetime
import os
from dotenv import load_dotenv
import certifi

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/codeshield_db")

def test_connection():
    """Test MongoDB connection"""
    try:
        client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=5000,
            tlsCAFile=certifi.where()
        )
        client.server_info()
        print("✅ MongoDB connection successful!")
        return client
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        return None

def inject_sample_data(client):
    """Inject sample vulnerability scan data"""
    db = client["codeshield_db"]
    collection = db["scan_results"]
    
    sample_scans = [
        {
            "scan_time": datetime.utcnow(),
            "code_snippet": "eval(user_input)",
            "vulnerable": True,
            "risk_score": 95.5,
            "severity": "Critical",
            "highlights": "Line 1: eval(user_input)  ← SUSPECT (possible vuln)\n\nRisk Score: 95.5% | Severity: Critical",
            "suggested_fix": "Do NOT pass user input to exec/eval/os.system – very dangerous",
            "email_sent": True
        },
        {
            "scan_time": datetime.utcnow(),
            "code_snippet": "password = 'hardcoded123'",
            "vulnerable": True,
            "risk_score": 78.2,
            "severity": "High",
            "highlights": "Line 1: password = 'hardcoded123'  ← SUSPECT (possible vuln)\n\nRisk Score: 78.2% | Severity: High",
            "suggested_fix": "Use environment variables:\nimport os\npassword = os.getenv('DB_PASS')",
            "email_sent": True
        },
        {
            "scan_time": datetime.utcnow(),
            "code_snippet": "import os\ndata = os.getenv('API_KEY')",
            "vulnerable": False,
            "risk_score": 15.3,
            "severity": "Low",
            "highlights": "Line 1: import os\nLine 2: data = os.getenv('API_KEY')\n\nRisk Score: 15.3% | Severity: Low",
            "suggested_fix": "",
            "email_sent": False
        },
        {
            "scan_time": datetime.utcnow(),
            "code_snippet": "query = f'SELECT * FROM users WHERE id = {user_id}'",
            "vulnerable": True,
            "risk_score": 88.7,
            "severity": "Critical",
            "highlights": "Line 1: query = f'SELECT * FROM users WHERE id = {user_id}'  ← SUSPECT (possible vuln)\n\nRisk Score: 88.7% | Severity: Critical",
            "suggested_fix": "Use parameterized queries:\ncursor.execute('SELECT ... = ?', (value,))",
            "email_sent": True
        }
    ]
    
    try:
        result = collection.insert_many(sample_scans)
        print(f"✅ Inserted {len(result.inserted_ids)} sample scans into MongoDB")
        print(f"   Document IDs: {result.inserted_ids}")
        return True
    except Exception as e:
        print(f"❌ Failed to insert data: {e}")
        return False

def get_scan_count(client):
    """Get total number of scans in database"""
    db = client["codeshield_db"]
    collection = db["scan_results"]
    count = collection.count_documents({})
    print(f"📊 Total scans in database: {count}")
    return count

def get_recent_scans(client, limit=5):
    """Fetch recent scans from database"""
    db = client["codeshield_db"]
    collection = db["scan_results"]
    
    scans = list(collection.find().sort("scan_time", -1).limit(limit))
    print(f"\n📋 Recent {limit} scans:")
    for i, scan in enumerate(scans, 1):
        print(f"\n{i}. Scan ID: {scan['_id']}")
        print(f"   Time: {scan['scan_time']}")
        print(f"   Vulnerable: {scan['vulnerable']}")
        print(f"   Risk Score: {scan['risk_score']}%")
        print(f"   Severity: {scan['severity']}")
        print(f"   Code: {scan['code_snippet'][:50]}...")
    
    return scans

if __name__ == "__main__":
    print("=" * 60)
    print("MongoDB Connection & Data Injection Test")
    print("=" * 60)
    
    # Test connection
    client = test_connection()
    if not client:
        print("\n❌ Cannot proceed without MongoDB connection")
        exit(1)
    
    # Get current count
    get_scan_count(client)
    
    # Ask user if they want to inject sample data
    print("\n" + "=" * 60)
    choice = input("Do you want to inject sample scan data? (y/n): ").lower()
    
    if choice == 'y':
        inject_sample_data(client)
        get_scan_count(client)
    
    # Show recent scans
    print("\n" + "=" * 60)
    get_recent_scans(client)
    
    client.close()
    print("\n✅ Test completed!")
