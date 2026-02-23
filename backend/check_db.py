import os
from dotenv import load_dotenv
from pymongo import MongoClient
import certifi

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/codeshield_db")

try:
    client = MongoClient(MONGO_URI, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=5000)
    
    # Get the database (codeshield_db)
    db = client["codeshield_db"]
    
    print(f"✓ Connected to MongoDB")
    print(f"Database: {db.name}")
    print()
    
    # Check collections
    scans_count = db.scans.count_documents({})
    repo_scans_count = db.repository_scans.count_documents({})
    users_count = db.users.count_documents({})
    
    print(f"Scans collection: {scans_count} documents")
    print(f"Repository scans collection: {repo_scans_count} documents")
    print(f"Users collection: {users_count} documents")
    print()
    
    # Sample a scan if exists
    if scans_count > 0:
        sample_scan = db.scans.find_one()
        print("Sample scan document:")
        print(f"  - scan_time: {sample_scan.get('scan_time')}")
        print(f"  - user_email: {sample_scan.get('user_email')}")
        print(f"  - vulnerable: {sample_scan.get('vulnerable')}")
        print(f"  - risk_score: {sample_scan.get('risk_score')}")
    
    if repo_scans_count > 0:
        sample_repo = db.repository_scans.find_one()
        print("\nSample repo scan document:")
        print(f"  - scan_time: {sample_repo.get('scan_time')}")
        print(f"  - user_email: {sample_repo.get('user_email')}")
        print(f"  - repository: {sample_repo.get('repository')}")
        print(f"  - vulnerable_files: {sample_repo.get('vulnerable_files')}")
    
    if users_count > 0:
        sample_user = db.users.find_one()
        print("\nSample user document:")
        print(f"  - email: {sample_user.get('email')}")
        print(f"  - auth_provider: {sample_user.get('auth_provider')}")
    
    client.close()
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
