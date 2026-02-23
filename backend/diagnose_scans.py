import os
from dotenv import load_dotenv
from pymongo import MongoClient
import certifi
import json

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/codeshield_db")

try:
    client = MongoClient(MONGO_URI, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=5000)
    db = client["codeshield_db"]
    
    print("=" * 60)
    print("DATABASE DIAGNOSTIC REPORT")
    print("=" * 60)
    
    # Check collections
    scans_count = db.scans.count_documents({})
    repo_scans_count = db.repository_scans.count_documents({})
    
    print(f"\n📊 Collection Counts:")
    print(f"  - Scans: {scans_count}")
    print(f"  - Repository Scans: {repo_scans_count}")
    
    # Examine recent scans in detail
    if scans_count > 0:
        print(f"\n🔍 Recent Single File Scans (last 3):")
        print("-" * 60)
        for i, scan in enumerate(db.scans.find().sort("scan_time", -1).limit(3), 1):
            print(f"\nScan #{i}:")
            print(f"  Time: {scan.get('scan_time')}")
            print(f"  User: {scan.get('user_email', 'anonymous')}")
            print(f"  Vulnerable: {scan.get('vulnerable')}")
            print(f"  Risk Score: {scan.get('risk_score')}")
            print(f"  Model: {scan.get('model_used', scan.get('model', 'unknown'))}")
            
            # Check highlights structure
            highlights = scan.get('highlights', [])
            print(f"  Highlights type: {type(highlights)}")
            if isinstance(highlights, list):
                print(f"  Highlights count: {len(highlights)}")
                if highlights:
                    print(f"  First highlight: {json.dumps(highlights[0], indent=4)}")
            else:
                print(f"  Highlights value: {highlights}")
    
    if repo_scans_count > 0:
        print(f"\n🔍 Recent Repository Scans (last 2):")
        print("-" * 60)
        for i, scan in enumerate(db.repository_scans.find().sort("scan_time", -1).limit(2), 1):
            print(f"\nRepo Scan #{i}:")
            print(f"  Time: {scan.get('scan_time')}")
            print(f"  User: {scan.get('user_email', 'anonymous')}")
            print(f"  Repository: {scan.get('repository')}")
            print(f"  Vulnerable Files: {scan.get('vulnerable_files')}")
            print(f"  Model: {scan.get('model_used')}")
            
            file_results = scan.get('file_results', [])
            print(f"  File Results count: {len(file_results)}")
            if file_results:
                # Show first vulnerable file
                for f in file_results[:2]:
                    if f.get('vulnerable'):
                        print(f"\n  Sample vulnerable file:")
                        print(f"    Path: {f.get('file_path')}")
                        print(f"    Risk: {f.get('risk_score')}")
                        highlights = f.get('highlights', [])
                        print(f"    Highlights type: {type(highlights)}")
                        if isinstance(highlights, list) and highlights:
                            print(f"    First highlight: {json.dumps(highlights[0], indent=6)}")
                        break
    
    print("\n" + "=" * 60)
    client.close()
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
