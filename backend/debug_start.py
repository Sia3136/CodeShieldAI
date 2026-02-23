import sys
import os

# Add current directory to path
sys.path.append(os.getcwd())

print("Attempting to import app...")
try:
    from app import app
    print("Import successful!")
except Exception as e:
    print(f"Import failed: {e}")
    import traceback
    traceback.print_exc()
