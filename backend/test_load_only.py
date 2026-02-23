import sys
import os
sys.path.insert(0, '.')

from app import ModelManager

print("Testing model loading...")
manager = ModelManager()
try:
    print("Attempting to load GraphCodeBERT...")
    scanner = manager.get_scanner("GraphCodeBERT")
    print("✓ GraphCodeBERT loaded")
except Exception as e:
    print(f"✗ Failed: {e}")
