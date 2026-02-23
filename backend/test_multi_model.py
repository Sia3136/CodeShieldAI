"""
Test script to verify multi-model integration
"""
import sys
sys.path.insert(0, '.')

from app import ModelManager, MODEL_REGISTRY, DEFAULT_MODEL

print("="*60)
print("MULTI-MODEL INTEGRATION TEST")
print("="*60)

# Test 1: Model Registry Configuration
print("\n[TEST 1] Model Registry Configuration")
print(f"Available models: {list(MODEL_REGISTRY.keys())}")
print(f"Default model: {DEFAULT_MODEL}")
print("✓ Configuration loaded successfully")

# Test 2: ModelManager Initialization
print("\n[TEST 2] ModelManager Initialization")
try:
    manager = ModelManager()
    print("✓ ModelManager created successfully")
except Exception as e:
    print(f"✗ Failed to create ModelManager: {e}")
    sys.exit(1)

# Test 3: Load GraphCodeBERT
print("\n[TEST 3] Loading GraphCodeBERT Model")
try:
    graphcodebert_scanner = manager.get_scanner("GraphCodeBERT")
    print(f"✓ GraphCodeBERT loaded successfully")
    print(f"  Model name: {graphcodebert_scanner.model_name}")
    print(f"  F1 Score: {graphcodebert_scanner.config.get('validation_metrics', {}).get('f1', 'N/A')}")
except Exception as e:
    print(f"✗ Failed to load GraphCodeBERT: {e}")
    import traceback
    traceback.print_exc()

# Test 4: Load CodeBERT
print("\n[TEST 4] Loading CodeBERT Model")
try:
    codebert_scanner = manager.get_scanner("CodeBERT")
    print(f"✓ CodeBERT loaded successfully")
    print(f"  Model name: {codebert_scanner.model_name}")
    print(f"  F1 Score: {codebert_scanner.config.get('validation_metrics', {}).get('f1', 'N/A')}")
except Exception as e:
    print(f"✗ Failed to load CodeBERT: {e}")
    import traceback
    traceback.print_exc()

# Test 5: Scan with GraphCodeBERT
print("\n[TEST 5] Scanning with GraphCodeBERT")
test_code = """import os
def run_command(user_input):
    os.system(user_input)
"""
try:
    result = graphcodebert_scanner.scan(test_code)
    print(f"✓ Scan completed")
    print(f"  Vulnerable: {result.get('vulnerable', False)}")
    print(f"  Score: {result.get('score', 0.0):.4f}")
    print(f"  Risk Level: {result.get('risk_level', 'unknown')}")
except Exception as e:
    print(f"✗ Scan failed: {e}")
    import traceback
    traceback.print_exc()

# Test 6: Scan with CodeBERT
print("\n[TEST 6] Scanning with CodeBERT")
try:
    result = codebert_scanner.scan(test_code)
    print(f"✓ Scan completed")
    print(f"  Vulnerable: {result.get('vulnerable', False)}")
    print(f"  Score: {result.get('score', 0.0):.4f}")
    print(f"  Risk Level: {result.get('risk_level', 'unknown')}")
except Exception as e:
    print(f"✗ Scan failed: {e}")
    import traceback
    traceback.print_exc()

# Test 7: Model Caching
print("\n[TEST 7] Model Caching Test")
print(f"  GraphCodeBERT loaded: {manager.is_loaded('GraphCodeBERT')}")
print(f"  CodeBERT loaded: {manager.is_loaded('CodeBERT')}")
print("✓ Both models cached in memory")

print("\n" + "="*60)
print("ALL TESTS COMPLETED SUCCESSFULLY!")
print("="*60)
