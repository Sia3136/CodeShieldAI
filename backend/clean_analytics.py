import re

# Read the file
with open(r'c:\Users\Jardosh\Desktop\Siya\v s code\Code-a-thon_VIT\app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find and remove the orphaned code between the two exception handlers
# Pattern: from line with "query_filter = {}" to the second "except Exception as e:" before @app.get("/analytics/scan-history")

lines = content.split('\n')

# Find the line with the orphaned code start (around line 1275)
start_idx = None
end_idx = None

for i, line in enumerate(lines):
    if i > 1270 and 'query_filter = {}' in line and line.strip().startswith('query_filter'):
        start_idx = i
        print(f"Found orphaned code start at line {i+1}")
        break

# Find the second exception handler (the duplicate one)
exception_count = 0
for i, line in enumerate(lines):
    if i > 1260 and 'except Exception as e:' in line:
        exception_count += 1
        if exception_count == 2:
            end_idx = i
            print(f"Found orphaned code end at line {i+1}")
            break

if start_idx and end_idx:
    # Remove the orphaned lines
    new_lines = lines[:start_idx] + lines[end_idx:]
    
    # Write back
    with open(r'c:\Users\Jardosh\Desktop\Siya\v s code\Code-a-thon_VIT\app.py', 'w', encoding='utf-8') as f:
        f.write('\n'.join(new_lines))
    
    print(f"✓ Removed {end_idx - start_idx} orphaned lines ({start_idx+1} to {end_idx})")
else:
    print("Could not find orphaned code boundaries")
