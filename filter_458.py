# filter_458.py
import json
import re
from pathlib import Path
import sys

input_path = Path("cybergym_data/tasks.json")
if not input_path.exists():
    print(f"❌ Error: {input_path} not found.")
    sys.exit(1)

tasks = []
print("📖 Loading tasks.json...")

# Load JSON Lines format
for line in input_path.read_text().splitlines():
    line = line.strip()
    if line:
        try:
            tasks.append(json.loads(line))
        except json.JSONDecodeError:
            continue

print(f"✅ Loaded {len(tasks)} tasks")

# Print sample descriptions to help refine keywords
print("\n🔍 Sample vulnerability descriptions:")
for i, t in enumerate(tasks[:5]):
    desc = t.get("vulnerability_description", "")[:150]
    print(f"  {i+1}. [{t['task_id']}] {desc}...")

# Keyword-based filtering for heap-buffer-overflow READ
def is_heap_read_vuln(description: str) -> bool:
    desc_lower = description.lower()
    
    # Must mention heap + buffer overflow variant
    has_heap_overflow = any(phrase in desc_lower for phrase in [
        "heap-buffer-overflow",
        "heap buffer overflow", 
        "heap overflow",
        "heap-based buffer overflow"
    ])
    
    # Must mention READ access (case-insensitive, but avoid false positives)
    # Look for "read" in context of memory access, not function names
    has_read_access = bool(re.search(r'\bread\b.*(?:access|operation|vulnerability|error|fault)', desc_lower)) or \
                      bool(re.search(r'(?:out-of-bounds|OOB|buffer).*read', desc_lower)) or \
                      "read of size" in desc_lower or \
                      "heap-read" in desc_lower
    
    return has_heap_overflow and has_read_access

heap_read = [t for t in tasks if is_heap_read_vuln(t.get("vulnerability_description", ""))]

print(f"\n🎯 Found {len(heap_read)} Heap-buffer-overflow READ instances (via keyword matching)")

if len(heap_read) == 0:
    print("⚠️ 0 matches. Let's debug:")
    print("\n📋 Searching for tasks with 'heap' in description:")
    heap_tasks = [t for t in tasks if "heap" in t.get("vulnerability_description", "").lower()]
    for t in heap_tasks[:3]:
        print(f"  - {t['task_id']}: {t['vulnerability_description'][:200]}...")
    sys.exit(1)

# Save outputs
task_ids = [t["task_id"] for t in heap_read]
Path("heap_read_458_task_ids.json").write_text(json.dumps(task_ids, indent=2))
Path("heap_read_458_manifest.json").write_text(json.dumps(heap_read, indent=2))
print(f"✅ Saved {len(task_ids)} task IDs & manifest")

# Show a few matched examples for verification
print("\n📋 Matched examples:")
for t in heap_read[:3]:
    print(f"  • {t['task_id']}: {t['vulnerability_description'][:120]}...")