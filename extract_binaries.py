# extract_binaries.py
import subprocess, json, pathlib, re, sys

def extract_task_binaries(task_id: str, metadata: dict):
    """Extract vul/fix binaries from Docker images to cybergym-server-data"""
    # Parse task_id like "arvo:59650" → project="arvo", issue="59650"
    match = re.match(r'([^:]+):(\d+)', task_id)
    if not match:
        print(f"⚠️ Could not parse task_id: {task_id}")
        return False
    
    project, issue = match.groups()
    hash_id = metadata.get("task_id")  # e.g., "674fd565bb1a"
    
    base_dir = pathlib.Path("cybergym-server-data") / project / issue
    for variant in ["vul", "fix"]:
        # Try hash-based tag first, then fallback to issue-based
        image_tags = [
            f"n132/arvo:{hash_id}-{variant}",
            f"n132/arvo:{issue}-{variant}"
        ]
        
        image = None
        for tag in image_tags:
            result = subprocess.run(["docker", "images", "-q", tag], capture_output=True, text=True)
            if result.stdout.strip():
                image = tag
                break
        
        if not image:
            print(f"⚠️ Image not found for {task_id}-{variant}")
            continue
        
        out_dir = base_dir / variant / "out"
        out_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"📦 Extracting {image} → {out_dir}")
        # Create a temporary container and copy /out directory
        container = subprocess.run(
            ["docker", "create", "--name", f"temp_extract_{hash_id}_{variant}", image],
            capture_output=True, text=True
        ).stdout.strip()
        
        if not container:
            print(f"❌ Failed to create container for {image}")
            continue
        
        try:
            # Copy /out from container to host
            subprocess.run(
                ["docker", "cp", f"{container}:/out/.", str(out_dir)],
                check=True, capture_output=True
            )
            print(f"✅ Extracted to {out_dir}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Copy failed: {e.stderr.decode()[:200]}")
        finally:
            # Clean up temp container
            subprocess.run(["docker", "rm", "-f", container], capture_output=True)
    
    return True

if __name__ == "__main__":
    # Load your 19 tasks
    tasks = json.loads(pathlib.Path("subset_20.json").read_text())
    manifest = {t["task_id"]: t for t in json.loads(pathlib.Path("heap_read_458_manifest.json").read_text())}
    
    print(f"🔹 Extracting binaries for {len(tasks)} tasks...")
    for tid in tasks:
        print(f"\n[{tasks.index(tid)+1}/{len(tasks)}] {tid}")
        # Extract metadata from submit.sh (as before)
        task_dir = pathlib.Path(f"./tasks/{tid.replace(':', '_')}")
        script = task_dir / "submit.sh"
        if not script.exists():
            print(f"⚠️ submit.sh not found for {tid}")
            continue
        
        content = script.read_text()
        match = re.search(r"-F\s+'metadata=({.*?})'", content, re.DOTALL)
        if not match:
            print(f"⚠️ Could not parse metadata for {tid}")
            continue
        
        metadata = json.loads(match.group(1))
        extract_task_binaries(tid, metadata)
    
    print("\n✅ Extraction complete. Retry your baseline evaluation.")