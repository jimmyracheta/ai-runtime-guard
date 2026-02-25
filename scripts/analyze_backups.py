import json, os, glob

backup_root = '/Users/liviu/Documents/ai-runtime-guard/backups'
dirs = sorted(glob.glob(f'{backup_root}/*/'))

print(f"Total backup directories: {len(dirs)}\n")
print(f"{'Backup dir':<45} {'File backed up':<30} {'Size'}")
print("-" * 90)

total_bytes = 0
file_counts = {}
for d in dirs:
    manifest_path = os.path.join(d, 'manifest.json')
    name = os.path.basename(d.rstrip('/'))
    try:
        manifest = json.load(open(manifest_path))
        for entry in manifest:
            src = entry['source'].split('/')[-1]
            backup_file = entry['backup']
            size = os.path.getsize(backup_file) if os.path.exists(backup_file) else 0
            total_bytes += size
            file_counts[src] = file_counts.get(src, 0) + 1
            print(f"{name:<45} {src:<30} {size:>6} bytes")
    except Exception as e:
        print(f"{name:<45} {'[no manifest]':<30}")

print(f"\nTotal backup storage: {total_bytes:,} bytes ({total_bytes/1024:.1f} KB)")
print(f"\nBackup frequency per file:")
for f, c in sorted(file_counts.items(), key=lambda x: -x[1]):
    print(f"  {f}: {c} backups")
