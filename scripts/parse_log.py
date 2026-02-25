import json

lines = open('/Users/liviu/Documents/ai-runtime-guard/activity.log').readlines()
for l in lines:
    d = json.loads(l.strip())
    ts = d.get('timestamp', '')
    tool = d.get('tool', '')[:15]
    decision = d.get('policy_decision', '')[:10]
    cmd = d.get('command', d.get('path', d.get('block_reason', '')))[:60]
    print(f"{ts} | {tool:<15} | {decision:<10} | {cmd}")
