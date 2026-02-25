import json
from datetime import datetime

lines = open('/Users/liviu/Documents/ai-runtime-guard/activity.log').readlines()
events = []
for l in lines:
    d = json.loads(l.strip())
    ts = datetime.fromisoformat(d['timestamp'].replace('Z', '+00:00'))
    events.append((ts, d))

# Find gaps > 20 seconds
print("=== GAPS > 20 seconds ===")
for i in range(1, len(events)):
    gap = (events[i][0] - events[i-1][0]).total_seconds()
    if gap > 20:
        prev = events[i-1][1]
        curr = events[i][1]
        prev_cmd = prev.get('command', prev.get('path', ''))[:50]
        curr_cmd = curr.get('command', curr.get('path', ''))[:50]
        print(f"\nGAP: {gap:.0f}s")
        print(f"  BEFORE: {events[i-1][0].strftime('%H:%M:%S')} | {prev['tool']} | {prev['policy_decision']} | {prev_cmd}")
        print(f"  AFTER:  {events[i][0].strftime('%H:%M:%S')} | {curr['tool']} | {curr['policy_decision']} | {curr_cmd}")

# Also show all gaps
print("\n=== ALL INTER-EVENT GAPS ===")
for i in range(1, len(events)):
    gap = (events[i][0] - events[i-1][0]).total_seconds()
    prev = events[i-1][1]
    curr = events[i][1]
    prev_cmd = prev.get('command', prev.get('path', ''))[:40]
    curr_cmd = curr.get('command', curr.get('path', ''))[:40]
    marker = " <<<<< LONG GAP" if gap > 20 else ""
    print(f"{gap:6.1f}s | {events[i-1][0].strftime('%H:%M:%S')}→{events[i][0].strftime('%H:%M:%S')} | {prev['tool'][:12]}→{curr['tool'][:12]}{marker}")
