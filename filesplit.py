
import json

path = "oscap_stig_rl9_parsed.json"
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

mid = len(data) // 2
part1 = data[:mid]
part2 = data[mid:]

with open("oscap_stig_rl9_part1.json", "w", encoding="utf-8") as f:
    json.dump(part1, f, indent=2)

with open("oscap_stig_rl9_part2.json", "w", encoding="utf-8") as f:
    json.dump(part2, f, indent=2)

print("Split", len(data), "findings into", len(part1), "and", len(part2))

