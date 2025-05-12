import json
import os

def process_file(file_path):
    with open(file_path) as f:
        data = json.load(f)

    grouped = {}

    for match in data["matches"]:
        vuln_id = match["vulnerability"]["id"]
        artifact_name = match["artifact"]["name"]
        purl = match["artifact"]["purl"]
        locations = [loc["path"] for loc in match["artifact"].get("locations", [])]

        if vuln_id not in grouped:
            grouped[vuln_id] = {
                "names": set(),
                "locations": set(),
                "purls": set()
            }

        grouped[vuln_id]["names"].add(artifact_name)
        grouped[vuln_id]["locations"].update(locations)
        grouped[vuln_id]["purls"].add(purl)

    # Format desired structure
    result = {
        "matches": [
            {
                "vulnerability": {"id": vuln_id},
                "artifact": {
                    "name": sorted(list(values["names"])),
                    "locations": sorted(list(values["locations"])),
                    "purls": sorted(list(values["purls"]))
                }
            }
            for vuln_id, values in grouped.items()
        ]
    }
    return result

def save_results(results, output_file):
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

# Directory containing SBOM files
input_dir = "sbom_scans"
output_dir = "purl_vuln_dedup"

# Ensure output directory exists
os.makedirs(output_dir, exist_ok=True)

# Process each SBOM file
for file_name in os.listdir(input_dir):
    if file_name.endswith("vulns.json"):
        input_file = os.path.join(input_dir, file_name)
        output_file = os.path.join(output_dir, f"formatted_{file_name}")
        
        print(f"Processing {input_file}...")
        result = process_file(input_file)
        save_results(result, output_file)
        print(f"Saved formatted results to {output_file}")