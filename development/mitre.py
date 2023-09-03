import requests
import tomllib
import os
import sys


url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
headers = {
    "accept": "application/json"
}

mitreData = requests.get(url, headers=headers).json()
mitreMapped = {}

for object in mitreData["objects"]:
    tactics = []
    if object["type"] == "attack-pattern" and "external_references" in object:
        for reference in object["external_references"]:
            if "external_id" in reference and reference["external_id"].startswith("T"):
                if "kill_chain_phases" in object:
                    for tactic in object["kill_chain_phases"]:
                        tactics.append(tactic["phase_name"])
                technique = reference["external_id"]
                name = object["name"]
                url = reference["url"]
                filtered_object = {
                        "tactics": str(tactics),
                        "technique": technique,
                        "name": name,
                        "url": url
                }
                filtered_object["deprecated"] = False if "x_mitre_deprecated" not in object else object["x_mitre_deprecated"]
                mitreMapped[technique] = filtered_object

alert_data = {}
# rule_folder = "C:\\Users\\anthony\\Desktop\\Self Study\\Detection Engineering\\custom_alerts"
# rule_folder = "C:\\Users\\anthony\\Desktop\\Self Study\\Detection Engineering\\converted_detections"
rule_folder = "detections/"
for root, dirs, files in os.walk(rule_folder):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml_file:
                alert = tomllib.load(toml_file)
                filtered_object_array = []

                if alert["rule"]["threat"][0]["framework"] == "MITRE ATT&CK":
                    for threat in alert["rule"]["threat"]:
                        technique_id = threat["technique"][0]["id"]
                        technique_name = threat["technique"][0]["name"]
                        if "tactic" in threat:
                            tactic = threat["tactic"]["name"]
                            subtechnique_id = "none" if "subtechnique" not in threat["technique"][0] else threat["technique"][0]["id"]
                            subtechnique_name = "none" if "subtechnique" not in threat["technique"][0] else threat["technique"][0]["name"]
                        else:
                            tactic = "none"

                        filtered_object = {
                            "tactic" : tactic,
                            "technique_id": technique_id,
                            "technique_name": technique_name,
                            "subtechnique_id": subtechnique_id,
                            "subtechnique_name": subtechnique_name
                        }
                        filtered_object_array.append(filtered_object)
                        alert_data[file] = filtered_object_array

mitre_tactic_list = [
    "none",
    "reconnaissance",
    "resource development",
    "initial access",
    "execution",
    "persistence",
    "privilege escalation",
    "defense evasion",
    "credential access",
    "discovery",
    "lateral movement",
    "collection",
    "command and control",
    "exfiltration",
    "impact"
]

success = True

for file in alert_data:
    for line in alert_data[file]:
        tactic = line["tactic"].lower()
        technique_id = line["technique_id"]
        subtechnique_id = line["subtechnique_id"]

        # Check MITRE tactics exist
        if tactic not in mitre_tactic_list:
            print(f"The MITRE tactic supplied does not exist: {tactic} in {file}")

        # Check to make sure the MITRE Technique ID is valid
        try:
            if mitreMapped[technique_id]:
                pass
        except KeyError:
            print(f"Invalid MITRE technique ID: {technique_id} in {file}")
            success = False

        # Check if MITRE TID + Name combintation is valid
        try:
            mitre_name = mitreMapped[technique_id]["name"]
            alert_name = line["technique_name"]
            if alert_name != mitre_name:
                print(f"MITRE technique ID and name mismatch: {file} EXPECTED {mitre_name} GIVEN {alert_name}")
                success = False
        except KeyError:
            print(f"Provided TID invalid key")
            success = False

        # Check if the subTID Name Entry is valid
        try:
            if subtechnique_id != "none":
                mitre_name = mitreMapped[subtechnique_id]["name"]
                alert_name = line["subtechnique_name"]
                if alert_name != mitre_name:
                    print(f"MITRE subtechqnieu ID and name mismatch in: {file} Expected {mitre_name} GIVEN {alert_name}")
                    success = False
        except KeyError:
            print(f"Provided subTID invalid key")
            success = False

        # Check if the technique is deprecated
        try:
            if mitreMapped[technique_id]["deprecated"] == True:
                print(f"Deprecated MITRE alert: {file}")
                success = False
        except KeyError:
            pass

if not success:
    sys.exit(1)