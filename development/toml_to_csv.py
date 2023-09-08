import tomllib
import os

rule_folder = "detections/"  # "C:\\Users\\anthony\\Desktop\\Self Study\\Detection Engineering\\converted_detections"
alert_data = {}
for root, dirs, files in os.walk(rule_folder):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml_file:
                alert = tomllib.load(toml_file)
                date = alert["metadata"]["creation_date"]
                name = alert["rule"]["name"]
                author = alert["rule"]["author"]
                risk_score = alert["rule"]["risk_score"]
                severity = alert["rule"]["severity"]
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
                            "technique": f"{technique_id} - {technique_name}",
                            "subtechnique": f"{subtechnique_id} - {subtechnique_name}",
                        }
                        filtered_object_array.append(filtered_object)
                alert_data[file] = {
                    "date" : date,
                    "name" : name,
                    "author" : author,
                    "risk_score" : risk_score,
                    "severity" : severity,
                    "mitre": filtered_object_array
                }

output_path = "metrics/detectiondata.csv"

with open(output_path, "w") as outfile:
    outfile.write("name,date,author,risk_score,severity,tactic,technique,subtechnique\n")
    for line in alert_data.values():
        print(line)
        date = line["date"]
        name = line["name"]
        author = str(line["author"]).replace(",", ";")
        risk_score = str(line["risk_score"])
        severity = line["severity"]

        tactic = []
        tech = []
        subtech = []

        for technique in line["mitre"]:
            tactic.append(technique["tactic"])
            tech.append(technique["technique"])
            subtech.append(technique["subtechnique"])

        separator = "; "
        outfile.write(f"{name},{date},{author},{risk_score},{severity}," + separator.join(tactic) + "," + separator.join(tech) + "," + separator.join(subtech))
        outfile.write("\n")