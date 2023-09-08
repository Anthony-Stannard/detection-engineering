import tomllib
import os
import datetime
from dateutil.relativedelta import relativedelta


today = datetime.date.today()
current_month = str(today).split("-")[0] + "-" + str(today).split("-")[1]
one_month_ago = str(today-relativedelta(months=1)).split("-")[0] + "-" + str(today-relativedelta(months=1)).split("-")[1]
two_months_ago = str(today-relativedelta(months=1)).split("-")[0] + "-" + str(today-relativedelta(months=2)).split("-")[1]

current = {}
one_month = {}
two_months = {}


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
                obj = {
                    "date" : date,
                    "name" : name,
                    "author" : author,
                    "risk_score" : risk_score,
                    "severity" : severity,
                    "mitre": filtered_object_array
                }

                date_compare = f'{date.split("/")[0]}-{date.split("/")[1]}'
                print(date_compare, current_month, one_month_ago, two_months_ago)
                if date_compare == current_month:
                    current[file] = obj
                elif date_compare == one_month_ago:
                    one_month[file] = obj
                elif date_compare == two_months_ago:
                    two_months[file] = obj

                alert_data[file] = obj

output_path = "metrics/latestdetections.md"

        # tactic = []
        # tech = []
        # subtech = []

        # for technique in line["mitre"]:
        #     tactic.append(technique["tactic"])
        #     tech.append(technique["technique"])
        #     subtech.append(technique["subtech"])

with open(output_path, "w") as outfile:
    outfile.write("# Detection Report\n")
    # Current Month
    outfile.write("## Current Month\n")
    outfile.write("### New Alerts\n")
    outfile.write("| Alert | Date | Author | Risk Score | Serverity |\n")
    for line in current.values():
        date = line["date"]
        name = line["name"]
        author = str(line["author"]).replace(",", ";")
        risk_score = str(line["risk_score"])
        severity = line["severity"]
        outfile.write("| --- | --- | --- | --- | --- |\n")
        outfile.write(f"| {name} | {date} | {author} | {risk_score} | {severity} |\n")

    # Last Month
    outfile.write("## Last Month\n")
    outfile.write("### Alerts\n")
    outfile.write("| Alert | Date | Author | Risk Score | Serverity |\n")
    for line in one_month.values():
        date = line["date"]
        name = line["name"]
        author = str(line["author"]).replace(",", ";")
        risk_score = str(line["risk_score"])
        severity = line["severity"]

        outfile.write("| --- | --- | --- | --- | --- |\n")
        outfile.write(f"| {name} | {date} | {author} | {risk_score} | {severity} |\n")

    # Two Months Ago
    outfile.write("## Two Months ago\n")
    outfile.write("### Alerts\n")
    outfile.write("| Alert | Date | Author | Risk Score | Serverity |\n")
    for line in two_months.values():
        date = line["date"]
        name = line["name"]
        author = str(line["author"]).replace(",", ";")
        risk_score = str(line["risk_score"])
        severity = line["severity"]

        outfile.write("| --- | --- | --- | --- | --- |\n")
        outfile.write(f"| {name} | {date} | {author} | {risk_score} | {severity} |\n")