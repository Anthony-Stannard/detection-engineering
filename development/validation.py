import tomllib
import os
import sys

success = False
def validate_toml(alert):
    if alert['rule']['type'] == "query":  # query based alert
        required_fields = ["description", "name", "rule_id", "risk_score", "severity", "type", "query"]
    elif alert['rule']['type'] == "eql":  # Event correlation alert
        required_fields = ["description", "name", "rule_id", "risk_score", "severity", "type", "query", "language"]
    elif alert["rule"]["type"] == "threshold":  # threshold based alert
        required_fields = ["description", "name", "rule_id", "risk_score", "severity", "type", "query", "threshold"]
    else:
        print("This type of alert doesn't have a required fields setting yet.")
        return False

    present_fields = []
    for table in alert:
        present_fields += [field for field in alert[table]]


    missing_fields = [field for field in required_fields if field not in present_fields]
    if missing_fields:
        print(f"The following fields do not exist in {file}: {missing_fields}")
        return False
    else:
        print(f"Validation passed for: {file}")
    return True


# rule_folder = "C:\\Users\\anthony\\Desktop\\Self Study\\Detection Engineering\\custom_alerts"
rule_folder = "detections/"
for root, dirs, files in os.walk(rule_folder):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml_file:
                alert = tomllib.load(toml_file)
                success = validate_toml(alert)


if not success:
    sys.exit(1)