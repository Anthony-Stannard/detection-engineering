import requests
import tomllib
import os


api_key = os.environ["ELASTIC_KEY"]

url = "https://3bfe4fc11ddd4bc8998955cc2ff0076c.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules"
headers = {
    "Content-Type": "application/json;charset=UTF-8",
    "kbn-xsrf": "true",
    "Authorization": f"ApiKey {api_key}"
}


rule_folder = "detections/"
# rule_folder = "C:\\Users\\anthony\\Desktop\\Self Study\\Detection Engineering\\converted_detections"
for root, dirs, files in os.walk(rule_folder):
    for file in files:
        data = "{\n"
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml_file:
                alert = tomllib.load(toml_file)

                if alert['rule']['type'] == "query":  # query based alert
                    required_fields = ["author", "description", "name", "rule_id", "risk_score", "severity", "type", "query", "threat"]
                elif alert['rule']['type'] == "eql":  # Event correlation alert
                    required_fields = ["author", "description", "name", "rule_id", "risk_score", "severity", "type", "query", "language", "threat"]
                elif alert["rule"]["type"] == "threshold":  # threshold based alert
                    required_fields = ["author", "description", "name", "rule_id", "risk_score", "severity", "type", "query", "threshold", "threat"]
                else:
                    raise NotImplementedError("This type of alert doesn't have a required fields setting yet.")

                for field in alert["rule"]:
                    if field in required_fields:
                        if type(alert["rule"][field]) == list:
                            value = f"{alert['rule'][field]}".replace("'", "\"").strip()
                            data += f'  "{field}": {value},\n'
                        elif type(alert["rule"][field]) == str:
                            if field == "description" or field == "query":
                                value = f"{alert['rule'][field]}".replace("\\", "\\\\").replace('"', '\\"').strip()
                            else:
                                value = f"{alert['rule'][field]}".replace('"', '\\"').strip()
                            data += f'  "{field}": "{value}",\n'
                        elif type(alert["rule"][field]) == int:
                            value = f"{alert['rule'][field]}".strip()
                            data += f'  "{field}": {value},\n'
                        elif type(alert["rule"][field]) == dict:
                            value = f"{alert['rule'][field]}".strip().replace("'", '"')
                            data += f'  "{field}": {value},\n'
                data += '  "enabled": true\n}'

            print(data)

        elastic_data = requests.post(url, headers=headers, data=data).json()
        print(elastic_data)