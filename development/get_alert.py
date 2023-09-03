import requests

api_key = os.environ["ELASTIC_KEY"]

id = "45d273fb-1dca-457d-9855-bcb302180c21"
url = f"https://3bfe4fc11ddd4bc8998955cc2ff0076c.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules?rule_id={id}"

headers = {
    "Content-Type": "application/json;charset=UTF-8",
    "kbn-xsrf": "true",
    "Authorization": f"ApiKey {api_key}"
}

elastic_data = requests.get(url, headers=headers).json()
print(elastic_data)
