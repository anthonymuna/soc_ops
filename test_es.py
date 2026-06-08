import json
import urllib.request

try:
    req = urllib.request.Request("http://localhost:9200/syndicate4-ml-alerts/_search?size=5")
    with urllib.request.urlopen(req) as response:
        print("ES 9200:")
        print(json.dumps(json.loads(response.read().decode()), indent=2))
except Exception as e:
    print("ES 9200 failed:", e)

try:
    req = urllib.request.Request("http://localhost:8000/alerts")
    with urllib.request.urlopen(req) as response:
        print("\nAPI 8000:")
        print(json.dumps(json.loads(response.read().decode()), indent=2))
except Exception as e:
    print("API 8000 failed:", e)
