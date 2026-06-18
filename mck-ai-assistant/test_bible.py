import requests
import json

url = "https://bibleql.org/graphql"
headers = {
    "Authorization": "Bearer bql_live_-EzSr24e7Hkmbyzu1avSFrHIccm0OVOJZ4AwnxWvBrs",
    "Content-Type": "application/json"
}

query = """
{
  passage(translation: "eng-web", reference: "John 3:16") {
    reference
    text
  }
}
"""

try:
    response = requests.post(url, headers=headers, json={"query": query})
    print(f"api.bibleql.org status: {response.status_code}")
    print(response.text)
except Exception as e:
    print(e)
