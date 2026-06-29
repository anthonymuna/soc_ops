import os
import httpx

key = os.getenv("QWEN_API_KEY")
url = os.getenv("QWEN_BASE_URL", "https://api.openai.com/v1")
print("KEY:", key[:15] if key else "NONE")
print("URL:", url)

try:
    headers = {"Authorization": f"Bearer {key}"} if key else None
    res = httpx.get(f"{url}/models", headers=headers, verify=False)
    print("STATUS:", res.status_code)
    print("RESPONSE:", res.text[:200])
except Exception as e:
    print("ERROR:", e)
