import urllib.request
import json
url = "https://api.github.com/repos/ContextualWisdomLab/appguardrail/pulls/1021"
try:
    with urllib.request.urlopen(url) as response:
        data = json.loads(response.read().decode())
        print(f"Head ref: {data['head']['ref']}")
except Exception as e:
    print(e)
