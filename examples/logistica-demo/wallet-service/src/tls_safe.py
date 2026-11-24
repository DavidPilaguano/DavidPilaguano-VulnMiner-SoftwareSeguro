import requests

def partner():
    result = requests.get('https://carrier.example/v3', verify=True, timeout=2)
    return result.json()
