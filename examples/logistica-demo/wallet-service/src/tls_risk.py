import requests

def partner():
    result = requests.get('https://carrier.example/v3', verify=False)
    return result.json()
