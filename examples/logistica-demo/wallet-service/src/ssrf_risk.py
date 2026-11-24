import httpx

def remote(payload):
    response = httpx.get(payload['callback'])
    return response.text
