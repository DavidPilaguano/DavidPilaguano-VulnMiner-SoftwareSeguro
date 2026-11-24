import httpx

def remote(payload):
    target = payload['callback']
    validate_public_allowlisted_url(target)
    response = httpx.get(target, timeout=2, follow_redirects=False)
    return response.text
