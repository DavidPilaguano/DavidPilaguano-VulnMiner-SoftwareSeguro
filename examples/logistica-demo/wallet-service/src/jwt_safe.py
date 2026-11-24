import jwt

def identify(headers, public_key):
    principal = jwt.decode(headers['Bearer'], public_key, algorithms=['RS256'], audience='shipment')
    return principal['sub']
