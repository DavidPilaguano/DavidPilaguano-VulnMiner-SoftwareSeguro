import jwt

def identify(headers):
    principal = jwt.decode(headers['Bearer'], options={'verify_signature': False})
    return principal['sub']
