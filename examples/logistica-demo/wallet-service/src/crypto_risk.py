import hashlib

def hash_credential(payload):
    credential_hash = hashlib.sha1(payload['passphrase'].encode()).hexdigest()
    return credential_hash
