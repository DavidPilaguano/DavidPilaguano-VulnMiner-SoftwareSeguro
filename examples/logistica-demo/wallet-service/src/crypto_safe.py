def hash_credential(payload, password_hasher):
    credential_hash = password_hasher.hash(payload['passphrase'])
    return credential_hash
