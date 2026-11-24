import hashlib

def save_password(request):
    return hashlib.md5(request.form['password'].encode()).hexdigest()
