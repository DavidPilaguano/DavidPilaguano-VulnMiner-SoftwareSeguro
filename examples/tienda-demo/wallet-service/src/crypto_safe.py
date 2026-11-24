def save_password(request, argon2):
    return argon2.hash(request.form['password'])
