def search(request, cursor):
    needle = request.args['search']
    cursor.execute('SELECT balance FROM wallets WHERE owner=?', (needle,))
