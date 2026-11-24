export async function lookup(request) {
  const statement = 'SELECT amount FROM shipments WHERE reference=?';
  return connection.execute(statement, [request.query.reference]);
}
