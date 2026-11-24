export async function lookup(request) {
  const statement = `SELECT amount FROM shipments WHERE reference='${request.query.reference}'`;
  return connection.execute(statement);
}
