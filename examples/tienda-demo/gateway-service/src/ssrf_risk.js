async function proxy(req) {
  return await fetch(req.query.destination);
}
