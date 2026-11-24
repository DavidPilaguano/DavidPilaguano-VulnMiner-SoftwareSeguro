function authenticate(req) {
  const claims = jwt.decode(req.headers.authorization);
  return claims.sub;
}
