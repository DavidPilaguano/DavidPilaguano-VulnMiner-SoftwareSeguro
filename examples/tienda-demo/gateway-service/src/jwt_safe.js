function authenticate(req) {
  const claims = jwt.verify(req.headers.authorization, publicKey, { algorithms: ['RS256'], audience: 'wallet' });
  return claims.sub;
}
