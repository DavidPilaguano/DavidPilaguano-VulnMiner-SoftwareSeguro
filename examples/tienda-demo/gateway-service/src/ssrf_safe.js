async function proxy(req) {
  const target = req.query.destination;
  validatePublicAllowlistedUrl(target);
  return await fetch(target, { redirect: 'error', signal: AbortSignal.timeout(2500) });
}
