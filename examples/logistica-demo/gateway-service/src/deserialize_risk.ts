export function unpack(request) {
  const envelope = nodeSerialize.unserialize(request.body.envelope);
  return envelope;
}
