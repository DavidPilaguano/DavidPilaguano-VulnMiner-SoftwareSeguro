export function unpack(request) {
  const envelope = JSON.parse(request.body.envelope);
  validateSchema(envelope, 'shipment');
  return envelope;
}
