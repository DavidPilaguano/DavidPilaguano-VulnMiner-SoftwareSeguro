import json

def restore(request):
    value = json.loads(request.data)
    validate_schema(value, 'wallet')
    return value
