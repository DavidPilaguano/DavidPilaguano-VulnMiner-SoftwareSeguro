import pickle

def restore(request):
    value = pickle.loads(request.data)
    return value
