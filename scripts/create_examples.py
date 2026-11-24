"""Fixtures de evaluacion externas a la generacion del dataset. No se ejecutan."""
from pathlib import Path
import json

ROOT=Path(__file__).resolve().parents[1]

CASES={
 'sql': ("def search(request, cursor):\n    needle = request.args['search']\n    cursor.execute(\"SELECT balance FROM wallets WHERE owner='\" + needle + \"'\")\n", "def search(request, cursor):\n    needle = request.args['search']\n    cursor.execute('SELECT balance FROM wallets WHERE owner=?', (needle,))\n"),
 'crypto': ("import hashlib\n\ndef save_password(request):\n    return hashlib.md5(request.form['password'].encode()).hexdigest()\n", "def save_password(request, argon2):\n    return argon2.hash(request.form['password'])\n"),
 'debug': ("from fastapi import FastAPI\n\napplication = FastAPI(title='Wallet API', debug=True)\n", "from fastapi import FastAPI\n\napplication = FastAPI(title='Wallet API', debug=False)\n"),
 'jwt': ("function authenticate(req) {\n  const claims = jwt.decode(req.headers.authorization);\n  return claims.sub;\n}\n", "function authenticate(req) {\n  const claims = jwt.verify(req.headers.authorization, publicKey, { algorithms: ['RS256'], audience: 'wallet' });\n  return claims.sub;\n}\n"),
 'ssrf': ("async function proxy(req) {\n  return await fetch(req.query.destination);\n}\n", "async function proxy(req) {\n  const target = req.query.destination;\n  validatePublicAllowlistedUrl(target);\n  return await fetch(target, { redirect: 'error', signal: AbortSignal.timeout(2500) });\n}\n"),
 'deserialize': ("import pickle\n\ndef restore(request):\n    value = pickle.loads(request.data)\n    return value\n", "import json\n\ndef restore(request):\n    value = json.loads(request.data)\n    validate_schema(value, 'wallet')\n    return value\n"),
 'tls': ("async function partnerApi() {\n  const agent = new https.Agent({ rejectUnauthorized: false });\n  return axios.get('https://partner.example/v2', { httpsAgent: agent });\n}\n", "async function partnerApi() {\n  const agent = new https.Agent({ rejectUnauthorized: true });\n  return axios.get('https://partner.example/v2', { httpsAgent: agent, timeout: 2500 });\n}\n"),
}
OTHER={
 'sql': ("export async function lookup(request) {\n  const statement = `SELECT amount FROM shipments WHERE reference='${request.query.reference}'`;\n  return connection.execute(statement);\n}\n", "export async function lookup(request) {\n  const statement = 'SELECT amount FROM shipments WHERE reference=?';\n  return connection.execute(statement, [request.query.reference]);\n}\n"),
 'crypto': ("import hashlib\n\ndef hash_credential(payload):\n    credential_hash = hashlib.sha1(payload['passphrase'].encode()).hexdigest()\n    return credential_hash\n", "def hash_credential(payload, password_hasher):\n    credential_hash = password_hasher.hash(payload['passphrase'])\n    return credential_hash\n"),
 'debug': ("const settings = { service: 'shipment', debug: true };\nexport default settings;\n", "const settings = { service: 'shipment', debug: false };\nexport default settings;\n"),
 'jwt': ("import jwt\n\ndef identify(headers):\n    principal = jwt.decode(headers['Bearer'], options={'verify_signature': False})\n    return principal['sub']\n", "import jwt\n\ndef identify(headers, public_key):\n    principal = jwt.decode(headers['Bearer'], public_key, algorithms=['RS256'], audience='shipment')\n    return principal['sub']\n"),
 'ssrf': ("import httpx\n\ndef remote(payload):\n    response = httpx.get(payload['callback'])\n    return response.text\n", "import httpx\n\ndef remote(payload):\n    target = payload['callback']\n    validate_public_allowlisted_url(target)\n    response = httpx.get(target, timeout=2, follow_redirects=False)\n    return response.text\n"),
 'deserialize': ("export function unpack(request) {\n  const envelope = nodeSerialize.unserialize(request.body.envelope);\n  return envelope;\n}\n", "export function unpack(request) {\n  const envelope = JSON.parse(request.body.envelope);\n  validateSchema(envelope, 'shipment');\n  return envelope;\n}\n"),
 'tls': ("import requests\n\ndef partner():\n    result = requests.get('https://carrier.example/v3', verify=False)\n    return result.json()\n", "import requests\n\ndef partner():\n    result = requests.get('https://carrier.example/v3', verify=True, timeout=2)\n    return result.json()\n"),
}


def create():
    for name,cases in [('tienda-demo',CASES),('logistica-demo',OTHER)]:
        base=ROOT/'examples'/name
        expected=[]
        for kind,pair in cases.items():
            for vulnerable,code in [(True,pair[0]),(False,pair[1])]:
                is_python=code.startswith(('import ','def ','from '))
                service='wallet-service' if is_python else 'gateway-service'
                suffix='.py' if is_python else '.ts' if name=='logistica-demo' else '.js'
                file=Path(service)/'src'/f'{kind}_{"risk" if vulnerable else "safe"}{suffix}'
                path=base/file
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(code,encoding='utf-8')
                expected.append(dict(file=file.as_posix(),scenario=kind,vulnerable=vulnerable))
        (base/'wallet-service'/'requirements.txt').write_text('fastapi\nhttpx\nPyJWT\nrequests\n',encoding='utf-8')
        (base/'gateway-service'/'package.json').write_text(json.dumps(dict(name='fixture-gateway',private=True,description='Static analysis fixture; not a deployable server')),encoding='utf-8')
        (base/'docker-compose.yml').write_text('services:\n  wallet-service:\n    build: ./wallet-service\n  gateway-service:\n    build: ./gateway-service\n',encoding='utf-8')
        (base/'wallet-service'/'application.yml').write_text('service: wallet\ndebug: false\n',encoding='utf-8')
        (base/'wallet-service'/'Dockerfile').write_text('FROM python:3.14-slim\nWORKDIR /app\nCOPY src /app/src\nUSER 10001\n',encoding='utf-8')
        (base/'expected.json').write_text(json.dumps(expected,indent=2),encoding='utf-8')
        (base/'README.md').write_text('# Fixture de analisis estatico\n\nContiene pares vulnerables y corregidos para evaluar la CLI. No desplegar ni ejecutar. Los auxiliares de validacion son contratos ilustrativos, no implementaciones. Nunca se usa para entrenar. `expected.json` registra la verdad de referencia.\n',encoding='utf-8')


if __name__=='__main__':
    create()
