"""Casos sinteticos originales. Nunca descarga ni ejecuta codigo vulnerable."""
from pathlib import Path
import csv
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from vulnminer.catalog import SCENARIOS, catalog

# Six implementation families per scenario/language; entire families stay together.
# Each tuple is (vulnerable, corrected). Placeholders are domain identifiers.
PY = {
"sql": [
("cursor.execute(\"SELECT * FROM {table} WHERE name='\" + request.args['{key}'] + \"'\")", "cursor.execute('SELECT * FROM {table} WHERE name=?', (request.args['{key}'],))"),
("db.execute(f\"SELECT * FROM {table} WHERE id={{request.args['{key}']}}\")", "db.execute('SELECT * FROM {table} WHERE id=:id', dict(id=request.args['{key}']))"),
("query = 'DELETE FROM {table} WHERE name=%s' % request.form['{key}']\ncursor.execute(query)", "query = 'DELETE FROM {table} WHERE name=%s'\ncursor.execute(query, (request.form['{key}'],))"),
("statement = 'SELECT * FROM {table} WHERE id=' + str(payload['{key}'])\ndb.execute(statement)", "statement = 'SELECT * FROM {table} WHERE id=?'\ndb.execute(statement, (payload['{key}'],))"),
("cursor.execute('SELECT * FROM {table} WHERE name=\\\"{{}}\\\"'.format(params['{key}']))", "cursor.execute('SELECT * FROM {table} WHERE name=%s', [params['{key}']])"),
("sql = f\"UPDATE {table} SET active=1 WHERE id={{user_input['{key}']}}\"\nconnection.execute(sql)", "sql = 'UPDATE {table} SET active=1 WHERE id=:value'\nconnection.execute(sql, dict(value=user_input['{key}']))"),
],
"crypto": [
("password_digest = hashlib.md5(request.form['{key}'].encode()).hexdigest()", "password_digest = argon2.hash(request.form['{key}'])"),
("credential_hash = hashlib.sha1(payload['{key}'].encode()).hexdigest()", "credential_hash = password_hasher.hash(payload['{key}'])"),
("stored_password = md5(params['{key}'].encode()).hexdigest()", "stored_password = bcrypt.hashpw(params['{key}'].encode(), bcrypt.gensalt())"),
("signature = hashlib.new('md5', secret['{key}'].encode()).digest()", "signature = hmac.digest(key, secret['{key}'].encode(), 'sha256')"),
("password_hash = sha1(user_input['{key}'].encode()).digest()", "password_hash = scrypt(user_input['{key}'].encode(), salt=random_salt, n=16384, r=8, p=1)"),
("credential = hashlib.md5(data['{key}'].encode()).digest()", "credential = pbkdf2_hmac('sha256', data['{key}'].encode(), salt, 600000)"),
],
"debug": [
("app.run(debug=True, port={port})", "app.run(debug=False, port={port})"),
("DEBUG = True\nSERVICE_PORT = {port}", "DEBUG = False\nSERVICE_PORT = {port}"),
("app.config['DEBUG'] = True\napp.config['SERVICE'] = '{table}'", "app.config['DEBUG'] = False\napp.config['SERVICE'] = '{table}'"),
("settings.DEBUG = True\nsettings.PORT = {port}", "settings.DEBUG = False\nsettings.PORT = {port}"),
("application = FastAPI(debug=True, title='{table}')", "application = FastAPI(debug=False, title='{table}')"),
("server = Flask('{table}')\nserver.run(host='0.0.0.0', debug=True)", "server = Flask('{table}')\nserver.run(host='127.0.0.1', debug=False)"),
],
"jwt": [
("claims = jwt.decode(request.headers['{key}'], options={{'verify_signature': False}})", "claims = jwt.decode(request.headers['{key}'], public_key, algorithms=['RS256'], audience='orders')"),
("identity = jwt.decode(payload['{key}'], options=dict(verify_signature=False))", "identity = jwt.decode(payload['{key}'], secret, algorithms=['HS256'], issuer='identity')"),
("user = jwt.decode(params['{key}'], verify=False)", "user = jwt.decode(params['{key}'], key=public_key, algorithms=['ES256'], audience='catalog')"),
("auth = jwt.decode(user_input['{key}'], options={{'verify_signature': False, 'verify_exp': False}})", "auth = jwt.decode(user_input['{key}'], public_key, algorithms=['RS256'], options={{'require': ['exp', 'aud']}})"),
("token_claims = jwt.decode(data['{key}'], options={{'verify_signature': False}})", "token_claims = jwt.decode(data['{key}'], signing_key, algorithms=['HS256'], audience='billing')"),
("principal = jwt.decode(headers['{key}'], verify=False, algorithms=['none'])", "principal = jwt.decode(headers['{key}'], public_key, algorithms=['RS256'], issuer='trusted')"),
],
"ssrf": [
("response = requests.get(request.args['{key}'])", "target = request.args['{key}']\nvalidate_public_allowlisted_url(target)\nresponse = requests.get(target, timeout=5, allow_redirects=False)"),
("result = httpx.get(payload['{key}'])", "result = httpx.get('https://{table}.example/api', timeout=3)"),
("body = urllib.request.urlopen(params['{key}']).read()", "url = params['{key}']\nvalidate_public_allowlisted_url(url)\nbody = approved_http_client.get(url, follow_redirects=False)"),
("remote = requests.post(user_input['{key}'], json=data)", "remote = requests.post('https://{table}.example/submit', json=data, timeout=5)"),
("content = httpx.request('GET', data['{key}'])", "target = data['{key}']\nvalidate_public_allowlisted_url(target)\ncontent = httpx.request('GET', target, timeout=5, follow_redirects=False)"),
("with urllib.request.urlopen(request.form['{key}']) as stream:\n    content = stream.read()", "target = 'https://{table}.example/data'\nwith urllib.request.urlopen(target, timeout=4) as stream:\n    content = stream.read(4096)"),
],
"deserialize": [
("obj = pickle.loads(request.data)\nstore('{table}', obj)", "obj = json.loads(request.data)\nvalidate_schema(obj, '{table}')"),
("record = pickle.load(request.stream)\nprocess('{table}', record)", "record = json.load(request.stream)\nvalidate_schema(record, '{table}')"),
("result = marshal.loads(payload['{key}'])", "result = json.loads(payload['{key}'])\nvalidate_schema(result, '{table}')"),
("entity = yaml.unsafe_load(params['{key}'])", "entity = yaml.safe_load(params['{key}'])\nvalidate_schema(entity, '{table}')"),
("decoded = pickle.loads(base64.b64decode(user_input['{key}']))", "decoded = json.loads(base64.b64decode(user_input['{key}']))\nvalidate_schema(decoded, '{table}')"),
("model = yaml.load(data['{key}'], Loader=yaml.Loader)", "model = yaml.load(data['{key}'], Loader=yaml.SafeLoader)\nvalidate_schema(model, '{table}')"),
],
"tls": [
("response = requests.get('https://{table}.example/api', verify=False)", "response = requests.get('https://{table}.example/api', verify=True, timeout=5)"),
("client = httpx.Client(verify=False)\nclient.get('https://{table}.example')", "client = httpx.Client(verify=True, timeout=5)\nclient.get('https://{table}.example')"),
("ctx = ssl._create_unverified_context()\nurllib.request.urlopen('https://{table}.example', context=ctx)", "ctx = ssl.create_default_context()\nurllib.request.urlopen('https://{table}.example', context=ctx, timeout=5)"),
("ctx.check_hostname = False\nctx.verify_mode = ssl.CERT_NONE\nconnect('{table}', ctx)", "ctx.check_hostname = True\nctx.verify_mode = ssl.CERT_REQUIRED\nconnect('{table}', ctx)"),
("session.verify = False\nresult = session.get('https://{table}.example')", "session.verify = True\nresult = session.get('https://{table}.example', timeout=4)"),
("reply = httpx.post('https://{table}.example/api', verify=False, json=payload)", "reply = httpx.post('https://{table}.example/api', verify=True, json=payload, timeout=5)"),
],
}
JS = {
"sql": [
("db.query(\"SELECT * FROM {table} WHERE id=\" + req.query.{key});", "db.query('SELECT * FROM {table} WHERE id=?', [req.query.{key}]);"),
("connection.execute(`SELECT * FROM {table} WHERE name='${{req.body.{key}}}'`);", "connection.execute('SELECT * FROM {table} WHERE name=?', [req.body.{key}]);"),
("const sql = 'DELETE FROM {table} WHERE id=' + params.{key};\nclient.query(sql);", "const sql = 'DELETE FROM {table} WHERE id=$1';\nclient.query(sql, [params.{key}]);"),
("pool.query(`UPDATE {table} SET active=1 WHERE id=${{input.{key}}}`);", "pool.query('UPDATE {table} SET active=1 WHERE id=$1', [input.{key}]);"),
("const statement = \"SELECT * FROM {table} WHERE id=\".concat(request.query.{key});\ndb.execute(statement);", "const statement = 'SELECT * FROM {table} WHERE id=?';\ndb.execute(statement, [request.query.{key}]);"),
("repository.query(`SELECT * FROM {table} WHERE name='${{payload.{key}}}'`);", "repository.query('SELECT * FROM {table} WHERE name=$1', [payload.{key}]);"),
],
"crypto": [
("const passwordDigest = crypto.createHash('md5').update(req.body.{key}).digest('hex');", "const passwordDigest = await argon2.hash(req.body.{key});"),
("const credential = crypto.createHash('sha1').update(input.{key}).digest('hex');", "const credential = await bcrypt.hash(input.{key}, 12);"),
("const passwordHash = createHash('md5').update(params.{key}).digest();", "const passwordHash = await scryptAsync(params.{key}, randomBytes(16), 64);"),
("const signature = crypto.createHash('md5').update(secret.{key}).digest('base64');", "const signature = crypto.createHmac('sha256', signingKey).update(secret.{key}).digest('base64');"),
("const stored = createHash('sha1').update(payload.{key}).digest('hex');", "const stored = await argon2.hash(payload.{key});"),
("const credentialHash = crypto.createHash('md5').update(data.{key}).digest('hex');", "const credentialHash = await bcrypt.hash(data.{key}, 14);"),
],
"debug": [
("const config = {{ debug: true, port: {port} }};", "const config = {{ debug: false, port: {port} }};"),
("app.set('debug', true);\napp.set('name', '{table}');", "app.set('debug', false);\napp.set('name', '{table}');"),
("module.exports = {{ debug: true, service: '{table}' }};", "module.exports = {{ debug: false, service: '{table}' }};"),
("settings.debug = true;\nsettings.port = {port};", "settings.debug = false;\nsettings.port = {port};"),
("const server = createServer({{ debug: true, name: '{table}' }});", "const server = createServer({{ debug: false, name: '{table}' }});"),
("const options = {{ service: '{table}', debug: true }};\nstartServer(options);", "const options = {{ service: '{table}', debug: false }};\nstartServer(options);"),
],
"jwt": [
("const claims = jwt.decode(req.headers.{key});", "const claims = jwt.verify(req.headers.{key}, publicKey, {{ algorithms: ['RS256'], audience: 'orders' }});"),
("const user = jwt.decode(req.body.{key}, {{ complete: true }});", "const user = jwt.verify(req.body.{key}, secret, {{ algorithms: ['HS256'], issuer: 'trusted' }});"),
("const identity = decode(params.{key});\nreq.user = identity;", "const identity = verify(params.{key}, publicKey, {{ algorithms: ['RS256'] }});\nreq.user = identity;"),
("const principal = jwt.decode(input.{key}, {{ json: true }});", "const principal = jwt.verify(input.{key}, signingKey, {{ algorithms: ['ES256'], audience: 'billing' }});"),
("const auth = jwt.decode(payload.{key});\nsession.user = auth.sub;", "const auth = jwt.verify(payload.{key}, key, {{ algorithms: ['RS256'], issuer: 'identity' }});\nsession.user = auth.sub;"),
("const token = jwt.decode(data.{key});\nreturn token.roles;", "const token = jwt.verify(data.{key}, publicKey, {{ algorithms: ['RS256'], audience: 'catalog' }});\nreturn token.roles;"),
],
"ssrf": [
("const reply = await fetch(req.query.{key});", "const target = req.query.{key};\nvalidatePublicAllowlistedUrl(target);\nconst reply = await fetch(target, {{ redirect: 'error', signal: AbortSignal.timeout(3000) }});"),
("const result = await axios.get(req.body.{key});", "const result = await axios.get('https://{table}.example/api', {{ timeout: 3000 }});"),
("https.get(params.{key}, callback);", "const target = params.{key};\nvalidatePublicAllowlistedUrl(target);\nhttps.get(target, {{ timeout: 3000 }}, callback);"),
("const body = await fetch(input.{key}).then(r => r.text());", "const body = await fetch('https://{table}.example/data', {{ signal: AbortSignal.timeout(3000) }}).then(r => r.text());"),
("const response = await axios.post(payload.{key}, data);", "const target = payload.{key};\nvalidatePublicAllowlistedUrl(target);\nconst response = await axios.post(target, data, {{ maxRedirects: 0, timeout: 3000 }});"),
("http.request(request.query.{key}, callback).end();", "http.request('https://{table}.example/api', {{ timeout: 3000 }}, callback).end();"),
],
"deserialize": [
("const obj = serialize.unserialize(req.body.{key});", "const obj = JSON.parse(req.body.{key});\nvalidateSchema(obj, '{table}');"),
("const entity = unserialize(params.{key});", "const entity = JSON.parse(params.{key});\nvalidateSchema(entity, '{table}');"),
("const result = nodeSerialize.unserialize(input.{key});", "const result = JSON.parse(input.{key});\nvalidateSchema(result, '{table}');"),
("const record = serialize.unserialize(Buffer.from(payload.{key}, 'base64').toString());", "const record = JSON.parse(Buffer.from(payload.{key}, 'base64').toString());\nvalidateSchema(record, '{table}');"),
("const model = unserialize(request.body.{key});\nstore('{table}', model);", "const model = JSON.parse(request.body.{key});\nvalidateSchema(model, '{table}');"),
("const decoded = nodeSerialize.unserialize(data.{key});\nprocessRecord('{table}', decoded);", "const decoded = JSON.parse(data.{key});\nvalidateSchema(decoded, '{table}');"),
],
"tls": [
("const agent = new https.Agent({{ rejectUnauthorized: false }});\naxios.get('https://{table}.example', {{ httpsAgent: agent }});", "const agent = new https.Agent({{ rejectUnauthorized: true }});\naxios.get('https://{table}.example', {{ httpsAgent: agent, timeout: 3000 }});"),
("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\nfetch('https://{table}.example/api');", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';\nfetch('https://{table}.example/api');"),
("https.get('https://{table}.example', {{ rejectUnauthorized: false }}, callback);", "https.get('https://{table}.example', {{ rejectUnauthorized: true, timeout: 3000 }}, callback);"),
("const options = {{ hostname: '{table}.example', rejectUnauthorized: false }};\nhttps.request(options);", "const options = {{ hostname: '{table}.example', rejectUnauthorized: true, timeout: 3000 }};\nhttps.request(options);"),
("const client = axios.create({{ httpsAgent: new https.Agent({{ rejectUnauthorized: false }}) }});\nclient.get('https://{table}.example');", "const client = axios.create({{ httpsAgent: new https.Agent({{ rejectUnauthorized: true }}), timeout: 3000 }});\nclient.get('https://{table}.example');"),
("tls.connect({{ host: '{table}.example', rejectUnauthorized: false }});", "tls.connect({{ host: '{table}.example', rejectUnauthorized: true }});"),
],
}


def generate():
    dest = ROOT / 'data'
    dest.mkdir(exist_ok=True)
    records, seen = [], set()
    for language, scenarios in [('Python', PY), ('JavaScript', JS)]:
        for kind, families in scenarios.items():
            for family, pair in enumerate(families):
                split = 'train' if family < 4 else 'validation' if family == 4 else 'test'
                for variant in range(6):
                    for vulnerable, template in [(1, pair[0]), (0, pair[1])]:
                        code = template.format(table=['orders','accounts','products','invoices','customers','payments'][variant], key=['name','id','value','ref','item','token'][variant], port=8100+variant)
                        digest = hashlib.sha256(code.encode()).hexdigest()
                        if digest in seen:
                            continue
                        seen.add(digest)
                        info = SCENARIOS[kind]
                        records.append(dict(id=f'VM-{len(records)+1:04}', project=f'controlled-{language.lower()}-{kind}-family{family}', family=family, scenario=kind, language=language, code=code, vulnerable=vulnerable, labels=json.dumps(info['labels'] if vulnerable else []), cwe=info['cwe'] if vulnerable else '', source='original-controlled-v1', source_url='scripts/generate_dataset.py', split=split, sha256=digest))
    with (dest / 'dataset.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)
    (dest / 'catalog.json').write_text(json.dumps(catalog(), ensure_ascii=False, indent=2), encoding='utf-8')
    with (dest / 'cwe_owasp.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['scenario', 'cwe', 'owasp', 'basis'])
        for kind, info in SCENARIOS.items():
            writer.writerow([kind, info['cwe'], ';'.join(info['labels']), 'Relacion contextual del escenario; ver docs/fuentes.md'])
    print(f'Dataset: {len(records)} registros; seguros: {sum(not r["vulnerable"] for r in records)}')
    return records


if __name__ == '__main__':
    generate()
