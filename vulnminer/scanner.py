"""Lectura estatica acotada; el modelo asigna etiquetas, las reglas aportan evidencia."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import re
import joblib
import numpy as np
import yaml
from .catalog import SCENARIOS, catalog

IGNORED = {'.git','.venv','venv','node_modules','__pycache__','dist','build','target','.idea','.next','reportes','reports','output'}
EXTENSIONS = {'.py','.js','.jsx','.ts','.tsx','.yml','.yaml','.properties','.json','.xml','.toml','.txt'}
MANIFESTS = {'package.json','pom.xml','requirements.txt','pyproject.toml','build.gradle','go.mod'}
ANCHORS = {
    'sql': r'\b(?:execute|query|raw)\s*\(',
    'crypto': r'\b(?:md5|sha1|createHash|hashlib\.new)\s*\(',
    'debug': r'''\bdebug[\x27\x22]?\s*[:=]|\bdebug[\x27\x22]\]\s*=|\.set\([\x27\x22]debug[\x27\x22]''',
    'jwt': r'\b(?:jwt\.(?:decode|verify)|decode|verify)\s*\(',
    'ssrf': r'\b(?:requests|httpx|axios|https?|urllib\.request)\.(?:get|post|request|urlopen)\s*\(|\bfetch\s*\(',
    'deserialize': r'\b(?:pickle\.(?:loads?|load)|marshal\.loads|yaml\.(?:load|unsafe_load|safe_load)|(?:\w+\.)?unserialize|JSON\.parse|json\.loads?)\s*\(',
    'tls': r'verify\s*=|rejectUnauthorized|CERT_NONE|CERT_REQUIRED|check_hostname|_create_unverified_context|NODE_TLS_REJECT_UNAUTHORIZED',
}
COMPILED = {k:re.compile(v,re.I) for k,v in ANCHORS.items()}
SUSPICIOUS = re.compile(r'md5|sha1|debug\s*[=:]\s*(?:true|1)|DEBUG[\x27\x22]?\s*\]?\s*=\s*True|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|verify_signature[\x27\x22]?\s*[:=]\s*False|jwt\.decode|pickle\.loads?|unserialize\(|yaml\.unsafe_load|yaml\.Loader\b|CERT_NONE|_create_unverified_context|\beval\(|\bexec\(|shell\s*=\s*True',re.I)


def load_model():
    # No user-provided pickle path. Only load the packaged artifact.
    path = Path(__file__).parent/'artifacts'/'model.joblib'
    if not path.is_file():
        raise ValueError('Falta el modelo entrenado. Ejecute python scripts/train.py durante la preparacion.')
    return joblib.load(path)


def files_under(root, output=None):
    skipped=[]
    def visit(directory):
        try:
            children=sorted(directory.iterdir(),key=lambda p:p.name)
        except OSError as exc:
            skipped.append(dict(path=str(directory.relative_to(root)),reason=type(exc).__name__))
            return
        for p in children:
            if p.is_symlink() or (output is not None and p.resolve()==output):
                continue
            if p.is_dir():
                if p.name not in IGNORED and not p.name.startswith('.'):
                    yield from visit(p)
            elif p.name=='Dockerfile' or p.suffix.lower() in EXTENSIONS:
                try:
                    if p.stat().st_size>1_000_000:
                        skipped.append(dict(path=p.relative_to(root).as_posix(),reason='Mayor a 1 MB'))
                    else:
                        yield p
                except OSError as exc:
                    skipped.append(dict(path=p.relative_to(root).as_posix(),reason=type(exc).__name__))
    return list(visit(root)),skipped


def discover_services(root, files):
    services={}
    for path in files:
        if path.name in MANIFESTS or path.name=='Dockerfile':
            folder=path.parent
            # A root manifest describes the tool/project and does not swallow subservices.
            services[folder]=dict(name=folder.name, path=folder.relative_to(root).as_posix(), technologies=[])
    for compose in [p for p in files if p.name in {'docker-compose.yml','docker-compose.yaml','compose.yml','compose.yaml'}]:
        try:
            obj=yaml.safe_load(compose.read_text(encoding='utf-8')) or {}
            for name,conf in obj.get('services',{}).items():
                if not isinstance(conf,dict):
                    continue
                build=conf.get('build')
                context=build.get('context') if isinstance(build,dict) else build
                if not isinstance(context,str):
                    continue
                folder=(compose.parent/context).resolve()
                if folder.is_relative_to(root) and folder.is_dir():
                    services[folder]=dict(name=str(name),path=folder.relative_to(root).as_posix(),technologies=[])
        except (OSError,ValueError,AttributeError,TypeError,yaml.YAMLError):
            pass
    if not services:
        services[root]=dict(name=root.name,path='.',technologies=[])
    for folder,info in services.items():
        owned=[p for p in files if p.is_relative_to(folder)]
        info['technologies']=sorted({language(p) for p in owned})
    return services


def language(path):
    return {'.py':'Python','.js':'JavaScript','.jsx':'JavaScript','.ts':'TypeScript','.tsx':'TypeScript'}.get(path.suffix.lower(),'Configuracion')


def scan(root, standards=('owasp2025','api2023'), output=None):
    root=Path(root).resolve()
    if not root.is_dir():
        raise ValueError(f'No existe el directorio: {root}')
    model=load_model()
    paths,skipped=files_under(root,Path(output).resolve() if output else None)
    services=discover_services(root,paths)
    findings=[]
    analyzed=0
    for path in paths:
        try:
            content=path.read_text(encoding='utf-8-sig')
        except (OSError,UnicodeError) as exc:
            skipped.append(dict(path=path.relative_to(root).as_posix(),reason=type(exc).__name__))
            continue
        analyzed+=1
        lines=content.splitlines()
        candidates=[]
        for i,line in enumerate(lines):
            if line.lstrip().startswith(('#','//','/*','*')):
                continue
            kinds=[kind for kind,pattern in COMPILED.items() if pattern.search(line)]
            unknown=bool(re.search(r'\beval\(|\bexec\(|shell\s*=\s*True',line))
            if not kinds and not unknown:
                continue
            # Only neighboring statements in the same block; never cross blank boundaries.
            start=i
            while start>max(0,i-2) and lines[start-1].strip():
                start-=1
            end=i+1
            while end<min(len(lines),i+3) and lines[end].strip():
                end+=1
            candidates.append((i,line,'\n'.join(lines[start:end]),kinds,unknown))
        if not candidates:
            continue
        matrix=model['features'].transform([c[2] for c in candidates])
        probability=model['estimator'].predict_proba(matrix)
        if isinstance(probability,list):
            probability=np.column_stack([p[:,1] for p in probability])
        for candidate,vector,feature_row in zip(candidates,probability,matrix):
            i,line,context,kinds,unknown=candidate
            learned={label:float(p) for label,p in zip(model['classes'],vector) if p>=model['threshold']}
            supported=set(label for kind in kinds for label in SCENARIOS[kind]['labels'])
            labels=sorted(set(learned)&supported)
            # The model can abstain even when static evidence warrants manual review.
            suspicion=bool(SUSPICIOUS.search(line))
            if language(path)=='Python' and 'jwt.decode' in line and not re.search(r'verify\s*=\s*False|verify_signature[\x27\x22]?\s*[:=]\s*False',context):
                suspicion=False
            pending=not labels and (unknown or suspicion)
            if not labels and not pending:
                continue
            filtered=[label for label in labels if ('owasp2025' in standards if label.startswith('A0') or label.startswith('A10:') else 'api2023' in standards)]
            if labels and not filtered:
                continue
            labels=filtered
            matched=[kind for kind in kinds if set(SCENARIOS[kind]['labels'])&set(labels)]
            # Resolve overlapping evidence (e.g. HTTP call with TLS disabled).
            priority=['tls','jwt','deserialize','sql','crypto','debug','ssrf']
            kind=next((k for k in priority if k in matched),None)
            info=SCENARIOS[kind] if kind else None
            owners=[folder for folder in services if path.is_relative_to(folder)]
            owner=max(owners,key=lambda p:len(p.parts)) if owners else None
            relative=path.relative_to(root).as_posix()
            uid=hashlib.sha256(f'{relative}:{i+1}:{line}'.encode()).hexdigest()[:12]
            confidence=max((learned[label] for label in labels),default=float(max(vector)))
            finding=dict(id=f'VM-{uid}',service=services[owner]['name'] if owner else 'configuracion-raiz',file=relative,line=i+1,language=language(path),description=info['title'] if info else 'Patron sensible sin clasificacion suficientemente respaldada',evidence=line.strip()[:500],context=context[:1500],owasp_top10=[s for s in labels if s in __import__('vulnminer.catalog',fromlist=['WEB']).WEB],owasp_api=[s for s in labels if s.startswith('API')],cwe=info['cwe'] if info else None,confidence=round(confidence,4),label_scores={s:round(learned[s],4) for s in labels},severity=info['severity'] if info else 'Sin estimar',severity_justification=info['reason'] if info else 'No hay evidencia suficiente para estimar el impacto.',recommendation=info['remedy'] if info else 'Revisar origen de la entrada, controles y flujo de datos; ampliar pruebas.',verification_status='Pendiente de revision' if pending else 'Requiere verificacion',confirmed=False)
            # Avoid repeating the same scenario on adjacent lines of one expression.
            if findings and findings[-1]['file']==relative and i+1-findings[-1]['line']<=2 and findings[-1]['owasp_top10']==finding['owasp_top10'] and findings[-1]['owasp_api']==finding['owasp_api']:
                continue
            findings.append(finding)
    selected_catalog=[c for c in catalog() if ('api2023' in standards if c['id'].startswith('API') else 'owasp2025' in standards)]
    return dict(schema_version='1.0',generated_at=datetime.now(timezone.utc).isoformat(),project=root.name,root=str(root),standards=list(standards),model=dict(algorithm=model['algorithm'],threshold=model['threshold'],confidence_note='Puntuacion del clasificador; no es probabilidad calibrada ni severidad.'),services=list(services.values()),files_analyzed=analyzed,skipped_files=skipped,findings=findings,catalog=selected_catalog,limitations=['Analisis lexico local sin prueba de explotabilidad ni flujo interprocedimental.','Datos de entrenamiento sinteticos controlados; generalizacion real no demostrada.','Ausencia de hallazgos no certifica seguridad.','Dependencias e inventario se leen como configuracion; sin base CVE ni auditoria de cadena de suministro.','Configuraciones fuera de los patrones entrenados requieren revision; Java no esta soportado.','El reporte contiene evidencia del codigo y puede contener informacion sensible.'])
