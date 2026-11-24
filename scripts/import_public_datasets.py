"""Descarga versiones fijadas de OWASP Benchmark y conserva oraculos y licencias.

No ejecuta codigo descargado. El corpus publico se mantiene separado del suplemento
controlado; las particiones agrupan plantillas estructuralmente semejantes.
"""
from pathlib import Path
from collections import Counter
import ast
import csv
import gzip
import hashlib
import json
import re
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.generate_dataset import generate
from vulnminer.catalog import SCENARIOS, catalog
from sklearn.model_selection import StratifiedGroupKFold

SOURCES=[
 dict(name='BenchmarkPython',repo='OWASP-Benchmark/BenchmarkPython',commit='f1291485808b66e20ddb6b01b10dc71b3df8c8ba',language='Python',folder='testcode',suffix='.py',oracle='expectedresults-0.1.csv',license='GPL-3.0-only',cache='public-python'),
 dict(name='BenchmarkJava',repo='OWASP-Benchmark/BenchmarkJava',commit='10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17',language='Java',folder='src/main/java/org/owasp/benchmark/testcode',suffix='.java',oracle='expectedresults-1.2.csv',license='GPL-2.0-only',cache='public-java'),
]
CWE_LABELS={'22':['A01:2025'],'601':['A01:2025'],'614':['A02:2025'],'611':['A02:2025'],'327':['A04:2025'],'328':['A04:2025'],'330':['A04:2025'],'89':['A05:2025'],'78':['A05:2025'],'79':['A05:2025'],'90':['A05:2025'],'94':['A05:2025'],'643':['A05:2025'],'501':['A06:2025'],'502':['A08:2025']}

QUOTED_OR_COMMENT=re.compile(r'"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|/\*.*?\*/|//[^\n]*',re.S)


def remove_java_comments(code):
    return QUOTED_OR_COMMENT.sub(lambda m:'' if m.group().startswith(('/*','//')) else m.group(),code)


def remove_method(code,name):
    match=re.search(r'(?:@Override\s*)?public\s+void\s+'+name+r'\s*\(',code)
    if not match:
        return code
    opening=code.find('{',match.end())
    depth=1
    i=opening+1
    # Braces in strings do not occur in the removed Benchmark doGet wrappers.
    while i<len(code) and depth:
        depth+=(code[i]=='{')-(code[i]=='}')
        i+=1
    return code[:match.start()]+code[i:]


def prepare(code,language):
    if language=='Python':
        tree=ast.parse(code)
        functions=[n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name.endswith('_post')]
        if functions:
            tree=ast.Module(body=functions[0].body,type_ignores=[])
        # ast.unparse removes comments; remove docstrings as well.
        for node in ast.walk(tree):
            body=getattr(node,'body',None)
            if isinstance(body,list) and body and isinstance(body[0],ast.Expr) and isinstance(body[0].value,ast.Constant) and isinstance(body[0].value.value,str):
                body.pop(0)
        code=ast.unparse(tree)
    else:
        code=remove_method(remove_java_comments(code),'doGet')
        code=re.sub(r'(?m)^\s*(?:package|import)\s+[^;]+;','',code)
        code=re.sub(r'@WebServlet\([^\n]+\)','',code)
    code=re.sub(r'BenchmarkTest\d+(?:_(?:get|post))?','BenchmarkCase',code)
    code=re.sub(r'/(?:benchmark/)?(?:pathtraver|trustbound|securecookie|weakrand|crypto|hash|sqli|cmdi|xss|ldapi|xpathi|xxe|codeinj|deserialization|redirect)-\d+/','/endpoint/',code)
    return '\n'.join(line.rstrip() for line in code.splitlines() if line.strip()).strip()


def structural_fingerprint(code):
    # Ignore literal values and identifier names for split grouping, not for ML.
    code=re.sub(r'"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27','STR',code)
    code=re.sub(r'\b\d+(?:\.\d+)?\b','NUM',code)
    code=re.sub(r'[A-Za-z_][A-Za-z_0-9]*','ID',code)
    return hashlib.sha256(re.sub(r'\s+','',code).encode()).hexdigest()


def fetch(source):
    cache=ROOT/'tmp'/source['cache']
    if not (cache/'.git').is_dir():
        subprocess.run(['git','clone','--quiet','--filter=blob:none','--sparse','https://github.com/'+source['repo']+'.git',str(cache)],check=True)
    subprocess.run(['git','-C',str(cache),'sparse-checkout','set','--no-cone','/'+source['folder']+'/', '/'+source['oracle'],'/LICENSE','/README.md'],check=True)
    current=subprocess.check_output(['git','-C',str(cache),'rev-parse','HEAD'],text=True).strip()
    if current!=source['commit']:
        subprocess.run(['git','-C',str(cache),'fetch','--quiet','origin',source['commit']],check=True)
        subprocess.run(['git','-C',str(cache),'checkout','--quiet',source['commit']],check=True)
    return cache


def run():
    baseline=ROOT/'output/baseline_synthetic'
    baseline.mkdir(parents=True,exist_ok=True)
    for name in ['comparison.csv','metrics.json','dataset_statistics.json']:
        previous=ROOT/'output/evaluation'/name
        if previous.exists() and not (baseline/name).exists():
            shutil.copy2(previous,baseline/name)
    controlled=generate()
    # Preserve the supplement separately; do not pass origin or labels as features.
    shutil.copy2(ROOT/'data/dataset.csv',ROOT/'data/controlled.csv')
    public=[]
    manifests=[]
    for source in SOURCES:
        cache=fetch(source)
        target=ROOT/'data/public'/source['name']
        target.mkdir(parents=True,exist_ok=True)
        for name in ['LICENSE',source['oracle']]:
            shutil.copy2(cache/name,target/name)
        oracle=(cache/source['oracle']).read_bytes()
        rows=[r for r in csv.reader(oracle.decode('utf-8-sig').splitlines()) if r and not r[0].startswith('#')]
        raw=[]
        for name,category,state,cwe,*_ in rows:
            path=cache/source['folder']/(name+source['suffix'])
            original=path.read_text(encoding='utf-8-sig')
            code=prepare(original,source['language'])
            is_vulnerable=int(state.lower()=='true')
            assert cwe in CWE_LABELS,(source['name'],cwe)
            digest=hashlib.sha256(code.encode()).hexdigest()
            fingerprint=structural_fingerprint(code)
            url=f'https://github.com/{source["repo"]}/blob/{source["commit"]}/{source["folder"]}/{path.name}'
            public.append(dict(id=f'{source["name"]}-{name}',project='public-family-'+fingerprint[:20],family='public-'+fingerprint[:20],scenario=category,language=source['language'],code=code,vulnerable=is_vulnerable,labels=json.dumps(CWE_LABELS[cwe] if is_vulnerable else []),cwe='CWE-'+cwe if is_vulnerable else '',source=source['name'],source_url=url,split='',sha256=digest,source_commit=source['commit'],source_license=source['license'],original_cwe='CWE-'+cwe,original_sha256=hashlib.sha256(original.encode()).hexdigest()))
            raw.append(dict(id=name,path=source['folder']+'/'+path.name,code=original,oracle_category=category,oracle_vulnerable=is_vulnerable,cwe='CWE-'+cwe))
        # Original copyright notices and unmodified code are retained in this archive.
        with gzip.GzipFile(filename=str(target/'original_sources.jsonl.gz'),mode='wb',mtime=0) as stream:
            stream.write(('\n'.join(json.dumps(r,ensure_ascii=False) for r in raw)+'\n').encode())
        manifests.append(dict(**{k:v for k,v in source.items() if k!='cache'},records_downloaded=len(raw),expectedresults_sha256=hashlib.sha256(oracle).hexdigest(),archive_sha256=hashlib.sha256((target/'original_sources.jsonl.gz').read_bytes()).hexdigest(),url='https://github.com/'+source['repo']))
        print(source['name'],len(raw),'registros descargados y etiquetados',flush=True)
    # Reject ambiguous duplicates rather than silently choosing one oracle label.
    by_hash={}
    for row in public:
        by_hash.setdefault(row['sha256'],[]).append(row)
    ambiguous={digest for digest,rows in by_hash.items() if len({r['labels'] for r in rows})>1}
    dedup=[rows[0] for digest,rows in by_hash.items() if digest not in ambiguous]
    # Seven group folds: approximately 71/14/14, with complete structural groups.
    import numpy as np
    strata=[r['source']+'-'+r['scenario']+'-'+str(r['vulnerable']) for r in dedup]
    groups=[r['project'] for r in dedup]
    splitter=StratifiedGroupKFold(n_splits=7,shuffle=True,random_state=42)
    for fold,(_,indexes) in enumerate(splitter.split(np.zeros(len(dedup)),strata,groups)):
        split='test' if fold==0 else 'validation' if fold==1 else 'train'
        for index in indexes:
            dedup[index]['split']=split
    records=controlled+dedup
    all_hashes=Counter(r['sha256'] for r in records)
    assert max(all_hashes.values())==1,'Duplicados entre suplemento y corpus publico'
    fields=list(dict.fromkeys(k for row in records for k in row))
    with (ROOT/'data/dataset.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
    # Individual per-source subsets allow inspection and independent experiments.
    for source in SOURCES:
        subset=[r for r in dedup if r['source']==source['name']]
        with (ROOT/'data/public'/source['name']/'prepared.csv').open('w',newline='',encoding='utf-8') as f:
            writer=csv.DictWriter(f,fieldnames=fields)
            writer.writeheader()
            writer.writerows(subset)
    audit=dict(sources=manifests,raw_public_records=len(public),public_records_retained=len(dedup),duplicate_records_removed=sum(len(rows)-1 for digest,rows in by_hash.items() if digest not in ambiguous),ambiguous_records_removed=sum(len(by_hash[d]) for d in ambiguous),controlled_records=len(controlled),total_records=len(records),source_counts=dict(Counter(r['source'] for r in records)),partitions=dict(Counter(r['split'] for r in records)),public_structural_groups=len(set(groups)),split_method='StratifiedGroupKFold 7; fold 0 test, 1 validation, others train; controlled families 0..3/4/5.',notes=['Public benchmarks are synthetic test suites, not production incident code.','No API labels are inferred solely from a Benchmark CWE.','Comments, test IDs, category routes and Python wrapper docstrings are removed before features.','Structural groups ignore identifier and literal differences; no group crosses partitions.'])
    (ROOT/'data/public_manifest.json').write_text(json.dumps(audit,ensure_ascii=False,indent=2),encoding='utf-8')
    (ROOT/'data/catalog.json').write_text(json.dumps(catalog(),ensure_ascii=False,indent=2),encoding='utf-8')
    with (ROOT/'data/cwe_owasp.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.writer(f)
        writer.writerow(['scenario','cwe','owasp','basis'])
        for kind,info in SCENARIOS.items():
            writer.writerow([kind,info['cwe'],';'.join(info['labels']),'Escenario contextual; consultar docs/fuentes.md'])
        for cwe,labels in CWE_LABELS.items():
            writer.writerow(['public-oracle','CWE-'+cwe,';'.join(labels),'OWASP Top 10:2025; sin inferir etiquetas API'])
    print(json.dumps({k:v for k,v in audit.items() if k not in ['sources','notes']},ensure_ascii=True,indent=2),flush=True)
    return audit


if __name__=='__main__':
    run()
