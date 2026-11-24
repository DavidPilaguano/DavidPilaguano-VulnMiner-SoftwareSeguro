"""Evalua toda la CLI en una muestra determinista del holdout publico.

No cambia el modelo ni el umbral; no ejecuta los programas de Benchmark.
"""
from pathlib import Path
from collections import defaultdict
import csv
import gzip
import hashlib
import json
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from vulnminer.scanner import scan
from vulnminer.reporting import write_reports


def run():
    rows=list(csv.DictReader((ROOT/'data/dataset.csv').open(encoding='utf-8',newline='')))
    groups=defaultdict(list)
    for row in rows:
        if row['split']=='test' and row['source'] in ['BenchmarkPython','BenchmarkJava']:
            groups[(row['source'],row['scenario'],row['vulnerable'])].append(row)
    sample=[]
    for values in groups.values():
        sample.extend(sorted(values,key=lambda row:hashlib.sha256(row['id'].encode()).hexdigest())[:2])
    base=ROOT/'examples/benchmark-holdout'
    if base.exists():
        # Only remove previously generated source files explicitly owned by this script.
        for path in base.rglob('BenchmarkTest*'):
            if path.is_file() and path.suffix in {'.py','.java'}:
                path.unlink()
    base.mkdir(parents=True,exist_ok=True)
    truth=[]
    for source,folder,manifest in [('BenchmarkPython','python-service','requirements.txt'),('BenchmarkJava','java-service','pom.xml')]:
        service=base/folder
        service.mkdir(exist_ok=True)
        (service/manifest).write_text('# Static fixture only\n' if source=='BenchmarkPython' else '<project><modelVersion>4.0.0</modelVersion><groupId>fixture</groupId><artifactId>benchmark-holdout</artifactId><version>1</version></project>',encoding='utf-8')
        lookup={json.loads(line)['id']:json.loads(line) for line in gzip.open(ROOT/'data/public'/source/'original_sources.jsonl.gz','rt',encoding='utf-8')}
        import shutil
        shutil.copy2(ROOT/'data/public'/source/'LICENSE',service/'LICENSE')
        for row in sample:
            if row['source']!=source:
                continue
            name=row['id'].removeprefix(source+'-')
            original=lookup[name]
            relative=Path(folder)/Path(original['path']).name
            (base/relative).write_text(original['code'],encoding='utf-8')
            truth.append(dict(file=relative.as_posix(),vulnerable=int(row['vulnerable']),labels=json.loads(row['labels']),source=source,scenario=row['scenario'],dataset_id=row['id'],source_url=row['source_url']))
    (base/'expected.json').write_text(json.dumps(truth,ensure_ascii=False,indent=2),encoding='utf-8')
    (base/'README.md').write_text('# Holdout público de OWASP Benchmark\n\nMuestra determinista de casos de prueba, máximo dos por fuente, escenario y estado. Los originales mantienen sus avisos y licencias en cada servicio. No ejecutar ni desplegar. Los programas pertenecen a las particiones reservadas del dataset; esta evaluación mide la CLI sobre el mismo holdout y no es un ensayo ciego de producción.\n',encoding='utf-8')
    report=scan(base)
    write_reports(report,ROOT/'output/reports/benchmark-holdout',['json','html'])
    tp=fp=fn=tn=0
    label_tp=label_fp=label_fn=0
    errors=[]
    for case in truth:
        findings=[f for f in report['findings'] if f['file']==case['file']]
        predicted=bool(findings)
        actual=bool(case['vulnerable'])
        tp+=predicted and actual
        fp+=predicted and not actual
        fn+=not predicted and actual
        tn+=not predicted and not actual
        labels={label for finding in findings for label in finding['owasp_top10']+finding['owasp_api']}
        expected=set(case['labels'])
        label_tp+=len(labels&expected)
        label_fp+=len(labels-expected)
        label_fn+=len(expected-labels)
        if predicted!=actual or labels!=expected:
            errors.append(dict(**case,predicted=predicted,predicted_labels=sorted(labels)))
    result=dict(sample_size=len(truth),sampling='Maximo dos por fuente/escenario/estado, orden SHA-256 del id; solo split=test.',tp=tp,fp=fp,fn=fn,tn=tn,precision=tp/(tp+fp) if tp+fp else 0,recall=tp/(tp+fn) if tp+fn else 0,f1=2*tp/(2*tp+fp+fn) if tp else 0,label_f1_micro=2*label_tp/(2*label_tp+label_fp+label_fn) if label_tp else 0,errors=errors,findings=len(report['findings']),warning='Metricas de CLI por archivo y etiquetas; distintas de las del clasificador en fragmentos preparados.')
    (ROOT/'output/evaluation/public_cli.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='errors'},ensure_ascii=True,indent=2))
    return result


if __name__=='__main__':
    run()
