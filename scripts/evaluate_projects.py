"""Evaluacion end-to-end por archivo, incluyendo extraccion y abstencion."""
from pathlib import Path
import json
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from vulnminer.scanner import scan
from vulnminer.reporting import write_reports
from vulnminer.catalog import SCENARIOS


def evaluate():
    results=[]
    for name in ['tienda-demo','logistica-demo']:
        base=ROOT/'examples'/name
        report=scan(base)
        write_reports(report,ROOT/'output'/'reports'/name,['json','html'])
        truth=json.loads((base/'expected.json').read_text(encoding='utf-8'))
        errors=[]
        tp=fp=fn=tn=0
        label_tp=label_fp=label_fn=0
        for case in truth:
            findings=[f for f in report['findings'] if f['file']==case['file']]
            predicted=bool(findings)
            actual=case['vulnerable']
            tp+=predicted and actual
            fp+=predicted and not actual
            fn+=not predicted and actual
            tn+=not predicted and not actual
            labels=set(l for f in findings for l in f['owasp_top10']+f['owasp_api'])
            expected=set(SCENARIOS[case['scenario']]['labels']) if actual else set()
            label_tp+=len(labels&expected)
            label_fp+=len(labels-expected)
            label_fn+=len(expected-labels)
            if predicted!=actual or labels!=expected:
                errors.append(dict(**case,predicted=predicted,expected_labels=sorted(expected),predicted_labels=sorted(labels)))
        seen=set(l for f in report['findings'] for l in f['owasp_top10']+f['owasp_api'])
        unexpected=[f for f in report['findings'] if f['file'] not in {c['file'] for c in truth}]
        results.append(dict(project=name,truth_files=len(truth),tp=tp,fp=fp,fn=fn,tn=tn,precision=tp/(tp+fp) if tp+fp else 0,recall=tp/(tp+fn) if tp+fn else 0,f1=2*tp/(2*tp+fp+fn) if tp else 0,label_precision_micro=label_tp/(label_tp+label_fp) if label_tp+label_fp else 0,label_recall_micro=label_tp/(label_tp+label_fn) if label_tp+label_fn else 0,covered_categories=sorted(seen),errors=errors,unlabeled_config_findings=unexpected))
    dest=ROOT/'output'/'evaluation'/'projects.json'
    dest.write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(results,ensure_ascii=True,indent=2))
    return results


if __name__=='__main__':
    evaluate()
