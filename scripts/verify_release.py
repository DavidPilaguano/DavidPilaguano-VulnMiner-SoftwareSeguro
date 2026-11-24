"""Verifica el paquete instalado y registra resultados reales de unittest y CLI."""
from pathlib import Path
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]


def run():
    import vulnminer
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1
    check=subprocess.run([sys.executable,'-m','pip','check'],text=True,capture_output=True,check=True)
    projects=[]
    for name in ['tienda-demo','logistica-demo']:
        output=ROOT/'output/reports/prueba-local'/name
        command=[sys.executable,'-I','-m','vulnminer','scan',str(ROOT/'examples'/name),'--format','json,html','--output',str(output)]
        completed=subprocess.run(command,text=True,capture_output=True,check=True)
        print(completed.stdout,flush=True)
        report=json.loads((output/'analisis.json').read_text(encoding='utf-8'))
        assert len(report['findings'])==7
        assert all('_risk.' in f['file'] for f in report['findings'])
        projects.append(dict(project=name,services=len(report['services']),files_analyzed=report['files_analyzed'],findings=len(report['findings']),json=True,html=(output/'analisis.html').is_file()))
    notebooks=[json.loads(path.read_text(encoding='utf-8')) for path in (ROOT/'notebooks').glob('*.ipynb')]
    cells=[cell for notebook in notebooks for cell in notebook['cells'] if cell['cell_type']=='code']
    assert len(notebooks)==5 and all(cell['execution_count'] is not None for cell in cells)
    assert not [output for cell in cells for output in cell.get('outputs',[]) if output['output_type']=='error']
    manifest=json.loads((ROOT/'data/public_manifest.json').read_text(encoding='utf-8'))
    meta=json.loads((ROOT/'vulnminer/artifacts/metadata.json').read_text(encoding='utf-8'))
    assert hashlib.sha256((ROOT/'data/dataset.csv').read_bytes()).hexdigest()==meta['dataset_sha256']
    evaluation=json.loads((ROOT/'output/evaluation/metrics.json').read_text(encoding='utf-8'))
    log=dict(date='2026-11-24',environment='Paquete instalado en entorno virtual; ejecucion aislada -I',package_version=vulnminer.__version__,package_path=vulnminer.__file__,python=platform.python_version(),versions={name:importlib.metadata.version(name) for name in ['scikit-learn','numpy','pandas','scipy','joblib','PyYAML']},command='python -I scripts/verify_release.py',unit_tests=dict(run=result.testsRun,failures=len(result.failures),errors=len(result.errors)),dependency_check=check.stdout.strip(),notebooks=dict(count=5,executed_code_cells=len(cells),errors=0),projects=projects,public_records=manifest['public_records_retained'],dataset_records=manifest['total_records'],model_test_f1_macro=evaluation['candidates'][meta['selected']]['test']['f1_macro'],limitations='Benchmarks y suplemento controlados; no se demuestra generalizacion de produccion.')
    (ROOT/'output/evaluation/verificacion_local.json').write_text(json.dumps(log,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Verificacion de release completada.',flush=True)
    return 0


if __name__=='__main__':
    raise SystemExit(run())
