"""Ejecuta los notebooks SEMMA actualizados y construye el informe editorial."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import nbformat as nbf
from nbclient import NotebookClient

SETUP="""from pathlib import Path
import sys, json
ROOT = Path.cwd()
if not (ROOT / 'data/dataset.csv').exists():
    ROOT = ROOT.parent
sys.path.insert(0, str(ROOT))
import pandas as pd
from IPython.display import display, Image
df = pd.read_csv(ROOT / 'data/dataset.csv', keep_default_na=False)
df['labels'] = df.labels.map(json.loads)
manifest = json.loads((ROOT / 'data/public_manifest.json').read_text(encoding='utf-8'))
results = json.loads((ROOT / 'output/evaluation/metrics.json').read_text(encoding='utf-8'))
selected = results['candidates'][results['selected']]
"""


def notebooks():
    definitions=[
        ('01_sample','Sample: fuentes públicas, muestreo y trazabilidad',[
            ('markdown','Se usan dos suites públicas con oráculos oficiales: OWASP BenchmarkPython y BenchmarkJava. Son programas de prueba controlados, no código de incidentes de producción. Se conserva un suplemento original para categorías API que esos oráculos no etiquetan.'),
            ('code',"display(pd.DataFrame(manifest['sources'])[['name','language','commit','license','records_downloaded']])\ndisplay(df.groupby(['source','split']).size().unstack(fill_value=0))\nprint('Casos descargados:', manifest['raw_public_records'])\nprint('Duplicados excluidos:', manifest['duplicate_records_removed'])\nprint('Total preparado:', len(df))"),
            ('code',"import hashlib\nfor source in manifest['sources']:\n    oracle = ROOT / 'data/public' / source['name'] / source['oracle']\n    assert hashlib.sha256(oracle.read_bytes()).hexdigest() == source['expectedresults_sha256']\nassert not df.sha256.duplicated().any()\nassert df.groupby('project').split.nunique().max() == 1\npublic = df[df.source != 'original-controlled-v1']\nassert not public.code.str.contains(r'BenchmarkTest\\d+').any()\nprint('Oráculos verificados, sin duplicados exactos ni grupos repartidos.')"),
            ('markdown','Las particiones públicas se obtienen mediante siete folds estratificados por fuente, escenario y estado, agrupando por huella estructural sin identificadores ni literales. Se reservan dos folds para validación y prueba. Las familias propias conservan su separación original. Esto reduce fuga por plantillas, pero no prueba independencia semántica completa ni separación por repositorio: ambos Benchmark participan en las tres particiones.'),
        ]),
        ('02_explore','Explore: distribución, calidad y representatividad',[
            ('markdown','Se describe cada procedencia por separado. La suma de frecuencias de etiquetas no equivale a filas, porque una observación puede tener varias etiquetas. No se atribuyen etiquetas API a los casos públicos únicamente por su CWE.'),
            ('code',"display(df.groupby(['source','language','vulnerable']).size().rename('registros').to_frame())\ndisplay(df.code.str.len().describe().to_frame('longitud'))\nprint('Faltantes requeridos:', (df[['id','code','source','language','split']] == '').sum().to_dict())\nprint('Etiquetas inconsistentes:', sum(bool(r.labels) != bool(r.vulnerable) for r in df.itertuples()))"),
            ('code',"for name in ['fuentes','categorias','seguridad','lenguajes','patrones','desbalance']:\n    display(Image(filename=str(ROOT / 'output/evaluation' / (name+'.png'))))"),
            ('markdown','Los casos públicos dominan el corpus y contienen flujos más largos que los fragmentos propios. Las distribuciones por origen y por categoría son desiguales; una media global puede ocultar diferencias de desempeño. El enriquecimiento aumenta diversidad dentro de benchmarks y no demuestra representatividad de producción.'),
        ]),
        ('03_modify','Modify: limpieza y representaciones sin metadatos de etiqueta',[
            ('markdown','La importación conserva originales comprimidos y crea fragmentos preparados. Python usa AST para extraer el cuerpo del handler POST; Java elimina el wrapper GET, comentarios y encabezados. Se retiran IDs BenchmarkTest, rutas que contienen categorías y docstrings. Se conservan operaciones, condiciones, literales y controles que afectan al comportamiento.'),
            ('code',"from scripts.import_public_datasets import structural_fingerprint\nassert df.groupby('project').split.nunique().max() == 1\nfrom vulnminer.features import make_features\nparts = {s: df[df.split == s] for s in ['train','validation','test']}\nfeatures = make_features()\nX = {'train': features.fit_transform(parts['train'].code)}\nX.update({s: features.transform(parts[s].code) for s in ['validation','test']})\nprint({s: matrix.shape for s,matrix in X.items()})"),
            ('code',"from scipy.sparse import load_npz\nfor split in parts:\n    matrix = load_npz(ROOT / 'output/evaluation' / f'features_{split}.npz')\n    print(split, matrix.shape, 'no ceros:', matrix.nnz)\nprint('Solo code alimenta el modelo; source, CWE, labels e id no son características.')"),
            ('markdown','TF-IDF combina caracteres 3..5 y tokens 1..2, con vocabulario e IDF ajustados únicamente sobre entrenamiento. Se usa class_weight=balanced. Las matrices, etiquetas y orden de filas se exportan. Las huellas de agrupación no se utilizan como predictores.'),
        ]),
        ('04_model','Model: comparación híbrida y experimento solo público',[
            ('markdown','El entrenamiento completo se ejecuta con scripts/train.py. Se comparan regresión logística One-vs-Rest (C=0.5/2.0) y Random Forest multisalida (160 árboles, profundidad sin límite/18), semilla 42. El umbral global se selecciona en 0.30/0.40/0.50/0.60 usando F1 macro de validación. Este notebook permite reentrenar explícitamente; por defecto inspecciona el experimento congelado.'),
            ('code',"REENTRENAR = False\nif REENTRENAR:\n    from scripts.train import run\n    results = run()\n    selected = results['candidates'][results['selected']]\ndisplay(pd.read_csv(ROOT / 'output/evaluation/comparison.csv'))\nassert results['selected'] == max(range(len(results['candidates'])), key=lambda i:(results['candidates'][i]['validation']['f1_macro'], results['candidates'][i]['algorithm']=='LogisticRegression'))\nprint('Seleccionado por validación:', selected['algorithm'], selected['parameter'], selected['threshold'])"),
            ('code',"import joblib\nbundle = joblib.load(ROOT / 'vulnminer/artifacts/model.joblib')\nscores = bundle['estimator'].predict_proba(bundle['features'].transform(['app.run(debug=True)']))[0]\ndisplay(pd.DataFrame({'categoria':bundle['classes'],'puntuacion':scores}))\npublic_result = results['public_only']\nprint('Solo público: particiones', public_result['records'])\nprint('Solo público: F1 macro prueba', public_result['test']['f1_macro'])\ndisplay(Image(filename=str(ROOT / 'output/evaluation/model_comparison.png')))"),
            ('markdown','El artefacto principal es híbrido porque conserva cobertura API basada en el suplemento. El artefacto public_model.joblib se entrena exclusivamente con los casos descargados y su propio vocabulario, con seis categorías generales y sin etiquetas API. Sus métricas tienen otro universo de categorías y no son directamente comparables con el F1 macro híbrido. No se cambia el ganador por observar un mejor resultado de prueba en otro candidato.'),
        ]),
        ('05_assess','Assess: resultados por fuente, errores y funcionamiento real',[
            ('markdown','La evaluación separa el clasificador sobre fragmentos preparados, la CLI sobre fuentes originales y las fixtures funcionales. Se reportan F1 macro/micro, precisión, recall y matrices binarias por etiqueta. No se interpreta confianza como severidad ni como probabilidad calibrada.'),
            ('code',"display(pd.DataFrame(selected['test']['per_category']).T)\ndisplay(pd.DataFrame([{ 'fuente':source, 'registros':m['records'], 'F1_macro_etiquetas_con_soporte':m['f1_macro_supported'], 'F1_micro':m['f1_micro']} for source,m in results['test_by_source'].items()]))\nprint('Entrenamiento / validación / prueba:', [selected[s]['f1_macro'] for s in ['train','validation','test']])\ndisplay(Image(filename=str(ROOT / 'output/evaluation/confusion_matrices.png')))"),
            ('code',"errors = json.loads((ROOT / 'output/evaluation/errors.json').read_text(encoding='utf-8'))\nprint('Registros con error:',len(errors))\ndisplay(pd.DataFrame(errors).head(8))\nprojects = json.loads((ROOT / 'output/evaluation/projects.json').read_text(encoding='utf-8'))\ndisplay(pd.DataFrame([{k:v for k,v in p.items() if k in ['project','tp','fp','fn','tn','precision','recall','f1']} for p in projects]))\npublic_cli = json.loads((ROOT / 'output/evaluation/public_cli.json').read_text(encoding='utf-8'))\ndisplay(pd.DataFrame([{k:v for k,v in public_cli.items() if k not in ['errors']}]))"),
            ('markdown','El descenso entre validación y prueba es una limitación material. Los resultados sintéticos originales se conservan en output/baseline_synthetic/ como antecedente, con otra distribución y menor cobertura, sin presentarlos como comparación controlada de mejora. La CLI puede perder controles al extraer contexto o generar falsos positivos aunque el clasificador funcione sobre fragmentos preparados. Se requiere más diversidad y una evaluación ciega en repositorios completos. Los dos incidentes documentados al final del informe ilustran impacto, no acreditan que esta herramienta los hubiera detectado.'),
        ]),
    ]
    for name,title,cells in definitions:
        path=ROOT/'notebooks'/f'{name}.ipynb'
        nb=nbf.read(path,as_version=4) if path.exists() else nbf.v4.new_notebook()
        nb.cells=[nbf.v4.new_markdown_cell('# '+title+'\n\nVulnMiner · DavidPilaguano · SEMMA con datos públicos verificables.'),nbf.v4.new_code_cell(SETUP)]
        nb.cells.extend(nbf.v4.new_markdown_cell(text) if kind=='markdown' else nbf.v4.new_code_cell(text) for kind,text in cells)
        nb.metadata['kernelspec']=dict(display_name='Python 3',language='python',name='python3')
        NotebookClient(nb,timeout=600,kernel_name='python3',resources={'metadata':{'path':str(ROOT)}}).execute()
        nbf.write(nb,path)
        print('Notebook ejecutado:',path.name,flush=True)


if __name__=='__main__':
    if '--report-only' not in sys.argv:
        notebooks()
    from scripts.report_v2 import report
    report()
