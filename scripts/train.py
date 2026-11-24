"""SEMMA reproducible: explorar, transformar, comparar y evaluar sin fuga de test."""
from pathlib import Path
import csv
import hashlib
import json
import platform
import sys
import time
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
from scipy.sparse import save_npz
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score, multilabel_confusion_matrix, precision_score, recall_score
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import MultiLabelBinarizer
from vulnminer.features import make_features


def metrics(y, pred, classes):
    return dict(precision_micro=precision_score(y, pred, average='micro', zero_division=0), recall_micro=recall_score(y, pred, average='micro', zero_division=0), f1_micro=f1_score(y, pred, average='micro', zero_division=0), f1_macro=f1_score(y, pred, average='macro', zero_division=0), exact_match=float(np.all(y == pred, axis=1).mean()), per_category=classification_report(y, pred, target_names=classes, output_dict=True, zero_division=0), confusion_matrices=multilabel_confusion_matrix(y, pred).tolist())


def explore(df, out):
    out.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({'font.size': 10, 'figure.figsize': (10, 5)})
    counts = Counter(label for labels in df.labels for label in labels)
    stats = dict(records=len(df), safe=int((df.vulnerable == 0).sum()), vulnerable=int(df.vulnerable.sum()), languages=df.language.value_counts().to_dict(), partitions=df.split.value_counts().to_dict(), projects=int(df.project.nunique()), duplicate_hashes=int(df.sha256.duplicated().sum()), missing_required=int(df[['code','language','project','split','labels']].isna().sum().sum()), labels=dict(counts), length=df.code.str.len().describe().to_dict())
    (out / 'dataset_statistics.json').write_text(json.dumps(stats, indent=2), encoding='utf-8')
    df.groupby(['split','language','vulnerable']).size().rename('count').to_csv(out / 'distribution.csv')
    charts = [
        ('categorias', dict(sorted(counts.items())), 'Distribucion multietiqueta OWASP'),
        ('seguridad', {'No vulnerable': stats['safe'], 'Vulnerable': stats['vulnerable']}, 'Balance de ejemplos controlados'),
        ('lenguajes', stats['languages'], 'Distribucion por lenguaje'),
        ('patrones', {s: int(df.code.str.contains(s, case=False, regex=False).sum()) for s in ['execute','query','md5','debug','jwt','verify','fetch','loads']}, 'Frecuencia de tokens relevantes'),
        ('desbalance', dict(sorted(counts.items(), key=lambda x:x[1])), 'Desbalance de etiquetas (multietiqueta)'),
    ]
    for filename, values, title in charts:
        fig, ax = plt.subplots()
        ax.bar(list(values), list(values.values()), color='#256b85')
        ax.set_title(title)
        ax.set_ylabel('Registros')
        ax.tick_params(axis='x', rotation=35)
        fig.tight_layout()
        fig.savefig(out / f'{filename}.png', dpi=150)
        plt.close(fig)
    return stats


def run():
    out, art = ROOT / 'output' / 'evaluation', ROOT / 'vulnminer' / 'artifacts'
    out.mkdir(parents=True, exist_ok=True)
    art.mkdir(exist_ok=True)
    df = pd.read_csv(ROOT / 'data' / 'dataset.csv', keep_default_na=False)
    df['labels'] = df.labels.map(json.loads)
    assert len(df) >= 500 and (df.vulnerable == 0).sum() >= 100
    assert not df.sha256.duplicated().any(), 'Duplicados exactos'
    assert df.groupby('project').split.nunique().max() == 1, 'Fuga por proyecto'
    assert all(bool(r.labels) == bool(r.vulnerable) for r in df.itertuples())
    # Audit normalized near duplicates as well; report rather than hide shared tokens.
    from vulnminer.features import normalize
    canonical = df.code.map(lambda s: __import__('re').sub(r'orders|accounts|products|invoices|customers|payments|\b81\d\d\b', 'DOMAIN', normalize(s)))
    cross = pd.DataFrame({'canonical':canonical, 'split':df.split}).groupby('canonical').split.nunique()
    stats = explore(df, out)
    stats['canonical_cross_partition_duplicates'] = int((cross > 1).sum())
    (out / 'dataset_statistics.json').write_text(json.dumps(stats, indent=2), encoding='utf-8')
    splits = {s:df[df.split == s].copy() for s in ['train','validation','test']}
    mlb = MultiLabelBinarizer()
    ytrain = mlb.fit_transform(splits['train'].labels)
    classes = mlb.classes_.tolist()
    targets = {s:mlb.transform(part.labels) for s, part in splits.items()}
    features = make_features()
    matrices = {'train':features.fit_transform(splits['train'].code)}
    for name in ['validation','test']:
        matrices[name] = features.transform(splits[name].code)
    for name, matrix in matrices.items():
        save_npz(out / f'features_{name}.npz', matrix)
        np.save(out / f'targets_{name}.npy', targets[name])
        (out / f'rows_{name}.json').write_text(json.dumps(splits[name].id.tolist()), encoding='utf-8')
    # Select only with validation. Test metrics are calculated after freezing choice.
    candidates = []
    fitted = []
    for algorithm, settings in [('LogisticRegression', [0.5, 2.0]), ('RandomForest', [None, 18])]:
        for setting in settings:
            estimator = (OneVsRestClassifier(LogisticRegression(C=setting, class_weight='balanced', max_iter=1500, random_state=42)) if algorithm == 'LogisticRegression' else RandomForestClassifier(n_estimators=160, max_depth=setting, class_weight='balanced', random_state=42, n_jobs=-1))
            start = time.perf_counter()
            estimator.fit(matrices['train'], ytrain)
            probability = probabilities(estimator, matrices['validation'])
            scores = [(f1_score(targets['validation'], probability >= t, average='macro', zero_division=0), t) for t in [0.30,0.40,0.50,0.60]]
            score, threshold = max(scores, key=lambda v:(v[0], v[1]))
            entry = dict(algorithm=algorithm, parameter=setting, threshold=threshold, seconds=time.perf_counter()-start, validation=metrics(targets['validation'], probability >= threshold, classes))
            candidates.append(entry)
            fitted.append(estimator)
            print(f'{algorithm} parametro={setting} validacion F1 macro={score:.4f}', flush=True)
    best = max(range(len(candidates)), key=lambda i:(candidates[i]['validation']['f1_macro'], candidates[i]['algorithm']=='LogisticRegression'))
    chosen = candidates[best]
    summary = dict(seed=42, selection='F1 macro de validacion; empate: regresion logistica por simplicidad. Test no selecciona hiperparametros.', classes=classes, selected=best, candidates=candidates, versions=dict(python=platform.python_version(), sklearn=sklearn.__version__, numpy=np.__version__), dataset_sha256=hashlib.sha256((ROOT/'data/dataset.csv').read_bytes()).hexdigest(), statistics=stats, matrix_shapes={k:list(v.shape) for k,v in matrices.items()})
    for estimator, entry in zip(fitted, candidates):
        entry['test'] = metrics(targets['test'], probabilities(estimator, matrices['test']) >= entry['threshold'], classes)
    selected_prediction = probabilities(fitted[best], matrices['test']) >= chosen['threshold']
    errors = []
    for row, truth, pred in zip(splits['test'].itertuples(), targets['test'], selected_prediction):
        fp = [classes[i] for i in range(len(classes)) if pred[i] and not truth[i]]
        fn = [classes[i] for i in range(len(classes)) if truth[i] and not pred[i]]
        if fp or fn:
            errors.append(dict(id=row.id, code=row.code, false_positive=fp, false_negative=fn, language=row.language, scenario=row.scenario))
    (out/'errors.json').write_text(json.dumps(errors, ensure_ascii=False, indent=2), encoding='utf-8')
    (out/'metrics.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    with (out/'comparison.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['algorithm','parameter','threshold','validation_f1_macro','test_precision_micro','test_recall_micro','test_f1_micro','test_f1_macro'])
        for c in candidates:
            writer.writerow([c['algorithm'],c['parameter'],c['threshold'],c['validation']['f1_macro'],*[c['test'][k] for k in ['precision_micro','recall_micro','f1_micro','f1_macro']]])
    fig, ax = plt.subplots(figsize=(10,5))
    x = np.arange(len(candidates))
    ax.bar(x-.17,[c['validation']['f1_macro'] for c in candidates],.34,label='Validacion')
    ax.bar(x+.17,[c['test']['f1_macro'] for c in candidates],.34,label='Prueba independiente')
    ax.set_xticks(x, [f'{c["algorithm"]}\n{c["parameter"]}' for c in candidates])
    ax.set_ylim(0,1.05)
    ax.set_ylabel('F1 macro')
    ax.legend()
    fig.tight_layout()
    fig.savefig(out/'model_comparison.png',dpi=150)
    plt.close(fig)
    fig, axes = plt.subplots(2,5,figsize=(15,6))
    for ax,label,cm in zip(axes.flat, classes, chosen['test']['confusion_matrices']):
        ax.imshow(cm,cmap='Blues')
        for (r,c),value in np.ndenumerate(np.array(cm)):
            ax.text(c,r,str(value),ha='center',va='center',color='black')
        ax.set(title=label,xticks=[0,1],yticks=[0,1],xlabel='Prediccion',ylabel='Real')
    for ax in list(axes.flat)[len(classes):]:
        ax.set_visible(False)
    fig.tight_layout()
    fig.savefig(out/'confusion_matrices.png',dpi=150)
    plt.close(fig)
    artifact = dict(features=features, estimator=fitted[best], classes=classes, threshold=chosen['threshold'], algorithm=chosen['algorithm'], metadata=summary)
    joblib.dump(artifact,art/'model.joblib',compress=3)
    (art/'metadata.json').write_text(json.dumps({k:v for k,v in summary.items() if k!='candidates'},ensure_ascii=False,indent=2),encoding='utf-8')
    print(f'Seleccionado: {chosen["algorithm"]}; test F1 macro={chosen["test"]["f1_macro"]:.4f}; errores={len(errors)}',flush=True)
    return summary


def probabilities(estimator, matrix):
    p = estimator.predict_proba(matrix)
    return np.column_stack([col[:,1] for col in p]) if isinstance(p,list) else p


if __name__ == '__main__':
    run()
