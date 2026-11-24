"""Genera notebooks ejecutados e informe PDF usando resultados reales guardados."""
from pathlib import Path
from collections import Counter
import html
import json
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import nbformat as nbf
from nbclient import NotebookClient

SETUP="""from pathlib import Path
import sys, json
ROOT = Path.cwd()
if not (ROOT / 'data' / 'dataset.csv').exists():
    ROOT = ROOT.parent
sys.path.insert(0, str(ROOT))
import pandas as pd
from IPython.display import display, Image
df = pd.read_csv(ROOT / 'data/dataset.csv', keep_default_na=False)
df['labels'] = df.labels.map(json.loads)
print('Raíz del laboratorio:', ROOT)
"""


def notebooks():
    helper=Path.home()/'.codex/skills/jupyter-notebook/scripts/new_notebook.py'
    definitions=[
    ('01_sample','Sample: muestreo y trazabilidad',[
        ('markdown','Objetivo: verificar el muestreo controlado, etiquetas, procedencia y separación por familias antes de entrenar. Hipótesis: separar plantillas completas reduce fuga por variantes, aunque persiste similitud semántica.'),
        ('code',"display(df[['id','project','language','vulnerable','labels','source','split']].head(8))\ndisplay(df.groupby(['split','language','vulnerable']).size().rename('registros').to_frame())"),
        ('code',"assert len(df) >= 500\nassert (df.vulnerable == 0).sum() >= 100\nassert not df.sha256.duplicated().any()\nassert df.groupby('project').split.nunique().max() == 1\ndisplay(pd.read_csv(ROOT / 'data/cwe_owasp.csv'))\nprint('Registros:', len(df), '| Corregidos:', (df.vulnerable == 0).sum(), '| Grupos artificiales:', df.project.nunique())"),
        ('markdown','Conclusión: 1.008 registros, 504 corregidos y 84 grupos artificiales. Las seis variantes de una familia permanecen juntas. Particiones 672/168/168: cuatro familias de entrenamiento, una de validación y una de prueba. Se identificaron OWASP Benchmark y NIST SARD, pero no se incorporó ningún registro suyo; ver `docs/fuentes.md`. El dataset no representa la diversidad ni la prevalencia de producción.'),
    ]),
    ('02_explore','Explore: calidad y distribución',[
        ('markdown','Objetivo: describir balance, lenguajes, longitudes, patrones y calidad. Las frecuencias de categorías cuentan etiquetas, por lo que su suma supera el total de filas vulnerables.'),
        ('code',"display(df.code.str.len().describe().to_frame('longitud'))\nprint('Duplicados:', df.sha256.duplicated().sum())\nprint('Campos requeridos vacíos:', (df[['id','code','language','project','split']] == '').sum().to_dict())\nprint('Etiquetas inconsistentes:', sum(bool(r.labels) != bool(r.vulnerable) for r in df.itertuples()))"),
        ('code',"for chart in ['categorias','seguridad','lenguajes','patrones','desbalance']:\n    display(Image(filename=str(ROOT / 'output/evaluation' / (chart + '.png'))))"),
        ('markdown','Interpretación: el balance binario es exactamente 50/50 y ambos lenguajes tienen igual soporte. A07 tiene doble soporte porque agrupa JWT y TLS. Las longitudes cortas facilitan el aprendizaje local y limitan su validez para archivos grandes. Los tokens frecuentes describen el diseño de los casos, no causalidad de una vulnerabilidad. No hay duplicados exactos ni faltantes requeridos. La ausencia de CWE en casos corregidos es intencional.'),
    ]),
    ('03_modify','Modify: representación y aislamiento',[
        ('markdown','Objetivo: obtener matrices TF-IDF sin ajustar el vocabulario con validación o prueba. Se conservan constantes de seguridad como False, true y md5. No se usa scenario, CWE, project ni labels como característica. El clasificador no ve metadatos de etiquetado.'),
        ('code',"from vulnminer.features import make_features, normalize\nfrom sklearn.preprocessing import MultiLabelBinarizer\nparts = {s: df[df.split == s] for s in ['train','validation','test']}\nfeatures = make_features()\nX_train = features.fit_transform(parts['train'].code)\nX_validation = features.transform(parts['validation'].code)\nX_test = features.transform(parts['test'].code)\nmlb = MultiLabelBinarizer()\ny_train = mlb.fit_transform(parts['train'].labels)\nprint('Matrices:', X_train.shape, X_validation.shape, X_test.shape)\nprint('Etiquetas:', mlb.classes_.tolist())\nprint('Normalización:', normalize('# comment\\napp.run(debug=True)'))"),
        ('code',"from scipy.sparse import load_npz\nfor split in parts:\n    saved = load_npz(ROOT / 'output/evaluation' / f'features_{split}.npz')\n    print(split, 'matriz entregada', saved.shape, 'no ceros', saved.nnz)\ncanonical_stats = json.loads((ROOT / 'output/evaluation/dataset_statistics.json').read_text())\nprint('Duplicados canónicos entre particiones:', canonical_stats['canonical_cross_partition_duplicates'])"),
        ('markdown','Justificación: los n-gramas de caracteres 3..5 toleran cambios de identificadores; los tokens 1..2 retienen operaciones y constantes. Se eliminan comentarios de línea y se normalizan saltos de línea, sin reemplazar constantes relevantes. Los datos ya generados pasan controles de duplicados e integridad antes de transformar: si fallan se interrumpe el entrenamiento. Ambos algoritmos usan ponderación de clases; no se requiere sobremuestreo. La auditoría canónica solo cubre sustituciones documentadas de dominios y puertos.'),
    ]),
    ('04_model','Model: comparación y selección',[
        ('markdown','Objetivo: comparar regresión logística One-vs-Rest y Random Forest multisalida. Se prueban C={0.5,2.0} y profundidad={sin límite,18}, con 160 árboles; umbrales 0.30, 0.40, 0.50 y 0.60. Se decide por F1 macro de validación y se prefiere regresión logística en empate. Esta celda realiza el entrenamiento real y serializa el pipeline; puede tardar unos segundos.'),
        ('code',"from scripts.train import run\nexperiment = run()\ndisplay(pd.read_csv(ROOT / 'output/evaluation/comparison.csv'))\nselected = experiment['candidates'][experiment['selected']]\nprint('Modelo elegido:', selected['algorithm'], 'parámetro:', selected['parameter'], 'umbral:', selected['threshold'])"),
        ('code',"display(Image(filename=str(ROOT / 'output/evaluation/model_comparison.png')))\nimport joblib\nbundle = joblib.load(ROOT / 'vulnminer/artifacts/model.joblib')\nexample = \"app.run(debug=True, port=8099)\"\nscores = bundle['estimator'].predict_proba(bundle['features'].transform([example]))[0]\ndisplay(pd.DataFrame({'categoria':bundle['classes'], 'puntuacion':scores}))"),
        ('markdown','Interpretación: la selección no usa las métricas de prueba. El vocabulario permanece ajustado únicamente con entrenamiento; no se reentrena usando validación para alterar el experimento. Las etiquetas se predicen directamente desde el texto mediante aprendizaje supervisado. Un ejemplo corregido tiene todas las etiquetas a cero. Las puntuaciones no se calibraron como probabilidades de explotación.'),
    ]),
    ('05_assess','Assess: métricas, errores y herramienta',[
        ('markdown','Objetivo: medir precisión, recall, F1 micro/macro, matrices binarias por etiqueta y errores, además de evaluar el flujo completo sobre dos fixtures ajenas al entrenamiento. Las fixtures se usaron para depurar el extractor; no son una evaluación ciega.'),
        ('code',"metrics = json.loads((ROOT / 'output/evaluation/metrics.json').read_text())\nselected = metrics['candidates'][metrics['selected']]\ndisplay(pd.DataFrame(selected['test']['per_category']).T)\ndisplay(Image(filename=str(ROOT / 'output/evaluation/confusion_matrices.png')))\nerrors = json.loads((ROOT / 'output/evaluation/errors.json').read_text())\nprint('Registros de prueba con error:', len(errors))\ndisplay(pd.DataFrame(errors).head(12))"),
        ('code',"from scripts.evaluate_projects import evaluate\nprojects = evaluate()\ndisplay(pd.DataFrame([{k:v for k,v in p.items() if k not in ['errors','unlabeled_config_findings','covered_categories']} for p in projects]))\nfor error in errors[:3]:\n    print(error['id'], 'FP:', error['false_positive'], 'FN:', error['false_negative'])\n    print(error['code'])"),
        ('markdown','Conclusión: el holdout por familia mide generalización dentro de siete patrones sintéticos. Los falsos positivos sobre fragmentos corregidos muestran que el modelo puede ignorar controles locales. La extracción y el umbral cambian los resultados de la CLI respecto a la clasificación aislada. El desempeño perfecto en unas pocas fixtures no implica desempeño perfecto en repositorios reales. Las categorías sin datos se declaran no evaluadas. Falta la evaluación del proyecto desconocido del docente y la validación manual/dinámica de explotabilidad.'),
    ]),
    ]
    folder=ROOT/'notebooks'
    folder.mkdir(exist_ok=True)
    for filename,title,cells in definitions:
        path=folder/f'{filename}.ipynb'
        if not path.exists():
            if helper.is_file():
                subprocess.run([sys.executable,str(helper),'--kind','experiment','--title',title,'--out',str(path)],check=True,capture_output=True)
            else:
                nbf.write(nbf.v4.new_notebook(),path)
        nb=nbf.read(path,as_version=4)
        nb.cells=[nbf.v4.new_markdown_cell(f'# {title}\n\nLaboratorio ESPE · Semilla 42 · Fuentes y límites documentados.'),nbf.v4.new_code_cell(SETUP)]
        nb.cells += [nbf.v4.new_markdown_cell(text) if kind=='markdown' else nbf.v4.new_code_cell(text) for kind,text in cells]
        nb.metadata['kernelspec']=dict(display_name='Python 3',language='python',name='python3')
        NotebookClient(nb,timeout=300,kernel_name='python3',resources={'metadata':{'path':str(ROOT)}}).execute()
        nbf.write(nb,path)
        print(f'Notebook ejecutado: {path.name}',flush=True)


def report():
    import reportlab
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Image
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    metrics=json.loads((ROOT/'output/evaluation/metrics.json').read_text(encoding='utf-8'))
    projects=json.loads((ROOT/'output/evaluation/projects.json').read_text(encoding='utf-8'))
    chosen=metrics['candidates'][metrics['selected']]
    stats=metrics['statistics']
    errors=json.loads((ROOT/'output/evaluation/errors.json').read_text(encoding='utf-8'))
    fp=Counter(l for e in errors for l in e['false_positive'])
    fn=Counter(l for e in errors for l in e['false_negative'])
    styles=getSampleStyleSheet()
    fontpath=Path('C:/Windows/Fonts/arial.ttf')
    if fontpath.is_file():
        pdfmetrics.registerFont(TTFont('ReportFont',str(fontpath)))
        pdfmetrics.registerFont(TTFont('ReportFontBold','C:/Windows/Fonts/arialbd.ttf'))
        font,bold='ReportFont','ReportFontBold'
    else:
        font,bold='Helvetica','Helvetica-Bold'
    for style in styles.byName.values():
        style.fontName=font
    styles['Normal'].fontSize=10
    styles['Normal'].leading=15
    styles['Normal'].spaceAfter=10
    styles['Heading1'].fontName=bold
    styles['Heading1'].textColor=colors.HexColor('#156b82')
    styles['Heading1'].spaceAfter=18
    styles.add(ParagraphStyle(name='CoverTitle',fontName=bold,fontSize=34,leading=39,textColor=colors.HexColor('#153b50'),alignment=TA_CENTER,spaceAfter=24))
    styles.add(ParagraphStyle(name='SmallBody',fontName=font,fontSize=8,leading=11))
    story=[]
    markdown=[]
    def para(text):
        story.append(Paragraph(html.escape(text),styles['Normal']))
        markdown.append(text+'\n')
    def heading(text):
        story.append(Paragraph(html.escape(text),styles['Heading1']))
        markdown.append('## '+text+'\n')
    def page(text):
        story.append(PageBreak())
        heading(text)
    def table(rows,widths=None):
        wrapped=[[Paragraph(html.escape(str(c)),styles['SmallBody']) for c in row] for row in rows]
        t=Table(wrapped,colWidths=widths,repeatRows=1,hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#dbeaf0')),('VALIGN',(0,0),(-1,-1),'TOP'),('BOTTOMPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),7),('LINEBELOW',(0,0),(-1,-1),.4,colors.HexColor('#ccd7de'))]))
        story.append(t)
        story.append(Spacer(1,12))
        mdrows=['| '+' | '.join(str(c) for c in row)+' |' for row in rows]
        mdrows.insert(1,'| '+' | '.join('---' for _ in rows[0])+' |')
        markdown.append('\n'.join(mdrows)+'\n')
    def chart(name,width=16*cm):
        from PIL import Image as PILImage
        path=ROOT/'output/evaluation'/name
        with PILImage.open(path) as im:
            w,h=im.size
        story.append(Image(str(path),width=width,height=width*h/w))
        story.append(Spacer(1,12))
        markdown.append(f'![{name}](../output/evaluation/{name})\n')
    story.append(Spacer(1,3*cm))
    story.append(Paragraph('VulnMiner',styles['CoverTitle']))
    story.append(Paragraph('Minería de datos para clasificación de riesgos en microservicios',styles['Title']))
    story.append(Spacer(1,cm))
    para('Universidad de las Fuerzas Armadas ESPE - Carrera de Ingeniería en Software')
    para('Desarrollo de Software Seguro | Laboratorio 1 | Docente: Prof. Geovanny Cudco')
    para('Informe técnico de implementación y experimentación. 24 de noviembre de 2026.')
    para('Autor: DavidPilaguano. Repositorio: DavidPilaguano-VulnMiner-SoftwareSeguro. Entrega de la actividad: 26 de noviembre de 2026.')
    para(f'Resultado principal: {chosen["algorithm"]}, F1 macro de prueba {chosen["test"]["f1_macro"]:.4f}, con 1.008 fragmentos sintéticos y separación por familia. Este resultado no acredita generalización a producción.')
    page('1. Problema, objetivo y alcance')
    para('Los microservicios distribuyen código, interfaces y configuración entre componentes heterogéneos. La actividad exige aprender patrones de posibles vulnerabilidades y producir evidencias verificables desde un único comando ejecutado en la raíz del proyecto.')
    para('El objetivo es integrar las cinco fases SEMMA con un clasificador supervisado multietiqueta, contrastar dos algoritmos y exportar hallazgos OWASP Top 10:2025 y OWASP API Security Top 10:2023. La herramienta no utiliza LLM ni ejecuta el proyecto examinado.')
    para('Se soportan Python y JavaScript. TypeScript comparte el análisis léxico de JavaScript; no se afirma validación independiente de todas sus construcciones. Se leen configuraciones y manifiestos, con detección parcial centrada en depuración y TLS.')
    table([['Cobertura evaluada','Alcance'],['A01, A02, A04, A05, A07, A08','Seis categorías de aplicaciones, limitadas a siete escenarios.'],['API2, API7, API8, API10','Cuatro categorías API, bajo el contexto de los ejemplos.'],['A03, A06, A09, A10; API1, API3, API4, API5, API6, API9','Catálogo presente; categorías expresamente no evaluadas.']],[7*cm,9*cm])
    para('Los hallazgos son potenciales y requieren revisión. La ausencia de un hallazgo no equivale a seguridad. La confidencia del modelo se comunica como puntuación no calibrada y no determina por sí sola la severidad.')
    page('2. Sample: construcción y procedencia')
    para('Se identificaron OWASP Benchmark y NIST SARD como fuentes públicas posibles. Para esta entrega se eligieron exclusivamente casos controlados originales, permitidos por la consigna; no se importaron datos externos ni se atribuyeron resultados a sus suites.')
    para('Siete escenarios: SQL dinámica, criptografía débil, depuración activa, JWT sin firma verificada, SSRF, deserialización insegura y TLS sin validación. Cada escenario incluye dos lenguajes, seis familias, seis dominios y un par vulnerable/corregido. Son 84 grupos artificiales, no repositorios reales.')
    table([['Partición','Registros','Familias'],['Entrenamiento',672,'0, 1, 2, 3'],['Validación',168,'4'],['Prueba',168,'5'],['Total',1008,'504 vulnerables y 504 corregidos']],[5*cm,4*cm,7*cm])
    para('La proporción 66,7/16,7/16,7 conserva familias completas y se justifica frente al 70/15/15 recomendado. Nunca se reparten variantes de la misma familia entre particiones. No se encontraron duplicados exactos ni duplicados canónicos después de sustituir dominios y puertos conocidos; persiste similitud semántica entre patrones.')
    para('Se conservan id, procedencia, grupo, lenguaje, código, estado, etiquetas, CWE, partición y SHA-256. El diccionario y la tabla CWE-OWASP se entregan en data/. Las correspondencias API son contextuales, no equivalencias universales de CWE.')
    page('3. Explore: calidad y distribución')
    para(f'El dataset tiene {stats["records"]} filas, {stats["safe"]} corregidas y {stats["vulnerable"]} vulnerables. Python y JavaScript aportan 504 filas cada uno. No hay faltantes en campos requeridos; CWE vacío y lista de etiquetas vacía son correctos para ejemplos mitigados.')
    chart('categorias.png')
    chart('seguridad.png',width=12*cm)
    para('A07 presenta doble soporte porque cubre autenticación JWT y validación del servidor TLS. Las frecuencias son multietiqueta: una fila puede sumar en ambas taxonomías. El balance artificial no representa la prevalencia real de vulnerabilidades.')
    page('4. Explore: lenguajes, patrones y sesgos')
    chart('lenguajes.png',width=13*cm)
    chart('patrones.png',width=13*cm)
    para(f'Longitud media: {stats["length"]["mean"]:.1f} caracteres; mínimo {stats["length"]["min"]:.0f}, máximo {stats["length"]["max"]:.0f}. Los ejemplos son cortos, con un defecto principal por fragmento. Ese diseño facilita el aprendizaje pero no representa flujos entre servicios, controles externos ni defectos combinados.')
    para('Las frecuencias de tokens describen cómo fueron construidos los ejemplos. No prueban vulnerabilidad por sí solas. El gráfico adicional desbalance.png y las tablas estadísticas se entregan en output/evaluation/.')
    page('5. Modify: preparación y características')
    para('La normalización elimina comentarios de línea y uniforma saltos de línea. Se preservan constantes relevantes, incluyendo true/false, nombres criptográficos y operadores SQL. Los datos se validan antes de entrenar; duplicados, etiquetas inconsistentes o mezcla de grupos provocan error.')
    para('Se unen dos representaciones TF-IDF: caracteres de longitud 3 a 5 y tokens/unigramas-bigramas. Los límites son 22.000 y 8.000 características respectivamente, min_df=2 y frecuencia sublineal. Solo code entra al clasificador; no se usan CWE, escenario, nombre de archivo ni proyecto como predictores.')
    table([['Partición','Dimensión de matriz'],*[ [name,str(shape)] for name,shape in metrics['matrix_shapes'].items()]],[7*cm,9*cm])
    para('El vocabulario y los pesos IDF se ajustan exclusivamente en entrenamiento. Validación y prueba solo se transforman. Se conservan matrices dispersas NPZ, etiquetas NPY e identificadores de filas JSON. Las listas OWASP se codifican con MultiLabelBinarizer; un caso corregido es un vector de ceros.')
    para('La ponderación balanced reduce el efecto de etiquetas menos frecuentes; no se aplicó sobremuestreo. Las variantes de identificadores permanecen en su familia. Los metadatos del pipeline y las versiones se incluyen junto al modelo.')
    page('6. Model: comparación experimental')
    para('Se comparó regresión logística One-vs-Rest (C=0.5 y 2.0, class_weight=balanced, max_iter=1500) con Random Forest multisalida (160 árboles, profundidad sin límite o 18, class_weight=balanced). Semilla 42. Los umbrales 0.30, 0.40, 0.50 y 0.60 se ajustaron con validación.')
    table([['Modelo / parámetro','Umbral','F1 macro validación','F1 macro prueba'],*[ [f'{c["algorithm"]} / {c["parameter"]}',c['threshold'],f'{c["validation"]["f1_macro"]:.4f}',f'{c["test"]["f1_macro"]:.4f}'] for c in metrics['candidates']]],[6*cm,2*cm,4*cm,4*cm])
    chart('model_comparison.png',width=15*cm)
    para(f'Se eligió {chosen["algorithm"]}, parámetro {chosen["parameter"]}, umbral {chosen["threshold"]}, usando exclusivamente F1 macro de validación. En empate se prefiere el modelo lineal por simplicidad. Después se evaluaron las configuraciones congeladas sobre prueba; sus métricas no seleccionaron el modelo. No se readaptó el vocabulario con validación ni prueba.')
    page('7. Assess: métricas y errores')
    test=chosen['test']
    table([['Métrica en prueba','Valor'],['Precision micro',f'{test["precision_micro"]:.4f}'],['Recall micro',f'{test["recall_micro"]:.4f}'],['F1 micro',f'{test["f1_micro"]:.4f}'],['F1 macro',f'{test["f1_macro"]:.4f}'],['Coincidencia exacta de etiquetas',f'{test["exact_match"]:.4f}']],[10*cm,6*cm])
    table([['Categoría','Precision','Recall','F1','Soporte'],*[[label,*[f'{test["per_category"][label][k]:.3f}' for k in ['precision','recall','f1-score']],int(test['per_category'][label]['support'])] for label in metrics['classes']]],[4*cm,3*cm,3*cm,3*cm,3*cm])
    para(f'{len(errors)} registros de prueba tienen al menos un error. Falsas etiquetas positivas: {dict(fp)}. Falsas etiquetas negativas: {dict(fn)}. El archivo errors.json conserva el fragmento y las etiquetas erróneas. El recall alto no elimina el riesgo: los casos sintéticos son estrechos y los errores recaen también en controles que el modelo no reconoce como suficientes.')
    page('8. Assess: matrices y generalización')
    chart('confusion_matrices.png',width=16*cm)
    para('Cada matriz es binaria por etiqueta: filas reales y columnas predichas; orden 0 (ausencia), 1 (presencia). Es una evaluación multietiqueta, no una matriz multiclase exclusiva.')
    para('Se evaluó el flujo completo sobre dos proyectos de fixtures ajenos al entrenamiento, con servicios Python y JavaScript/TypeScript. Cada uno incluye siete casos vulnerables y siete corregidos. Los nombres y estructuras no son filas del CSV. Se utilizaron para corregir falsos positivos del extractor y después como pruebas de regresión; no son una validación ciega.')
    table([['Proyecto','TP/FP/FN/TN','Precision','Recall','F1'],*[[p['project'],f'{p["tp"]}/{p["fp"]}/{p["fn"]}/{p["tn"]}',f'{p["precision"]:.3f}',f'{p["recall"]:.3f}',f'{p["f1"]:.3f}'] for p in projects]],[5*cm,4*cm,2.4*cm,2.3*cm,2.3*cm])
    para('La CLI detecta seis categorías generales y cuatro de API en las fixtures. El rendimiento perfecto sobre esos pocos pares es un control funcional y no una estimación de producción. La evaluación del proyecto desconocido del docente sigue pendiente de recibir dicho proyecto y su verdad de referencia.')
    page('9. Arquitectura y herramienta CLI')
    para('Módulos: catalog define las veinte categorías y los escenarios; features implementa las transformaciones; scanner descubre servicios y extrae contexto; reporting exporta JSON/HTML; cli valida argumentos y coordina la ejecución. scripts contiene generación, entrenamiento, evaluación y construcción de entregables.')
    para('Descubrimiento: se buscan manifiestos de Python/Node/Java, Dockerfile y contextos build de Compose dentro de la raíz. El servicio más cercano recibe el hallazgo. Los archivos de configuración de la raíz se informan separadamente cuando no hay servicio propietario. Reconocer un pom.xml no implica analizar Java: el análisis de código Java no está soportado.')
    para('El extractor localiza operaciones sensibles y obtiene ventanas de contexto sin cruzar líneas vacías. El pipeline aprendido predice etiquetas; se exige umbral y evidencia compatible. Si hay un patrón sensible sin clasificación respaldada se emite pendiente de revisión. Las reglas no asignan etiquetas cuando el clasificador devuelve ceros, lo que se verifica mediante una prueba.')
    para('Cada hallazgo incluye id estable, servicio, archivo, línea, lenguaje, descripción, evidencia/contexto, ambas listas OWASP, CWE cuando procede, puntuación general y por etiqueta, severidad estimada con justificación, recomendación, estado y confirmed=false. El HTML permite filtrar por servicio y muestra categorías no evaluadas.')
    para('La herramienta omite carpetas de dependencias y compilación, enlaces simbólicos y archivos mayores a 1 MB; registra omisiones. El HTML escapa evidencia para impedir que el contenido analizado se interprete como marcado. No se ejecuta código del proyecto ni se cargan modelos suministrados por el usuario.')
    page('10. Instalación, comprobaciones y demostración')
    para('Instalar con python -m pip install -e ".[lab]" en un entorno virtual. Ejecutar desde la raíz del proyecto: vulnminer scan . --standards owasp2025,api2023 --format json,html --output ./reportes. También funciona python -m vulnminer scan . cuando el ejecutable no está en PATH.')
    para('La versión de scikit-learn se fija en 1.8.0, coincidente con el modelo entregado. Durante la preparación se corrigió una incompatibilidad de versiones y se repitió el entrenamiento. metadata.json registra Python, numpy y scikit-learn. El paquete incluye model.joblib: no es necesario ejecutar entrenamiento para cada escaneo.')
    para('Se ejecutaron 10 pruebas automatizadas: cobertura y líneas, pares seguros y metadatos, catálogo, filtro de estándares, abstención al retirar el aprendizaje, escape HTML y esquema JSON, exclusiones y patrones desconocidos, YAML, errores/códigos CLI e independencia del dataset. Los cinco notebooks se ejecutan de principio a fin.')
    para('Los reportes de ejemplo y las matrices se entregan como evidencia reproducible. Para regenerar: scripts/reproduce.ps1 -Install. El guion docs/demostracion.md explica cómo presentar SEMMA, comparar modelos y ejecutar el proyecto del docente cuando esté disponible.')
    para('Limitaciones: extracción léxica, ventanas cortas, ausencia de flujo interprocedimental, sin análisis dinámico, sin base CVE, sin inventario completo, sin verificación de autorización y sin calibración de confianza. Las mitigaciones de los pares seguros suponen auxiliares correctamente implementados. Los reportes pueden incluir información sensible del código fuente.')
    page('11. Conclusiones y referencias')
    para('La experiencia muestra que un modelo supervisado con TF-IDF puede reconocer patrones controlados y asignar etiquetas de ambos estándares dentro de una CLI reproducible. La regresión logística superó a Random Forest en el criterio de validación del experimento. La herramienta satisface la cobertura mínima mediante seis categorías generales y cuatro de API.')
    para('La pregunta orientadora solo puede responderse dentro del alcance medido: el modelo logra F1 macro de prueba 0.9556 sobre familias sintéticas reservadas, con errores documentados. No hay base para extrapolar esa cifra a repositorios reales. La evaluación externa y la revisión humana son indispensables para concluir sobre utilidad operativa.')
    para('Mejoras propuestas: incorporar ejemplos públicos con licencias y procedencia verificadas; reservar repositorios reales para un ensayo ciego; usar AST y flujo de datos; incorporar controles entre archivos; calibrar puntuaciones y estudiar curvas precisión-recall; ampliar categorías solo después de disponer de datos y evaluación suficientes.')
    refs=[('Consigna del laboratorio','Modelo_mineria_datos.pdf, ESPE, 19 de noviembre de 2026.'),('OWASP Top 10:2025','https://top10.owasp.org/2025/'),('OWASP API Security Top 10:2023','https://api-security.owasp.org/editions/2023/en/0x11-t10/'),('OWASP Benchmark, fuente identificada no incorporada','https://owasp.org/www-project-benchmark/'),('NIST SARD, fuente identificada no incorporada','https://samate.nist.gov/SARD/'),('Correspondencias y fuentes por escenario','docs/fuentes.md y data/cwe_owasp.csv'),('Versiones y experimento reproducible','output/evaluation/metrics.json y vulnminer/artifacts/metadata.json')]
    for title,url in refs:
        para(f'{title}: {url}')
    dest=ROOT/'output/pdf'
    dest.mkdir(parents=True,exist_ok=True)
    def footer(canvas,doc):
        canvas.saveState()
        canvas.setFont(font,8)
        canvas.setFillColor(colors.HexColor('#657986'))
        canvas.drawString(2*cm,1.2*cm,'ESPE | VulnMiner | Informe técnico')
        canvas.drawRightString(19*cm,1.2*cm,str(doc.page))
        canvas.restoreState()
    doc=SimpleDocTemplate(str(dest/'informe_tecnico.pdf'),pagesize=(21*cm,29.7*cm),rightMargin=2*cm,leftMargin=2*cm,topMargin=2*cm,bottomMargin=2*cm,title='VulnMiner - Informe técnico SEMMA',author='DavidPilaguano')
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    (ROOT/'docs/informe_tecnico.md').write_text('# VulnMiner: informe técnico\n\n'+'\n'.join(markdown),encoding='utf-8')
    print('Informe PDF y fuente Markdown generados.',flush=True)


if __name__=='__main__':
    if '--report-only' not in sys.argv:
        notebooks()
    report()
