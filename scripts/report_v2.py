"""Informe editorial basado exclusivamente en experimentos guardados y fuentes citadas."""
from pathlib import Path
from collections import Counter
import html
import json
import textwrap
ROOT=Path(__file__).resolve().parents[1]

REPO='https://github.com/DavidPilaguano/DavidPilaguano-VulnMiner-SoftwareSeguro'
MOVEIT='https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023'
CERT='https://cert.europa.eu/publications/security-advisories/2023-033/'
CAPITAL='https://www.justice.gov/usao-wdwa/pr/seattle-tech-worker-arrested-data-theft-involving-large-financial-services-company'


def figures(metrics):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    out=ROOT/'output/evaluation'
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,'axes.spines.right':False,'axes.labelcolor':'#263f53','text.color':'#19334a','axes.titleweight':'bold','figure.facecolor':'white','axes.facecolor':'white'})
    stats=metrics['statistics']
    def save(fig,name):
        fig.tight_layout()
        fig.savefig(out/name,dpi=180,bbox_inches='tight')
        plt.close(fig)
    fig,ax=plt.subplots(figsize=(9,3.3))
    values=stats['sources']
    bars=ax.barh(list(values),list(values.values()),color=['#163b58','#168d9a','#d29945'])
    ax.bar_label(bars,padding=5)
    ax.set_xlim(0,max(values.values())*1.17)
    ax.set_xlabel('Registros después de deduplicación')
    ax.set_title('La mayoría del corpus procede de fuentes públicas')
    save(fig,'report_sources.png')
    fig,ax=plt.subplots(figsize=(9,3.5))
    x=np.arange(len(metrics['candidates']))
    ax.bar(x-.2,[c['validation']['f1_macro'] for c in metrics['candidates']],.4,label='Validación',color='#168d9a')
    ax.bar(x+.2,[c['test']['f1_macro'] for c in metrics['candidates']],.4,label='Prueba',color='#163b58')
    ax.set_xticks(x,[('LR · C='+str(c['parameter'])) if c['algorithm']=='LogisticRegression' else 'RF · '+('sin límite' if c['parameter'] is None else 'prof. '+str(c['parameter'])) for c in metrics['candidates']])
    ax.set_ylim(0,1.05)
    ax.set_ylabel('F1 macro')
    ax.set_title('El ganador se fija con validación, antes de consultar prueba')
    ax.legend(frameon=False,ncol=2,loc='lower left')
    save(fig,'report_comparison.png')
    fig,ax=plt.subplots(figsize=(9,3.1))
    values=metrics['test_by_source']
    bars=ax.barh(list(values),[m['f1_macro_supported'] for m in values.values()],color=['#163b58','#168d9a','#d29945'])
    ax.bar_label(bars,fmt='%.3f',padding=4)
    ax.set_xlim(0,1.05)
    ax.set_xlabel('F1 macro sobre etiquetas con soporte en cada fuente')
    ax.set_title('Resultados desagregados: el promedio no cuenta toda la historia')
    save(fig,'report_source_scores.png')


def report():
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,PageBreak,Table,TableStyle,Image,KeepTogether
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.graphics.shapes import Drawing,Rect,String,Line,Polygon
    from PIL import Image as PILImage
    metrics=json.loads((ROOT/'output/evaluation/metrics.json').read_text(encoding='utf-8'))
    manifest=json.loads((ROOT/'data/public_manifest.json').read_text(encoding='utf-8'))
    selected=metrics['candidates'][metrics['selected']]
    stats=metrics['statistics']
    public=metrics['public_only']
    projects=json.loads((ROOT/'output/evaluation/projects.json').read_text(encoding='utf-8'))
    cli=json.loads((ROOT/'output/evaluation/public_cli.json').read_text(encoding='utf-8'))
    errors=json.loads((ROOT/'output/evaluation/errors.json').read_text(encoding='utf-8'))
    figures(metrics)
    font,bold='Helvetica','Helvetica-Bold'
    if Path('C:/Windows/Fonts/arial.ttf').is_file():
        pdfmetrics.registerFont(TTFont('Editorial','C:/Windows/Fonts/arial.ttf'))
        pdfmetrics.registerFont(TTFont('EditorialBold','C:/Windows/Fonts/arialbd.ttf'))
        font,bold='Editorial','EditorialBold'
    navy=colors.HexColor('#102c43')
    teal=colors.HexColor('#008a95')
    muted=colors.HexColor('#5a7182')
    light=colors.HexColor('#edf4f7')
    gold=colors.HexColor('#dba753')
    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle('BodyEditorial',fontName=font,fontSize=10.2,leading=15.1,textColor=navy,spaceAfter=10))
    styles.add(ParagraphStyle('SmallEditorial',fontName=font,fontSize=8.4,leading=11.6,textColor=navy,spaceAfter=5))
    styles.add(ParagraphStyle('H1Editorial',fontName=bold,fontSize=23,leading=28,textColor=navy,spaceAfter=17))
    styles.add(ParagraphStyle('H2Editorial',fontName=bold,fontSize=12,leading=16,textColor=teal,spaceBefore=8,spaceAfter=8))
    styles.add(ParagraphStyle('Eyebrow',fontName=bold,fontSize=9,leading=12,textColor=teal,spaceAfter=9))
    styles.add(ParagraphStyle('CoverTitleEditorial',fontName=bold,fontSize=43,leading=48,textColor=colors.white,spaceAfter=18))
    styles.add(ParagraphStyle('CoverLeadEditorial',fontName=font,fontSize=19,leading=26,textColor=colors.HexColor('#e1eef2'),spaceAfter=22))
    styles.add(ParagraphStyle('CoverBodyEditorial',fontName=font,fontSize=11,leading=17,textColor=colors.HexColor('#e1eef2'),spaceAfter=13))
    styles.add(ParagraphStyle('MetricValue',fontName=bold,fontSize=25,leading=31,textColor=teal,spaceAfter=3))
    styles.add(ParagraphStyle('MetricLabel',fontName=font,fontSize=9,leading=13,textColor=navy))
    story=[]
    markdown=['# VulnMiner · Informe técnico\n','Autor: DavidPilaguano. ESPE. 24 de noviembre de 2026.\n']
    width=17.2*cm
    def p(text,style='BodyEditorial'):
        story.append(Paragraph(html.escape(str(text)),styles[style]))
        markdown.append(str(text)+'\n')
    def heading(text):
        story.append(Paragraph(html.escape(text),styles['H2Editorial']))
        markdown.append('### '+text+'\n')
    def page(index,title,subtitle):
        story.append(PageBreak())
        p(f'{index:02d} / INFORME TÉCNICO','Eyebrow')
        story.append(Paragraph(html.escape(title),styles['H1Editorial']))
        markdown.append('## '+title+'\n')
        if subtitle:
            p(subtitle)
    def table(rows,widths=None):
        values=[[Paragraph(html.escape(str(value)),styles['SmallEditorial']) for value in row] for row in rows]
        t=Table(values,colWidths=widths,repeatRows=1,hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),light),('VALIGN',(0,0),(-1,-1),'TOP'),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),('LINEBELOW',(0,0),(-1,-1),.3,colors.HexColor('#d1dfe6'))]))
        story.extend([t,Spacer(1,10)])
        lines=['| '+' | '.join(str(v) for v in row)+' |' for row in rows]
        lines.insert(1,'| '+' | '.join('---' for _ in rows[0])+' |')
        markdown.append('\n'.join(lines)+'\n')
    def chart(name,w=width):
        path=ROOT/'output/evaluation'/name
        with PILImage.open(path) as im:
            iw,ih=im.size
        story.extend([Image(str(path),width=w,height=w*ih/iw),Spacer(1,10)])
        markdown.append(f'![{name}](../output/evaluation/{name})\n')
    def callout(title,text,tint=light):
        titlep=Paragraph(html.escape(title),styles['H2Editorial'])
        body=Paragraph(html.escape(text),styles['BodyEditorial'])
        box=Table([[titlep],[body]],colWidths=[width])
        box.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),tint),('LEFTPADDING',(0,0),(-1,-1),14),('RIGHTPADDING',(0,0),(-1,-1),14),('TOPPADDING',(0,0),(-1,0),8),('BOTTOMPADDING',(0,-1),(-1,-1),9)]))
        story.extend([KeepTogether(box),Spacer(1,12)])
        markdown.extend(['### '+title+'\n',text+'\n'])
    def cards(items):
        row=[]
        for value,label in items:
            row.append([Paragraph(html.escape(str(value)),styles['MetricValue']),Paragraph(html.escape(label),styles['MetricLabel'])])
        t=Table([row],colWidths=[width/len(row)]*len(row))
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),light),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),12),('TOPPADDING',(0,0),(-1,-1),13),('BOTTOMPADDING',(0,0),(-1,-1),13),('BOX',(0,0),(-1,-1),.3,colors.HexColor('#d1dfe6'))]))
        story.extend([t,Spacer(1,17)])
        markdown.append('; '.join(str(v)+' '+label for v,label in items)+'\n')
    def flow(labels):
        drawing=Drawing(width,68)
        gap=13
        nodewidth=(width-gap*(len(labels)-1))/len(labels)
        for i,label in enumerate(labels):
            x=i*(nodewidth+gap)
            drawing.add(Rect(x,9,nodewidth,52,rx=5,ry=5,fillColor=light,strokeColor=colors.HexColor('#ccdfe5')))
            lines=textwrap.wrap(label,16)
            for j,line in enumerate(lines):
                drawing.add(String(x+nodewidth/2,40-j*12,line,fontName=font,fontSize=8.7,fillColor=navy,textAnchor='middle'))
            if i<len(labels)-1:
                drawing.add(Line(x+nodewidth+2,35,x+nodewidth+gap-4,35,strokeColor=teal))
                drawing.add(Polygon([x+nodewidth+gap-3,35,x+nodewidth+gap-7,38,x+nodewidth+gap-7,32],fillColor=teal,strokeColor=teal))
        story.extend([drawing,Spacer(1,12)])
        markdown.append(' → '.join(labels)+'\n')
    def ref(title,url):
        story.append(Paragraph('<link href="'+html.escape(url,quote=True)+'" color="#008a95">'+html.escape(title)+'</link>',styles['SmallEditorial']))
        markdown.append(f'[{title}]({url})\n')
    # 01 - Cover.
    story.append(Spacer(1,3.2*cm))
    p('ESPE / DESARROLLO DE SOFTWARE SEGURO','CoverBodyEditorial')
    story.append(Paragraph('VulnMiner',styles['CoverTitleEditorial']))
    story.append(Paragraph('Aprendizaje supervisado para analizar riesgos en microservicios',styles['CoverLeadEditorial']))
    p('SEMMA · OWASP Top 10:2025 · OWASP API Security Top 10:2023','CoverBodyEditorial')
    story.append(Spacer(1,.7*cm))
    cards([(f'{stats["records"]:,}'.replace(',','.'),'registros preparados'),('2','fuentes públicas descargadas'),(f'{selected["test"]["f1_macro"]:.4f}','F1 macro · modelo híbrido')])
    p('DavidPilaguano','CoverBodyEditorial')
    p('Informe técnico / Edición con datos públicos / 24 de noviembre de 2026','CoverBodyEditorial')
    p('Docente: Prof. Geovanny Cudco. Entrega de la actividad: 26 de noviembre de 2026.','CoverBodyEditorial')
    p('Los benchmarks públicos y el suplemento propio son casos controlados. Este informe presenta resultados, fortalezas y límites sin atribuir detección de incidentes reales.','CoverBodyEditorial')
    # 02 - Strengths.
    page(2,'Qué aporta la solución','La principal mejora es una evaluación más amplia y trazable: se sustituyó la dependencia exclusiva de ejemplos propios por un corpus mayoritariamente público, sin ocultar la caída del desempeño fuera de los patrones originales.')
    strengths=[
        ('Fuentes verificables','Dos suites OWASP descargadas, commits fijados, oráculos oficiales, originales comprimidos y licencias conservadas. Evidencia: data/public_manifest.json.'),
        ('Evaluación sin elegir por prueba','Se comparan dos algoritmos y cuatro configuraciones. El ganador y el umbral se fijan con validación; las métricas de prueba se muestran después, incluso cuando favorecen a otro candidato.'),
        ('Atribución transparente','Se informa por fuente y se entrega un modelo adicional entrenado solo con datos públicos. Las cuatro categorías API del modelo principal proceden del suplemento propio, no de etiquetas inventadas de Benchmark.'),
        ('Integración y evidencia','La CLI usa el modelo serializado, identifica servicios y genera JSON/HTML con archivo, línea, evidencia, recomendaciones y estado de revisión. No ejecuta el código analizado ni utiliza LLM.'),
        ('Límites comprobables','Se contrastan fragmentos preparados y fuentes originales. Hay trece pruebas funcionales y una muestra pública reservada. La confianza se distingue de la severidad; las categorías sin cobertura se declaran.'),
    ]
    for title,text in strengths:
        heading(title)
        p(text)
    callout('Fortaleza no significa garantía','La trazabilidad, la reproducibilidad y la honestidad de la evaluación son ventajas demostrables. No se afirma que el enriquecimiento haya mejorado el F1 global ni que el producto sustituya revisión humana o un SAST con flujo de datos.')
    # 03 - Data.
    page(3,'Sample · fuentes y particiones','Se importaron los archivos de prueba y los CSV de resultados esperados de OWASP BenchmarkPython y BenchmarkJava. Solo se leyeron los programas: no se ejecutaron aplicaciones vulnerables ni se instalaron sus dependencias.')
    table([['Procedencia','Descargados','Usados','Licencia'],*[ [s['name'],s['records_downloaded'],stats['sources'][s['name']],s['license']] for s in manifest['sources']],['Suplemento propio','No aplica',manifest['controlled_records'],'Casos originales']],[5.4*cm,3*cm,3*cm,5.8*cm])
    chart('report_sources.png')
    p(f'Se descargaron {manifest["raw_public_records"]} registros públicos. Se eliminaron {manifest["duplicate_records_removed"]} duplicados exactos tras preparar el código y {manifest["ambiguous_records_removed"]} casos ambiguos. El corpus final suma {stats["records"]} filas: {stats["safe"]} no vulnerables y {stats["vulnerable"]} vulnerables.')
    table([['Entrenamiento','Validación','Prueba'],[stats['partitions']['train'],stats['partitions']['validation'],stats['partitions']['test']]],[width/3]*3)
    p('Las suites públicas usan siete folds estratificados y agrupados: cinco para entrenar, uno para validar y uno para probar. Las familias del suplemento permanecen en sus particiones originales. Los grupos estructurales no se reparten; ambas suites sí aparecen en las tres particiones. No es una separación por repositorio desconocido.')
    # 04 - Explore.
    page(4,'Explore · diversidad y desbalance','Los benchmarks aportan Java y Python, escenarios más largos y controles que los fragmentos breves no representaban. El suplemento conserva JavaScript y los escenarios API. TypeScript comparte el extractor léxico de JavaScript.')
    chart('categorias.png',w=15.9*cm)
    chart('lenguajes.png',w=12.8*cm)
    p('Las frecuencias son multietiqueta: no deben sumarse como si fueran observaciones exclusivas. Las etiquetas API solo aparecen en el suplemento controlado. Los gráficos de balance, patrones y desbalance, las estadísticas de longitud y la distribución por fuente se entregan en output/evaluation/.')
    # 05 - Modify.
    page(5,'Modify · preparación sin atajos','La limpieza evita que el clasificador aprenda identificadores de los casos o comentarios que delaten su etiqueta. La conservación de originales permite auditar cada transformación.')
    flow(['Original + oráculo','Handler / clase','Sin IDs ni comentarios','TF-IDF solo train'])
    table([['Transformación','Propósito'],['Python: AST y cuerpo del handler POST','Retirar wrapper GET, comentarios y docstrings sin ejecutar código.'],['Java: retirar GET, comentarios y encabezados','Conservar el cuerpo relevante y auxiliares de clase.'],['Eliminar BenchmarkTest y rutas con categoría','Evitar señales explícitas del generador o del etiquetado.'],['Deduplicación y huella estructural','Agrupar variantes ignorando identificadores y literales; no mezclar grupos entre particiones.'],['TF-IDF de caracteres 3..5 y tokens 1..2','Aprender operaciones y contexto; preservar constantes relevantes.']],[6.8*cm,10.4*cm])
    p('Solo code entra al vectorizador: CWE, etiquetas, procedencia, archivo e ID son metadatos. El vocabulario y los IDF se ajustan únicamente con entrenamiento. Se aplica class_weight=balanced, sin sobremuestreo. Las matrices dispersas, etiquetas y orden de filas se exportan.')
    table([['Partición','Forma de la matriz'],*[[k,str(v)] for k,v in metrics['matrix_shapes'].items()]],[7*cm,10.2*cm])
    callout('Lo que esta separación no prueba','La agrupación estructural reduce duplicados cercanos, pero no garantiza independencia semántica entre todos los casos generados. Tampoco evalúa transferencia a un repositorio de producción completamente nuevo.')
    # 06 - Model.
    page(6,'Model · comparación y selección','Regresión logística One-vs-Rest: C=0.5 y 2.0, max_iter=1500. Random Forest multisalida: 160 árboles, profundidad sin límite o 18. Semilla 42; umbrales globales 0.30, 0.40, 0.50 y 0.60, ajustados únicamente con validación.')
    table([['Algoritmo / ajuste','Umbral','F1 val.','F1 prueba'],*[[c['algorithm']+' / '+str(c['parameter']),c['threshold'],f'{c["validation"]["f1_macro"]:.4f}',f'{c["test"]["f1_macro"]:.4f}'] for c in metrics['candidates']]],[8.2*cm,2.5*cm,3.1*cm,3.4*cm])
    chart('report_comparison.png')
    p(f'Se conserva {selected["algorithm"]}, C={selected["parameter"]}, umbral={selected["threshold"]}, por obtener el mejor F1 macro de validación ({selected["validation"]["f1_macro"]:.4f}). No se reemplaza por Random Forest tras observar que este tiene mejor F1 de prueba: hacerlo usaría la prueba para seleccionar.')
    callout('Dos artefactos con funciones distintas','model.joblib es el modelo híbrido integrado en la CLI. public_model.joblib se entrena solo con los casos públicos, con vocabulario propio y seis etiquetas generales. No permite atribuir cobertura API a los benchmarks.')
    # 07 - Assess.
    page(7,'Assess · resultados del modelo principal','El conjunto de prueba contiene observaciones que no participaron en ajuste del vectorizador, estimadores ni umbral. El F1 macro asigna el mismo peso a cada etiqueta; el F1 micro agrega sus decisiones.')
    test=selected['test']
    cards([(f'{test["f1_macro"]:.4f}','F1 macro'),(f'{test["f1_micro"]:.4f}','F1 micro'),(f'{test["exact_match"]:.4f}','Coincidencia exacta')])
    table([['Categoría','Precisión','Recall','F1','Soporte'],*[[label,*[f'{test["per_category"][label][key]:.3f}' for key in ['precision','recall','f1-score']],int(test['per_category'][label]['support'])] for label in metrics['classes']]],[4.1*cm,3.3*cm,3.1*cm,3.2*cm,3.5*cm])
    p(f'Precisión micro: {test["precision_micro"]:.4f}; recall micro: {test["recall_micro"]:.4f}. Hay {len(errors)} registros con al menos una etiqueta errónea. No se traduce el F1 a un porcentaje de certeza de una vulnerabilidad individual.')
    p(f'F1 macro entrenamiento / validación / prueba: {selected["train"]["f1_macro"]:.4f} / {selected["validation"]["f1_macro"]:.4f} / {test["f1_macro"]:.4f}. La caída de prueba indica una limitación de generalización y exige cautela operativa.')
    # 08 - Source.
    page(8,'Assess · qué aportan los datos públicos','El experimento solo público entrena regresión logística C=2.0, con vocabulario e IDF propios y umbral elegido en validación pública. No utiliza ningún caso del suplemento y no etiqueta riesgos API a partir del CWE.')
    cards([(f'{public["test"]["f1_macro"]:.4f}','F1 macro · solo público'),(f'{public["test"]["f1_micro"]:.4f}','F1 micro · solo público'),(str(len(public['classes'])),'Categorías generales')])
    table([['Experimento','Train','Validación','Prueba'],['Solo público',public['records']['train'],public['records']['validation'],public['records']['test']]], [7*cm,3.4*cm,3.4*cm,3.4*cm])
    chart('report_source_scores.png')
    p('El gráfico desagrega el modelo híbrido por procedencia, usando F1 macro solo sobre categorías que tienen soporte real en cada fuente. Sus valores no comparten exactamente el mismo conjunto de etiquetas y se acompañan de las métricas completas en metrics.json.')
    callout('La cifra anterior no era una referencia de producción','El F1 macro previo de 0.9556 pertenecía al dataset propio de 1.008 fragmentos. Cambiaron población, longitud y categorías. Ese resultado se conserva en output/baseline_synthetic/ como antecedente; no es un experimento controlado para afirmar mejora o empeoramiento causal.')
    # 09 - Errors.
    page(9,'Errores y capacidad de generalización','Las matrices de confusión son binarias por etiqueta: filas reales y columnas predichas, en orden 0/1. Permiten separar falsas alarmas de omisiones.')
    chart('confusion_matrices.png',w=16.5*cm)
    fp=Counter(label for error in errors for label in error['false_positive'])
    fn=Counter(label for error in errors for label in error['false_negative'])
    p('Falsas etiquetas positivas: '+', '.join(f'{k}: {v}' for k,v in fp.items())+'.')
    p('Falsas etiquetas negativas: '+', '.join(f'{k}: {v}' for k,v in fn.items())+'.')
    p('El modelo puede confundir una operación peligrosa con un uso protegido, o ignorar un control situado lejos del sink. También puede omitir variantes de URL o deserialización que no se parecen a las formas vistas. Los errores completos conservan fragmento, fuente, escenario y etiquetas en errors.json; no se eliminaron del reporte para mejorar la presentación.')
    # 10 - CLI.
    page(10,'Arquitectura · del repositorio al reporte','El clasificador es el componente central; las reglas complementan localización y evidencia. Una prueba con un clasificador que devuelve ceros verifica que las reglas no asignan por sí solas etiquetas OWASP.')
    flow(['Descubrir servicios','Extraer contexto','TF-IDF + modelo','Evidencia y umbral','JSON / HTML'])
    table([['Componente','Responsabilidad'],['catalog / features','Catálogo completo, escenarios y representación compartida.'],['scanner','Lectura estática, manifiestos, Compose, archivos y contexto. Python usa bloques de función; Java y JS/TS usan extracción léxica.'],['reporting / cli','Validación de argumentos, resumen y exportación con escape HTML.'],['scripts','Importación, entrenamiento, evaluación, notebooks e informe reproducibles.']],[5.2*cm,12*cm])
    p('Cada hallazgo identifica servicio, archivo, línea y evidencia, además de etiquetas, CWE contextual, puntuación, severidad justificada, remediación y estado. Todos tienen confirmed=false. Una categoría sin evidencia suficiente se deja pendiente de revisión.')
    p('No se ejecuta código del proyecto ni se cargan modelos arbitrarios suministrados por el usuario. Se omiten dependencias, enlaces simbólicos, binarios y archivos de más de 1 MB; las omisiones se registran. El reporte puede contener código sensible y debe custodiarse como tal.')
    callout('Cobertura parcial explícita','Siete categorías generales tienen datos y mecanismos parciales: A01, A02, A04, A05, A06, A07 y A08. Las cuatro API del suplemento son API2, API7, API8 y API10. A03, A09, A10 y las seis API restantes no están evaluadas. Un catálogo completo no equivale a detección completa.')
    # 11 - Functional.
    page(11,'La CLI sobre código original','Se separa el rendimiento del clasificador sobre texto preparado del rendimiento de toda la herramienta sobre archivos originales. Esta diferencia muestra el costo de extracción y localización de evidencia.')
    table([['Evaluación por archivo','TP','FP','FN','TN','F1'],*[[p['project'],p['tp'],p['fp'],p['fn'],p['tn'],f'{p["f1"]:.3f}'] for p in projects],['Holdout público',cli['tp'],cli['fp'],cli['fn'],cli['tn'],f'{cli["f1"]:.3f}']],[6.2*cm,2.2*cm,2.2*cm,2.2*cm,2.2*cm,2.2*cm])
    p(f'La muestra pública contiene {cli["sample_size"]} casos reservados: hasta dos por fuente, escenario y estado, escogidos por orden SHA-256 del ID. Se usan los originales con sus avisos y licencias. F1 micro de etiquetas de la CLI: {cli["label_f1_micro"]:.4f}. El modelo y el umbral permanecen congelados.')
    p('Los dos proyectos propios sirven como regresión funcional y fueron usados al depurar el extractor. La muestra de Benchmark pertenece al mismo holdout estadístico ya evaluado; no es un nuevo ensayo ciego. La herramienta produce falsas alarmas y omisiones sobre los originales, aun cuando el resultado en las fixtures propias sea perfecto.')
    heading('Instalación y prueba')
    p('El README permite clonar, crear un entorno virtual e instalar con pip install . El modelo serializado está incluido y el escaneo no reentrena. Para regenerar experimentos se instala el extra [lab] y se ejecuta import_public_datasets.py antes de train.py.')
    callout('Comando de análisis','vulnminer scan . --standards owasp2025,api2023 --format json,html --output ./reportes')
    p('Las trece pruebas funcionales verifican además procedencia pública, integridad de oráculos, ausencia de IDs de casos en características y lectura de archivos Java. El proyecto desconocido de evaluación debe probarse cuando esté disponible.')
    # 12 - Limits + references, before final two case studies.
    page(12,'Conclusiones, límites y fuentes','Un corpus público amplía la diversidad y permite auditar el aprendizaje, pero no elimina la naturaleza controlada del experimento ni garantiza utilidad sobre producción.')
    p(f'El modelo híbrido obtiene F1 macro {test["f1_macro"]:.4f}; el experimento solo público obtiene {public["test"]["f1_macro"]:.4f} en su propio espacio de seis etiquetas. La CLI sobre los {cli["sample_size"]} originales reservados obtiene F1 por archivo {cli["f1"]:.4f}. Las tres cifras responden a preguntas diferentes y no deben intercambiarse.')
    p('Límites: sin flujo interprocedimental, sin resolución de tipos Java, sin pruebas dinámicas, sin base CVE, sin calibración probabilística y con cobertura parcial. Las etiquetas API dependen del suplemento. Tampoco se demuestra ausencia de similitud semántica entre todas las plantillas ni generalización a repositorios desconocidos.')
    p('Siguientes mejoras: reservar repositorios reales para un ensayo ciego, ampliar ejemplos API con oráculos independientes, analizar flujo de datos y controles entre archivos, calibrar puntuaciones y fijar umbrales por categoría utilizando únicamente validación. Estas mejoras se proponen; no se reportan como realizadas.')
    heading('Fuentes de datos y estándares')
    for source in manifest['sources']:
        ref(source['name']+' · commit '+source['commit'][:12]+' · '+source['license'],source['url']+'/tree/'+source['commit'])
    ref('OWASP Benchmark: propósito y documentación','https://owasp.org/www-project-benchmark/')
    ref('OWASP Top 10:2025','https://top10.owasp.org/2025/')
    ref('OWASP API Security Top 10:2023','https://api-security.owasp.org/editions/2023/en/0x11-t10/')
    ref('Repositorio, scripts, métricas y trazabilidad completa',REPO)
    p('Consulta de fuentes: 24 de noviembre de 2026. Los originales mantienen avisos y licencias por procedencia; THIRD_PARTY_NOTICES.md distingue esas licencias del código de la herramienta. Los dos casos siguientes se basan en fuentes primarias y son ilustraciones retrospectivas, no resultados de escaneo.','SmallEditorial')
    # 13 - Case 1, penultimate.
    page(13,'Caso real 1 · MOVEit Transfer','2023 / Inyección SQL / CVE-2023-34362')
    callout('Qué ocurrió','Progress informó una inyección SQL en MOVEit Transfer que permitía a un atacante no autenticado acceder a la base de datos. La comunicación del fabricante documenta explotación activa en mayo y junio de 2023. CERT-EU describió la posibilidad de acceder a datos y ejecutar sentencias que modificaran o eliminaran elementos de la base.')
    heading('Relación con el problema estudiado')
    p('La relación retrospectiva es CWE-89 y A05:2025 Injection: entrada no confiable termina alterando una consulta. Esta asociación usa la taxonomía de la entrega, aunque el incidente ocurrió antes de la edición 2025. No se atribuye automáticamente una categoría API sin evidencia adicional.')
    flow(['Entrada externa','Consulta SQL alterada','Acceso no autorizado','Exfiltración / impacto'])
    heading('Lección y controles')
    p('El caso muestra el impacto de no separar datos e instrucciones. Los controles pertinentes incluyen consultas parametrizadas, privilegios mínimos y gestión oportuna de parches. Para este incidente, el fabricante recomendó aplicar las correcciones, revisar artefactos y accesos no autorizados y seguir sus medidas de contención.')
    callout('Qué puede y qué no puede demostrar VulnMiner','Los Benchmark incorporan SQLi etiquetada y el modelo aprende patrones asociados a CWE-89. No se descargó ni analizó el código vulnerable de MOVEit. Su implementación .NET/C# queda fuera de los lenguajes cubiertos: este trabajo no demuestra detección de esa CVE ni que hubiera impedido el incidente.')
    heading('Fuentes primarias del caso')
    ref('Progress · aviso original, descripción y medidas de remediación',MOVEIT)
    ref('CERT-EU · Security Advisory 2023-033',CERT)
    # 14 - Case 2, last.
    page(14,'Caso real 2 · Capital One','2019 / Configuración de seguridad incorrecta en un servicio expuesto')
    callout('Qué ocurrió','El Departamento de Justicia de Estados Unidos informó el 29 de julio de 2019 que la intrusión en datos de Capital One se produjo a través de un firewall de aplicaciones web mal configurado. El comunicado describe acceso a información almacenada relacionada con solicitudes de crédito y la posterior investigación del FBI.')
    heading('Relación con el problema estudiado')
    p('La relación con A02:2025 Security Misconfiguration es una interpretación técnica retrospectiva de la debilidad descrita por la fuente. No se inventa un CWE ni una etiqueta API específica a partir de ese comunicado. La evidencia citada no detalla un flujo suficiente para afirmar aquí una cadena SSRF concreta.')
    flow(['Servicio expuesto','WAF mal configurado','Acceso a datos','Impacto y respuesta'])
    heading('Lección y controles')
    p('Una configuración incorrecta puede abrir una ruta de acceso aun cuando existan componentes de protección. La revisión de reglas efectivas, permisos mínimos, segmentación, configuración como código y pruebas de exposición debe acompañar el análisis del código de aplicación. Estas son lecciones del estudio, no una reconstrucción completa de la investigación.')
    callout('Qué puede y qué no puede demostrar VulnMiner','La herramienta detecta algunos patrones locales de configuración, como depuración o cookies inseguras. No audita reglas efectivas de WAF ni permisos IAM desplegados. Por eso no se afirma que habría detectado o prevenido este incidente. El caso ilustra una categoría más amplia que la cobertura implementada.')
    heading('Fuente primaria del caso')
    ref('U.S. Department of Justice · comunicado del 29 de julio de 2019',CAPITAL)
    p('Cierre: el valor de un reporte de seguridad también está en precisar lo que su evidencia no permite concluir. Las fortalezas de VulnMiner son trazabilidad, reproducibilidad e integración; sus resultados requieren revisión y validación externa.','SmallEditorial')
    target=ROOT/'output/pdf/informe_tecnico.pdf'
    target.parent.mkdir(parents=True,exist_ok=True)
    def furniture(canvas,doc):
        canvas.saveState()
        if doc.page==1:
            canvas.setFillColor(navy)
            canvas.rect(0,0,21*cm,29.7*cm,fill=1,stroke=0)
            canvas.setFillColor(teal)
            canvas.rect(0,28.9*cm,21*cm,.8*cm,fill=1,stroke=0)
            canvas.setFillColor(colors.HexColor('#9fc0d0'))
        else:
            canvas.setStrokeColor(colors.HexColor('#d4e1e7'))
            canvas.line(1.9*cm,28.25*cm,19.1*cm,28.25*cm)
            canvas.setFillColor(muted)
            canvas.setFont(font,8)
            canvas.drawString(1.9*cm,28.55*cm,'VULNMINER / DATOS PÚBLICOS Y EVALUACIÓN SUPERVISADA')
        canvas.setFont(font,8)
        canvas.drawString(1.9*cm,1.15*cm,'DavidPilaguano  |  ESPE  |  24.11.2026')
        canvas.drawRightString(19.1*cm,1.15*cm,f'{doc.page:02d}')
        canvas.restoreState()
    doc=SimpleDocTemplate(str(target),pagesize=(21*cm,29.7*cm),leftMargin=1.9*cm,rightMargin=1.9*cm,topMargin=2.1*cm,bottomMargin=1.9*cm,title='VulnMiner · SEMMA con datasets públicos',author='DavidPilaguano')
    doc.build(story,onFirstPage=furniture,onLaterPages=furniture)
    (ROOT/'docs/informe_tecnico.md').write_text('\n'.join(markdown),encoding='utf-8',newline='\n')
    print('Informe editorial generado:',target,flush=True)


if __name__=='__main__':
    report()
