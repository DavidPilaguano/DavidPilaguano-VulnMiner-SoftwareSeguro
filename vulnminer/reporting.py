import html
import json
from pathlib import Path


def write_reports(report, output, formats):
    output=Path(output)
    output.mkdir(parents=True,exist_ok=True)
    results=[]
    if 'json' in formats:
        p=output/'analisis.json'
        p.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        results.append(p)
    if 'html' in formats:
        esc=lambda v:html.escape(str(v),quote=True)
        cards=[]
        for f in report['findings']:
            labels=', '.join(f['owasp_top10']+f['owasp_api']) or 'Sin categoria: pendiente de revision'
            cards.append(f'''<article data-service="{esc(f['service'])}"><p class="tag">{esc(f['id'])} / {esc(f['service'])}</p><h2>{esc(f['description'])}</h2><p>{esc(f['file'])}:{f['line']} · {esc(f['language'])}</p><p><b>{esc(labels)}</b> · {esc(f['cwe'] or 'CWE sin determinar')}</p><pre>{esc(f['context'])}</pre><p>Confianza: {f['confidence']:.1%} · Severidad estimada: <b>{esc(f['severity'])}</b></p><p>{esc(f['severity_justification'])}</p><p><b>Remediacion:</b> {esc(f['recommendation'])}</p><p class="status">{esc(f['verification_status'])} · Hallazgo potencial</p></article>''')
        options=''.join(f'<option value="{esc(s["name"])}">{esc(s["name"])}</option>' for s in report['services'])
        rows=''.join(f'<tr><td>{esc(c["id"])}</td><td>{esc(c["name"])}</td><td>{esc(c["status"])}</td></tr>' for c in report['catalog'])
        warnings=''.join(f'<li>{esc(s)}</li>' for s in report['limitations'])
        document=f'''<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>VulnMiner - {esc(report['project'])}</title><style>body{{font:16px/1.6 system-ui;margin:0;background:#edf2f6;color:#172a3b}}main{{max-width:1100px;margin:auto;padding:32px}}header,article,section{{background:white;padding:26px;border-radius:12px;margin-bottom:20px}}header{{border-top:6px solid #156b82}}h1{{font-size:36px;margin:0}}h2{{font-size:22px}}.tag{{color:#156b82;font-weight:700}}pre{{background:#142c3c;color:#edf5fa;padding:18px;white-space:pre-wrap;overflow-wrap:anywhere;border-radius:8px}}.status{{color:#8b4700}}table{{border-collapse:collapse;width:100%}}td,th{{text-align:left;border-bottom:1px solid #ddd;padding:10px}}select{{padding:10px;font:inherit}}.stats{{display:flex;gap:30px;flex-wrap:wrap}}@media(max-width:600px){{main{{padding:12px}}table{{font-size:12px}}}}</style></head><body><main><header><p class="tag">ESPE / DESARROLLO DE SOFTWARE SEGURO</p><h1>VulnMiner</h1><p>Proyecto: {esc(report['project'])} · {esc(report['generated_at'])}</p><div class="stats"><b>{len(report['services'])} servicios</b><b>{report['files_analyzed']} archivos</b><b>{len(report['findings'])} hallazgos potenciales</b></div><p>Modelo: {esc(report['model']['algorithm'])}. {esc(report['model']['confidence_note'])}</p><label>Filtrar por microservicio: <select id="service"><option value="">Todos</option>{options}</select></label></header>{''.join(cards) or '<section>No se detectaron patrones respaldados. Esto no certifica seguridad.</section>'}<section><h2>Cobertura declarada</h2><table><thead><tr><th>Categoria</th><th>Nombre</th><th>Estado</th></tr></thead><tbody>{rows}</tbody></table></section><section><h2>Limitaciones</h2><ul>{warnings}</ul><p>Archivos omitidos: {len(report['skipped_files'])}. Consulte el JSON para ver el detalle.</p></section></main><script>document.getElementById('service').addEventListener('change',function(){{document.querySelectorAll('article').forEach(a=>a.hidden=this.value!==''&&a.dataset.service!==this.value)}});</script></body></html>'''
        p=output/'analisis.html'
        p.write_text(document,encoding='utf-8')
        results.append(p)
    return results
