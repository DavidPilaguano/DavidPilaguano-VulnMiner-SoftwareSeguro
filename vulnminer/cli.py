import argparse
import json
import sys
from pathlib import Path
from . import __version__
from .catalog import catalog
from .scanner import scan
from .reporting import write_reports


def csv_choice(value, valid):
    values=value.split(',')
    if not values or any(v not in valid for v in values):
        raise argparse.ArgumentTypeError(f'Valores permitidos: {",".join(valid)}')
    return list(dict.fromkeys(values))


def main(argv=None):
    parser=argparse.ArgumentParser(prog='vulnminer',description='Analisis supervisado OWASP de microservicios. No ejecuta el codigo analizado.')
    parser.add_argument('--version',action='version',version=__version__)
    commands=parser.add_subparsers(dest='command',required=True)
    sub=commands.add_parser('scan',help='Analizar un directorio con el modelo ya entrenado')
    sub.add_argument('path',nargs='?',default='.')
    sub.add_argument('--standards',type=lambda s:csv_choice(s,['owasp2025','api2023']),default=['owasp2025','api2023'])
    sub.add_argument('--format',type=lambda s:csv_choice(s,['json','html']),default=['json','html'])
    sub.add_argument('--output',default='./reportes')
    sub.add_argument('--fail-on-findings',action='store_true',help='Finalizar con codigo 1 si hay hallazgos')
    commands.add_parser('catalog',help='Mostrar las veinte categorias y su cobertura')
    args=parser.parse_args(argv)
    if args.command=='catalog':
        print(json.dumps(catalog(),ensure_ascii=True,indent=2))
        return 0
    try:
        output=Path(args.output).resolve()
        if output==Path(args.path).resolve():
            raise ValueError('El directorio de reportes debe ser distinto del directorio analizado.')
        report=scan(args.path,args.standards,output)
        paths=write_reports(report,output,args.format)
    except (ValueError,OSError) as exc:
        print(f'Error: {exc}',file=sys.stderr)
        return 2
    print(f'VULNMINER - SECURITY SCAN\nProyecto: {report["project"]}\nMicroservicios: {len(report["services"])}\nArchivos analizados: {report["files_analyzed"]}\nHallazgos potenciales: {len(report["findings"])}')
    for f in report['findings']:
        print(f'{f["id"]} | {f["service"]} | {f["file"]}:{f["line"]} | {",".join(f["owasp_top10"]+f["owasp_api"]) or "Pendiente"} | confianza={f["confidence"]:.2f} | {f["verification_status"]}')
    for path in paths:
        print(f'Reporte: {path}')
    return 1 if args.fail_on_findings and report['findings'] else 0


if __name__=='__main__':
    raise SystemExit(main())
