"""Archivo portable de entrega, sin entornos virtuales ni caches."""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT=Path(__file__).resolve().parents[1]
INCLUDE=['README.md','pyproject.toml','requirements-lock.txt','.gitignore','.gitattributes','Modelo_mineria_datos.pdf','vulnminer','scripts','tests','data','docs','notebooks','examples','output/evaluation','output/reports','output/pdf','output/packages']


def package():
    dest=ROOT/'output'/'entrega_vulnminer.zip'
    files=[]
    for item in INCLUDE:
        path=ROOT/item
        candidates=list(path.rglob('*')) if path.is_dir() else [path]
        files.extend(p for p in candidates if p.is_file() and '__pycache__' not in p.parts and '.ipynb_checkpoints' not in p.parts and p.suffix!='.pyc')
    manifest={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
    with zipfile.ZipFile(dest,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for path in files:
            archive.write(path,path.relative_to(ROOT).as_posix())
        archive.writestr('MANIFEST_SHA256.json',json.dumps(manifest,indent=2))
    with zipfile.ZipFile(dest) as archive:
        assert archive.testzip() is None
    print(f'Entrega: {dest} | {len(files)} archivos | {dest.stat().st_size} bytes')


if __name__=='__main__':
    package()
