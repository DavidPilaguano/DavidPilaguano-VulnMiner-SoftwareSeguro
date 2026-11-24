# Datos de terceros y atribución

Los archivos de OWASP Benchmark se distribuyen como una colección de datos de investigación, con licencia y procedencia por fuente. No se presentan como código original de VulnMiner ni se les asigna una licencia común incompatible.

## OWASP Benchmark for Python

- Repositorio: https://github.com/OWASP-Benchmark/BenchmarkPython
- Commit: `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`.
- Licencia declarada: GNU GPL versión 3 (`GPL-3.0-only`).
- El aviso de los archivos identifica el proyecto OWASP Benchmark y al autor Theo Cartsonis, 2025.
- Licencia íntegra: `data/public/BenchmarkPython/LICENSE`.
- Originales sin modificar con sus avisos: `data/public/BenchmarkPython/original_sources.jsonl.gz`.
- Oráculo: `expectedresults-0.1.csv`, conservado en esa carpeta.

## OWASP Benchmark for Java

- Repositorio: https://github.com/OWASP-Benchmark/BenchmarkJava
- Commit: `10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17`.
- Licencia declarada: GNU GPL versión 2 (`GPL-2.0-only`).
- El aviso de los archivos identifica el proyecto OWASP Benchmark y al autor Dave Wichers, 2015.
- Licencia íntegra: `data/public/BenchmarkJava/LICENSE`.
- Originales sin modificar con sus avisos: `data/public/BenchmarkJava/original_sources.jsonl.gz`.
- Oráculo: `expectedresults-1.2.csv`, conservado en esa carpeta.

## Transformaciones y distribución

`scripts/import_public_datasets.py` documenta las modificaciones al texto preparado: extracción del handler o clase, retiro de wrappers y comentarios, anonimización de identificadores de casos y rutas de categoría, deduplicación y agrupación para separar particiones. Cada fila pública conserva URL al original, commit, licencia y CWE de referencia. `prepared.csv` y las filas públicas de `data/dataset.csv` son representaciones derivadas identificables por `source`.

`examples/benchmark-holdout/` contiene una muestra de originales, conserva sus avisos y entrega la licencia correspondiente en cada servicio. Las fuentes no se ejecutan. Los avisos y licencias originales deben acompañar futuras redistribuciones de esos datos. Los nombres OWASP y Benchmark se usan para atribuir las fuentes, sin afirmar aval de la herramienta por sus autores.

Los casos propios y el código de la herramienta se distinguen mediante sus rutas y metadatos. Este archivo no cambia los derechos de esas obras ni los de las dependencias de Python.
