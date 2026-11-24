# Diccionario de datos

Codificación UTF-8, delimitador coma, encabezado y campos entrecomillados según CSV. Cada fila representa un fragmento; los saltos de línea dentro de `code` se conservan.

| Campo | Tipo | Significado |
|---|---|---|
| id | texto único | Identificador VM de registro, no de vulnerabilidad confirmada. |
| project | texto | Grupo de separación: familia propia o huella estructural pública; no equivale a un repositorio independiente. |
| family | texto / entero | Familia propia 0..5 o huella estructural pública. Cada familia queda en una sola partición. |
| scenario | texto | Escenario propio o categoría del oráculo público; no se usa como entrada predictiva. |
| language | texto | Python, JavaScript o Java. |
| code | texto | Única entrada de los vectorizadores y del clasificador. |
| vulnerable | entero 0/1 | Verdad de referencia del caso controlado. No es certeza sobre producción. |
| labels | lista JSON | Identificadores OWASP; lista vacía para ejemplos corregidos. |
| cwe | texto/vacío | Debilidad del caso vulnerable. Vacío para caso corregido. |
| source | texto | `original-controlled-v1`, `BenchmarkPython` o `BenchmarkJava`. |
| source_url | ruta | Script propio o URL al archivo público en un commit fijado. |
| split | texto | train, validation o test, fijado antes de entrenar. |
| sha256 | hexadecimal | SHA-256 del fragmento UTF-8 para auditar duplicados. |

No se consideran faltantes las etiquetas vacías y los CWE vacíos de casos corregidos. La matriz de características es dispersa, con una fila por registro de cada partición; `output/evaluation/rows_*.json` conserva su orden y `targets_*.npy` las etiquetas en el orden de `metrics.json`.

## Campos adicionales de procedencia pública

| Campo | Significado |
|---|---|
| source_commit | SHA completo del commit descargado. Vacío para el suplemento. |
| source_license | Licencia de esa fuente; no se aplica automáticamente al resto del proyecto. |
| original_cwe | CWE del escenario según el oráculo, incluso para un caso no vulnerable. |
| original_sha256 | SHA-256 del texto original leído, antes de la preparación. |

Los originales se conservan con sus avisos en data/public/. Los vacíos de estos campos en el suplemento propio son intencionales. Consulte public_manifest.json para cantidades y hashes de los oráculos.
