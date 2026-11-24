# Diccionario de datos

Codificación UTF-8, delimitador coma, encabezado y campos entrecomillados según CSV. Cada fila representa un fragmento; los saltos de línea dentro de `code` se conservan.

| Campo | Tipo | Significado |
|---|---|---|
| id | texto único | Identificador VM de registro, no de vulnerabilidad confirmada. |
| project | texto | Grupo de origen controlado: lenguaje, escenario y familia. No es un repositorio público. |
| family | entero 0..5 | Familia de implementación. 0..3 entrenamiento, 4 validación, 5 prueba. |
| scenario | texto | sql, crypto, debug, jwt, ssrf, deserialize o tls; no se usa como entrada predictiva. |
| language | texto | Python o JavaScript. |
| code | texto | Única entrada de los vectorizadores y del clasificador. |
| vulnerable | entero 0/1 | Verdad de referencia del caso controlado. No es certeza sobre producción. |
| labels | lista JSON | Identificadores OWASP; lista vacía para ejemplos corregidos. |
| cwe | texto/vacío | Debilidad del caso vulnerable. Vacío para caso corregido. |
| source | texto | `original-controlled-v1`, procedencia sintética explícita. |
| source_url | ruta | Script reproducible de procedencia. |
| split | texto | train, validation o test, fijado antes de entrenar. |
| sha256 | hexadecimal | SHA-256 del fragmento UTF-8 para auditar duplicados. |

No se consideran faltantes las etiquetas vacías y los CWE vacíos de casos corregidos. La matriz de características es dispersa, con una fila por registro de cada partición; `output/evaluation/rows_*.json` conserva su orden y `targets_*.npy` las etiquetas en el orden de `metrics.json`.
