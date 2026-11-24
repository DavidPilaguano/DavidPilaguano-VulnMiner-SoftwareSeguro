# Fuentes, procedencia y correspondencias

Consulta: 24 de noviembre de 2026. El manifiesto reproducible es `data/public_manifest.json`.

## Datos públicos descargados y utilizados

| Fuente | Versión fijada | Descargados | Retenidos | Licencia |
|---|---|---:|---:|---|
| [OWASP BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython) | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` | 1.230 | 1.230 | GPL-3.0-only |
| [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) | `10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17` | 2.740 | 2.736 | GPL-2.0-only |
| Suplemento original | `original-controlled-v1` | 1.008 | 1.008 | Casos propios |

Se descargaron **3.970** casos públicos con oráculos oficiales (`expectedresults-0.1.csv` y `expectedresults-1.2.csv`). Se excluyeron cuatro duplicados exactos del texto preparado. El corpus híbrido final tiene **4.974** registros: 3.966 públicos y 1.008 propios; 2.603 no vulnerables y 2.371 vulnerables. Estos benchmarks públicos también son **suites de casos controlados**, no muestras de incidentes reales ni de producción.

Cada fuente conserva licencia, CSV de referencia, originales sin modificar en `original_sources.jsonl.gz` y una tabla preparada. El manifiesto registra commit, SHA-256 del oráculo y del archivo original comprimido. Cada fila conserva URL al archivo en el commit, lenguaje, estado original, CWE y licencia. Los programas descargados no se ejecutaron.

[NIST SARD](https://samate.nist.gov/SARD/) permanece identificado como posible ampliación; no se incorporaron registros suyos. El entrenamiento y la clasificación no utilizan LLM; las etiquetas públicas se leen de los CSV oficiales.

## Preparación y separación

Python extrae mediante AST el cuerpo del handler POST, eliminando wrapper GET, comentarios y docstrings. Java conserva la clase relevante y auxiliares tras eliminar el wrapper GET, importaciones, encabezados y comentarios. Se eliminan identificadores BenchmarkTest y rutas con nombres de categorías. Los CWE y las etiquetas nunca son características predictivas.

Los casos públicos se agrupan por una huella estructural que ignora nombres de identificadores y valores literales. `StratifiedGroupKFold(7, shuffle=True, random_state=42)` reserva un fold para prueba y otro para validación. Las familias propias mantienen su partición previa. Totales: **3.504 entrenamiento, 735 validación y 735 prueba**. Ningún grupo se reparte entre particiones. Ambas suites aparecen en las tres particiones: no se afirma separación por repositorio ni independencia semántica total.

Los valores faltantes de CWE y las listas de etiquetas vacías en ejemplos no vulnerables son intencionales. En filas públicas `original_cwe` conserva el CWE del escenario incluso cuando el oráculo indica que no es vulnerable.

## Correspondencias públicas CWE–OWASP

Se usa la clasificación general OWASP 2025; no se deducen categorías API automáticamente a partir del CWE.

| CWE del oráculo | Categoría general | Fuente de la correspondencia |
|---|---|---|
| CWE-22, CWE-601 | A01:2025 | [A01 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/) |
| CWE-614, CWE-611 | A02:2025 | [A02 Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/) |
| CWE-327, CWE-328, CWE-330 | A04:2025 | [A04 Cryptographic Failures](https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/) |
| CWE-89, CWE-78, CWE-79, CWE-90, CWE-94, CWE-643 | A05:2025 | [A05 Injection](https://top10.owasp.org/2025/A05_2025-Injection/) |
| CWE-501 | A06:2025 | [A06 Insecure Design](https://top10.owasp.org/2025/A06_2025-Insecure_Design/) |
| CWE-502 | A08:2025 | [A08 Software or Data Integrity Failures](https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/) |

## Suplemento propio y cobertura API

Los 1.008 casos originales corresponden a siete escenarios: SQL dinámica, criptografía débil, depuración, JWT, SSRF, deserialización y TLS. Sus cuatro categorías API son **contextuales**: JWT usado para autenticar → API2; URL de un endpoint controlada externamente → API7; depuración de servicio API → API8; consumo de API externa sin validar TLS → API10. No son una correspondencia universal de CWE.

El escenario JWT utiliza CWE-347 y se etiqueta contextualmente como A07/API2 por su uso de autenticación. CWE-347 aparece en el listado oficial de A04; no se afirma que forme parte del listado oficial de A07. Los auxiliares de validación de los pares corregidos representan contratos que deben implementarse correctamente en una aplicación real.

## Alcance de los experimentos

- El modelo híbrido aprende de las dos fuentes públicas y del suplemento, con once etiquetas (siete generales y cuatro API).
- `public_model.joblib` usa solo los 3.966 casos públicos, con vocabulario propio y seis etiquetas generales. No tiene cobertura API.
- Los modelos se comparan y seleccionan con validación. El mejor candidato en prueba no reemplaza al ganador de validación.
- El F1 previo de 0,9556 pertenece a otra población, el dataset original. Se conserva como antecedente en `output/baseline_synthetic/`, no como comparación causal de mejora.
- La muestra CLI pública tiene 96 originales apartados, seleccionados del holdout. Evalúa extracción y clasificación conjunta, no un nuevo repositorio ciego de producción.

No se evalúan A03, A09 ni A10; tampoco API1, API3, API4, API5, API6 ni API9. Las categorías cubiertas tienen alcance parcial.

## Dos incidentes documentados

1. **MOVEit Transfer, 2023**: [aviso de Progress sobre CVE-2023-34362](https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023) y [CERT-EU 2023-033](https://cert.europa.eu/publications/security-advisories/2023-033/). Relación retrospectiva con SQLi/A05. VulnMiner no analizó el código de MOVEit ni demuestra detección de esa CVE.
2. **Capital One, 2019**: [comunicado del DOJ del 29 de julio de 2019](https://www.justice.gov/usao-wdwa/pr/seattle-tech-worker-arrested-data-theft-involving-large-financial-services-company). La fuente describe un WAF mal configurado. Se relaciona conceptualmente con A02; el producto no audita reglas WAF ni permisos IAM y no se afirma prevención del incidente.
