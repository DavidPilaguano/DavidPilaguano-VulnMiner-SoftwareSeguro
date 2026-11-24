# Fuentes, procedencia y correspondencias

Consulta de referencias: 24 de noviembre de 2026. El PDF de la actividad es la especificación de requisitos.

## Fuentes identificadas

- [OWASP Top 10:2025](https://top10.owasp.org/2025/): identificadores y alcance de las categorías de aplicaciones.
- [OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/): catálogo de riesgos de API.
- [OWASP Benchmark](https://owasp.org/www-project-benchmark/): suite pública de evaluación identificada como ampliación futura. **No se importaron sus registros**. No se atribuyen al proyecto resultados de Benchmark.
- [NIST SARD](https://samate.nist.gov/SARD/): repositorio público identificado para ampliar los lenguajes y escenarios. **No se importaron sus registros**.

El dataset entregado es **100 % sintético y controlado**, generado por `scripts/generate_dataset.py`. La actividad permite casos controlados. Se incluyen 84 grupos de origen artificiales, no 84 repositorios reales. Los nombres de dominios usan `.example`. Los pares corregidos representan una mitigación local bajo los contratos de sus auxiliares; no acreditan la seguridad de una aplicación completa. Los auxiliares de validación de URL deben resolver DNS, bloquear IP privadas, fijar destinos y controlar redirecciones en una implementación real.

No se utilizaron LLM, servicios remotos de inferencia ni herramientas SAST preexistentes como clasificador de la aplicación. Los modelos ejecutados son regresión logística y Random Forest de scikit-learn. La generación del dataset es determinista y está íntegramente en código.

## Relación CWE y OWASP

La tabla es una correspondencia **contextual de los escenarios**, no una equivalencia universal entre CWE y OWASP API. Un CWE aislado no demuestra que exista una API ni que se explote una vulnerabilidad.

| Escenario | CWE | OWASP 2025 | API 2023 | Justificación y referencia |
|---|---|---|---|---|
| SQL dinámica con entrada externa | CWE-89 | A05 | - | [A05 Injection](https://top10.owasp.org/2025/A05_2025-Injection/) incluye inyección SQL. |
| MD5/SHA-1 en credenciales o firmas | CWE-327 | A04 | - | [A04 Cryptographic Failures](https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/). Un hash débil para checksum no es automáticamente esta vulnerabilidad. |
| Depuración habilitada en servicio | CWE-489 | A02 | API8 | [A02](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/) incluye código de depuración activo; [API8](https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/) contempla configuración insegura de API. Requiere verificar el perfil de producción. |
| JWT aceptado sin verificar firma | CWE-347 | A07 | API2 | CWE específico de verificación de firma; la asignación a [A07](https://top10.owasp.org/2025/A07_2025-Authentication_Failures/) y [API2](https://api-security.owasp.org/editions/2023/en/0xa2-broken-authentication/) es contextual por su uso para autenticar. No se presenta CWE-347 como entrada del listado oficial de CWE de A07. |
| Solicitud a URL externa controlada por usuario | CWE-918 | A01 | API7 | [A01:2025](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/) incorpora SSRF; [API7](https://api-security.owasp.org/editions/2023/en/0xa7-server-side-request-forgery/) trata ese riesgo en API. Validar controles aguas arriba. |
| Deserialización de objetos no confiables | CWE-502 | A08 | - | [A08](https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/) trata integridad y deserialización insegura. |
| Consumo de API externa sin verificar TLS | CWE-295 | A07 | API10 | [A07](https://top10.owasp.org/2025/A07_2025-Authentication_Failures/) lista CWE-295; [API10](https://api-security.owasp.org/editions/2023/en/0xaa-unsafe-consumption-of-apis/) recomienda autenticar el transporte al consumir otras API. |

La asignación de etiquetas se aprende de los ejemplos. En inferencia se exige puntuación suficiente y evidencia de un escenario compatible. Las expresiones regulares localizan operaciones y respaldan evidencia; no pueden asignar categorías cuando se sustituye el clasificador por uno negativo (prueba automatizada).

## Muestreo y sesgos

Por cada uno de los siete escenarios y dos lenguajes se construyen seis familias de implementación, seis variantes de dominio y dos estados (vulnerable/corregido): 7 × 2 × 6 × 6 × 2 = 1.008 registros. Las variantes de una familia permanecen en una misma partición.

Se usa 66,7 % entrenamiento (672), 16,7 % validación (168) y 16,7 % prueba (168). Se aparta de la recomendación 70/15/15 para reservar familias completas: cuatro familias para entrenamiento, una para validación y una para prueba. No se dividen aleatoriamente los pares ni las variantes. La independencia es por familia de plantilla, no independencia semántica total. Se auditan duplicados exactos y duplicados tras sustituir los dominios conocidos; esa auditoría no prueba ausencia de toda similitud estructural.

El equilibrio binario es artificial (504/504); A07 tiene doble soporte al cubrir JWT y TLS. No se realiza sobremuestreo. Se usa ponderación de clases en ambos algoritmos. Las métricas no estiman el desempeño sobre la prevalencia real de vulnerabilidades.

## Categorías no evaluadas

OWASP: A03, A06, A09 y A10. API: API1, API3, API4, API5, API6 y API9. El catálogo incluye sus identificadores completos, pero no se afirma cobertura de cadenas de suministro, autorización, lógica de negocio, inventario, monitoreo ni manejo excepcional. No hay consulta a una base de CVE. Las categorías evaluadas tienen cobertura **parcial**, limitada a los siete escenarios.
