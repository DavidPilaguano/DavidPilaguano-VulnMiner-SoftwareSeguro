# Guion de demostración

1. Activar el entorno, ejecutar `vulnminer --version` y `vulnminer catalog`. Mostrar las veinte categorías y las nueve sin evaluación.
2. Abrir los notebooks en orden SEMMA. Mostrar las 4.974 filas, las dos fuentes públicas, los commits fijados y las particiones por grupos estructurales. Aclarar que Benchmark también contiene casos controlados.
3. Mostrar `output/evaluation/comparison.csv`, la selección por validación y los falsos positivos y falsos negativos del conjunto de prueba en `errors.json`.
4. Ejecutar `vulnminer scan ./examples/tienda-demo --format json,html --output ./reportes-demo`. Mostrar servicio, ruta, línea, CWE, evidencia, etiquetas, confianza, justificación y recomendación.
5. Abrir el HTML y usar el filtro de microservicio. Mostrar que los archivos `_safe` no se notifican en esta fixture y que los resultados son potenciales.
6. Repetir con `examples/logistica-demo`, que incluye TypeScript.
7. Ejecutar `python -m unittest discover -s tests -v`. La prueba con un clasificador negativo demuestra que las reglas no asignan etiquetas por sí solas.
8. Para el proyecto desconocido del docente: cambiar a su directorio raíz y ejecutar `vulnminer scan . --standards owasp2025,api2023 --format json,html --output ./reportes`.
9. Revisar manualmente una muestra de hallazgos y archivos sin hallazgos. Registrar TP, FP, FN y TN contra una verdad de referencia independiente. No declarar precisión sobre el proyecto del docente sin esa revisión.

El escaneo usa el modelo ya serializado; no ejecutar `train.py` durante el análisis del proyecto nuevo. Los ejemplos son fixtures estáticas y no servidores listos para desplegar. La presentación presencial y la validación del proyecto desconocido no pueden sustituirse por estas fixtures.

10. Mostrar `output/evaluation/public_only.json` y distinguir el experimento solo público del híbrido.
11. Mostrar `examples/benchmark-holdout` y `public_cli.json`: los originales reservados revelan falsos positivos y omisiones que no aparecen en las fixtures propias.
12. Presentar las fortalezas del informe y los dos casos reales del final como contexto, sin atribuirles resultados del escáner.
