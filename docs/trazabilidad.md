# Matriz de cumplimiento

| Requisito | Implementación y evidencia |
|---|---|
| RF01 | 1.008 ejemplos, 504 corregidos; generador y CSV reproducibles. |
| RF02 | Cinco notebooks ejecutados, informe y scripts SEMMA. |
| RF03 | Regresión logística y Random Forest, dos configuraciones por algoritmo y cuatro umbrales de validación. |
| RF04 | Localización léxica de operaciones, contexto y lectura de configuración; complementa al modelo. |
| RF05 | Clasificación multietiqueta y catálogo de veinte categorías; cobertura parcial explícita. |
| RF06 | Descubrimiento mediante manifiestos, Dockerfile y contextos Compose locales. |
| RF07 | Entry point `vulnminer scan .`, con modelo empaquetado. |
| RF08 | Servicio, ruta relativa, línea verificada y evidencia en cada hallazgo. |
| RF09 | JSON y HTML con filtro por microservicio. |
| RF10 | Holdout por familia, métricas multietiqueta y dos fixtures externas al entrenamiento. |

## Condiciones cuantitativas

- Dos lenguajes en el dataset: Python y JavaScript; extracción compatible con TypeScript.
- Seis categorías generales: A01, A02, A04, A05, A07, A08.
- Cuatro categorías API: API2, API7, API8, API10.
- Sin clasificador LLM ni dependencia de un SAST externo.
- CLI no necesita entrenar de nuevo; el modelo se incluye en el paquete.

## Trabajo externo pendiente

El proyecto desconocido debe ser proporcionado por el docente. Su ejecución y evaluación independiente, así como la exposición del 26 de noviembre de 2026, requieren ese material y la participación de los estudiantes. No se presenta la evaluación sintética como sustituto de esa demostración. Repositorio de entrega: https://github.com/DavidPilaguano/DavidPilaguano-VulnMoner-SoftwareSeguro. Autor identificado por el usuario: DavidPilaguano.
