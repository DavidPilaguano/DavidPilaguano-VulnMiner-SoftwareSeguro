# DavidPilaguano · VulnMiner · SoftwareSeguro

Repositorio del laboratorio: [DavidPilaguano-VulnMiner-SoftwareSeguro](https://github.com/DavidPilaguano/DavidPilaguano-VulnMiner-SoftwareSeguro). Autor: **DavidPilaguano**. El programa conserva el comando `vulnminer`.

## Probar en esta computadora

Desde la carpeta del repositorio, ejecutar `./scripts/probar.ps1`. El script prepara `.venv`, instala el paquete con el modelo incluido, ejecuta las pruebas y analiza los dos proyectos de ejemplo sin reentrenar. Los reportes de esta comprobación quedan en `output/reports/prueba-local/`.

Para analizar otro proyecto después de esa preparación:

```powershell
& ./.venv/Scripts/vulnminer.exe scan 'C:\ruta\al\proyecto' --format json,html --output ./reportes
```

Herramienta CLI del laboratorio de Desarrollo de Software Seguro. Implementa SEMMA y clasificación supervisada multietiqueta para analizar microservicios Python, JavaScript y TypeScript, con reportes OWASP Top 10:2025 y OWASP API Security Top 10:2023. Se entrega el modelo entrenado: **el escaneo no reentrena**.

## Instalación y ejecución

Requisitos: Python 3.11 o posterior y pip. Verificación realizada con Python 3.14 y scikit-learn 1.8.0. Se fija la versión de scikit-learn para hacer compatible el artefacto serializado. Recomendado: entorno virtual.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[lab]"
vulnminer scan ./examples/tienda-demo --standards owasp2025,api2023 --format json,html --output ./output/reports/tienda-demo
```

Desde cualquier proyecto que el docente proporcione, después de instalar:

```powershell
cd C:\ruta\al\proyecto-microservicios
vulnminer scan . --standards owasp2025,api2023 --format json,html --output ./reportes
```

Si el ejecutable no está en PATH, usar `python -m vulnminer scan . --output ./reportes` con el mismo entorno activo. No usar continuaciones `\` de Bash en PowerShell.

También se entrega `output/packages/vulnminer_espe-1.0.0-py3-none-any.whl`, que incluye el modelo. Puede instalarse con `python -m pip install ./output/packages/vulnminer_espe-1.0.0-py3-none-any.whl`. `requirements-lock.txt` registra las versiones exactas usadas en el laboratorio; para repetir ese entorno, instalarlo antes del proyecto.

`vulnminer catalog` presenta las veinte categorías y la cobertura. `--fail-on-findings` devuelve 1 si existen hallazgos; 0 significa ejecución satisfactoria y 2 error de uso o lectura. Un código 0 no certifica seguridad.

## Entregables

| Producto | Ubicación |
|---|---|
| Código e instalación | `vulnminer/`, `pyproject.toml`, este documento |
| Dataset: 1.008 registros, 504 corregidos | `data/dataset.csv` |
| Diccionario y correspondencias | `data/diccionario.md`, `data/cwe_owasp.csv`, `docs/fuentes.md` |
| Cinco notebooks ejecutados SEMMA | `notebooks/01_sample.ipynb` a `05_assess.ipynb` |
| Modelo y pipeline TF-IDF serializados | `vulnminer/artifacts/model.joblib` |
| Estadísticas, matrices, errores y gráficos | `output/evaluation/` |
| Reportes de dos proyectos de ejemplo | `output/reports/` |
| Informe técnico | `output/pdf/informe_tecnico.pdf`, `docs/informe_tecnico.md` |
| Demostración y requisitos | `docs/demostracion.md`, `docs/trazabilidad.md` |
| Pruebas funcionales | `tests/test_vulnminer.py` |

## Reproducibilidad

```powershell
python scripts/generate_dataset.py
python scripts/train.py
python scripts/create_examples.py
python scripts/evaluate_projects.py
python scripts/build_deliverables.py
python -m unittest discover -s tests -v
```

O ejecutar `./scripts/reproduce.ps1 -Install`. Los notebooks se ejecutan desde el script de entregables. Cada notebook permite inspeccionar una fase; el de Model vuelve a entrenar y genera los artefactos de la comparación. El ajuste selecciona C/profundidad y umbral mediante validación, y después calcula prueba. La semilla es 42.

## Diseño y límites

Flujo: descubrir servicios → leer archivos → localizar operaciones sensibles → vectorizar fragmentos → predecir etiquetas con el modelo → exigir evidencia compatible → registrar hallazgos potenciales → exportar reportes. Se incluyen seis categorías generales y cuatro de API; las diez restantes se declaran no evaluadas. Consulte `docs/fuentes.md` para alcance parcial y procedencia.

El dataset es sintético; sus 84 grupos son familias artificiales. Los ejemplos no se usan para entrenamiento, pero sí para depurar y evaluar la CLI; no constituyen un ensayo ciego de producción. El enfoque es léxico, sin propagación interprocedimental de datos. TypeScript usa el extractor léxico de JavaScript y no tiene evaluación estadística independiente. Se leen Dockerfile, Compose, YAML, properties, OpenAPI y manifiestos, pero no hay análisis semántico completo ni catálogo de CVE. Un patrón desconocido puede quedar pendiente de revisión o pasar inadvertido.

La herramienta no ejecuta el código inspeccionado. Omite dependencias, binarios, enlaces simbólicos y archivos mayores a 1 MB; registra omisiones. Los reportes contienen evidencia y deben custodiarse como código fuente. El HTML escapa contenido del proyecto. El archivo joblib incluido es un artefacto confiable del proyecto; no debe reemplazarse por archivos de procedencia desconocida.

No hay LLM ni llamadas a API de IA en la aplicación. La confianza es una puntuación no calibrada; la severidad se estima por impacto del escenario y se justifica por separado. Todos los resultados requieren verificación humana.

El proyecto del docente no está presente en esta carpeta. La evaluación sobre ese proyecto y la exposición en clase son pasos externos pendientes; se entrega el comando y el guion para realizarlos.
