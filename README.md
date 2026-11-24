# VulnMiner

VulnMiner es una herramienta de línea de comandos que identifica posibles vulnerabilidades en proyectos de microservicios y genera reportes JSON y HTML con evidencias, ubicaciones y recomendaciones.

Utiliza clasificación supervisada multietiqueta y la metodología SEMMA para reconocer patrones conforme a OWASP Top 10:2025 y OWASP API Security Top 10:2023. **El modelo entrenado está incluido: no es necesario reentrenarlo para instalar o utilizar la herramienta.**

Admite código Python y JavaScript, además de extracción léxica compatible con TypeScript. También lee configuraciones y manifiestos de servicios. Los resultados son hallazgos potenciales que requieren revisión.

## Requisitos

- Python 3.11 o posterior, con `pip` y `venv` disponibles.
- Git para clonar el repositorio, o descargar y extraer el ZIP desde GitHub.
- Conexión a Internet para instalar dependencias. El escaneo utiliza un modelo local y no requiere una API de IA.

La instalación y las pruebas se verificaron en Windows con Python 3.14 y scikit-learn 1.8.0. Se incluyen instrucciones equivalentes para Linux y macOS; esos sistemas no forman parte de la verificación realizada.

## Descargar el proyecto

```shell
git clone https://github.com/DavidPilaguano/DavidPilaguano-VulnMiner-SoftwareSeguro.git
cd DavidPilaguano-VulnMiner-SoftwareSeguro
```

Si se descargó un ZIP, abrir una terminal en la carpeta extraída que contiene `pyproject.toml`.

## Instalar y probar

Se recomienda usar un entorno virtual para separar las dependencias de otras aplicaciones. Los siguientes comandos se ejecutan desde la raíz del repositorio y no requieren activar el entorno.

### Windows · PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m vulnminer scan ./examples/tienda-demo --standards owasp2025,api2023 --format json,html --output ./reportes/tienda-demo
```

Si `python` no está disponible pero se cuenta con el lanzador de Python para Windows, usar `py -3 -m venv .venv` en el primer comando.

### Linux y macOS · Bash o Zsh

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install .
./.venv/bin/python -m vulnminer scan ./examples/tienda-demo --standards owasp2025,api2023 --format json,html --output ./reportes/tienda-demo
```

### Consultar los resultados

El ejemplo contiene dos servicios y pares de fragmentos vulnerables y corregidos. En la verificación realizada se generaron siete hallazgos potenciales. Los archivos de salida son:

- `reportes/tienda-demo/analisis.json`: resultados estructurados, evidencias y metadatos.
- `reportes/tienda-demo/analisis.html`: reporte para abrir en un navegador, con filtro por microservicio.

Las fixtures de ejemplo están destinadas al análisis estático; no son servidores preparados para desplegar. No es necesario instalar sus dependencias ni ejecutarlas.

Para probar la segunda fixture, sustituir `examples/tienda-demo` por `examples/logistica-demo` en el comando de escaneo y elegir otra carpeta de salida.

## Analizar un proyecto propio

Reemplazar la ruta de entrada por el directorio raíz del proyecto que se desea analizar. La carpeta de salida debe ser distinta de la raíz analizada.

En Windows, desde el repositorio de VulnMiner:

```powershell
.\.venv\Scripts\python.exe -m vulnminer scan "C:\ruta\al\proyecto" --standards owasp2025,api2023 --format json,html --output ./reportes/mi-proyecto
```

En Linux o macOS, desde el repositorio de VulnMiner:

```bash
./.venv/bin/python -m vulnminer scan /ruta/al/proyecto --standards owasp2025,api2023 --format json,html --output ./reportes/mi-proyecto
```

También se puede activar el entorno virtual y utilizar directamente el comando `vulnminer`. Con ese entorno activo, es posible cambiar a la raíz de cualquier proyecto y ejecutar:

```shell
vulnminer scan . --standards owasp2025,api2023 --format json,html --output ./reportes
```

## Comandos y opciones

| Comando u opción | Función |
|---|---|
| `vulnminer --help` | Mostrar la ayuda general. |
| `vulnminer --version` | Consultar la versión instalada. |
| `vulnminer catalog` | Mostrar las veinte categorías y su cobertura declarada. |
| `vulnminer scan RUTA` | Analizar un directorio con el modelo incluido. |
| `--standards owasp2025,api2023` | Seleccionar uno o ambos estándares. |
| `--format json,html` | Generar uno o ambos formatos. |
| `--output RUTA` | Seleccionar la carpeta de reportes. |
| `--fail-on-findings` | Devolver código 1 si se generan hallazgos. |

Sin un entorno activado, sustituir `vulnminer` por `.\.venv\Scripts\python.exe -m vulnminer` en Windows o `./.venv/bin/python -m vulnminer` en Linux/macOS, desde la raíz de este repositorio.

Los códigos de salida son 0 para ejecución satisfactoria, 1 para hallazgos cuando se solicita `--fail-on-findings` y 2 para errores de uso o lectura. Una ejecución satisfactoria no certifica la seguridad del proyecto.

## Ejecutar las pruebas

Después de instalar, desde la raíz del repositorio:

```powershell
# Windows
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

```bash
# Linux y macOS
./.venv/bin/python -m unittest discover -s tests -v
```

La suite contiene diez pruebas funcionales sobre cobertura, ubicaciones, pares corregidos, clasificación, abstención, configuración, reportes y separación de datos.

En Windows también se dispone de un asistente de preparación y prueba:

```powershell
.\scripts\probar.ps1
```

Este prepara el entorno, instala el proyecto, ejecuta las pruebas y analiza las dos fixtures. Sus reportes quedan en `output/reports/prueba-local/`.

## Instalar desde el paquete distribuible

El archivo `output/packages/vulnminer_espe-1.0.0-py3-none-any.whl` incluye el programa y el modelo entrenado. Se puede instalar en un entorno Python compatible mediante:

```shell
python -m pip install ./output/packages/vulnminer_espe-1.0.0-py3-none-any.whl
```

En este comando, `python` debe corresponder al entorno en el que se desea instalar. Una vez instalado el paquete, no es necesario conservar el clon para ejecutar el programa.

## Desarrollo y reproducción de los experimentos

Para modificar el código, entrenar modelos o ejecutar los notebooks, instalar las dependencias adicionales en el entorno elegido:

```shell
python -m pip install -e ".[lab]"
```

Después, desde la raíz del repositorio y utilizando ese mismo entorno:

```shell
python scripts/generate_dataset.py
python scripts/train.py
python scripts/create_examples.py
python scripts/evaluate_projects.py
python scripts/build_deliverables.py
python -m unittest discover -s tests -v
```

Estos comandos regeneran datos, modelos y resultados. `build_deliverables.py` ejecuta los cinco notebooks; el de Model vuelve a entrenar. La selección utiliza F1 macro de validación antes de evaluar prueba, con semilla 42. En Windows, `scripts/reproduce.ps1 -Install` automatiza la reproducción y el empaquetado.

`requirements-lock.txt` registra las versiones directas usadas para generar los entregables originales. Su disponibilidad puede depender de la versión de Python y del sistema operativo. Para el uso habitual basta con `pip install .`; scikit-learn se fija en 1.8.0 para mantener la compatibilidad del modelo serializado.

## Contenido del repositorio

| Recurso | Ubicación |
|---|---|
| Aplicación CLI | [`vulnminer/`](vulnminer/) |
| Dataset: 1.008 registros, 504 corregidos | [`data/dataset.csv`](data/dataset.csv) |
| Diccionario de datos | [`data/diccionario.md`](data/diccionario.md) |
| Fuentes y correspondencias CWE–OWASP | [`docs/fuentes.md`](docs/fuentes.md), [`data/cwe_owasp.csv`](data/cwe_owasp.csv) |
| Cinco notebooks SEMMA ejecutados | [`notebooks/`](notebooks/) |
| Modelo y pipeline serializados | [`vulnminer/artifacts/`](vulnminer/artifacts/) |
| Métricas, matrices y gráficos | [`output/evaluation/`](output/evaluation/) |
| Proyectos de ejemplo | [`examples/`](examples/) |
| Reportes de referencia | [`output/reports/`](output/reports/) |
| Informe técnico | [`output/pdf/informe_tecnico.pdf`](output/pdf/informe_tecnico.pdf) |
| Pruebas funcionales | [`tests/test_vulnminer.py`](tests/test_vulnminer.py) |
| Entrega empaquetada | [`output/entrega_vulnminer.zip`](output/entrega_vulnminer.zip) |

## Alcance y limitaciones

El dataset es sintético: sus 84 grupos son familias artificiales. Las fixtures se usan para evaluación funcional y depuración; no constituyen un ensayo ciego de producción. La cobertura es parcial: seis categorías generales y cuatro de API, dentro de siete escenarios. Las diez categorías restantes se declaran no evaluadas en el catálogo.

El análisis es léxico y local, sin propagación interprocedimental de datos ni comprobación de explotabilidad. TypeScript comparte el extractor de JavaScript y no tiene evaluación estadística independiente. Se leen Dockerfile, Compose, YAML, properties, OpenAPI y manifiestos, pero no se realiza un análisis semántico completo ni una consulta a bases de CVE. Un patrón desconocido puede quedar pendiente de revisión o pasar inadvertido.

La herramienta no ejecuta el código inspeccionado. Omite dependencias, binarios, enlaces simbólicos y archivos mayores a 1 MB, y registra las omisiones. Los reportes contienen evidencia del código y deben custodiarse como el código fuente. El HTML escapa el contenido analizado.

No hay LLM ni llamadas a API de IA en la aplicación. Las puntuaciones no están calibradas como probabilidades de explotación; la severidad se estima por el impacto del escenario y se justifica por separado. Todos los hallazgos requieren verificación humana. El modelo joblib distribuido debe conservar su procedencia confiable.

## Autor y contexto

Proyecto académico de Desarrollo de Software Seguro de la Universidad de las Fuerzas Armadas ESPE, desarrollado bajo la metodología SEMMA. Autor: [DavidPilaguano](https://github.com/DavidPilaguano).
