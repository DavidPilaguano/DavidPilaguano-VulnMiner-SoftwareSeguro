param([switch]$Install)
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    if ($Install) {
        python -m pip install -e '.[lab]'
        if ($LASTEXITCODE -ne 0) { throw 'Fallo la instalacion' }
    }
    $steps = @('scripts/generate_dataset.py', 'scripts/train.py', 'scripts/create_examples.py', 'scripts/evaluate_projects.py', 'scripts/build_deliverables.py')
    foreach ($step in $steps) {
        python $step
        if ($LASTEXITCODE -ne 0) { throw "Fallo $step" }
    }
    python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Fallaron las pruebas' }
    python -m pip wheel . --no-deps --wheel-dir output/packages
    if ($LASTEXITCODE -ne 0) { throw 'Fallo el empaquetado' }
    python scripts/package_submission.py
    if ($LASTEXITCODE -ne 0) { throw 'Fallo la creacion del ZIP' }
} finally { Pop-Location }
