param([string]$Proyecto)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Push-Location $taskRoot
try {
    if (-not (Test-Path -LiteralPath '.venv/Scripts/python.exe')) {
        python -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear el entorno virtual' }
    }
    $taskPython = Join-Path $taskRoot '.venv/Scripts/python.exe'
    & $taskPython -m pip install -e .
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo instalar VulnMiner' }
    & $taskPython -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Fallaron las pruebas' }
    foreach ($demo in @('tienda-demo', 'logistica-demo')) {
        & $taskPython -m vulnminer scan "examples/$demo" --standards owasp2025,api2023 --format json,html --output "output/reports/prueba-local/$demo"
        if ($LASTEXITCODE -ne 0) { throw "Fallo el escaneo de $demo" }
    }
    if ($Proyecto) {
        & $taskPython -m vulnminer scan $Proyecto --format json,html --output 'output/reports/proyecto-docente'
        if ($LASTEXITCODE -ne 0) { throw 'Fallo el escaneo del proyecto indicado' }
    }
    Write-Host 'Pruebas completadas. Abra los archivos analisis.html de output/reports/prueba-local/.'
} finally { Pop-Location }
