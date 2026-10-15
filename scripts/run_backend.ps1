# Starts FalkorDB (docker), seeds the demo graph if needed and runs the AegisGraph API on http://localhost:8000
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
docker compose up -d | Out-Null
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { python -m venv .venv; & $py -m pip install -r requirements.txt }
Set-Location (Join-Path $root "backend")
$health = & $py -c "from aegis import graph as g; from aegis.config import settings; print('seeded' if g.ping() and g.graph_exists(settings.prod_graph_name) else 'empty')"
if ($health -ne "seeded") { & $py -m aegis seed | Out-Null; Write-Host "seeded demo graphs" }
& $py -m aegis api --port 8000
