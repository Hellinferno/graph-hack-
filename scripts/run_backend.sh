#!/usr/bin/env bash
# Starts FalkorDB (docker), seeds the demo graph if needed and runs the AegisGraph API on http://localhost:8000
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
docker compose up -d >/dev/null
if [ -x ".venv/Scripts/python.exe" ]; then py=".venv/Scripts/python.exe"; elif [ -x ".venv/bin/python" ]; then py=".venv/bin/python"; else
  python3 -m venv .venv && py=".venv/bin/python" && "$py" -m pip install -r requirements.txt; fi
py="$root/$py"
cd backend
if [ "$("$py" -c "from aegis import graph as g; from aegis.config import settings; print('seeded' if g.ping() and g.graph_exists(settings.prod_graph_name) else 'empty')")" != "seeded" ]; then
  "$py" -m aegis seed >/dev/null && echo "seeded demo graphs"
fi
exec "$py" -m aegis api --port 8000
