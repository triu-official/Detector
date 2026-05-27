#!/usr/bin/env bash
set -euo pipefail
pip-audit -r requirements.txt
bandit -q -r app
ruff check .
pytest -q
