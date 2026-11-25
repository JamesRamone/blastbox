#!/usr/bin/env bash
set -euo pipefail

export PATH="/.sprite/bin:$PATH"
exec /.sprite/bin/python3 /home/sprite/blastbox-web/server.py
