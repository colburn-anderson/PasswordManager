#!/usr/bin/env bash
set -e

# 1) Create venv if missing
if [ ! -d venv ]; then
  echo "Creating virtual environment…"
  python3 -m venv venv
fi

# 2) Activate & install deps if needed
source venv/bin/activate
if [ ! -f venv/installed.flag ]; then
  echo "Installing dependencies…"
  pip install -r requirements.txt
  touch venv/installed.flag
fi

# 3) Launch the app
python main.py
