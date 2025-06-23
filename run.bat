@echo off
REM 1) Create venv if it doesn't exist
IF NOT EXIST venv (
  echo Creating virtual environment…
  python -m venv venv
)

REM 2) Activate & install deps if needed
call venv\Scripts\activate.bat
IF NOT EXIST venv\installed.flag (
  echo Installing dependencies…
  pip install -r requirements.txt
  type nul > venv\installed.flag
)

REM 3) Launch the app
python main.py
