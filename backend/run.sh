#!/usr/bin/env bash
# services/backend/run.sh
cd backend || exit 1
python -m pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
