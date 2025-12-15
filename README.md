# Full Log Fetcher — Streamlit Demo

This repository contains a small demo Streamlit app (`app.py`) that lets you upload a CSV (for example, log exports), preview it, view basic summary statistics, plot numeric columns, and download the data.

## Quick start (Windows PowerShell)

```powershell
# create and activate venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# install requirements
pip install -r requirements.txt

# run the app
streamlit run app.py
``` 

Open the URL printed in the terminal (usually http://localhost:8501).

## Features
- CSV upload (sidebar)
- Sample data generator
- Data preview and summary
- Numeric column plotting
- Download current dataframe as CSV

## Deployment
- Deploy to Streamlit Cloud: connect the repository and set the start command to `streamlit run app.py`.
- Docker / cloud platforms: containerize with a Python base image and run `streamlit run app.py --server.port $PORT`.

If you'd like, I can also add a simple Dockerfile and CI config for deployment.
