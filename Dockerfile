FROM python:3.8

WORKDIR /app

COPY requirements.txt .
COPY vulnerabilities_scanner.py .

RUN pip install --no-cache-dir -r requirements.txt
