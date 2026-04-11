FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data/reports

ENV PYTHONUNBUFFERED=1
ENV AUTOSEC_MOCK_MODE=false

EXPOSE 5000

ENTRYPOINT ["python", "main.py"]