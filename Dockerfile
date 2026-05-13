FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    nmap \
    git \
    perl \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data/reports

ENV PYTHONUNBUFFERED=1
ENV AUTOSEC_MOCK_MODE=false

EXPOSE 5000

ENTRYPOINT ["python", "main.py"]