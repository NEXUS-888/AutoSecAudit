FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    nmap \
    git \
    perl \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --branch 2.5.0 --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --create-home --shell /bin/bash autosec && \
    mkdir -p /app/data/reports && \
    chown -R autosec:autosec /app /opt/nikto

ENV PYTHONUNBUFFERED=1
ENV AUTOSEC_HOST=0.0.0.0
ENV AUTOSEC_MOCK_MODE=false

EXPOSE 5000

USER autosec

ENTRYPOINT ["python", "main.py"]