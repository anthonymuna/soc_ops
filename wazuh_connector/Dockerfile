FROM python:3.11-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl openssh-client autossh && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dc_siem.pem .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

COPY connector.py .

CMD ["./entrypoint.sh"]
