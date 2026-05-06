FROM python:3.11-slim

RUN apt-get update -qq && apt-get install -y -qq \
  curl wget git nmap net-tools iputils-ping \
  openssh-client hydra \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir --timeout 120 --retries 5 \
  atomic-operator \
  requests

COPY run_atomics.py .
COPY atomics_schedule.json .

RUN mkdir -p /tmp/atomic-runner

CMD ["python", "-u", "run_atomics.py"]
