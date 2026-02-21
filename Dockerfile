FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends libyara-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir yara-python || true

COPY . .

RUN python setup_sandbox.py

EXPOSE 5000

CMD ["python", "run_detector.py"]
