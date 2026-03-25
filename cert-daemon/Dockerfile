FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends gcc libffi-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY daemon/ ./daemon/
COPY schemas/ ./schemas/

RUN useradd -r -s /bin/false certd
USER certd

EXPOSE 8080
CMD ["python", "-m", "daemon.main"]
