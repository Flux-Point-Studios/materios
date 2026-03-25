FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends gcc libffi-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY explorer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install materios-verify sibling package
COPY materios-verify/ /app/materios-verify/
RUN pip install --no-cache-dir /app/materios-verify/

COPY explorer/ /app/explorer/

RUN useradd -r -s /bin/false explorer
USER explorer

EXPOSE 8080
CMD ["python", "-m", "uvicorn", "explorer.app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
