# Small official Python image. A fixed version, so every build is the same.
FROM python:3.12.7-slim-bookworm

# Don't write .pyc files; send output straight to the logs, without buffering.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencies first: this layer is cached and only rebuilt when requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY redactor.py .
# Default rules. In Kubernetes a ConfigMap is mounted over this file.
COPY rules.yaml /etc/redactor/rules.yaml

# Run as a normal user, not root.
RUN useradd --uid 10001 --no-create-home redactor
USER 10001

EXPOSE 8080

# Service mode by default. To use the CLI instead, pass other arguments:
#   docker run -i redactor --rules /etc/redactor/rules.yaml < input.ndjson
ENTRYPOINT ["python", "redactor.py"]
CMD ["--serve", "--addr", ":8080", "--rules", "/etc/redactor/rules.yaml"]
