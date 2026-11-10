FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
ENV ROBUSTIDPS_API_BASE="https://robustidps.ai" \
    RUNTIME_AGENT_ID="docs-qa-prod"
# ROBUSTIDPS_API_KEY MUST be injected at runtime from a secret manager
CMD ["python", "main.py"]
