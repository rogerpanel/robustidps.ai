# Agent run service for the RobustIDPS web app. Build context: ./bluesec
# (docker-compose.prod.yml, service bluesec-runner).
#
# The competition's reference client is installed from its public repository
# at a pinned commit (it is not redistributed in this repository), and the
# robust agent overlay is copied into it, exactly as install.sh does for the
# command-line setup. The image is separate from the backend so its pinned
# dependencies never affect the web application.
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG REFERENCE_REPO=https://github.com/False-Positive-Community/bluesec1-agent.git
ARG REFERENCE_COMMIT=97ac8212b0e7a9f62c7e475a42e8576257064285
RUN pip install --no-cache-dir \
      "bluesec1-agent @ git+${REFERENCE_REPO}@${REFERENCE_COMMIT}" \
      "anthropic>=1.12.1,<2" "jsonschema>=4,<5" "fastapi>=0.110,<1" "uvicorn>=0.29,<1"

COPY robust /tmp/robust
RUN SITE="$(python -c 'import bluesec1_agent, os; print(os.path.dirname(bluesec1_agent.__file__))')" \
    && rm -rf "$SITE/robust" && cp -r /tmp/robust "$SITE/robust" && rm -rf /tmp/robust \
    && python -c "import bluesec1_agent.robust.cli"

WORKDIR /app
COPY runner/server.py runner/entry.py /app/
RUN useradd --create-home --uid 10001 runner && mkdir -p /runs/traces && chown -R runner /runs

# entry.py makes the shared volume writable, then drops to the `runner` user.
EXPOSE 8100
CMD ["python", "/app/entry.py"]
