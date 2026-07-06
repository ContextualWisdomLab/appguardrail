# AppGuardrail — scan without installing anything:
#
#   docker build -t appguardrail .
#   docker run --rm -v "$PWD:/src" appguardrail scan /src
#
# Exit code 1 = deploy-blocking findings (same contract as the CLI).
FROM python:3.12-slim

# ponytail: pip install from the local source keeps the image in lockstep with
# the repo; switch to `pip install appguardrail` for a release-pinned image.
WORKDIR /app
COPY pyproject.toml README.md ./
COPY scanner/ scanner/
COPY appguardrail_core/ appguardrail_core/
RUN pip install --no-cache-dir --disable-pip-version-check .

# Non-root: scanning only needs read access to the mounted source.
RUN useradd --create-home scanner
USER scanner

WORKDIR /src
ENTRYPOINT ["appguardrail"]
CMD ["--help"]
