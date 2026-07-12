# AppGuardrail — scan without installing anything:
#
#   docker build -t appguardrail .
#   docker run --rm -v "$PWD:/src" appguardrail scan /src
#
# Exit code 1 = deploy-blocking findings (same contract as the CLI).
FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf

# Run the copied source directly. This keeps the image in lockstep with the repo
# while avoiding a build-time package install command that would need hash pins.
ENV PYTHONPATH=/app
WORKDIR /app
COPY scanner/ scanner/
COPY appguardrail_core/ appguardrail_core/

# Non-root: scanning only needs read access to the mounted source.
RUN useradd --create-home scanner
USER scanner

HEALTHCHECK --interval=5m --timeout=10s --start-period=30s --retries=3 CMD python -m scanner.cli.appguardrail --help >/dev/null || exit 1

WORKDIR /src
ENTRYPOINT ["python", "-m", "scanner.cli.appguardrail"]
CMD ["--help"]
