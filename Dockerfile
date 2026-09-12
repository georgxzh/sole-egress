# SEP-1 harness image. Pure stdlib at runtime; no network needed to run.
FROM python:3.11-slim

WORKDIR /app
COPY . /app

# The harness runs entirely on stdlib. `cryptography` is optional (adds an
# Ed25519 identity signature); install it if the build host has network, but the
# harness runs fine without it (falls back to the hash-chain attestation).
ENV PYTHONUNBUFFERED=1

# Default: run the full two-config experiment offline and write results/.
CMD ["python", "sole_verify/sole_verify.py", "run", "--local"]
