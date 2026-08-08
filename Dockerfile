# =============================================================================
# Stage 1 — build the Go-based scanners at pinned versions.
# Compiling here (rather than downloading arch-specific release zips) means the
# binaries are built for whatever platform you build the image on — no amd64 vs
# arm64 juggling between your Mac Silicon and a linux/amd64 CI host. CGO_ENABLED=0
# makes them fully static, so they run in the slim final image unchanged.
# =============================================================================
FROM golang:1.25-bookworm AS tools
ENV CGO_ENABLED=0
# GOTOOLCHAIN=auto lets `go install` pull a newer Go toolchain if a pinned tool
# needs one (nuclei v3.11.0 requires >= 1.25.7), instead of hard-failing.
ENV GOTOOLCHAIN=auto

# Versions pinned to what the scanners were validated against.
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.0 \
 && go install -v github.com/owasp-amass/amass/v5/cmd/amass@v5.1.1 \
 && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.15.0

# =============================================================================
# Stage 2 — the actual application image.
# =============================================================================
FROM python:3.11-slim

WORKDIR /app

# nmap from Debian's repos. Its -oX XML schema (xmloutputversion 1.05) has been
# stable for years, so the repo version parses identically to your local 7.95.
# ca-certificates is required for the scanners to make HTTPS calls at runtime.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy just the compiled scanner binaries from the builder stage.
COPY --from=tools /go/bin/nuclei    /usr/local/bin/nuclei
COPY --from=tools /go/bin/amass     /usr/local/bin/amass
COPY --from=tools /go/bin/subfinder /usr/local/bin/subfinder

# Copy dependency list first so Docker caches this layer
# (rebuilds are faster when you're just changing code, not dependencies)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-load nuclei templates at build time so the first scan doesn't stall
# fetching ~10k templates over the network. Remove this line if you'd rather
# keep the image small and let the first run pull them.
RUN nuclei -update-templates || true

# Copy the rest of the project
COPY . .

# Placeholder command — swap this out once orchestrator.py exists for real
CMD ["python", "--version"]