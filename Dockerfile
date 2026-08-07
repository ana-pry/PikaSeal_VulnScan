FROM python:3.11-slim

WORKDIR /app

# Copy dependency list first so Docker caches this layer
# (rebuilds are faster when you're just changing code, not dependencies)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project
COPY . .

# Placeholder command — swap this out once orchestrator.py exists for real
CMD ["python", "--version"]