# -------------------- BASE IMAGE --------------------
FROM python:3.12-slim

# Use bash explicitly (fix for missing /bin/sh)
SHELL ["/usr/bin/bash", "-c"]


# -------------------- ENV SETUP --------------------
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/root/.local/bin:$PATH"

# -------------------- SYSTEM DEPENDENCIES --------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    wget \
    gnupg \
    unzip \
    git \
    ca-certificates \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# -------------------- UV SETUP --------------------
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && mv /root/.local/bin/uv /usr/local/bin/uv \
    && mv /root/.local/bin/uvx /usr/local/bin/uvx

# -------------------- TRIVY SETUP --------------------
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh \
    && mv ./bin/trivy /usr/local/bin/trivy \
    && rm -rf ./bin

# -------------------- WORKDIR & COPY --------------------
WORKDIR /app
COPY . /app

# -------------------- PYTHON DEPENDENCIES --------------------
RUN pip install --no-cache-dir fastapi uvicorn pydantic

# If you have requirements.txt, use this instead:
# RUN pip install --no-cache-dir -r requirements.txt

# -------------------- EXPOSE PORT --------------------
EXPOSE 5000

# -------------------- START FASTAPI SERVER --------------------
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000", "--reload"]
