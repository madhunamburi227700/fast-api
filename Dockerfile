# -------------------- BASE IMAGE --------------------
FROM python:3.12-slim

SHELL ["/usr/bin/bash", "-c"]

# -------------------- ENV --------------------
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    JAVA_HOME=/opt/java/openjdk \
    GOPATH=/go \
    PATH=/root/.local/bin:/opt/java/openjdk/bin:/usr/local/go/bin:/go/bin:$PATH

# -------------------- SYSTEM DEPENDENCIES --------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash curl wget unzip git ca-certificates build-essential \
    && rm -rf /var/lib/apt/lists/*

# -------------------- JAVA 19 --------------------
RUN wget -q https://github.com/adoptium/temurin19-binaries/releases/download/jdk-19.0.2%2B7/OpenJDK19U-jdk_x64_linux_hotspot_19.0.2_7.tar.gz -O /tmp/openjdk19.tar.gz \
    && mkdir -p /opt/java \
    && tar -xzf /tmp/openjdk19.tar.gz -C /opt/java \
    && mv /opt/java/jdk-19.0.2+7 /opt/java/openjdk \
    && rm /tmp/openjdk19.tar.gz

# -------------------- GO 1.24.4 --------------------
ENV GO_VERSION=1.24.4
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

# -------------------- UV --------------------
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && mv /root/.local/bin/uv /usr/local/bin/uv \
    && mv /root/.local/bin/uvx /usr/local/bin/uvx

# -------------------- TRIVY --------------------
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh \
    && mv ./bin/trivy /usr/local/bin/trivy \
    && rm -rf ./bin

# -------------------- WORKDIR --------------------
WORKDIR /app

# -------------------- COPY APP --------------------
COPY . /app

# -------------------- PYTHON DEPENDENCIES --------------------
RUN python -m pip install --upgrade pip
RUN pip install --no-cache-dir fastapi uvicorn pydantic requests

# -------------------- CREATE REQUIRED FOLDERS --------------------
RUN mkdir -p /app/maven_setup /app/jobs && chmod -R 777 /app/maven_setup /app/jobs

# -------------------- EXPOSE PORT --------------------
EXPOSE 5000

# -------------------- START APP --------------------
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000", "--reload"]
