# Modified by Antigravity using model Gemini 3.6 Flash on 2026-08-09
# https://developers.home-assistant.io/docs/add-ons/configuration#add-on-dockerfile
# https://github.com/home-assistant/docker-base
FROM ghcr.io/home-assistant/base:latest AS builder

RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-virtualenv \
    python3-dev \
    gcc \
    build-base \
    libffi-dev \
    openssl-dev \
    git

COPY dns/requirements.txt /tmp/dns.requirements.txt
COPY admin/requirements.txt /tmp/admin.requirements.txt
COPY opencanary/dependency_patches.json /tmp/dependency_patches.json
COPY opencanary/patch_dependencies.py /tmp/patch_dependencies.py

RUN virtualenv /env
ENV PATH="/env/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r /tmp/dns.requirements.txt
RUN git clone --depth 1 https://github.com/thinkst/opencanary.git /tmp/opencanary \
    && python3 /tmp/patch_dependencies.py --target /tmp/opencanary/pyproject.toml --config /tmp/dependency_patches.json \
    && pip install --no-cache-dir /tmp/opencanary \
    && rm -rf /tmp/opencanary /tmp/patch_dependencies.py /tmp/dependency_patches.json
RUN pip install --no-cache-dir -r /tmp/admin.requirements.txt

# Stage 2: Minimal runtime image
FROM ghcr.io/home-assistant/base:latest

LABEL \
    org.opencontainers.image.title="HomeDetector" \
    org.opencontainers.image.description="Intrusion Detection add-on for Home Assistant" \
    org.opencontainers.image.source="https://github.com/linickx/HomeDetector" \
    org.opencontainers.image.licenses="MIT License"

RUN apk add --no-cache python3 bash libffi openssl

# Copy built virtualenv from builder stage
COPY --from=builder /env /env

ENV VIRTUAL_ENV="/env"
ENV PATH="/env/bin:$PATH"

# Copy App Files
RUN mkdir -p /app/static
COPY opencanary/opencanary.conf /etc/opencanaryd/opencanary.conf
COPY admin/static/ /app/static/
COPY admin/templates/* /app/templates/
COPY dns/listener.py /app/
COPY admin/web.py /app/

COPY run.sh /
RUN chmod a+x /run.sh
CMD [ "/run.sh" ]
