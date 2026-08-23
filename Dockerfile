FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV CTF_WORKSPACE=/workspace
ENV CTF_CONFIG=/app/config/config.yaml

ARG RADARE2_VERSION=6.1.8

# Install the external analysis utilities shown by /api/tools.
# binutils provides: strings, readelf, objdump, and nm.
# upx-ucl installs /usr/bin/upx-ucl, so a compatibility symlink is
# created below because the application checks for the command `upx`.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       file \
       binutils \
       unzip \
       xxd \
       libimage-exiftool-perl \
       binwalk \
       foremost \
       tshark \
       steghide \
       upx-ucl \
       ruby \
       ruby-dev \
       git \
       build-essential \
       pkg-config \
       ca-certificates \
    && gem install zsteg --no-document \
    && ln -sf /usr/bin/upx-ucl /usr/local/bin/upx \
    && rm -rf /var/lib/apt/lists/*

# radare2/rabin2 are not shipped in Debian trixie stable, so build the
# pinned upstream release. rabin2 is installed as part of radare2.
RUN git clone --depth 1 --branch "${RADARE2_VERSION}" \
        https://github.com/radareorg/radare2.git /tmp/radare2 \
    && cd /tmp/radare2 \
    && ./configure --prefix=/usr/local \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/radare2

# Fail the image build immediately if one of the tools expected by the UI
# is unavailable. This prevents the Analysis Tools card from silently
# showing missing tools after a successful Docker build.
RUN set -eux; \
    for tool in \
        file strings xxd exiftool binwalk foremost tshark \
        radare2 rabin2 readelf objdump nm zsteg steghide upx; \
    do \
        command -v "$tool" >/dev/null; \
    done

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt

RUN pip install --no-cache-dir \
    -r /app/backend/requirements.txt

COPY . /app

RUN mkdir -p /workspace/artifacts

EXPOSE 8000

CMD [
    "uvicorn",
    "backend.main:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8000"
]
