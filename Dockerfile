FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV CTF_WORKSPACE=/workspace
ENV CTF_CONFIG=/app/config/config.yaml

ARG RADARE2_VERSION=6.1.8

# Install the external analysis utilities used by the integrated workbench.
# binutils provides: strings, readelf, objdump, and nm.
# upx-ucl installs /usr/bin/upx-ucl, so a compatibility symlink is created.
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
       ffmpeg \
       sox \
       poppler-utils \
       libarchive-tools \
       zbar-tools \
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

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt

RUN pip install --no-cache-dir \
    -r /app/backend/requirements.txt

# Fail the image build immediately if an expected analysis utility is missing.
RUN set -eux; \
    for tool in \
        file strings xxd exiftool binwalk foremost tshark \
        radare2 rabin2 readelf objdump nm zsteg steghide upx \
        ffmpeg ffprobe sox pdfinfo pdftotext pdfimages bsdtar zbarimg \
        pyinstxtractor-ng pydisasm; \
    do \
        command -v "$tool" >/dev/null; \
    done

COPY . /app

RUN mkdir -p /workspace/artifacts

EXPOSE 8000

CMD ["uvicorn", "backend.hack4gov_runtime:app", "--host", "0.0.0.0", "--port", "8000"]
