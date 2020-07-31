FROM meavelabs/t3z0s:rust as builder
WORKDIR /home/appuser
COPY . .
ENV SODIUM_SHARED=1
ENV SODIUM_USE_PKG_CONFIG=1
RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y \
    bison \
    build-essential \
    clang \
    cmake \
    flex \
    git \
    libc-ares-dev \
    libgcrypt-dev \
    libglib2.0-dev \
    libpcap-dev \
    libsodium-dev \
    libssl-dev \
    pkg-config \
    qtmultimedia5-dev \
    qttools5-dev
RUN [ "/bin/chown", "-R", "appuser:appuser", "." ]
USER appuser
RUN [ "/bin/bash" , "-c" , "source .cargo/env && \
    rustup install nightly && \
    rustup default nightly && \
    make prepare && \
    make install" ]
USER root
RUN make sbit-for-dumpcat