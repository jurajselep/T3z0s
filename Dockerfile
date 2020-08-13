FROM meavelabs/rust:nightly-20200726 as builder
USER root
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
    llvm \
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
    make prepare && make install-cmp-json-and-tshark && \
    make install" ]
USER root
RUN make sbit-for-dumpcat
