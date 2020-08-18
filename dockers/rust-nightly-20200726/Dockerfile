FROM ubuntu:latest as builder
USER root
WORKDIR /
RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y \
    bison \
    build-essential \
    clang \
    curl \
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
    ripgrep
RUN useradd -mU appuser
USER appuser
WORKDIR /home/appuser/
RUN [ "/bin/bash" , "-c" , "cd && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs >.rust.sh && \
    sh .rust.sh -y && rm -v .rust.sh && source $HOME/.cargo/env && \
    rustup install nightly-2020-07-26 && \
    rustup default nightly-2020-07-26 && \
    cargo install bindgen && \
    echo >>.bashrc && echo 'source $HOME/.cargo/env' >>.bashrc" ]