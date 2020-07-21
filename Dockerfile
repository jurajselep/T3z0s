#FROM kyras/tezedge_base:latest as builder
#WORKDIR /home/appuser/
#COPY . .
#RUN apt update && apt install -y \
#    bison \
#    build-essential \
#    clang \
#    cmake \
#    flex \
#    git \
#    libc-ares-dev \
#    libgcrypt-dev \
#    libglib2.0-dev \
#    libpcap-dev \
#    libssl-dev \
#    qtmultimedia5-dev \
#    qttools5-dev \
#    && make prepare && make build && make prepare-for-test

FROM meavelabs/t3z0s:rust as builder
WORKDIR /home/appuser/
COPY . .
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
    libssl-dev \
    qtmultimedia5-dev \
    qttools5-dev
RUN chown -R appuser:appuser .
USER appuser
RUN [ "/bin/bash" , "-c" , "source $HOME/.cargo/env && \
    rustup install nightly && \
    rustup default nightly && \
    make prepare && \
    make prepare-for-test && \
    make build" ]
USER root
RUN make sbit-for-dumpcat

#FROM ubuntu:latest
#WORKDIR /home/appuser/
#COPY --from=builder /home/appuser/wireshark/run ./
#RUN apt update && apt install build-essential libssl libglib2.0 libgcrypt libc-ares libpcap bison flex qt5-default qtmultimedia5