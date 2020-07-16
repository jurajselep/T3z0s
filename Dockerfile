FROM kyras/tezedge_base:latest as builder
WORKDIR /home/appuser/
COPY . .
RUN apt update && apt install -y \
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
    qttools5-dev \
    && make prepare && make build && make prepare-for-test

#FROM ubuntu:latest
#WORKDIR /home/appuser/
#COPY --from=builder /home/appuser/wireshark/run ./
#RUN apt update && apt install build-essential libssl libglib2.0 libgcrypt libc-ares libpcap bison flex qt5-default qtmultimedia5