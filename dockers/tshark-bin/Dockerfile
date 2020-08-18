FROM meavelabs/tshark:latest as builder

FROM ubuntu:latest as binary
USER root
WORKDIR /
RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y \
    curl \
    libc-ares2 \
    libgcrypt20 \
    libglib2.0-0 \
    libpcap0.8 \
    libsodium23 \
    libssl1.1 \
    ripgrep
RUN useradd -mU appuser
USER appuser
WORKDIR /home/appuser/
COPY --from=0 /home/appuser/opt ./opt
RUN rm -v /home/appuser/opt/bin/wireshark