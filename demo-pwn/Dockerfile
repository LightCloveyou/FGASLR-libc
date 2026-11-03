FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY pwn.c .
COPY lib ./lib

RUN gcc pwn.c -o pwn \
    -O0 \
    -Wl,-z,relro,-z,now \
    -L./lib \
    -Wl,--dynamic-linker=/home/pwn/lib/ld-linux-x86-64.so.2 \
    -Wl,-rpath=/home/pwn/lib

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    socat coreutils gosu && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash pwn

WORKDIR /home/pwn

COPY --from=builder /build/pwn /home/pwn/pwn
COPY entrypoint.sh /entrypoint.sh
COPY lib /home/pwn/lib

RUN chmod 755 /home/pwn/pwn /entrypoint.sh && \
    chmod -R 755 /home/pwn/lib

ENV PORT=9999

EXPOSE 9999

ENTRYPOINT ["/entrypoint.sh"]
