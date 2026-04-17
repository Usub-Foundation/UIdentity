FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu|g; s|http://security.ubuntu.com/ubuntu|https://security.ubuntu.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources \
 && printf 'Acquire::https::Verify-Peer "false";\nAcquire::https::Verify-Host "false";\n' > /etc/apt/apt.conf.d/99bootstrap-ca \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -f /etc/apt/apt.conf.d/99bootstrap-ca \
 && apt-get update \
 && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    git \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cmake -S . -B build -G Ninja \
 && cmake --build build --target UIdentity

FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu|g; s|http://security.ubuntu.com/ubuntu|https://security.ubuntu.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources \
 && printf 'Acquire::https::Verify-Peer "false";\nAcquire::https::Verify-Host "false";\n' > /etc/apt/apt.conf.d/99bootstrap-ca \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -f /etc/apt/apt.conf.d/99bootstrap-ca \
 && apt-get update \
 && apt-get install -y \
    libssl3 \
    libstdc++6 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/build/UIdentity /usr/local/bin/UIdentity

EXPOSE 22813

CMD ["/usr/local/bin/UIdentity"]
