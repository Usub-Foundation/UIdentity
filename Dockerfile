FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
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

CMD ["cmake", "--build", "build", "--target", "UIdentity"]
