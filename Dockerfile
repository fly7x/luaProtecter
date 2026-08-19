FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y build-essential cmake git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN git submodule update --init --recursive

RUN cmake -S . -B build -DUSE_LUAU=ON

RUN cmake --build build -j2

CMD ["./build/luaProtecter"]