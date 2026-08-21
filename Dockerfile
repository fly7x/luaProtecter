FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y \
        build-essential \
        cmake \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN cmake -S . -B build -DUSE_LUAU=ON

RUN cmake --build build -j2

EXPOSE 10000

CMD ["./build/luaProtecter"]