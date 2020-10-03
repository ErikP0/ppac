FROM ubuntu AS BASE

RUN apt-get update \
    && apt-get install -y git sed curl build-essential cmake clang libclang-dev \
    && apt-get clean
# install rust
RUN curl https://sh.rustup.rs -sSf | sh  -s -- -y

WORKDIR /usr/app/
RUN git clone -b v3.0.1 https://github.com/openethereum/openethereum.git
ADD . /usr/app/secret-store

# replace some files in openethereum
RUN cp -f secret-store/configuration.rs openethereum/parity/configuration.rs
RUN cp -f secret-store/server.rs openethereum/parity/secretstore/server.rs
# point to this secret store implementation
RUN sed -i 's/parity-secretstore = { git = "https:\/\/github.com\/paritytech\/secret-store", branch = "v1.x", optional = true }/parity-secretstore = { path = "..\/secret-store",  optional = true }/' openethereum/Cargo.toml

# build
WORKDIR /usr/app/openethereum
RUN ~/.cargo/bin/cargo build --release --features "secretstore"

FROM ubuntu
COPY --from=BASE /usr/app/openethereum/target/release/openethereum /usr/app/openethereum
WORKDIR /usr/app
