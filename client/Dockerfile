FROM rustlang/rust:nightly-slim AS BASE
RUN apt-get update && apt-get install -y libssl-dev pkg-config && apt-get clean
ADD . /usr/app/client
WORKDIR /usr/app/client
RUN cargo +nightly build --release --bin client

FROM debian:buster-slim
RUN apt-get update && apt-get install -y openssl && apt-get clean
COPY --from=BASE /usr/app/client/target/release/client /usr/app/client
WORKDIR /usr/app
