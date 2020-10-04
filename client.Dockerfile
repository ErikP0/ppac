FROM rustlang/rust:nightly-slim AS BASE
RUN apt-get update && apt-get install -y libssl-dev pkg-config make && apt-get clean
ADD . /usr/app/
WORKDIR /usr/app/
RUN make client

FROM debian:buster-slim
RUN apt-get update && apt-get install -y openssl && apt-get clean
COPY --from=BASE /usr/app/target/release/client /usr/app/client
WORKDIR /usr/app
