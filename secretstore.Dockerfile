FROM rust:1.46-slim AS BASE

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y curl build-essential cmake clang libclang-dev \
    && apt-get clean
# install rust
#RUN curl https://sh.rustup.rs -sSf | sh  -s -- -y
#ENV PATH="~/.cargo/bin:${PATH}"
ADD . /usr/app/
WORKDIR /usr/app/

# build
RUN make secretstore

FROM ubuntu
COPY --from=BASE /usr/app/target/secretstore /usr/app/secretstore
WORKDIR /usr/app
