FROM rustlang/rust:nightly-slim
RUN apt-get update && apt-get install -y libssl-dev pkg-config && apt-get clean
WORKDIR /usr/app/
