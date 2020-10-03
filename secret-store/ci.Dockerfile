# https://stackoverflow.com/questions/42130132/can-cargo-download-and-build-dependencies-without-also-building-the-application

# this container provides a rust environment where all dependencies of the project are precompiled and cached
# this reduces compile times

FROM rust:1.42-slim

# Install llvm
RUN apt-get update && apt-get install -y clang && apt-get clean

WORKDIR /usr/src

# Create blank project
RUN USER=root cargo new secret-store

# We want dependencies cached, so copy
COPY Cargo.toml /usr/src/secret-store/

WORKDIR /usr/src/secret-store

# This is a dummy build to get the dependencies cached.
RUN cargo build

