FROM rust:1.85-slim-bookworm AS builder


WORKDIR /zkp-server

COPY . .

RUN apt update 
# install dependencies
RUN apt install -y protobuf-compiler 
# install protobuf compiler

RUN cargo build --release --bin server --bin client 

# build the server and client binaries

