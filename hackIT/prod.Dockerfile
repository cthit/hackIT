FROM rust:1.44.1

WORKDIR /usr/src/app

RUN apt update -y && apt upgrade -y
RUN apt install -y wait-for-it

RUN rustup default nightly
RUN cargo install cargo-watch
RUN cargo install diesel_cli --no-default-features --features postgres

ADD . .
RUN cargo build --release

CMD bash -c "wait-for-it postgresql:5432 -q -- diesel migration run && cargo run --release"
