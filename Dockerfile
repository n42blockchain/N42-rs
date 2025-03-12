# syntax=docker.io/docker/dockerfile:1.7-labs
FROM lukemathwalker/cargo-chef:latest-rust-1 as chef
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config

## Builds a cargo-chef plan
#FROM chef AS planner
#COPY . .
#RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
#COPY --from=planner /app/recipe.json recipe.json

# Build profile, release by default
ARG BUILD_PROFILE=release
ENV BUILD_PROFILE=$BUILD_PROFILE

# Extra Cargo flags
ARG RUSTFLAGS=""
ENV RUSTFLAGS="$RUSTFLAGS"

# Extra Cargo features
ARG FEATURES=""
ENV FEATURES=$FEATURES

# Builds dependencies
#RUN cargo chef cook --profile $BUILD_PROFILE --features "$FEATURES" --recipe-path recipe.json

# Build application
COPY --exclude=target . .
RUN cargo build --profile $BUILD_PROFILE --features "$FEATURES" --locked --bin n42

# ARG is not resolved in COPY so we have to hack around it by copying the
# binary to a temporary location
RUN cp /app/target/$BUILD_PROFILE/n42 /app/n42

# Use Ubuntu as the release image
FROM ubuntu AS runtime
WORKDIR /app

# Copy n42 over from the build stage
COPY --from=builder /app/n42 /usr/local/bin

# Copy licenses
COPY LICENSE-* ./

EXPOSE 30303 30303/udp 9001 8545 8546
ENTRYPOINT ["/usr/local/bin/n42"]
