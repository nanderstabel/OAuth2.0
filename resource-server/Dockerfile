# Use Cargo Chef to optimize Docker builds
FROM rust:1 AS chef
RUN cargo install cargo-chef
WORKDIR /app

# Stage 1: Dependency Planner
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 2: Dependency Builder
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --package resource-server

# Stage 3: Runtime Image
FROM debian:bookworm-slim AS runtime
WORKDIR /app

# Install required runtime libraries
RUN apt-get update && apt-get install -y \
    libssl-dev \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/resource-server /usr/local/bin/

# Expose the port the server runs on
EXPOSE 3034

# Set the entrypoint to the binary
ENTRYPOINT ["/usr/local/bin/resource-server"]
