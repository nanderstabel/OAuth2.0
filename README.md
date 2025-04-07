# Authorization Code Flow Workspace

This project implements an **OAuth 2.0 Authorization Code Flow** with the following components:

- **Authorization Server**: Handles client registration, authorization, and token issuance.
- **Resource Server**: Protects resources and validates access tokens.
- **Client**: Simulates a client application that interacts with the Authorization Server and Resource Server.

## Prerequisites

Before running the project, ensure you have the following installed:

- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- [Rust](https://www.rust-lang.org/) (for running the client crate)

## Setup

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/nanderstabel/OAuth2.0.git
   cd OAuth2.0
   ```

2. **Ensure Required Files Exist**:
   - Place the `unsafe-private.pem` and `public.pem` files in the root of the project directory. These files are used for signing and verifying JWTs.

## Running the Docker Containers

1. **Build and Start the Containers**:
   Use Docker Compose to build and start the **Authorization Server** and **Resource Server**:

   ```bash
   docker compose up --build
   ```

2. **Verify the Services**:

   - The **Authorization Server** should be running at `http://localhost:3033`.
   - The **Resource Server** should be running at `http://localhost:3034`.

   Check the logs to ensure both services started successfully:

   ```bash
   docker compose logs
   ```

## Running the Client Crate

1. **Navigate to the Client Directory**:

   ```bash
   cd client
   ```

2. **Run the Client**:
   Use `cargo run` to execute the client crate:

   ```bash
   cargo run
   ```

3. **Expected Output**:
   The client will:

   - Register itself with the Authorization Server.
   - Obtain an authorization code.
   - Exchange the authorization code for an access token.
   - Use the access token to access a protected resource on the Resource Server.

   Example output:

   ```
   Registered Client ID: <client_id>
   Registered Client Secret: <client_secret>
   Authorization Code: <authorization_code>
   Access Token: <access_token>
   Protected Resource: Access granted to user: <client_id>
   ```

## Stopping the Containers

To stop the Docker containers, run:

```bash
docker compose down
```

## Troubleshooting

1. **Missing `unsafe-private.pem` or `public.pem`**:
   Ensure the `unsafe-private.pem` and `public.pem` files are present in the root directory. These files are required for signing and verifying JWTs.

2. **Port Conflicts**:
   If ports `3033` or `3034` are already in use, update the `docker-compose.yaml` file to use different ports.

3. **Environment Variables**:
   Ensure the `AUTHORIZATION_SERVER_URL` environment variable is correctly set in the `docker-compose.yaml` file for the **Resource Server**.

4. **Logs**:
   Check the logs for detailed error messages:
   ```bash
   docker compose logs
   ```
