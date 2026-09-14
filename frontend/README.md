# Oxidrop frontend

The frontend is a React and TypeScript single-page application built with Vite.
It is served by the Oxidrop Rust backend in production. During development, Vite
serves the UI on port `5173` and proxies `/api` requests to the backend on
`http://127.0.0.1:3000`.

## Project structure

```text
frontend/
├── public/                  # Static assets copied to the Vite build
├── src/
│   ├── components/
│   │   ├── ui/              # Reusable UI primitives
│   │   ├── api.tsx          # Typed openapi-fetch client
│   │   ├── dashboard.tsx    # Authenticated application layout
│   │   ├── overview.tsx     # Traffic and firewall overview
│   │   ├── configuration.tsx
│   │   ├── allow-lists.tsx
│   │   ├── usermanagement.tsx
│   │   ├── logs.tsx
│   │   ├── login-form.tsx
│   │   └── change-password.tsx
│   ├── api/schema.d.ts      # Generated TypeScript types for the API
│   ├── App.tsx              # Routes and authentication state
│   ├── router.tsx           # Protected and administrator-only routes
│   ├── main.tsx             # Browser entry point
│   └── index.css            # Global styles and Tailwind imports
├── openapi.json             # API contract exported by the Rust backend
├── package.json              # Deno tasks and frontend dependencies
└── vite.config.ts           # Vite, Tailwind, and backend proxy configuration
```

## Requirements

- [Deno](https://deno.com/) with npm package compatibility
- A running Oxidrop backend on port `3000` for login and API requests

From the repository root, start the backend with:

```shell
cargo run -p oxidrop
```

Then run the frontend from `frontend/`.

### Development CORS

The backend uses a restrictive production CORS origin based on its configured
HTTP port, for example `http://127.0.0.1:3000`. The Vite development server
started by `deno task dev` runs on `http://127.0.0.1:5173`, so development
requests require the allowed origin in
[`oxidrop/src/main.rs`](../oxidrop/src/main.rs) to be changed to port `5173`.
The equivalent `localhost` origin may also be used if the browser is opened
through `http://localhost:5173`.

After changing the Rust CORS configuration, restart or freshly compile the
backend before testing. Restore the production origin and rebuild the backend
before deploying.

## Deno commands

Install or refresh dependencies from `package.json` and `deno.lock`:

```shell
deno install
```

Start the Vite development server with hot reload:

```shell
deno task dev
```

Build the production frontend into `frontend/dist/`:

```shell
deno task build
```

Preview the production build locally:

```shell
deno task preview
```

Run the linter and tests:

```shell
deno task lint
deno task test
```

Run the tests in watch mode:

```shell
deno task test:watch
```

## API client workflow

The Rust backend publishes the API contract as `openapi.json`. The frontend uses
`openapi-typescript` to generate `src/api/schema.d.ts`, and `openapi-fetch` to
make typed requests.

Regenerate the client types after changing backend routes or schemas:

```shell
deno task generate:api
```

Use the shared client for authenticated requests so the session cookie is
included:

```ts
import { client } from "./components/api.tsx";

const { response, data } = await client.GET("/api/v1/config");
if (response.ok) {
  console.log(data);
}
```

The client uses `credentials: "include"`. Login uses the session cookie returned
by the backend; do not store passwords or session tokens in localStorage.

## API endpoints

All endpoints are relative to the backend origin and use the `/api/v1` prefix.
Most endpoints require an authenticated session. Administrator-only operations
additionally require the appropriate role and permissions.

### Authentication

```text
POST   /api/v1/login
GET    /api/v1/get_user
GET    /api/v1/role_and_permissions
POST   /api/v1/change_password
GET    /api/v1/logout
```

The initial account is documented in the repository [README](../README.md). A
user who must change their password is redirected to the password-change screen
before accessing the dashboard.

### Firewall configuration and monitoring

```text
GET    /api/v1/config
POST   /api/v1/config
GET    /api/v1/config/adapters
GET    /api/v1/config/traffic
GET    /api/v1/logs
GET    /api/v1/logs/ws
```

### Allow lists and packet counters

The IPv4 and IPv6 endpoints have the same request shape, with `v4` or `v6` in
the path:

```text
GET    /api/v1/config/allow_list/v4
POST   /api/v1/config/allow_list/v4
DELETE /api/v1/config/allow_list/v4
GET    /api/v1/config/allow_list/v6
POST   /api/v1/config/allow_list/v6
DELETE /api/v1/config/allow_list/v6

GET    /api/v1/config/packet_counts/v4
DELETE /api/v1/config/packet_counts/v4
GET    /api/v1/config/packet_counts/v6
DELETE /api/v1/config/packet_counts/v6
```

### Subnet rules

```text
GET    /api/v1/config/subnet/v4
POST   /api/v1/config/subnet/v4
DELETE /api/v1/config/subnet/v4
GET    /api/v1/config/subnet/v6
POST   /api/v1/config/subnet/v6
DELETE /api/v1/config/subnet/v6
```

### User administration

These endpoints require an administrator session:

```text
GET    /api/v1/users/get_all_user
POST   /api/v1/users/create_user
PUT    /api/v1/users/modify_user
PATCH  /api/v1/users/rename_user
DELETE /api/v1/users/delete_user
```

For request and response schemas, use `openapi.json` or the generated
`src/api/schema.d.ts` rather than duplicating types in components.

## Backend integration

The Rust build embeds the contents of `frontend/dist/` into the backend binary.
The normal full validation sequence from the repository root is:

```shell
deno task generate:api
deno fmt
deno task test
deno task build
```

The repository workflow runs these frontend checks after the Rust and eBPF
checks.
