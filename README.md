# toolkit-zero

[![Crates.io](https://img.shields.io/crates/v/toolkit-zero.svg)](https://crates.io/crates/toolkit-zero)

A feature-selective Rust utility crate. Declare only the modules your project requires via Cargo feature flags; each feature compiles exclusively the code it depends on, with no extraneous overhead.

---

<details>
<summary>Table of Contents</summary>

1\. [Overview](#overview)

2\. [Feature flags](#feature-flags)

3\. [Serialization](#serialization)

<details>
<summary>4. <a href="#socket--server">Socket — server</a></summary>

- [Plain routes](#plain-routes)
- [JSON body routes](#json-body-routes)
- [Query parameter routes](#query-parameter-routes)
- [Shared state](#shared-state)
- [Combining state with body / query](#combining-state-with-body--query)
- [Encrypted routes](#encrypted-routes)
- [Serving the server](#serving-the-server)
- [Graceful shutdown](#graceful-shutdown)
- [Background server](#background-server)
- [Building responses](#building-responses)
- [Sync handlers](#sync-handlers)
- [`#[mechanism]` attribute macro](#mechanism-attribute-macro)

</details>

<details>
<summary>5. <a href="#socket--client">Socket — client</a></summary>

- [Creating a client](#creating-a-client)
- [Plain requests](#plain-requests)
- [JSON body requests](#json-body-requests)
- [Query parameter requests](#query-parameter-requests)
- [Encrypted requests](#encrypted-requests)
- [Sync vs async sends](#sync-vs-async-sends)
- [`#[request]` attribute macro](#request-attribute-macro)

</details>

<details>
<summary>6. <a href="#location">Location</a></summary>

- [Blocking usage](#blocking-usage)
- [Async usage](#async-usage)
- [`#[browser]` attribute macro](#browser-attribute-macro)
- [Page templates](#page-templates)
- [LocationData fields](#locationdata-fields)
- [Errors](#locationerror-variants)

</details>

<details>
<summary>7. <a href="#encryption--timelock">Encryption — Timelock</a></summary>

- [Features](#timelock-features)
- [KDF presets](#kdf-presets)
- [Usage](#timelock-usage)

</details>

<details>
<summary>8. <a href="#dependency-graph--buildtimefingerprint">Dependency Graph — BuildTimeFingerprint</a></summary>

- [Sections captured](#sections-captured)
- [Setup](#setup)
- [Usage](#buildtimefingerprint-usage)
- [Debug export](#debug-export)
- [`#[dependencies]` attribute macro](#dependencies-attribute-macro)
- [Risks and considerations](#risks-and-considerations)

</details>

<details>
<summary>9. <a href="#browser--duct-tape">Browser — duct-tape</a></summary>

- [CLI launch options](#cli-launch-options)
- [Rust API — launch functions](#rust-api--launch-functions)
- [Target variants](#target-variants)
- [Programmatic control — BrowserHandle](#programmatic-control--browserhandle)
- [TabTarget](#tabtarget)
- [ThemeMode](#thememode)
- [Downloads panel](#downloads-panel)

</details>

</details>

---

## Overview

`toolkit-zero` follows a strict zero-overhead model: only the features you declare are compiled into your binary. Every module is isolated behind an independent feature gate; enabling a feature introduces exactly the dependencies that module requires — nothing more.

---

## Feature flags

| Feature | What it enables | Module exposed |
|---|---|---|
| `serialization` | ChaCha20-Poly1305 authenticated encryption — seal any struct to opaque bytes and back | `toolkit_zero::serialization` |
| `socket-server` | Typed HTTP server builder (includes `serialization`) | `toolkit_zero::socket::server` |
| `socket-client` | Typed HTTP client builder (includes `serialization`) | `toolkit_zero::socket::client` |
| `socket` | Both `socket-server` and `socket-client` | both socket sub-modules |
| `location-browser` | Browser-based geolocation (includes `socket-server`) | `toolkit_zero::location::browser` |
| `location` | Alias for `location-browser` | `toolkit_zero::location` |
| `enc-timelock-keygen-now` | Time-lock key derivation from the system clock | `toolkit_zero::encryption::timelock` |
| `enc-timelock-keygen-input` | Time-lock key derivation from a caller-supplied time | `toolkit_zero::encryption::timelock` |
| `enc-timelock-async-keygen-now` | Async variant of `enc-timelock-keygen-now` | `toolkit_zero::encryption::timelock` |
| `enc-timelock-async-keygen-input` | Async variant of `enc-timelock-keygen-input` | `toolkit_zero::encryption::timelock` |
| `encryption` | All four `enc-timelock-*` features | `toolkit_zero::encryption::timelock` |
| `dependency-graph-build` | Attach a normalised dependency-graph snapshot at build time | `toolkit_zero::dependency_graph::build` |
| `dependency-graph-capture` | Read the embedded snapshot at runtime | `toolkit_zero::dependency_graph::capture` |
| `browser` | Full-featured WebKit browser window + programmatic API + parallel downloader | `toolkit_zero::browser` |
| `backend-deps` | Re-exports all third-party deps used by each active module | `*::backend_deps` |

Add with `cargo add`:

```sh
# Serialization (ChaCha20-Poly1305) only
cargo add toolkit-zero --features serialization

# HTTP server only
cargo add toolkit-zero --features socket-server

# HTTP client only
cargo add toolkit-zero --features socket-client

# Both sides
cargo add toolkit-zero --features socket

# Geolocation (pulls in socket-server automatically)
cargo add toolkit-zero --features location

# Full time-lock encryption suite
cargo add toolkit-zero --features encryption

# Attach build-time fingerprint in build.rs
cargo add toolkit-zero --build --features dependency-graph-build

# Read build-time fingerprint at runtime
cargo add toolkit-zero --features dependency-graph-capture

# Browser (WebKit window + downloads + programmatic API)
cargo add toolkit-zero --features browser

# Re-export deps alongside socket-server
cargo add toolkit-zero --features socket-server,backend-deps
```

---

## Serialization

Feature: `serialization`

**ChaCha20-Poly1305** authenticated encryption transforms any [`bincode`](https://docs.rs/bincode)-encodable value into an opaque, authenticated byte blob. Without the correct key the ciphertext cannot be decrypted; any bit-level tampering is detected and rejected by the Poly1305 tag.

Keys are moved into `seal`/`open` and wrapped in `Zeroizing<String>` internally, wiping them from memory on drop.

**Entry points:**

| Function / Macro | Direction |
|---|---|
| `toolkit_zero::serialization::seal(&value, key)` | struct → `Vec<u8>` |
| `toolkit_zero::serialization::open::<T>(&bytes, key)` | `Vec<u8>` → struct |
| `#[serializable]` | derive `Encode+Decode` + inject `.seal()` / `::open()` |
| `#[serialize(...)]` | inline seal to a variable or file |
| `#[deserialize(...)]` | inline open from a variable blob or file |

`key` is `Option<String>`. Pass `None` to use the built-in default key.

**Types must derive `Encode` and `Decode`:**

```rust
use toolkit_zero::serialization::{seal, open, Encode, Decode};

#[derive(Encode, Decode, Debug, PartialEq)]
struct Config {
    threshold: f64,
    label: String,
}

// With the default key
let cfg = Config { threshold: 0.85, label: "prod".into() };
let blob = seal(&cfg, None).unwrap();
let back: Config = open(&blob, None).unwrap();
assert_eq!(cfg, back);

// With a custom shared key (moved in, zeroized on drop)
let blob2 = seal(&cfg, Some("my-secret".to_string())).unwrap();
let back2: Config = open(&blob2, Some("my-secret".to_string())).unwrap();
assert_eq!(cfg, back2);
```

**`#[serializable]` — inject methods directly on a struct or enum:**

```rust
use toolkit_zero::serialization::serializable;

#[serializable]
struct Config { host: String, port: u16 }

let c = Config { host: "localhost".into(), port: 8080 };
let blob = c.seal(None).unwrap();
let back = Config::open(&blob, None).unwrap();

// Per-field encrypted helpers:
#[serializable]
struct Creds {
    pub user: String,
    #[serializable(key = "field-secret")]
    pub password: String,
}
// → Creds::seal_password(&self), Creds::open_password(bytes)
```

**`#[serialize]` / `#[deserialize]` — inline seal/open as statements:**

```rust
use toolkit_zero::serialization::{serialize, deserialize};

// Variable mode
#[serialize(cfg, key = my_key)]
fn blob() -> Vec<u8> {}
// expands to: let blob: Vec<u8> = seal(&cfg, Some(my_key))?;

// File write mode
#[serialize(cfg, path = "config.bin")]
fn _() {}
// expands to: fs::write("config.bin", seal(&cfg, None)?)?;

// Deserialize from file
#[deserialize(path = "config.bin", key = my_key)]
fn cfg() -> Config {}
// expands to: let cfg: Config = open::<Config>(&fs::read("config.bin")?, Some(my_key))?;
```

---

## Socket — server

Feature: `socket-server`

A fluent, type-safe builder API for declaring and serving HTTP routes. Each route originates from a `ServerMechanism`, is optionally enriched with JSON body, query parameter, or shared-state expectations, and is finalised via `.onconnect(handler)`. Registered routes are served through a single `.await` call on the `Server`.

### Plain routes

No body and no query.  The handler receives nothing.

```rust
use toolkit_zero::socket::server::{Server, ServerMechanism, reply};

let mut server = Server::default();
server.mechanism(
    ServerMechanism::get("/health")
        .onconnect(|| async { reply!() })
);
```

All standard HTTP methods are available: `get`, `post`, `put`, `delete`, `patch`, `head`, and `options`.

### JSON body routes

Call `.json::<T>()` on the mechanism. The request body is deserialised as `T` before the handler is invoked; the handler always receives a validated, typed value. `T` must implement `serde::Deserialize`. A missing or malformed body automatically yields a `400 Bad Request` response.

```rust
use serde::Deserialize;
use toolkit_zero::socket::server::{Server, ServerMechanism, reply, Status};

#[derive(Deserialize)]
struct CreateItem { name: String }

#[derive(serde::Serialize)]
struct Item { id: u32, name: String }

let mut server = Server::default();
server.mechanism(
    ServerMechanism::post("/items")
        .json::<CreateItem>()
        .onconnect(|body: CreateItem| async move {
            let item = Item { id: 1, name: body.name };
            reply!(json => item, status => Status::Created)
        })
);
```

### Query parameter routes

Call `.query::<T>()` on the mechanism. Incoming query parameters are deserialised as `T` before the handler is invoked; the handler always receives a validated, typed value. `T` must implement `serde::Deserialize`.

**URL shape the server expects:**

```
GET /search?q=hello&page=2
```

Each field of `T` maps to one `key=value` pair.  Nested structs are not supported
by `serde_urlencoded`; keep query types flat.

```rust
use serde::Deserialize;
use toolkit_zero::socket::server::{Server, ServerMechanism, reply};

#[derive(Deserialize)]
struct SearchParams {
    q:    String,  // ?q=hello
    page: u32,     // &page=2
}

let mut server = Server::default();
server.mechanism(
    // Listens on GET /search?q=<string>&page=<u32>
    ServerMechanism::get("/search")
        .query::<SearchParams>()
        .onconnect(|params: SearchParams| async move {
            // params.q  == "hello"
            // params.page == 2
            reply!()
        })
);
```

Missing or malformed query parameters cause the server to return `400 Bad Request`
before the handler is invoked.

### Shared state

Call `.state(value)` on the mechanism. A cloned instance of the state is provided to each request handler. The state type must satisfy `Clone + Send + Sync + 'static`. Wrap mutable shared state in `Arc<Mutex<_>>` or `Arc<RwLock<_>>`.

```rust
use std::sync::{Arc, Mutex};
use serde::Serialize;
use toolkit_zero::socket::server::{Server, ServerMechanism, reply};

#[derive(Serialize, Clone)]
struct Item { id: u32, name: String }

let store: Arc<Mutex<Vec<Item>>> = Arc::new(Mutex::new(vec![]));

let mut server = Server::default();
server.mechanism(
    ServerMechanism::get("/items")
        .state(store.clone())
        .onconnect(|state: Arc<Mutex<Vec<Item>>>| async move {
            let items = state.lock().unwrap().clone();
            reply!(json => items)
        })
);
```

### Combining state with body / query

State may be combined with a body or query expectation. The call order of `.state()` and `.json()` / `.query()` is not significant; the handler always receives `(state: S, body_or_query: T)`.

```rust
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use toolkit_zero::socket::server::{Server, ServerMechanism, reply, Status};

#[derive(Deserialize)]
struct NewItem { name: String }

#[derive(Serialize, Clone)]
struct Item { id: u32, name: String }

let store: Arc<Mutex<Vec<Item>>> = Arc::new(Mutex::new(vec![]));

let mut server = Server::default();
server.mechanism(
    ServerMechanism::post("/items")
        .json::<NewItem>()
        .state(store.clone())
        .onconnect(|state: Arc<Mutex<Vec<Item>>>, body: NewItem| async move {
            let id = {
                let mut s = state.lock().unwrap();
                let id = s.len() as u32 + 1;
                s.push(Item { id, name: body.name.clone() });
                id
            };
            reply!(json => Item { id, name: body.name }, status => Status::Created)
        })
);
```

### Encrypted routes

Call `.encryption::<T>(key)` (body) or `.encrypted_query::<T>(key)` (query) on the mechanism.  Provide a `SerializationKey::Default` (built-in key) or `SerializationKey::Value("your-key")` (custom key).

Before the handler is called, the body or query is decrypted (ChaCha20-Poly1305) using the supplied key.  A wrong key, mismatched secret, or corrupt payload returns `403 Forbidden` without ever reaching the handler.  The `T` the closure receives is always a trusted, fully-decrypted value.

`T` must implement `bincode::Decode<()>`.

```rust
use bincode::{Encode, Decode};
use toolkit_zero::socket::SerializationKey;
use toolkit_zero::socket::server::{Server, ServerMechanism, reply};

#[derive(Decode)]
struct SealedRequest { value: i32 }

#[derive(Encode)]
struct SealedResponse { result: i32 }

let mut server = Server::default();
server.mechanism(
    ServerMechanism::post("/compute")
        .encryption::<SealedRequest>(SerializationKey::Default)
        .onconnect(|req: SealedRequest| async move {
            reply!(sealed => SealedResponse { result: req.value * 2 })
        })
);
```

For encrypted query parameters, the client sends `?data=<base64url>` where the value is URL-safe base64 of the ChaCha20-Poly1305-sealed struct bytes.

### Serving the server

```rust
// Bind to a specific address — runs until the process exits
server.serve(([0, 0, 0, 0], 8080)).await;
```

> **Note:** Routes are evaluated in **registration order** — the first matching route wins.
> `serve()`, `serve_with_graceful_shutdown()`, and `serve_from_listener()` all panic immediately
> if called on a `Server` with no routes registered.

### Graceful shutdown

```rust
use tokio::sync::oneshot;

let (tx, rx) = oneshot::channel::<()>();

// Shut down later by calling: tx.send(()).ok();
server.serve_with_graceful_shutdown(([127, 0, 0, 1], 8080), async move {
    rx.await.ok();
}).await;
```

To use an OS-assigned port (e.g. to know the port before the server starts):

```rust
use tokio::net::TcpListener;
use tokio::sync::oneshot;

let listener = TcpListener::bind("127.0.0.1:0").await?;
let port = listener.local_addr()?.port();

let (tx, rx) = oneshot::channel::<()>();
server.serve_from_listener(listener, async move { rx.await.ok(); }).await;
```

### Background server

Call `serve_managed(addr)` instead of `serve(addr)` to get a `BackgroundServer` handle.
The server starts immediately; the handle lets you inspect and mutate the running instance:

```rust
use toolkit_zero::socket::server::{Server, ServerMechanism, reply};
use serde::Serialize;

#[derive(Serialize)] struct Pong   { ok:  bool   }
#[derive(Serialize)] struct Status { msg: String }

#[tokio::main]
async fn main() {
    let mut server = Server::default();
    server.mechanism(
        ServerMechanism::get("/ping")
            .onconnect(|| async { reply!(json => Pong { ok: true }) })
    );

    let mut bg = server.serve_managed(([127, 0, 0, 1], 8080));
    println!("Listening on {}", bg.addr());

    // Hot-plug a new route — no restart, no port gap
    bg.mechanism(
        ServerMechanism::get("/status")
            .onconnect(|| async { reply!(json => Status { msg: "ok".into() }) })
    ).await;

    // Migrate to a different port — in-flight requests finish first
    bg.rebind(([127, 0, 0, 1], 9090)).await;
    println!("Rebound to {}", bg.addr());

    bg.stop().await;
}
```

| Method | Behaviour |
|---|---|
| `bg.addr()` | Returns the current bind address |
| `bg.mechanism(route).await` | Inserts a route into the live server — **no restart, no port gap** |
| `bg.rebind(addr).await` | Gracefully drains in-flight requests, then restarts on the new address |
| `bg.stop().await` | Sends the shutdown signal and awaits the background task |

All routes registered before `serve_managed` and those added via `bg.mechanism` are
automatically carried over when `rebind` is called.

### Building responses

Use the `reply!` macro:

| Expression | Result |
|---|---|
| `reply!()` | `200 OK` with empty body |
| `reply!(json => value)` | `200 OK` with JSON-serialised body |
| `reply!(json => value, status => Status::Created)` | `201 Created` with JSON body |
| `reply!(message => my_reply_value, status => Status::NoContent)` | custom status on any `Reply` value |
| `reply!(sealed => value)` | `200 OK` with ChaCha20-Poly1305-sealed body (`application/octet-stream`) |
| `reply!(sealed => value, key => SerializationKey::Value("k"))` | sealed with explicit key |

`Status` re-exports the most common HTTP status codes as named variants (`Status::Ok`, `Status::Created`, `Status::NoContent`, `Status::BadRequest`, `Status::Forbidden`, `Status::NotFound`, `Status::InternalServerError`).

### Sync handlers

Every route finaliser (`onconnect`) provides an `unsafe` blocking counterpart, `onconnect_sync`, for cases where an existing synchronous API cannot readily be made asynchronous. **This variant is not recommended for production traffic.**

```rust
use toolkit_zero::socket::server::{Server, ServerMechanism, reply};

let mut server = Server::default();

// SAFETY: handler is fast; no shared mutable state; backpressure applied externally
unsafe {
    server.mechanism(
        ServerMechanism::get("/ping").onconnect_sync(|| {
            reply!()
        })
    );
}
```

`unsafe` is required because `onconnect_sync` dispatches work to Tokio's blocking thread pool, which carries important caveats:

- The pool limits live OS threads to 512 (default), but the **waiting-task queue is unbounded**. Under sustained traffic, queued tasks can accumulate without bound, risking out-of-memory conditions or severe latency before any task executes.
- Panics inside the handler are silently converted to a `500 Internal Server Error` response, masking runtime errors.
- Handlers that hold a lock (e.g. `Arc<Mutex<_>>`) can stall the thread pool indefinitely under contention from concurrent blocking tasks.

`onconnect_sync` is available on every builder variant: plain, `.json`, `.query`, `.state`, and their combinations.  All have identical safety requirements.

### `#[mechanism]` attribute macro

The `#[mechanism]` attribute is a concise alternative to the builder calls above.  It replaces the decorated `async fn` in-place with the equivalent `server.mechanism(…)` statement — no separate registration step required.

```rust
use toolkit_zero::socket::server::{Server, mechanism, reply, Status};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Deserialize)]                  struct NewItem  { name: String }
#[derive(Serialize, Clone)]             struct Item     { id: u32, name: String }

#[tokio::main]
async fn main() {
    let mut server = Server::default();
    let db: Arc<Mutex<Vec<Item>>> = Arc::new(Mutex::new(vec![]));

    // No body, no state
    #[mechanism(server, GET, "/health")]
    async fn health() { reply!() }

    // JSON body
    #[mechanism(server, POST, "/items", json)]
    async fn create_item(body: NewItem) {
        reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
    }

    // State + JSON body
    #[mechanism(server, POST, "/items/add", state(db.clone()), json)]
    async fn add_item(db: Arc<Mutex<Vec<Item>>>, body: NewItem) {
        let id = db.lock().unwrap().len() as u32 + 1;
        let item = Item { id, name: body.name };
        db.lock().unwrap().push(item.clone());
        reply!(json => item, status => Status::Created)
    }

    server.serve(([127, 0, 0, 1], 8080)).await;
}
```

**Supported forms:**

| Attribute | fn parameters |
|---|---|
| `#[mechanism(server, METHOD, "/path")]` | `()` |
| `#[mechanism(server, METHOD, "/path", json)]` | `(body: T)` |
| `#[mechanism(server, METHOD, "/path", query)]` | `(params: T)` |
| `#[mechanism(server, METHOD, "/path", encrypted(key))]` | `(body: T)` |
| `#[mechanism(server, METHOD, "/path", encrypted_query(key))]` | `(params: T)` |
| `#[mechanism(server, METHOD, "/path", state(expr))]` | `(state: S)` |
| `#[mechanism(server, METHOD, "/path", state(expr), json)]` | `(state: S, body: T)` |
| `#[mechanism(server, METHOD, "/path", state(expr), query)]` | `(state: S, params: T)` |
| `#[mechanism(server, METHOD, "/path", state(expr), encrypted(key))]` | `(state: S, body: T)` |
| `#[mechanism(server, METHOD, "/path", state(expr), encrypted_query(key))]` | `(state: S, params: T)` |

The keywords after the path (`json`, `query`, `state`, `encrypted`, `encrypted_query`) may appear in any order.

---

## Socket — client

Feature: `socket-client`

A fluent, type-safe builder API for issuing HTTP requests. Construct a `Client` from a `Target`, select an HTTP method, optionally attach a body or query parameters, and call `.send().await` (async) or `.send_sync()` (blocking).

### Creating a client

```rust
use toolkit_zero::socket::client::{Client, Target};

// Async-only — safe to create inside #[tokio::main]
let client = Client::new_async(Target::Localhost(8080));

// Sync-only — must be created before entering any async runtime
let client = Client::new_sync(Target::Localhost(8080));

// Both async and blocking — must be created before entering any async runtime
let client = Client::new(Target::Localhost(8080));

// Remote target
let client = Client::new_async(Target::Remote("https://api.example.com".into()));
```

| Constructor | `.send()` async | `.send_sync()` blocking | Safe inside `#[tokio::main]` |
|---|---|---|---|
| `Client::new_async(target)` | ✓ | ✗ — panics at call site | ✓ |
| `Client::new_sync(target)` | ✗ — panics at call site | ✓ | ✗ — panics at construction |
| `Client::new(target)` | ✓ | ✓ | ✗ — panics at construction |

> **Why `Client::new()` and `Client::new_sync()` panic inside an async context:**
> `reqwest::blocking::Client` creates its own single-threaded Tokio runtime internally.
> Tokio does not allow a runtime to start while another is already running on the same thread.
> `Client::new()` proactively detects this via `tokio::runtime::Handle::try_current()` and
> panics **at construction time** with an actionable message before any field is initialised.
> `Client::new_sync()` fails the same way through `reqwest` during construction.
>
> **Guidance:**
> - Async programs (`#[tokio::main]`) — use `Client::new_async()`.
> - Synchronous programs with no runtime — use `Client::new_sync()` or `Client::new()`.
> - Programs combining a synchronous entry point with a manual `tokio::Runtime` — construct the `Client` before starting the runtime.

### Plain requests

```rust
use serde::Deserialize;

#[derive(Deserialize)]
struct Item { id: u32, name: String }

// Async
let item: Item = client.get("/items/1").send().await?;

// Sync
let item: Item = client.get("/items/1").send_sync()?;
```

All standard HTTP methods are available: `get`, `post`, `put`, `delete`, `patch`, `head`, and `options`.

### JSON body requests

Attach a request body with `.json(value)`. `value` must implement `serde::Serialize`; the response is deserialised as `R: serde::Deserialize`.

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct NewItem { name: String }

#[derive(Deserialize)]
struct Item { id: u32, name: String }

let created: Item = client
    .post("/items")
    .json(NewItem { name: "widget".into() })
    .send()
    .await?;
```

### Query parameter requests

Attach query parameters with `.query(value)`. `value` must implement
`serde::Serialize`; the fields are serialised by `serde_urlencoded` and
appended to the request URL as `?key=value&...`.

**URL the client will send:**

```
GET /items?status=active&page=1
```

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct Filter {
    status: String,  // becomes ?status=active
    page:   u32,     // becomes &page=1
}

#[derive(Deserialize)]
struct Item { id: u32, name: String }

// Sends: GET /items?status=active&page=1
let items: Vec<Item> = client
    .get("/items")
    .query(Filter { status: "active".into(), page: 1 })
    .send()
    .await?;
```

URL parameter ordering follows struct field declaration order. Nested structs are not supported by `serde_urlencoded`; keep query types flat.

### Encrypted requests

Attach a ChaCha20-Poly1305-sealed body with `.encryption(value, key)`. The body is sealed prior to transmission; the response bytes are unsealed automatically. Both the request (`T`) and response (`R`) use `bincode` encoding: `T` must implement `bincode::Encode` and `R` must implement `bincode::Decode<()`.

```rust
use bincode::{Encode, Decode};
use toolkit_zero::socket::SerializationKey;
use toolkit_zero::socket::client::ClientError;

#[derive(Encode)]
struct Req { value: i32 }

#[derive(Decode)]
struct Resp { result: i32 }

let resp: Resp = client
    .post("/compute")
    .encryption(Req { value: 21 }, SerializationKey::Default)
    .send()
    .await?;
```

For encrypted query parameters, use `.encrypted_query(value, key)`.  The params are sealed (ChaCha20-Poly1305) and sent as `?data=<base64url>`.

```rust
let resp: Resp = client
    .get("/compute")
    .encrypted_query(Req { value: 21 }, SerializationKey::Default)
    .send()
    .await?;
```

Both `.send()` and `.send_sync()` are available on encrypted builders, returning `Result<R, ClientError>`.

### Sync vs async sends

| Method | Blocks the thread | Requires constructor |
|---|---|---|
| `.send().await` | No | `Client::new_async()` **or** `Client::new()` |
| `.send_sync()` | Yes | `Client::new_sync()` **or** `Client::new()` |

Using the wrong variant panics **at the call site** with an explicit message pointing to the correct constructor:

- Calling `.send()` on a `new_sync()` client → *`"Client was created with new_sync() — call new_async() or new() to use async sends"`*
- Calling `.send_sync()` on a `new_async()` client → *`"Client was created with new_async() — call new_sync() or new() to use sync sends"`*

These call-site panics are distinct from the **construction-time** panic that `Client::new()` (and `Client::new_sync()`) raises when constructed inside an active Tokio runtime — see [Creating a client](#creating-a-client).

### `#[request]` attribute macro

The `#[request]` attribute is a concise alternative to the builder calls above.  It replaces the decorated `fn` in-place with a `let` binding that performs the HTTP request — no separate variable declaration required.  The **function name** becomes the binding name; the **return type** becomes `R` in the `.send::<R>()` turbofish.  The function body is discarded.

```rust
use toolkit_zero::socket::client::{Client, Target, request};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone)] struct Item    { id: u32, name: String }
#[derive(Serialize)]                     struct NewItem  { name: String }
#[derive(Serialize)]                     struct Filter   { page: u32 }

async fn example() -> Result<(), reqwest::Error> {
    let client = Client::new_async(Target::Localhost(8080));

    // Plain async GET
    #[request(client, GET, "/items", async)]
    async fn items() -> Vec<Item> {}

    // POST with JSON body
    #[request(client, POST, "/items", json(NewItem { name: "widget".into() }), async)]
    async fn created() -> Item {}

    // GET with query params
    #[request(client, GET, "/items", query(Filter { page: 2 }), async)]
    async fn page() -> Vec<Item> {}

    // Synchronous DELETE
    #[request(client, DELETE, "/items/1", sync)]
    fn deleted() -> Item {}

    Ok(())
}
```

**Supported forms:**

| Attribute | Generated call | Error type from `?` |
|---|---|---|
| `#[request(client, METHOD, "/path", async)]` | `.send::<R>().await?` | `reqwest::Error` |
| `#[request(client, METHOD, "/path", sync)]` | `.send_sync::<R>()?` | `reqwest::Error` |
| `#[request(client, METHOD, "/path", json(expr), async\|sync)]` | `.json(expr).send::<R>()` | `reqwest::Error` |
| `#[request(client, METHOD, "/path", query(expr), async\|sync)]` | `.query(expr).send::<R>()` | `reqwest::Error` |
| `#[request(client, METHOD, "/path", encrypted(body, key), async\|sync)]` | `.encryption(body, key).send::<R>()` | `ClientError` |
| `#[request(client, METHOD, "/path", encrypted_query(params, key), async\|sync)]` | `.encrypted_query(params, key).send::<R>()` | `ClientError` |

The return type annotation on the `fn` is **required** — omitting it is a compile error.

---

## Location

Feature: `location` (or `location-browser`)

Acquires the device's geographic coordinates by opening a locally served consent page in the system default browser. The browser requests location permission through the standard Web Geolocation API; on approval, the coordinates are submitted to the local HTTP server. The server shuts itself down once a result is received and returns the data to the caller.

No external services are contacted. All network activity is confined to `127.0.0.1`.

### Blocking usage

Compatible with both synchronous entry points and active Tokio runtimes. When invoked within an existing runtime, an OS thread is spawned to avoid nesting runtimes.

```rust
use toolkit_zero::location::browser::{__location__, PageTemplate, LocationError};

match __location__(PageTemplate::default()) {
    Ok(data) => {
        println!("Latitude:  {:.6}", data.latitude);
        println!("Longitude: {:.6}", data.longitude);
        println!("Accuracy:  {:.0} m", data.accuracy);
    }
    Err(LocationError::PermissionDenied) => eprintln!("User denied location access"),
    Err(e) => eprintln!("Error: {e}"),
}
```

### Async usage

Recommended when executing within an active Tokio runtime — eliminates the OS thread spawn required by the blocking variant.

```rust
use toolkit_zero::location::browser::{__location_async__, PageTemplate};

#[tokio::main]
async fn main() {
    match __location_async__(PageTemplate::default()).await {
        Ok(data) => println!("lat={:.6}  lon={:.6}", data.latitude, data.longitude),
        Err(e)   => eprintln!("Error: {e}"),
    }
}
```

### `#[browser]` attribute macro

The `#[browser]` macro is a concise alternative to calling `__location__` /
`__location_async__` directly. It replaces the decorated `fn` item with an
inline location-capture statement. The function **name** becomes the binding;
the `PageTemplate` is built from the macro arguments. A `?` propagates any
`LocationError` to the enclosing function.

All arguments are optional and may appear in any order:

| Argument | Type | Notes |
|---|---|---|
| `sync` | flag | Use blocking `__location__`; default is `__location_async__().await` |
| `tickbox` | flag | Use `PageTemplate::Tickbox`; incompatible with `html` |
| `title = "…"` | string literal | Tab/heading title for Default or Tickbox |
| `body = "…"` | string literal | Body paragraph text |
| `consent = "…"` | string literal | Checkbox label (Tickbox only) |
| `html = "…"` | string literal | `PageTemplate::Custom`; mutually exclusive with all other template args |

```rust
use toolkit_zero::location::browser::{browser, LocationData, LocationError};

// Async, Default template — all built-in text
async fn run1() -> Result<LocationData, LocationError> {
    #[browser]
    fn loc() {}
    Ok(loc)
}

// Async, Tickbox with consent text
async fn run2() -> Result<LocationData, LocationError> {
    #[browser(tickbox, title = "Verify Location", consent = "I agree to share my location")]
    fn loc() {}
    Ok(loc)
}

// Async, completely custom HTML page
async fn run3() -> Result<LocationData, LocationError> {
    #[browser(html = "<!DOCTYPE html><html><body><h1>Grant access</h1>{}</body></html>")]
    fn loc() {}
    Ok(loc)
}

// Blocking, custom title
fn run4() -> Result<LocationData, LocationError> {
    #[browser(sync, title = "My App")]
    fn loc() {}
    Ok(loc)
}
```

### Page templates

`PageTemplate` controls what the user sees in the browser.

| Variant | Description |
|---|---|
| `PageTemplate::Default { title, body_text }` | Clean single-button consent page. Both fields are `Option<String>` and fall back to built-in text when `None`. |
| `PageTemplate::Tickbox { title, body_text, consent_text }` | Same as `Default` but adds a checkbox the user must tick before the button activates. |
| `PageTemplate::Custom(html)` | Fully custom HTML string. Place exactly one `{}` where the capture button should appear; the required JavaScript is injected automatically. |

```rust
use toolkit_zero::location::browser::{__location__, PageTemplate};

// Custom title only
let _data = __location__(PageTemplate::Default {
    title:     Some("My App — Verify Location".into()),
    body_text: None,
});

// Tick-box consent
let _data = __location__(PageTemplate::Tickbox {
    title:        None,
    body_text:    None,
    consent_text: Some("I agree to share my location with this app.".into()),
});

// Fully custom HTML
let html = r#"<!DOCTYPE html>
<html><body>
  <h1>Grant access</h1>
  {}
</body></html>"#;
let _data = __location__(PageTemplate::Custom(html.into()));
```

### LocationData fields

| Field | Type | Description |
|---|---|---|
| `latitude` | `f64` | Decimal degrees (WGS 84) |
| `longitude` | `f64` | Decimal degrees (WGS 84) |
| `accuracy` | `f64` | Horizontal accuracy in metres (95 % confidence) |
| `altitude` | `Option<f64>` | Metres above WGS 84 ellipsoid, if available |
| `altitude_accuracy` | `Option<f64>` | Accuracy of altitude in metres, if available |
| `heading` | `Option<f64>` | Degrees clockwise from true north `[0, 360)`, or `None` if stationary |
| `speed` | `Option<f64>` | Ground speed in m/s, or `None` if unavailable |
| `timestamp_ms` | `f64` | Browser Unix timestamp in milliseconds |

### LocationError variants

| Variant | Cause |
|---|---|
| `PermissionDenied` | User denied the browser's location permission prompt |
| `PositionUnavailable` | Device cannot determine its position |
| `Timeout` | No fix within the browser's built-in 30 s timeout |
| `ServerError` | Failed to start the local HTTP server or Tokio runtime |

---

## Encryption — Timelock

Feature: `encryption` (or any `enc-timelock-*` sub-feature)

Derives a deterministic 32-byte time-locked key through a three-pass, memory-hard KDF chain:

> **Argon2id** (pass 1) → **scrypt** (pass 2) → **Argon2id** (pass 3)

The key is only reproducible at the right time with the right salts.  Paired with a passphrase (joint KDF), the search space becomes **time-window × passphrase-space** — extremely expensive to brute-force.

### Timelock features

| Feature | Sync/Async | Entry point | Path |
|---|---|---|---|
| `enc-timelock-keygen-input` | sync | `timelock(…, None)` | Encryption — derive from explicit time |
| `enc-timelock-keygen-now` | sync | `timelock(…, Some(p))` | Decryption — derive from system clock + header |
| `enc-timelock-async-keygen-input` | async | `timelock_async(…, None)` | Async encryption |
| `enc-timelock-async-keygen-now` | async | `timelock_async(…, Some(p))` | Async decryption |
| `encryption` | both | both entry points | All four paths |

### KDF presets

[`KdfPreset`](https://docs.rs/toolkit-zero) provides named parameter sets calibrated per platform:

| Preset | Peak RAM | Platform / intended use |
|---|---|---|
| `Fast` / `FastX86` | ~128 MiB | Cross-platform / x86-64 dev & CI |
| `FastArm` | ~256 MiB | Linux ARM64 dev & CI |
| `FastMac` | ~512 MiB | macOS (Apple Silicon) dev & CI |
| `Balanced` / `BalancedX86` | ~512 MiB | Cross-platform / x86-64 production |
| `BalancedArm` | ~512 MiB | Linux ARM64 production |
| `BalancedMac` | ~1 GiB | macOS (Apple Silicon) production |
| `Paranoid` / `ParanoidX86` / `ParanoidArm` | ~768 MiB | Cross-platform / x86-64 / ARM64 max security |
| `ParanoidMac` | ~3 GiB | macOS max security (requires 8+ GiB unified memory) |
| `Custom(KdfParams)` | user-defined | Fully manual — tune to your hardware |

### Timelock usage

```rust
use toolkit_zero::encryption::timelock::*;

// ── Encryption side ── caller sets the unlock time ─────────────────────────
let salts = TimeLockSalts::generate();
let kdf   = KdfPreset::BalancedMac.params();      // ~2 s on M2
let at    = TimeLockTime::new(14, 30).unwrap();
// params = None → _at (encryption) path
let enc_key = timelock(
    Some(TimeLockCadence::None),
    Some(at),
    Some(TimePrecision::Minute),
    Some(TimeFormat::Hour24),
    Some(salts.clone()),
    Some(kdf),
    None,
).unwrap();

// Pack all settings — including salts and KDF params — into a self-contained
// header.  Salts and KDF params are not secret; store the header in plaintext
// alongside the ciphertext so the decryption side can reconstruct the key.
let header = pack(TimePrecision::Minute, TimeFormat::Hour24,
                  &TimeLockCadence::None, salts, kdf);

// ── Decryption side ── re-derives from the live clock ───────────────────────
// Load header from ciphertext; call at 14:30 local time.
// params = Some(header) → _now (decryption) path
let dec_key = timelock(
    None, None, None, None, None, None,
    Some(header),
).unwrap();
assert_eq!(enc_key.as_bytes(), dec_key.as_bytes());
```

For async usage replace `timelock` with `timelock_async` and `.await` the result.
All arguments are taken by value.  Requires the matching `enc-timelock-async-keygen-*`
feature(s).

---

## Dependency Graph — BuildTimeFingerprint

Features: `dependency-graph-build` · `dependency-graph-capture`

BuildTimeFingerprint attaches a normalised, deterministic snapshot of the build environment to the compiled binary. The snapshot is written to `$OUT_DIR/fingerprint.json` at compile time and embedded via `include_str!`; no runtime I/O is required.

The two features are intentionally independent so that each can be declared in the appropriate `Cargo.toml` section.

### Sections captured

| Section | Contents |
|---|---|
| `package` | Crate name + version |
| `build` | Profile, opt-level, target triple, rustc version, active feature flags |
| `deps` | Full normalised `cargo metadata` graph — sorted, no absolute paths |
| `cargo_lock_sha256` | SHA-256 of `Cargo.lock` (comment lines stripped) |
| `source` | SHA-256 of every `.rs` file under `src/` |

### Setup

```toml
[dependencies]
toolkit-zero = { features = ["dependency-graph-capture"] }

[build-dependencies]
toolkit-zero = { features = ["dependency-graph-build"] }
```

`build.rs`:

```rust
fn main() {
    // Pass true to also export a pretty-printed copy alongside Cargo.toml.
    toolkit_zero::dependency_graph::build::generate_fingerprint(cfg!(debug_assertions))
        .expect("fingerprint generation failed");
}
```

### BuildTimeFingerprint usage

Embed and read the snapshot in your binary:

```rust
use toolkit_zero::dependency_graph::capture;

const BUILD_TIME_FINGERPRINT: &str = include_str!(concat!(env!("OUT_DIR"), "/fingerprint.json"));

fn main() {
    let data = capture::parse(BUILD_TIME_FINGERPRINT).expect("failed to parse fingerprint");

    println!("{} v{}", data.package.name, data.package.version);
    println!("profile  : {}", data.build.profile);
    println!("target   : {}", data.build.target);
    println!("rustc    : {}", data.build.rustc_version);
    println!("lock sha : {}", data.cargo_lock_sha256);

    for (file, hash) in &data.source {
        println!("{file} -> {hash}");
    }

    // raw bytes of the normalised JSON
    let raw: &[u8] = BUILD_TIME_FINGERPRINT.as_bytes();
    println!("{} bytes", raw.len());
}
```

**`BuildTimeFingerprintData` fields:**

| Field | Type | Description |
|---|---|---|
| `package.name` | `String` | Crate name |
| `package.version` | `String` | Crate version |
| `build.profile` | `String` | `"debug"` / `"release"` / … |
| `build.opt_level` | `String` | `"0"` – `"3"` / `"s"` / `"z"` |
| `build.target` | `String` | Target triple |
| `build.rustc_version` | `String` | Full `rustc --version` string |
| `build.features` | `Vec<String>` | Sorted active feature names of the crate being built |
| `cargo_lock_sha256` | `String` | Hex SHA-256 of `Cargo.lock` |
| `source` | `BTreeMap<String, String>` | `path → "sha256:<hex>"` per `.rs` file |
| `deps` | `serde_json::Value` | Full normalised `cargo metadata` graph |

### Debug export

`generate_fingerprint(true)` (or the standalone `export(true)`) writes a **pretty-printed** `fingerprint.json` alongside the crate's `Cargo.toml` for local inspection. This file is distinct from the compact version written to `$OUT_DIR`; the binary always embeds the `$OUT_DIR` copy.

Passing `true` to `generate_fingerprint` only runs `cargo metadata` **once**, which is more efficient than calling `generate_fingerprint(false)` + `export(true)` separately.

> **Add `fingerprint.json` to `.gitignore`.**  The exported file contains the full dependency graph, per-file source hashes, target triple, and compiler version. Although the contents are not secret, committing the file adds repository noise and may expose build-environment details beyond what is intended.

### `#[dependencies]` attribute macro

The `#[dependencies]` macro is a concise alternative to the `include_str!` + `capture::parse()` boilerplate. It requires the `dependency-graph-capture` feature.

Apply it to an empty `fn` inside a function body; the function name becomes the `let` binding:

```rust
use toolkit_zero::dependency_graph::capture::dependencies;

fn show() -> Result<(), Box<dyn std::error::Error>> {
    #[dependencies]          // → let data: BuildTimeFingerprintData = parse(...)?;
    fn data() {}
    println!("{} v{}", data.package.name, data.package.version);
    Ok(())
}

fn raw_bytes() -> &'static [u8] {
    #[dependencies(bytes)]   // → let raw: &'static [u8] = as_bytes(...);
    fn raw() {}
    raw
}
```

| Form | Result type | Propagates `?` |
|---|---|---|
| `#[dependencies]` | `BuildTimeFingerprintData` | yes |
| `#[dependencies(bytes)]` | `&'static [u8]` | no |

### Risks and considerations

| Concern | Detail |
|---|---|
| **Not tamper-proof** | The fingerprint is embedded as plain text in the binary's read-only data section. Anyone with access to the binary can read it. It is informational, not a security boundary. |
| **Export file exposure** | `export(true)` writes `fingerprint.json` to the crate root. Add it to `.gitignore` to prevent accidental commits. |
| **Build-time overhead** | `cargo metadata` runs on every rebuild. The `cargo:rerun-if-changed` directives restrict this to changes in `src/`, `Cargo.toml`, or `Cargo.lock` — unchanged builds do not re-run. |
| **Feature capture scope** | `build.features` captures the active features of the crate being built, not toolkit-zero's own features. |
| **Absolute-path stripping** | `workspace_root`, `manifest_path`, `src_path`, `path`, and other machine-specific fields are removed from `cargo metadata` output. The fingerprint is stable across different machines and checkout locations. |
| **Compile-time only** | The snapshot reflects the build environment at compile time. It does not update at runtime. |

---

## Backend deps

Feature: `backend-deps`

When combined with any other feature, `backend-deps` appends a `backend_deps` sub-module to each active module. Each such sub-module re-exports (via `pub use`) every third-party crate used internally by the parent module, allowing downstream crates to access those dependencies without separate `Cargo.toml` declarations.

| Module | Path | Re-exports |
|---|---|---|
| `serialization` | `toolkit_zero::serialization::backend_deps` | `bincode`, `base64`, `zeroize` |
| `socket` (server side) | `toolkit_zero::socket::backend_deps` | `bincode`, `base64`, `serde`, `tokio`, `log`, `bytes`, `serde_urlencoded`, `hyper`, `hyper_util`, `http`, `http_body_util` |
| `socket` (client side) | `toolkit_zero::socket::backend_deps` | `bincode`, `base64`, `serde`, `tokio`, `log`, `reqwest` |
| `location` | `toolkit_zero::location::backend_deps` | `tokio`, `serde`, `webbrowser`, `rand` |
| `encryption` (timelock) | `toolkit_zero::encryption::timelock::backend_deps` | `argon2`, `scrypt`, `zeroize`, `chrono`, `rand`; `tokio` (async variants only) |
| `dependency_graph` | `toolkit_zero::dependency_graph::backend_deps` | `serde_json`; `sha2` (build side only) |

Each re-export is individually gated on its parent feature; only the dependencies that are currently compiled appear in `backend_deps`. Enabling `backend-deps` without any other feature compiles successfully but exposes no symbols.

```toml
# Example: socket-server + dep re-exports
toolkit-zero = { features = ["socket-server", "backend-deps"] }
```

Then in your code:

```rust
// Access hyper directly through toolkit-zero
use toolkit_zero::socket::backend_deps::hyper;

// Access bincode through serialization
use toolkit_zero::serialization::backend_deps::bincode;
```

---

## Browser — duct-tape

Feature: `browser`

duct-tape is a full-featured, **WebKit-native** browser window built on [iced](https://github.com/iced-rs/iced) (GPU-accelerated UI) and [wry](https://github.com/tauri-apps/wry) (cross-platform WebView). It ships as a standalone binary (`duct-tape`) and as a fully programmable Rust library API, making it trivial to embed a production-grade browser into any Rust application.

The name reflects the philosophy: high-performance plumbing assembled from best-in-class components, with our own parallel download engine layered on top where the platform would otherwise bottleneck you.

---

### Native WebKit — zero rendering overhead

duct-tape delegates **all page rendering to the platform's own WebKit engine**:

| Platform | Engine | Notes |
|---|---|---|
| macOS / iOS | WebKit (`WKWebView`) | Same engine as Safari; GPU-composited, Metal-backed |
| Linux | WebKitGTK | Full WebKit2 feature set |
| Windows | WebView2 (Chromium) | Edge's embedded rendering engine |

There is no Electron, no embedded Chromium, no extra process: the OS WebView is embedded directly inside the iced window via raw window handle. This means:

- **Sub-millisecond** page-layout and compositing (platform compositor handles it)
- **Zero additional memory overhead** for the renderer — the OS engine is already in RAM
- Full hardware acceleration — CSS transitions, WebGL, Canvas, video all run at native speed
- Every future platform WebKit security patch and performance improvement is inherited automatically, with no crate update required

The iced layer handles only the **chrome** (tabs, address bar, loading indicator, panels). It never touches the rendered web content.

---

### Custom parallel download engine

By default, WebKit downloads files over a single TCP connection. duct-tape **intercepts every download** before WebKit touches it, cancels the native transfer, and routes it through our own parallel engine built on `reqwest`.

#### How it works

1. **HEAD request** — probes `Content-Length` and `Accept-Ranges: bytes` headers.
2. **Threshold check** — files below 4 MiB use a single streaming connection (HEAD overhead is not worth it).
3. **Byte-range splitting** — files ≥ 4 MiB are divided into **8 equal-size chunks**. Each chunk is fetched with its own `Range: bytes=X-Y` HTTP request, in parallel, on separate TCP connections.
4. **Streaming write** — each chunk streams directly to its slice of the output file via `.chunk()` iteration (no full-chunk buffer). Memory usage stays flat regardless of file size.
5. **Atomic rename** — while downloading, the file lives at `<name>.tkz` (preventing accidental opens). On completion it is renamed to the final path atomically.
6. **Fallback** — servers without `Accept-Ranges` fall back to a single streaming connection automatically.

#### Performance comparison

| Scenario | Single-connection (browser default) | duct-tape (8 chunks) |
|---|---|---|
| Fast CDN, per-connection rate limit (e.g. 10 MB/s) | 10 MB/s | ~80 MB/s (8× limit) |
| High-latency connection (100 ms RTT) | Limited by slow-start TCP window | 8 windows open in parallel; latency paid once |
| Local LAN / no rate limit | Near line-speed | Same or slightly faster (concurrent window ramp) |
| Server without `Accept-Ranges` | Line rate | Graceful single-connection fallback |

In real-world benchmarks on CDN-hosted files (GitHub releases, package registries, etc.) duct-tape consistently achieves **3–8× higher throughput** than a single-connection download.

#### Download resilience — stash and resume

Every in-flight download is **persisted to a stash file** (`~/toolkit-zero/.browser-stash`) the moment it starts. If the browser is closed mid-download the stash is read on the next launch and all interrupted transfers are **automatically restarted** from the beginning (byte-range resume is attempted for partially-written `.tkz` files).

#### Progress reporting

Progress flows from eight concurrent background tokio tasks through a process-global `Mutex<Vec<ProgressUpdate>>` queue. The iced Tick handler drains the queue every 16 ms (while downloads are active), applying updates directly to state so the UI paint picks them up in the same frame with no extra message-round-trip.

The downloads panel shows, per download:
- Filename and source URL
- `⬇ bytes downloaded / total size` (e.g. `⬇ 124.3 MB / 550.0 MB`)
- **Live speed indicator** (`1.5 MB/s`) computed as `Δbytes / elapsed_since_last_tick`
- **Blacklight-purple progress bar** (same colour as the window border trace)
- Action buttons: cancel (in-progress), open / reveal in Finder (completed), or clear (done)

#### Duplicate downloads

Re-clicking a link that is already being downloaded does **not** replace the existing entry. Each new click produces a new entry with a `-2`, `-3`, … suffix appended to the file stem (e.g. `archive.zip`, `archive-2.zip`, `archive-3.zip`). A 500 ms debounce window filters out WebKit's spurious double-fire of the download callback.

---

### UI features

#### Tab system

- **Floating squircle tabs** with smooth pill-style activation glow
- Per-tab independent **back / forward navigation history** — switching tabs restores the correct page without re-requesting the server
- **Two-finger horizontal swipe** on macOS triggers browser back/forward natively via WebKit
- Tab **groups** with colour-coded indicators — create, rename, assign, delete groups; members can be cycled between groups with a right-click
- Opening a new tab always loads the built-in homepage

#### Address bar and URL resolution

The address bar (and all programmatic navigate calls) apply the same resolution logic:

| Input | Result |
|---|---|
| `https://example.com` or `http://…` or `file://…` | Used verbatim |
| `rust-lang.org` (contains `.`, no spaces) | Prepended with `https://` |
| `cargo build flags` (anything else) | Google search: `https://www.google.com/search?q=cargo+build+flags` |

#### Loading indicator

A thin **perimeter-tracing line** (the "border trace" / loader) animates around the window edge while a page is loading. The line is the same blacklight purple as the progress bar. Once the page finishes loading, the line fades out smoothly.

#### Theme system

Three modes selectable per-session (not persisted across restarts yet):

| Mode | Behaviour |
|---|---|
| `ThemeMode::Light` | Always light palette |
| `ThemeMode::Dark` | Always dark palette |
| `ThemeMode::Auto` | Light from 07:00–19:00 local time; dark otherwise |

The theme is pushed into the embedded homepage via JavaScript (`window.__tkzSetTheme`) so the built-in page always matches the shell.

#### Persistent history

Every page visit is appended to `~/toolkit-zero/history.hist` (toggle-able in the UI). The history panel supports:
- Time-based deletion with a slider + `Hours / Days / Weeks / Months` unit picker
- Delete all history in one click
- Click any entry to navigate

#### Quicklinks

The built-in homepage displays a grid of configurable quicklinks loaded from `~/toolkit-zero/quicklinks.json`. Inject/update your quicklinks programmatically or edit the JSON directly.

#### macOS Dock icon

On macOS, the Dock tile icon is set at runtime via `NSApplication::setApplicationIconImage:` using `objc2`. Winit's `window::Settings::icon` is a no-op on macOS (per-window icons are not a platform concept), so duct-tape calls the AppKit API directly after the window is fully initialised.

---

### CLI launch options

The `duct-tape` binary accepts optional arguments:

```sh
# Open the built-in homepage (default)
duct-tape

# Open a URL — back button returns to the homepage
duct-tape --url=https://example.com

# Address-bar resolution: adds https:// if no scheme; falls back to Google search
duct-tape --url=rust-lang.org
duct-tape --url="rust programming"

# Explicit Google search
duct-tape --search="cargo build flags"

# Open a local HTML file
duct-tape --file=/path/to/page.html
```

All flags perform safety checks — an empty value prints a usage message and exits with code 1.

---

### Rust API — launch functions

| Function | Description |
|---|---|
| `browser::launch_default()` | Open the built-in homepage; blocks until window closes |
| `browser::launch(target)` | Open with an explicit `Target`; blocks |
| `browser::launch_with_api(target, receiver)` | Launch + connect an `ApiReceiver` for programmatic control; blocks |
| `browser::launch_with_controller(target, closure)` | All-in-one — pass an async closure that receives the handle; spawns it and blocks internally |

All entry points **block the calling thread** (iced's event loop must run on the main thread). When called inside a `tokio::task::block_in_place` closure the async executor keeps running on other threads.

---

### Target variants

| Variant | Behaviour |
|---|---|
| `Target::Default` | Opens the built-in homepage |
| `Target::Url(String)` | Navigates to an `http://` / `https://` URL |
| `Target::File(PathBuf)` | Loads a local file via `file://`; relative CSS/JS refs resolved automatically |
| `Target::Html(String)` | Injects a raw HTML string directly into the WebView — no file needed |
| `Target::UrlFromHome(String)` | Loads the homepage first (seeds the webview back-stack), then navigates to the URL — pressing Back returns to the homepage |

---

### Programmatic control — launch_with_controller (recommended)

The cleanest way to drive the browser programmatically. Pass an async closure; duct-tape creates the channel pair, spawns your closure as a tokio task, and starts the window — all in a single call.

```rust
use toolkit_zero::browser::{self, Target, api::{BrowserHandle, TabTarget, ThemeMode}};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), browser::BrowserError> {
    browser::launch_with_controller(Target::Default, |handle: BrowserHandle| async move {
        // Wait for the window to fully initialise before sending commands.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        // Navigate the active (visible) tab
        handle.navigate(TabTarget::Active, "https://docs.rs");

        // Open a brand-new tab at a URL
        handle.navigate(TabTarget::New, "https://crates.io");

        // Navigate an existing tab by 0-based index
        // (creates a new tab if the index is out of range)
        handle.navigate(TabTarget::Index(1), "https://example.com");

        // Open a new tab at the homepage
        handle.open_new_tab::<&str>(None);

        // Open a new tab at a URL
        handle.open_new_tab(Some("https://rust-lang.org"));

        // Trigger a parallel download — appears in the downloads panel
        handle.start_download("https://example.com/archive.zip");

        // Switch the colour theme
        handle.set_theme(ThemeMode::Dark);
    })
}
```

#### How launch_with_controller works internally

1. Creates a `(BrowserHandle, ApiReceiver)` pair.
2. Installs the receiver into the browser's process-global command queue.
3. Calls `tokio::runtime::Handle::current().spawn(controller(handle))` — your closure starts running on the tokio runtime's worker threads.
4. Calls `tokio::task::block_in_place(|| launch(target))` — blocks the calling thread for the event loop while keeping the tokio executor alive for your spawned task.

---

### Programmatic control — launch_with_api (explicit)

For cases where you need to manage the channel pair yourself — e.g. storing the handle in shared state, passing it to multiple tasks with different lifetimes, or integrating with an existing tokio setup.

```rust
use toolkit_zero::browser::{self, Target, api::{BrowserHandle, TabTarget, ThemeMode}};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let (handle, receiver) = BrowserHandle::new();

    // Clone the handle for each task that needs it.
    let h1 = handle.clone();
    let h2 = handle.clone();

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        h1.navigate(TabTarget::Active, "https://docs.rs");
    });

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        h2.set_theme(ThemeMode::Dark);
        h2.start_download("https://example.com/file.tar.gz");
    });

    // receiver is consumed here; handle stays alive as long as any clone exists.
    tokio::task::block_in_place(|| {
        browser::launch_with_api(Target::Default, receiver)
    }).unwrap();
}
```

---

### BrowserHandle API reference

All methods are **fire-and-forget** — they enqueue a command and return immediately. The browser processes the queue on the next Tick (≤ 16 ms). `BrowserHandle` is `Clone + Send`; clone it freely across threads and tasks.

| Method | Description |
|---|---|
| `handle.navigate(tab: TabTarget, url: impl Into<String>)` | Navigate `tab` to `url` (same resolution as the address bar) |
| `handle.open_new_tab(url: Option<impl Into<String>>)` | `None` → new tab at homepage; `Some(url)` → new tab at URL |
| `handle.start_download(url: impl Into<String>)` | Trigger a parallel download of `url`; file lands in `~/Downloads/` |
| `handle.set_theme(mode: ThemeMode)` | Switch the colour theme immediately |

### TabTarget

| Variant | Behaviour |
|---|---|
| `TabTarget::Active` | The currently visible tab |
| `TabTarget::New` | Always opens a brand-new tab |
| `TabTarget::Index(usize)` | Existing tab by 0-based index; creates a new tab if the index is out of range |

### ThemeMode

| Variant | Behaviour |
|---|---|
| `ThemeMode::Light` | Always light palette |
| `ThemeMode::Dark` | Always dark palette |
| `ThemeMode::Auto` | Light 07:00–19:00 local time, dark otherwise |

---

## License

MIT — see [LICENSE](LICENSE).
