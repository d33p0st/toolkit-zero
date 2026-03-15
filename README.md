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
- [VEIL-encrypted routes](#veil-encrypted-routes)
- [Serving the server](#serving-the-server)
- [Graceful shutdown](#graceful-shutdown)
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
- [VEIL-encrypted requests](#veil-encrypted-requests)
- [Sync vs async sends](#sync-vs-async-sends)
- [`#[request]` attribute macro](#request-attribute-macro)

</details>

<details>
<summary>6. <a href="#location">Location</a></summary>

- [Blocking usage](#blocking-usage)
- [Async usage](#async-usage)
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
<summary>8. <a href="#dependency-graph--ironprint">Dependency Graph — IronPrint</a></summary>

- [Sections captured](#sections-captured)
- [Setup](#setup)
- [Usage](#ironprint-usage)
- [Debug export](#debug-export)
- [Risks and considerations](#risks-and-considerations)

</details>

</details>

---

## Overview

`toolkit-zero` follows a strict zero-overhead model: only the features you declare are compiled into your binary. Every module is isolated behind an independent feature gate; enabling a feature introduces exactly the dependencies that module requires — nothing more.

---

## Feature flags

| Feature | What it enables | Module exposed |
|---|---|---|
| `serialization` | VEIL cipher — seal any struct to opaque bytes and back | `toolkit_zero::serialization` |
| `socket-server` | Typed HTTP server builder (includes `serialization`) | `toolkit_zero::socket::server` |
| `socket-client` | Typed HTTP client builder (includes `serialization`) | `toolkit_zero::socket::client` |
| `socket` | Both `socket-server` and `socket-client` | both socket sub-modules |
| `location-native` | Browser-based geolocation (includes `socket-server`) | `toolkit_zero::location::browser` |
| `location` | Alias for `location-native` | `toolkit_zero::location` |
| `enc-timelock-keygen-now` | Time-lock key derivation from the system clock | `toolkit_zero::encryption::timelock` |
| `enc-timelock-keygen-input` | Time-lock key derivation from a caller-supplied time | `toolkit_zero::encryption::timelock` |
| `enc-timelock-async-keygen-now` | Async variant of `enc-timelock-keygen-now` | `toolkit_zero::encryption::timelock` |
| `enc-timelock-async-keygen-input` | Async variant of `enc-timelock-keygen-input` | `toolkit_zero::encryption::timelock` |
| `encryption` | All four `enc-timelock-*` features | `toolkit_zero::encryption::timelock` |
| `dependency-graph-build` | Attach a normalised dependency-graph snapshot at build time | `toolkit_zero::dependency_graph::build` |
| `dependency-graph-capture` | Read the embedded snapshot at runtime | `toolkit_zero::dependency_graph::capture` |
| `backend-deps` | Re-exports all third-party deps used by each active module | `*::backend_deps` |

Add with `cargo add`:

```sh
# VEIL cipher only
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

# Attach IronPrint fingerprint in build.rs
cargo add toolkit-zero --build --features dependency-graph-build

# Read IronPrint fingerprint at runtime
cargo add toolkit-zero --features dependency-graph-capture

# Re-export deps alongside socket-server
cargo add toolkit-zero --features socket-server,backend-deps
```

---

## Serialization

Feature: `serialization`

The VEIL cipher transforms any [`bincode`](https://docs.rs/bincode)-encodable value into an opaque, key-dependent byte sequence. The output carries no recognisable structure; every output byte is a function of the complete input and the key. Without the exact key, the transformation cannot be reversed.

**Entry points:**

| Function | Direction |
|---|---|
| `toolkit_zero::serialization::seal(&value, key)` | struct → `Vec<u8>` |
| `toolkit_zero::serialization::open::<T>(&bytes, key)` | `Vec<u8>` → struct |

`key` is `Option<&str>`.  Pass `None` to use the built-in default key.

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

// With a custom shared key
let blob2 = seal(&cfg, Some("my-secret")).unwrap();
let back2: Config = open(&blob2, Some("my-secret")).unwrap();
assert_eq!(cfg, back2);
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

Missing or malformed query parameters cause warp to return `400 Bad Request`
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

### VEIL-encrypted routes

Call `.encryption::<T>(key)` (body) or `.encrypted_query::<T>(key)` (query) on the mechanism.  Provide a `SerializationKey::Default` (built-in key) or `SerializationKey::Value("your-key")` (custom key).

Before the handler is called, the body or query is VEIL-decrypted using the supplied key.  A wrong key, mismatched secret, or corrupt payload returns `403 Forbidden` without ever reaching the handler.  The `T` the closure receives is always a trusted, fully-decrypted value.

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

For encrypted query parameters, the client sends `?data=<base64url>` where the value is URL-safe base64 of the VEIL-sealed struct bytes.

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

### Building responses

Use the `reply!` macro:

| Expression | Result |
|---|---|
| `reply!()` | `200 OK` with empty body |
| `reply!(json => value)` | `200 OK` with JSON-serialised body |
| `reply!(json => value, status => Status::Created)` | `201 Created` with JSON body |
| `reply!(message => warp::reply(), status => Status::NoContent)` | custom status on any reply |
| `reply!(sealed => value)` | `200 OK` with VEIL-sealed body (`application/octet-stream`) |
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
- Panics inside the handler are silently converted to a `Rejection`, masking runtime errors.
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

### VEIL-encrypted requests

Attach a VEIL-sealed body with `.encryption(value, key)`. The body is sealed prior to transmission; the response bytes are unsealed automatically. Both the request (`T`) and response (`R`) use `bincode` encoding: `T` must implement `bincode::Encode` and `R` must implement `bincode::Decode<()>`.

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

For encrypted query parameters, use `.encrypted_query(value, key)`.  The params are sealed and sent as `?data=<base64url>`.

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

Feature: `location` (or `location-native`)

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

## Dependency Graph — IronPrint

Features: `dependency-graph-build` · `dependency-graph-capture`

IronPrint attaches a normalised, deterministic snapshot of the build environment to the compiled binary. The snapshot is written to `$OUT_DIR/ironprint.json` at compile time and embedded via `include_str!`; no runtime I/O is required.

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
    toolkit_zero::dependency_graph::build::generate_ironprint()
        .expect("ironprint generation failed");
    // see "Debug export" below for the optional export() call
}
```

### IronPrint usage

Embed and read the snapshot in your binary:

```rust
use toolkit_zero::dependency_graph::capture;

const IRONPRINT: &str = include_str!(concat!(env!("OUT_DIR"), "/ironprint.json"));

fn main() {
    let data = capture::parse(IRONPRINT).expect("failed to parse ironprint");

    println!("{} v{}", data.package.name, data.package.version);
    println!("profile  : {}", data.build.profile);
    println!("target   : {}", data.build.target);
    println!("rustc    : {}", data.build.rustc_version);
    println!("lock sha : {}", data.cargo_lock_sha256);

    for (file, hash) in &data.source {
        println!("{file} -> {hash}");
    }

    // raw bytes of the normalised JSON
    let raw: &[u8] = capture::as_bytes(IRONPRINT);
    println!("{} bytes", raw.len());
}
```

**`IronprintData` fields:**

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

`export(enabled: bool)` writes a **pretty-printed** `ironprint.json` alongside the crate's `Cargo.toml` for local inspection. This file is distinct from the compact version written to `$OUT_DIR`; the binary always embeds the `$OUT_DIR` copy.

Pass `cfg!(debug_assertions)` to suppress the file automatically in release builds:

```rust
fn main() {
    toolkit_zero::dependency_graph::build::generate_ironprint()
        .expect("ironprint generation failed");
    toolkit_zero::dependency_graph::build::export(cfg!(debug_assertions))
        .expect("ironprint export failed");
}
```

> **Add `ironprint.json` to `.gitignore`.**  The exported file contains the full dependency graph, per-file source hashes, target triple, and compiler version. Although the contents are not secret, committing the file adds repository noise and may expose build-environment details beyond what is intended.

### Risks and considerations

| Concern | Detail |
|---|---|
| **Not tamper-proof** | The fingerprint is embedded as plain text in the binary's read-only data section. Anyone with access to the binary can read it. It is informational, not a security boundary. |
| **Export file exposure** | `export(true)` writes `ironprint.json` to the crate root. Add it to `.gitignore` to prevent accidental commits. |
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
| `serialization` | `toolkit_zero::serialization::backend_deps` | `bincode`, `base64` |
| `socket` (server side) | `toolkit_zero::socket::backend_deps` | `bincode`, `base64`, `serde`, `tokio`, `log`, `bytes`, `serde_urlencoded`, `warp` |
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
// Access warp directly through toolkit-zero
use toolkit_zero::socket::backend_deps::warp;

// Access bincode through serialization
use toolkit_zero::serialization::backend_deps::bincode;
```

---

## License

MIT — see [LICENSE](LICENSE).
