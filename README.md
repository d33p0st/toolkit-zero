# toolkit-zero

A feature-selective Rust utility toolkit. Pull in only the modules you need via Cargo feature flags — each feature compiles exactly what it requires and nothing more.

---

## Table of Contents

1. [Overview](#overview)
2. [Feature flags](#feature-flags)
3. [Serialization](#serialization)
4. [Socket — server](#socket--server)
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
5. [Socket — client](#socket--client)
   - [Creating a client](#creating-a-client)
   - [Plain requests](#plain-requests)
   - [JSON body requests](#json-body-requests)
   - [Query parameter requests](#query-parameter-requests)
   - [VEIL-encrypted requests](#veil-encrypted-requests)
   - [Sync vs async sends](#sync-vs-async-sends)
6. [Location](#location)
   - [Blocking usage](#blocking-usage)
   - [Async usage](#async-usage)
   - [Page templates](#page-templates)
   - [LocationData fields](#locationdata-fields)
   - [Errors](#locationerror-variants)
7. [Encryption — Timelock](#encryption--timelock)
   - [Features](#timelock-features)
   - [KDF presets](#kdf-presets)
   - [Usage](#timelock-usage)

---

## Overview

`toolkit-zero` is designed to be zero-waste: you declare only the features you want and cargo compiles only what those features require.  There is no "kitchen sink" import.

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
| `backend-deps` | Re-exports all third-party deps used by each active module | `*::backend_deps` |

Add to `Cargo.toml`:

```toml
[dependencies]
# VEIL cipher only
toolkit-zero = { version = "3.2", features = ["serialization"] }

# HTTP server only
toolkit-zero = { version = "3.2", features = ["socket-server"] }

# HTTP client only
toolkit-zero = { version = "3.2", features = ["socket-client"] }

# Both sides
toolkit-zero = { version = "3.2", features = ["socket"] }

# Geolocation (pulls in socket-server automatically)
toolkit-zero = { version = "3.2", features = ["location"] }

# Full time-lock encryption suite
toolkit-zero = { version = "3.2", features = ["encryption"] }

# Re-export deps alongside socket-server
toolkit-zero = { version = "3.2", features = ["socket-server", "backend-deps"] }
```

---

## Serialization

Feature: `serialization`

The VEIL cipher converts any [`bincode`](https://docs.rs/bincode)-encodable struct into an opaque, key-dependent byte blob.  The output has no recognisable structure and every output byte depends on the full input and the key.  Without the exact key the bytes cannot be inverted.

**Entry points:**

| Function | Direction |
|---|---|
| `toolkit_zero::serialization::seal(&value, key)` | struct → `Vec<u8>` |
| `toolkit_zero::serialization::open::<T>(&bytes, key)` | `Vec<u8>` → struct |

`key` is `Option<&str>`.  Pass `None` to use the built-in default key.

**Your types must derive `Encode` and `Decode`:**

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

A fluent builder API for declaring typed HTTP routes and serving them.  Every route starts from `ServerMechanism`, is enriched with optional body / query / state expectations, and is finalised with `.onconnect(async_handler)`.  Finalised routes are registered on a `Server`, which is then served with a single `.await`.

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

All seven HTTP methods are available: `get`, `post`, `put`, `delete`, `patch`, `head`, `options`.

### JSON body routes

Call `.json::<T>()` on the mechanism.  The JSON body is deserialised before the handler runs; the handler receives a ready-to-use `T`.  `T` must implement `serde::Deserialize`.  A missing or malformed body returns `400 Bad Request` automatically.

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

Call `.query::<T>()` on the mechanism.  When a request arrives, warp deserialises
the URL query string into `T` before calling the handler — the handler receives a
ready-to-use value.  `T` must implement `serde::Deserialize`.

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

Call `.state(value)` on the mechanism.  A fresh clone of the state is injected into every request.  The state must be `Clone + Send + Sync + 'static`.  Wrap mutable state in `Arc<Mutex<_>>` or `Arc<RwLock<_>>`.

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

State and a body (or query) can be combined.  The order of `.state()` and `.json()` / `.query()` does not matter.  The handler receives `(state: S, body_or_query: T)`.

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

Every route finaliser (`onconnect`) has an `unsafe` blocking counterpart — `onconnect_sync` — for cases where an existing blocking API cannot easily be made async.  **Not recommended for production traffic.**

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

`unsafe` is required because `onconnect_sync` dispatches to Tokio's blocking thread pool, which carries important caveats:

- The pool caps live OS threads at 512 (default), but the **waiting-task queue is unbounded**.  Under a traffic surge, tasks accumulate without limit, leading to OOM or severe latency before any queued task executes.
- Any panic inside the handler is silently converted to a `Rejection`, masking runtime errors.
- When the handler holds a lock (e.g. `Arc<Mutex<_>>`), lock contention across concurrent blocking tasks can stall the thread pool indefinitely.

`onconnect_sync` is available on every builder variant: plain, `.json`, `.query`, `.state`, and their combinations.  All have identical safety requirements.

---

## Socket — client

Feature: `socket-client`

A fluent builder API for issuing typed HTTP requests.  Construct a `Client` from a `Target`, pick an HTTP method, optionally attach a body or query parameters, and call `.send().await` or `.send_sync()`.

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
> **Rule of thumb:**
> - Async program (`#[tokio::main]`) → use `Client::new_async()`.
> - Sync program with no runtime → use `Client::new_sync()` or `Client::new()`.
> - Mixed program (sync `main`, manual `tokio::Runtime`) → build the `Client` *before* starting
>   the runtime.

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

All seven HTTP methods are available: `get`, `post`, `put`, `delete`, `patch`, `head`, `options`.

### JSON body requests

Attach a body with `.json(value)`.  `value` must implement `serde::Serialize`.  The response is deserialised as `R: serde::Deserialize`.

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

Attach query parameters with `.query(value)`.  `value` must implement
`serde::Serialize`.  The fields are serialised by `serde_urlencoded` and
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

Field order in the URL is determined by struct field declaration order.  Keep
query structs flat — nested structs are not supported by `serde_urlencoded`.

### VEIL-encrypted requests

Attach a VEIL-sealed body with `.encryption(value, key)`.  The body is sealed before the wire send and the response bytes are opened automatically.  Both `value` (request) and `R` (response) use `bincode` — `value: T` must implement `bincode::Encode`, `R` must implement `bincode::Decode<()>`.

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

---

## Location

Feature: `location` (or `location-native`)

Acquires the device's geographic coordinates by opening the system's default browser to a locally served consent page.  The browser prompts the user for location permission via the standard Web Geolocation API.  On success, the coordinates are POSTed back to the local server, which shuts itself down and returns the result to the caller.

No external service is contacted.  Everything happens on `127.0.0.1`.

### Blocking usage

Works from synchronous `main` **and** from inside an async Tokio runtime.  When called inside an existing runtime, an OS thread is spawned to avoid nesting runtimes.

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

Preferred when already inside a Tokio async context — avoids the extra OS thread spawn.

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

Derives a 32-byte time-locked key through a three-pass RAM-hard KDF chain:

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

## Backend deps

Feature: `backend-deps`

When combined with any other feature, `backend-deps` adds a `backend_deps` sub-module to every active module. Each `backend_deps` module re-exports (via `pub use`) every third-party crate that its parent uses internally.

This lets downstream crates access those dependencies without declaring them separately in their own `Cargo.toml`.

| Module | Path | Re-exports |
|---|---|---|
| `serialization` | `toolkit_zero::serialization::backend_deps` | `bincode`, `base64` |
| `socket` (server side) | `toolkit_zero::socket::backend_deps` | `bincode`, `base64`, `serde`, `tokio`, `log`, `bytes`, `serde_urlencoded`, `warp` |
| `socket` (client side) | `toolkit_zero::socket::backend_deps` | `bincode`, `base64`, `serde`, `tokio`, `log`, `reqwest` |
| `location` | `toolkit_zero::location::backend_deps` | `tokio`, `serde`, `webbrowser`, `rand` |
| `encryption` (timelock) | `toolkit_zero::encryption::timelock::backend_deps` | `argon2`, `scrypt`, `zeroize`, `chrono`, `rand`; `tokio` (async variants only) |

Each re-export inside `backend_deps` is individually gated on its parent feature, so only the deps that are actually compiled appear.  Enabling `backend-deps` alone (without any other feature) compiles cleanly but exposes nothing.

```toml
# Example: socket-server + dep re-exports
toolkit-zero = { version = "3.2", features = ["socket-server", "backend-deps"] }
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
