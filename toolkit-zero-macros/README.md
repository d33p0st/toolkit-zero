# toolkit-zero-macros

Procedural macros for [`toolkit-zero`](https://crates.io/crates/toolkit-zero).

> **This crate is an implementation detail of `toolkit-zero`.**  
> Do not depend on it directly. Add `toolkit-zero` with the appropriate
> feature flag and use the re-exported attribute macros:
>
> | Macro | `toolkit-zero` feature flag | `toolkit-zero-macros` feature gate | Import path |
> |---|---|---|---|
> | `#[mechanism]` | `socket-server` | `socket-server` | `toolkit_zero::socket::server::mechanism` |
> | `#[request]` | `socket-client` | `socket-client` | `toolkit_zero::socket::client::request` |
>
> Both are also available via `toolkit_zero::socket::prelude::*`.
>
> The `toolkit-zero-macros/socket-server` and `toolkit-zero-macros/socket-client` feature
> gates are automatically activated by the corresponding `toolkit-zero` features — you do
> not need to set them manually.

---

## `#[mechanism]` — server-side route declaration

A concise alternative to the `server.mechanism(ServerMechanism::…)` builder
chain. The decorated `async fn` is replaced in-place with the equivalent
`server.mechanism(…)` statement. The function body is transplanted verbatim
into the `.onconnect(…)` closure.

### Syntax

```text
#[mechanism(server, METHOD, "/path")]
#[mechanism(server, METHOD, "/path", json)]
#[mechanism(server, METHOD, "/path", query)]
#[mechanism(server, METHOD, "/path", encrypted(<key_expr>))]
#[mechanism(server, METHOD, "/path", encrypted_query(<key_expr>))]
#[mechanism(server, METHOD, "/path", state(<state_expr>))]
#[mechanism(server, METHOD, "/path", state(<state_expr>), json)]
#[mechanism(server, METHOD, "/path", state(<state_expr>), query)]
#[mechanism(server, METHOD, "/path", state(<state_expr>), encrypted(<key_expr>))]
#[mechanism(server, METHOD, "/path", state(<state_expr>), encrypted_query(<key_expr>))]
```

Positional: `server`, `METHOD`, `"/path"`. Keywords after the path may appear
in **any order**.

### Supported forms

| Attribute keywords | fn parameters |
|---|---|
| *(none)* | `()` |
| `json` | `(body: T)` |
| `query` | `(params: T)` |
| `encrypted(key)` | `(body: T)` — VEIL-decrypted before delivery |
| `encrypted_query(key)` | `(params: T)` — VEIL-decrypted before delivery |
| `state(expr)` | `(state: S)` |
| `state(expr), json` | `(state: S, body: T)` |
| `state(expr), query` | `(state: S, params: T)` |
| `state(expr), encrypted(key)` | `(state: S, body: T)` |
| `state(expr), encrypted_query(key)` | `(state: S, params: T)` |

### Example

```rust
use toolkit_zero::socket::server::{Server, mechanism, reply, Status};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Deserialize, Serialize, Clone)] struct Item    { id: u32, name: String }
#[derive(Deserialize)]                   struct NewItem  { name: String }

#[tokio::main]
async fn main() {
    let mut server = Server::default();
    let db: Arc<Mutex<Vec<Item>>> = Arc::new(Mutex::new(vec![]));

    // Plain GET
    #[mechanism(server, GET, "/health")]
    async fn health() { reply!() }

    // JSON body
    #[mechanism(server, POST, "/items", json)]
    async fn create(body: NewItem) {
        reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
    }

    // State + JSON body
    #[mechanism(server, POST, "/items/add", state(db.clone()), json)]
    async fn add(db: Arc<Mutex<Vec<Item>>>, body: NewItem) {
        let id = db.lock().unwrap().len() as u32 + 1;
        let item = Item { id, name: body.name };
        db.lock().unwrap().push(item.clone());
        reply!(json => item, status => Status::Created)
    }

    server.serve(([127, 0, 0, 1], 8080)).await;
}
```

---

## `#[request]` — client-side request shorthand

A concise alternative to the `client.method(endpoint)[.json/query/…].send()` builder
chain. The decorated `fn` item is replaced in-place with a `let` binding statement
that performs the HTTP request. The **function name** becomes the binding name;
the **return type** becomes `R` in the `.send::<R>()` turbofish. The function body
is discarded.

### Syntax

```text
#[request(client, METHOD, "/path", async|sync)]
#[request(client, METHOD, "/path", json(<body_expr>), async|sync)]
#[request(client, METHOD, "/path", query(<params_expr>), async|sync)]
#[request(client, METHOD, "/path", encrypted(<body_expr>, <key_expr>), async|sync)]
#[request(client, METHOD, "/path", encrypted_query(<params_expr>, <key_expr>), async|sync)]
```

Positional: `client`, `METHOD`, `"/path"`. Mode keyword (if any) comes before
`async`/`sync`. `async` uses `.send::<R>().await?`; `sync` uses `.send_sync::<R>()?`.

### Supported forms

| Attribute | Generated call | Error type from `?` |
|---|---|---|
| *(no mode)* | `.send::<R>()` / `.send_sync::<R>()` | `reqwest::Error` |
| `json(expr)` | `.json(expr).send::<R>()` | `reqwest::Error` |
| `query(expr)` | `.query(expr).send::<R>()` | `reqwest::Error` |
| `encrypted(body, key)` | `.encryption(body, key).send::<R>()` | `ClientError` |
| `encrypted_query(params, key)` | `.encrypted_query(params, key).send::<R>()` | `ClientError` |

The return type annotation on the fn is **required** — omitting it is a compile error.

### Example

```rust
use toolkit_zero::socket::client::{Client, Target, request};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone)] struct Item    { id: u32, name: String }
#[derive(Serialize)]                     struct NewItem  { name: String }
#[derive(Serialize)]                     struct Filter   { page: u32 }

async fn example() -> Result<(), reqwest::Error> {
    let client = Client::new_async(Target::Localhost(8080));

    // Plain async GET → let items: Vec<Item> = client.get("/items").send::<Vec<Item>>().await?;
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

---

## Usage

```toml
[dependencies]
# Server-side macro
toolkit-zero = { version = "3", features = ["socket-server"] }

# Client-side macro
toolkit-zero = { version = "3", features = ["socket-client"] }

# Both
toolkit-zero = { version = "3", features = ["socket"] }
```

```rust
// Server
use toolkit_zero::socket::server::mechanism;
// or
use toolkit_zero::socket::prelude::*;  // includes both mechanism and request

// Client
use toolkit_zero::socket::client::request;
// or
use toolkit_zero::socket::prelude::*;
```

---

## License

MIT — same as `toolkit-zero`.


---

## What this crate provides

A single attribute macro — `#[mechanism]` — that is a concise shorthand for
the `toolkit-zero` socket-server route builder chain.

Instead of:

```rust
server.mechanism(
    ServerMechanism::post("/items")
        .json::<NewItem>()
        .onconnect(|body: NewItem| async move {
            reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
        })
);
```

you write:

```rust
#[mechanism(server, POST, "/items", json)]
async fn create_item(body: NewItem) {
    reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
}
```

The macro expands to the exact same `server.mechanism(…)` statement in-place.
The function name is discarded; the body is transplanted verbatim into the
`.onconnect(…)` closure.

---

## Usage

Add `toolkit-zero` — **not** this crate — to your `Cargo.toml`:

```toml
[dependencies]
toolkit-zero = { version = "3", features = ["socket-server"] }
```

Then import the macro from the server module:

```rust
use toolkit_zero::socket::server::mechanism;
// or
use toolkit_zero::socket::prelude::*;
```

---

## Supported forms

| Attribute | Function parameters |
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

Valid HTTP methods: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`.

The keywords after the path (`json`, `query`, `state`, `encrypted`,
`encrypted_query`) may appear in **any order**.

---

## Full example

```rust
use toolkit_zero::socket::server::{Server, mechanism, reply, Status};
use toolkit_zero::socket::SerializationKey;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Deserialize, Serialize, Clone)] struct Item    { id: u32, name: String }
#[derive(Deserialize)]                   struct NewItem  { name: String }
#[derive(Deserialize)]                   struct Filter   { page: u32 }

#[tokio::main]
async fn main() {
    let mut server = Server::default();
    let db: Arc<Mutex<Vec<Item>>> = Arc::new(Mutex::new(vec![]));

    // Plain GET
    #[mechanism(server, GET, "/health")]
    async fn health() { reply!() }

    // JSON body
    #[mechanism(server, POST, "/items", json)]
    async fn create(body: NewItem) {
        reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
    }

    // Query params
    #[mechanism(server, GET, "/items", query)]
    async fn list(filter: Filter) {
        let _ = filter.page;
        reply!()
    }

    // State + JSON
    #[mechanism(server, POST, "/items/add", state(db.clone()), json)]
    async fn add(db: Arc<Mutex<Vec<Item>>>, body: NewItem) {
        let id = db.lock().unwrap().len() as u32 + 1;
        let item = Item { id, name: body.name };
        db.lock().unwrap().push(item.clone());
        reply!(json => item, status => Status::Created)
    }

    // VEIL-encrypted body
    #[mechanism(server, POST, "/secure", encrypted(SerializationKey::Default))]
    async fn secure(body: NewItem) {
        reply!(json => Item { id: 99, name: body.name })
    }

    server.serve(([127, 0, 0, 1], 8080)).await;
}
```

---

## License

MIT — same as `toolkit-zero`.
