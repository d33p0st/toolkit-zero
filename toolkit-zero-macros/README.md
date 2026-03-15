# toolkit-zero-macros

Procedural macros for [`toolkit-zero`](https://crates.io/crates/toolkit-zero).

> **This crate is an implementation detail of `toolkit-zero`.**  
> You should not depend on it directly. Add `toolkit-zero` with the
> `socket-server` feature instead and use the re-exported
> `toolkit_zero::socket::server::mechanism` attribute.

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
