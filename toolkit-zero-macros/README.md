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
> | `#[serializable]` | `serialization` | `serialization` | `toolkit_zero::serialization::serializable` |
> | `#[serialize]` | `serialization` | `serialization` | `toolkit_zero::serialization::serialize` |
> | `#[deserialize]` | `serialization` | `serialization` | `toolkit_zero::serialization::deserialize` |
>
> `#[mechanism]` / `#[request]` are also available via `toolkit_zero::socket::prelude::*`.
>
> Feature gates are automatically activated by the corresponding `toolkit-zero` features —
> you do not need to set them manually.

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

## `#[serializable]` — derive + inject seal/open methods

Automatically derives `bincode::Encode + bincode::Decode` on a struct or enum and
injects `.seal(key)` / `::open(bytes, key)` methods. Field-level
`#[serializable(key = "...")]` additionally generates per-field `seal_<field>` /
`open_<field>` helpers with a hardcoded key.

### Syntax

```text
#[serializable]
struct Foo { ... }

#[serializable]
enum Bar { ... }

#[serializable]
struct Creds {
    pub user: String,
    #[serializable(key = "field-key")]
    pub password: String,   // → seal_password / open_password
}
```

### Injected methods

```rust
// Struct-level
fn seal(&self, key: Option<String>) -> Result<Vec<u8>, SerializationError>
fn open(bytes: &[u8], key: Option<String>) -> Result<Self, SerializationError>

// Per annotated field
fn seal_<field>(&self) -> Result<Vec<u8>, SerializationError>
fn open_<field>(bytes: &[u8]) -> Result<FieldType, SerializationError>
```

### Example

```rust
use toolkit_zero::serialization::serializable;

#[serializable]
struct Config { host: String, port: u16 }

let c = Config { host: "localhost".into(), port: 8080 };
let blob = c.seal(None).unwrap();
let back = Config::open(&blob, None).unwrap();
```

---

## `#[serialize]` — inline seal statement

Replaces a `fn` item with a seal statement. Two modes:

- **Variable mode** — fn name → binding name, return type → type annotation (required).
- **File write mode** — presence of `path = "..."` → `fs::write(path, seal(...)?)?`.

### Syntax

```text
#[serialize(expr)]                              // variable, default key
#[serialize(expr, key = key_expr)]              // variable, custom key
#[serialize(expr, path = "file.bin")]           // file write, default key
#[serialize(expr, path = "file.bin", key = k)]  // file write, custom key
```

### Example

```rust
use toolkit_zero::serialization::serialize;

#[serialize(cfg, key = my_key)]
fn blob() -> Vec<u8> {}
// expands to: let blob: Vec<u8> = seal(&cfg, Some(my_key))?;

#[serialize(cfg, path = "config.bin")]
fn _() {}
// expands to: fs::write("config.bin", seal(&cfg, None)?)?;
```

---

## `#[deserialize]` — inline open statement

Replaces a `fn` item with an open statement. The return type annotation is required.
Two modes:

- **Variable mode** — open from a blob expression in scope.
- **File read mode** — presence of `path = "..."` → `open(&fs::read(path)?, ...)`.

### Syntax

```text
#[deserialize(blob_expr)]                       // variable, default key
#[deserialize(blob_expr, key = key_expr)]       // variable, custom key
#[deserialize(path = "file.bin")]               // file read, default key
#[deserialize(path = "file.bin", key = k)]      // file read, custom key
```

### Example

```rust
use toolkit_zero::serialization::deserialize;

#[deserialize(blob, key = my_key)]
fn config() -> Config {}
// expands to: let config: Config = open::<Config>(&blob, Some(my_key))?;

#[deserialize(path = "config.bin")]
fn config() -> Config {}
// expands to: let config: Config = open::<Config>(&fs::read("config.bin")?, None)?;
```

---

## Usage

```toml
[dependencies]
# Server-side macro
toolkit-zero = { version = "3", features = ["socket-server"] }

# Client-side macro
toolkit-zero = { version = "3", features = ["socket-client"] }

# Serialization macros
toolkit-zero = { version = "3", features = ["serialization"] }

# All socket + serialization
toolkit-zero = { version = "3", features = ["socket", "serialization"] }
```

```rust
// Server
use toolkit_zero::socket::server::mechanism;
// Client
use toolkit_zero::socket::client::request;
// Serialization
use toolkit_zero::serialization::{serializable, serialize, deserialize};
// or all socket
use toolkit_zero::socket::prelude::*;
```

---

## License

MIT — same as `toolkit-zero`.
