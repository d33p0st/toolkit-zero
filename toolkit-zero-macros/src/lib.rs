//! Procedural macros for `toolkit-zero`.
//!
//! This crate is an internal implementation detail of `toolkit-zero`.
//! Do not depend on it directly — all macros are re-exported through the
//! relevant `toolkit-zero` module:
//!
//! | Macro | Enable with | Import from |
//! |---|---|---|
//! | [`mechanism`] | `features = ["socket-server"]` | `toolkit_zero::socket::server` |
//! | [`request`] | `features = ["socket-client"]` | `toolkit_zero::socket::client` |
//! | [`serializable`] | `features = ["serialization"]` | `toolkit_zero::serialization` |
//! | [`serialize`] | `features = ["serialization"]` | `toolkit_zero::serialization` |
//! | [`deserialize`] | `features = ["serialization"]` | `toolkit_zero::serialization` |
//! | [`browser`] | `features = ["location"]` | `toolkit_zero::location` |
//! | [`timelock`] | any `enc-timelock-*` feature | `toolkit_zero::encryption::timelock` |
//! | [`dependencies`] | `features = ["dependency-graph-capture"]` | `toolkit_zero::dependency_graph::capture` |
//!
//! ---
//!
//! # `#[mechanism]` — server-side route declaration
//!
//! Replaces a decorated `fn` item with a `server.mechanism(…)` builder
//! statement. The function body is transplanted verbatim into the
//! `.onconnect(…)` closure; all variables from the enclosing scope are
//! accessible via `move` capture.
//!
//! ## Syntax
//!
//! ```text
//! #[mechanism(server, METHOD, "/path")]
//! #[mechanism(server, METHOD, "/path", json)]
//! #[mechanism(server, METHOD, "/path", query)]
//! #[mechanism(server, METHOD, "/path", encrypted(<key_expr>))]
//! #[mechanism(server, METHOD, "/path", encrypted_query(<key_expr>))]
//! #[mechanism(server, METHOD, "/path", state(<state_expr>))]
//! #[mechanism(server, METHOD, "/path", state(<state_expr>), json)]
//! #[mechanism(server, METHOD, "/path", state(<state_expr>), query)]
//! #[mechanism(server, METHOD, "/path", state(<state_expr>), encrypted(<key_expr>))]
//! #[mechanism(server, METHOD, "/path", state(<state_expr>), encrypted_query(<key_expr>))]
//! ```
//!
//! The first three arguments (`server`, `METHOD`, `"/path"`) are positional
//! and required. Keywords after the path (`json`, `query`, `state(…)`,
//! `encrypted(…)`, `encrypted_query(…)`) may appear in **any order**.
//!
//! ## Parameters
//!
//! | Argument | Type | Description |
//! |---|---|---|
//! | `server` | ident | The [`Server`](toolkit_zero::socket::server::Server) variable in scope |
//! | `METHOD` | ident | HTTP verb: `GET` `POST` `PUT` `DELETE` `PATCH` `HEAD` `OPTIONS` |
//! | `"/path"` | string literal | Route path |
//! | `json` | keyword | Deserialise JSON body; fn receives `(body: T)` |
//! | `query` | keyword | Deserialise URL query params; fn receives `(params: T)` |
//! | `encrypted(key)` | keyword + expr | Decrypt body (ChaCha20-Poly1305); fn receives `(body: T)` |
//! | `encrypted_query(key)` | keyword + expr | Decrypt query (ChaCha20-Poly1305); fn receives `(params: T)` |
//! | `state(expr)` | keyword + expr | Clone state into handler; fn first param is `(state: S)` |
//!
//! When `state` is combined with a body mode, the function receives two
//! parameters: state first, then body/params.
//!
//! ## Function signature rules
//!
//! - The function **may** be `async` or non-async — it is always wrapped in `async move { … }`.
//! - The return type annotation is ignored; Rust infers it from the `reply!` macro inside the body.
//! - The number of parameters must match the chosen mode exactly (compile error otherwise).
//!
//! ## What the macro expands to
//!
//! ```rust,ignore
//! // Input:
//! #[mechanism(server, POST, "/items", json)]
//! async fn create(body: NewItem) {
//!     reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
//! }
//!
//! // Expanded to:
//! server.mechanism(
//!     toolkit_zero::socket::server::ServerMechanism::post("/items")
//!         .json::<NewItem>()
//!         .onconnect(|body: NewItem| async move {
//!             reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
//!         })
//! );
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use toolkit_zero::socket::server::{Server, mechanism, reply, Status, SerializationKey};
//! use serde::{Deserialize, Serialize};
//! use std::sync::{Arc, Mutex};
//!
//! #[derive(Deserialize, Serialize, Clone)] struct Item    { id: u32, name: String }
//! #[derive(Deserialize)]                   struct NewItem  { name: String }
//! #[derive(Deserialize)]                   struct Filter   { page: u32 }
//!
//! #[tokio::main]
//! async fn main() {
//!     let mut server = Server::default();
//!     let db: Arc<Mutex<Vec<Item>>> = Arc::new(Mutex::new(vec![]));
//!
//!     // Plain GET — no body
//!     #[mechanism(server, GET, "/health")]
//!     async fn health() { reply!() }
//!
//!     // JSON body
//!     #[mechanism(server, POST, "/items", json)]
//!     async fn create(body: NewItem) {
//!         reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
//!     }
//!
//!     // URL query params
//!     #[mechanism(server, GET, "/items", query)]
//!     async fn list(filter: Filter) {
//!         let _ = filter.page;
//!         reply!()
//!     }
//!
//!     // Shared state + JSON body
//!     #[mechanism(server, POST, "/items/add", state(db.clone()), json)]
//!     async fn add(db: Arc<Mutex<Vec<Item>>>, body: NewItem) {
//!         let id = db.lock().unwrap().len() as u32 + 1;
//!         db.lock().unwrap().push(Item { id, name: body.name.clone() });
//!         reply!(json => Item { id, name: body.name }, status => Status::Created)
//!     }
//!
//!     // ChaCha20-Poly1305-encrypted body
//!     #[mechanism(server, POST, "/secure", encrypted(SerializationKey::Default))]
//!     async fn secure(body: NewItem) {
//!         reply!(json => Item { id: 99, name: body.name })
//!     }
//!
//!     server.serve(([127, 0, 0, 1], 8080)).await;
//! }
//! ```
//!
//! ---
//!
//! # `#[request]` — client-side request shorthand
//!
//! Replaces a decorated `fn` item with an inline `let` binding that performs
//! an HTTP request. The **function name** becomes the binding name; the
//! **return type** becomes `R` in the `.send::<R>()` turbofish. The function
//! body is discarded entirely.
//!
//! ## Syntax
//!
//! ```text
//! #[request(client, METHOD, "/path", async|sync)]
//! #[request(client, METHOD, "/path", json(<body_expr>), async|sync)]
//! #[request(client, METHOD, "/path", query(<params_expr>), async|sync)]
//! #[request(client, METHOD, "/path", encrypted(<body_expr>, <key_expr>), async|sync)]
//! #[request(client, METHOD, "/path", encrypted_query(<params_expr>, <key_expr>), async|sync)]
//! ```
//!
//! The first three arguments are positional. The mode keyword (if any) comes
//! before the mandatory `async` or `sync` terminator.
//!
//! ## Parameters
//!
//! | Argument | Description |
//! |---|---|
//! | `client` | The [`Client`](toolkit_zero::socket::client::Client) variable in scope |
//! | `METHOD` | HTTP verb: `GET` `POST` `PUT` `DELETE` `PATCH` `HEAD` `OPTIONS` |
//! | `"/path"` | Endpoint path string literal |
//! | `json(expr)` | Serialise `expr` as a JSON body (`Content-Type: application/json`) |
//! | `query(expr)` | Serialise `expr` as URL query parameters |
//! | `encrypted(body, key)` | Seal `body` (ChaCha20-Poly1305) with `key` before sending |
//! | `encrypted_query(params, key)` | Seal `params` (ChaCha20-Poly1305), send as `?data=<base64url>` |
//! | `async` | Finalise with `.send::<R>().await?` |
//! | `sync` | Finalise with `.send_sync::<R>()?` |
//!
//! ## Requirements
//!
//! - A **return type annotation is required** — it is used as `R` in the turbofish.
//!   Omitting it is a compile error.
//! - The enclosing function must return `Result<_, E>` where `E: From<reqwest::Error>`
//!   (plain/json/query modes) or `E: From<ClientError>` (encrypted modes), so that
//!   `?` can propagate.
//!
//! ## What the macro expands to
//!
//! ```rust,ignore
//! // Input:
//! #[request(client, POST, "/items", json(NewItem { name: "widget".into() }), async)]
//! async fn created() -> Item {}
//!
//! // Expanded to:
//! let created: Item = client.post("/items")
//!     .json(NewItem { name: "widget".into() })
//!     .send::<Item>()
//!     .await?;
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use toolkit_zero::socket::client::{Client, Target, request};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Deserialize, Serialize)] struct Item    { id: u32, name: String }
//! #[derive(Serialize)]              struct NewItem  { name: String }
//! #[derive(Serialize)]              struct Filter   { page: u32 }
//!
//! async fn example() -> Result<(), reqwest::Error> {
//!     let client = Client::new_async(Target::Localhost(8080));
//!
//!     // GET → let items: Vec<Item> = client.get("/items").send::<Vec<Item>>().await?
//!     #[request(client, GET, "/items", async)]
//!     async fn items() -> Vec<Item> {}
//!
//!     // POST with JSON body
//!     #[request(client, POST, "/items", json(NewItem { name: "widget".into() }), async)]
//!     async fn created() -> Item {}
//!
//!     // GET with query params
//!     #[request(client, GET, "/items", query(Filter { page: 2 }), async)]
//!     async fn page() -> Vec<Item> {}
//!
//!     // Synchronous DELETE
//!     #[request(client, DELETE, "/items/1", sync)]
//!     fn deleted() -> Item {}
//!
//!     Ok(())
//! }
//! ```
//!
//! ---
//!
//! # `#[serializable]` — derive + inject seal/open
//!
//! Automatically derives `bincode::Encode + bincode::Decode` on a struct or
//! enum and injects three methods:
//!
//! ```text
//! fn seal(&self, key: Option<String>) -> Result<Vec<u8>, SerializationError>
//! fn open(bytes: &[u8], key: Option<String>) -> Result<Self, SerializationError>
//! ```
//!
//! The `key` is **moved in** and internally wrapped in `Zeroizing<String>`,
//! wiping it from memory on drop.  Pass `None` to use the built-in default key.
//!
//! Field-level `#[serializable(key = "literal")]` additionally generates
//! per-field helpers with the key baked in:
//!
//! ```text
//! fn seal_<field>(&self)        -> Result<Vec<u8>, SerializationError>
//! fn open_<field>(bytes: &[u8]) -> Result<FieldType, SerializationError>
//! ```
//!
//! ## Syntax
//!
//! ```text
//! #[serializable]                      // on a struct or enum
//! struct Foo { … }
//!
//! #[serializable]                      // field annotation inside a struct
//! struct Bar {
//!     pub normal: String,
//!     #[serializable(key = "my-key")]  // generates seal_secret / open_secret
//!     pub secret: String,
//! }
//! ```
//!
//! > **Note:** `#[serializable]` on an enum does not scan fields for the
//! > field-level annotation — only named struct fields are supported for
//! > per-field helpers.
//!
//! ## What the macro expands to
//!
//! ```rust,ignore
//! // Input:
//! #[serializable]
//! struct Config { host: String, port: u16 }
//!
//! // Expanded to:
//! #[derive(::toolkit_zero::serialization::Encode, ::toolkit_zero::serialization::Decode)]
//! struct Config { host: String, port: u16 }
//!
//! impl Config {
//!     pub fn seal(&self, key: Option<String>) -> Result<Vec<u8>, SerializationError> {
//!         ::toolkit_zero::serialization::seal(self, key)
//!     }
//!     pub fn open(bytes: &[u8], key: Option<String>) -> Result<Self, SerializationError> {
//!         ::toolkit_zero::serialization::open::<Self>(bytes, key)
//!     }
//! }
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use toolkit_zero::serialization::serializable;
//!
//! #[serializable]
//! struct Config { host: String, port: u16 }
//!
//! let c = Config { host: "localhost".into(), port: 8080 };
//!
//! // Seal / open via struct methods
//! let blob = c.seal(None).unwrap();
//! let back = Config::open(&blob, None).unwrap();
//! assert_eq!(c.host, back.host);
//!
//! // Custom key — moved in, zeroized on drop
//! let blob2 = c.seal(Some("secret".to_string())).unwrap();
//! let back2 = Config::open(&blob2, Some("secret".to_string())).unwrap();
//!
//! // Per-field annotation
//! #[serializable]
//! struct Creds {
//!     pub user: String,
//!     #[serializable(key = "field-secret")]
//!     pub password: String,
//! }
//!
//! let creds = Creds { user: "alice".into(), password: "hunter2".into() };
//! let pw_blob = creds.seal_password().unwrap();    // key baked in
//! let pw_back = Creds::open_password(&pw_blob).unwrap();
//! assert_eq!("hunter2", pw_back);
//! ```
//!
//! ---
//!
//! # `#[serialize]` — inline seal statement
//!
//! Replaces a `fn` item with an inline seal statement. Two modes are
//! selected by the presence or absence of `path`:
//!
//! - **Variable mode** (`path` absent) — emits a `let` binding. The function
//!   name becomes the variable name; the **return type is required** and
//!   becomes the type annotation. The function body is discarded.
//! - **File write mode** (`path = "..."` present) — emits
//!   `std::fs::write(path, seal(…)?)?`. The function name and return type are
//!   ignored.
//!
//! ## Syntax
//!
//! ```text
//! // Variable mode
//! #[serialize(source_expr)]
//! #[serialize(source_expr, key = key_expr)]
//!
//! // File write mode  
//! #[serialize(source_expr, path = "file.bin")]
//! #[serialize(source_expr, path = "file.bin", key = key_expr)]
//! ```
//!
//! | Argument | Required | Description |
//! |---|---|---|
//! | `source_expr` | yes | Expression to seal (must be `bincode::Encode`) |
//! | `key = expr` | no | Key expression — `Option<String>` moved into `seal()` |
//! | `path = "..."` | no | File path — switches to file write mode |
//!
//! `key` and `path` may appear in any order after `source_expr`.
//!
//! ## What the macro expands to
//!
//! ```rust,ignore
//! // Variable mode:
//! #[serialize(cfg, key = my_key)]
//! fn blob() -> Vec<u8> {}
//! // →
//! let blob: Vec<u8> = ::toolkit_zero::serialization::seal(&cfg, Some(my_key))?;
//!
//! // Variable mode, default key:
//! #[serialize(cfg)]
//! fn blob() -> Vec<u8> {}
//! // →
//! let blob: Vec<u8> = ::toolkit_zero::serialization::seal(&cfg, None)?;
//!
//! // File write mode:
//! #[serialize(cfg, path = "out.bin", key = my_key)]
//! fn _() {}
//! // →
//! ::std::fs::write("out.bin", ::toolkit_zero::serialization::seal(&cfg, Some(my_key))?)?;
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use toolkit_zero::serialization::{serializable, serialize};
//!
//! #[serializable]
//! struct Config { threshold: f64 }
//!
//! fn save(cfg: &Config, key: String) -> Result<(), Box<dyn std::error::Error>> {
//!     // Seal to a variable
//!     #[serialize(cfg, key = key.clone())]
//!     fn blob() -> Vec<u8> {}
//!     // blob: Vec<u8> is now in scope
//!
//!     // Write directly to a file
//!     #[serialize(cfg, path = "config.bin", key = key)]
//!     fn _() {}
//!
//!     Ok(())
//! }
//! ```
//!
//! ---
//!
//! # `#[deserialize]` — inline open statement
//!
//! Replaces a `fn` item with an inline open statement. Two modes:
//!
//! - **Variable mode** (`path` absent) — opens from a blob expression already
//!   in scope. The function name becomes the binding name; the **return type
//!   is required** and used as the turbofish type `T` in `open::<T>`.
//! - **File read mode** (`path = "..."` present) — reads the file first, then
//!   opens. Same name/return-type rules apply.
//!
//! ## Syntax
//!
//! ```text
//! // Variable mode
//! #[deserialize(blob_expr)]
//! #[deserialize(blob_expr, key = key_expr)]
//!
//! // File read mode
//! #[deserialize(path = "file.bin")]
//! #[deserialize(path = "file.bin", key = key_expr)]
//! ```
//!
//! | Argument | Required | Description |
//! |---|---|---|
//! | `blob_expr` | yes (variable mode) | Expression whose value is `&[u8]` (reference taken automatically) |
//! | `path = "..."` | yes (file mode) | File to read; switches to file read mode |
//! | `key = expr` | no | Key expression — `Option<String>` moved into `open()` |
//!
//! ## What the macro expands to
//!
//! ```rust,ignore
//! // Variable mode:
//! #[deserialize(blob, key = my_key)]
//! fn config() -> Config {}
//! // →
//! let config: Config = ::toolkit_zero::serialization::open::<Config>(&blob, Some(my_key))?;
//!
//! // Variable mode, default key:
//! #[deserialize(blob)]
//! fn config() -> Config {}
//! // →
//! let config: Config = ::toolkit_zero::serialization::open::<Config>(&blob, None)?;
//!
//! // File read mode:
//! #[deserialize(path = "config.bin", key = my_key)]
//! fn config() -> Config {}
//! // →
//! let config: Config = ::toolkit_zero::serialization::open::<Config>(
//!     &::std::fs::read("config.bin")?,
//!     Some(my_key),
//! )?;
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use toolkit_zero::serialization::{serializable, serialize, deserialize};
//!
//! #[serializable]
//! struct Config { threshold: f64 }
//!
//! fn round_trip(cfg: &Config, key: String) -> Result<Config, Box<dyn std::error::Error>> {
//!     // Write to disk
//!     #[serialize(cfg, path = "config.bin", key = key.clone())]
//!     fn _() {}
//!
//!     // Read back
//!     #[deserialize(path = "config.bin", key = key)]
//!     fn loaded() -> Config {}
//!
//!     Ok(loaded)
//! }
//!
//! fn from_bytes(blob: Vec<u8>) -> Result<Config, Box<dyn std::error::Error>> {
//!     #[deserialize(blob)]
//!     fn cfg() -> Config {}
//!
//!     Ok(cfg)
//! }
//! ```
//!
//! ---
//!
//! # `#[browser]` — inline location capture
//!
//! Replaces a `fn` item with an inline call to either
//! [`__location__`](toolkit_zero::location::browser::__location__) (sync) or
//! [`__location_async__`](toolkit_zero::location::browser::__location_async__)
//! (async, default). The [`PageTemplate`](toolkit_zero::location::browser::PageTemplate)
//! is built from the macro arguments — no need to construct it manually.
//!
//! The function **name** becomes the binding that holds the resulting
//! [`LocationData`](toolkit_zero::location::browser::LocationData).
//! The function **body** is discarded. A `?` is appended so any
//! [`LocationError`](toolkit_zero::location::browser::LocationError) propagates
//! to the enclosing function.
//!
//! ## Syntax
//!
//! ```text
//! #[browser]                                        // async, Default template
//! #[browser(sync)]                                  // blocking, Default template
//! #[browser(title = "My App")]                      // async, Default, custom title
//! #[browser(title = "T", body = "B")]               // async, Default, title + body
//! #[browser(tickbox)]                               // async, Tickbox template (all defaults)
//! #[browser(tickbox, title = "T", consent = "C")]   // async, Tickbox with arguments
//! #[browser(html = "<html>…</html>")]               // async, Custom template
//! #[browser(sync, html = "…")]                      // sync + Custom template
//! ```
//!
//! All arguments are optional and may appear in **any order**.
//!
//! ## Arguments
//!
//! | Argument | Type | Notes |
//! |---|---|---|
//! | `sync` | flag | Use the blocking `__location__` function; default uses `__location_async__().await` |
//! | `tickbox` | flag | Use `PageTemplate::Tickbox`; incompatible with `html` |
//! | `title = "…"` | string literal | Tab/heading title for Default or Tickbox |
//! | `body = "…"` | string literal | Body paragraph text for Default or Tickbox |
//! | `consent = "…"` | string literal | Checkbox label for Tickbox only |
//! | `html = "…"` | string literal | Use `PageTemplate::Custom`; **mutually exclusive** with all other template args |
//!
//! ## Expansion examples
//!
//! ```rust,ignore
//! use toolkit_zero::location::{browser, LocationData};
//!
//! // Async, Default template with a custom title:
//! async fn get_loc() -> Result<LocationData, Box<dyn std::error::Error>> {
//!     #[browser(title = "My App")]
//!     fn loc() {}
//!     // expands to:
//!     // let loc = ::toolkit_zero::location::browser::__location_async__(
//!     //     ::toolkit_zero::location::browser::PageTemplate::Default {
//!     //         title:     Some("My App".to_string()),
//!     //         body_text: None,
//!     //     }
//!     // ).await?;
//!     Ok(loc)
//! }
//!
//! // Sync, Tickbox with consent text:
//! fn get_loc_sync() -> Result<LocationData, Box<dyn std::error::Error>> {
//!     #[browser(sync, tickbox, consent = "I agree")]
//!     fn loc() {}
//!     // expands to:
//!     // let loc = ::toolkit_zero::location::browser::__location__(
//!     //     ::toolkit_zero::location::browser::PageTemplate::Tickbox {
//!     //         title:        None,
//!     //         body_text:    None,
//!     //         consent_text: Some("I agree".to_string()),
//!     //     }
//!     // )?;
//!     Ok(loc)
//! }
//! ```
//!
//! ---
//!
//! # `#[timelock]` — inline key derivation
//!
//! Replaces a `fn` item with an inline call to either
//! [`timelock`](toolkit_zero::encryption::timelock::timelock) (sync) or
//! [`timelock_async`](toolkit_zero::encryption::timelock::timelock_async)
//! (async — add the `async` flag). The 7 positional `Option<…>` arguments
//! are built from named keyword arguments, and the correct path
//! (*encryption* or *decryption*) is selected automatically.
//!
//! The function **name** becomes the binding; the function **body** is
//! discarded. A `?` propagates any
//! [`TimeLockError`](toolkit_zero::encryption::timelock::TimeLockError).
//!
//! ## Two paths
//!
//! | Path | Supply | Required args |
//! |---|---|---|
//! | **Encryption** | Explicit time → derive key | `precision`, `format`, `time`, `salts`, `kdf` |
//! | **Decryption** | Stored header → same key | `params` (a [`TimeLockParams`](toolkit_zero::encryption::timelock::TimeLockParams)) |
//!
//! ## Syntax
//!
//! ```text
//! // Encryption path
//! #[timelock(precision = Minute, format = Hour24, time(14, 37), salts = s, kdf = k)]
//! #[timelock(precision = Hour, format = Hour24, time(9, 0), salts = s, kdf = k,
//!            cadence = DayOfWeek(Tuesday))]
//! #[timelock(async, precision = Minute, format = Hour24, time(14, 37), salts = s, kdf = k)]
//!
//! // Decryption path
//! #[timelock(params = header)]
//! #[timelock(async, params = header)]
//! ```
//!
//! All arguments are keyword-based and may appear in **any order**.
//!
//! ## Arguments
//!
//! | Argument | Type | Notes |
//! |---|---|---|
//! | `async` | flag | Use `timelock_async().await?`; default uses `timelock()?` |
//! | `params = expr` | `TimeLockParams` | **Decryption path.** Mutually exclusive with all other args |
//! | `precision = …` | `Hour` \| `Quarter` \| `Minute` | Encryption. Time quantisation level |
//! | `format = …` | `Hour12` \| `Hour24` | Encryption. Clock representation |
//! | `time(h, m)` | two int literals | Encryption. Target time (24-hour `h` 0–23, `m` 0–59) |
//! | `cadence = …` | see below | Optional. Calendar constraint; defaults to `None` |
//! | `salts = expr` | `TimeLockSalts` | Encryption. Three 32-byte KDF salts |
//! | `kdf = expr` | `KdfParams` | Encryption. KDF work-factor parameters |
//!
//! ## Cadence variants
//!
//! ```text
//! cadence = None
//! cadence = DayOfWeek(Tuesday)
//! cadence = DayOfMonth(15)
//! cadence = MonthOfYear(January)
//! cadence = DayOfWeekInMonth(Tuesday, January)
//! cadence = DayOfMonthInMonth(15, January)
//! cadence = DayOfWeekAndDayOfMonth(Tuesday, 15)
//! ```
//!
//! ## Expansion examples
//!
//! ```rust,ignore
//! use toolkit_zero::encryption::timelock::*;
//!
//! // Encryption — derive key for 14:37 with Minute precision.
//! fn encrypt() -> Result<TimeLockKey, TimeLockError> {
//!     let salts = TimeLockSalts::generate();
//!     let kdf   = KdfPreset::Balanced.params();
//!
//!     #[timelock(precision = Minute, format = Hour24, time(14, 37), salts = salts, kdf = kdf)]
//!     fn enc_key() {}
//!     // let enc_key = timelock(
//!     //     Some(TimeLockCadence::None),
//!     //     Some(TimeLockTime::new(14, 37).unwrap()),
//!     //     Some(TimePrecision::Minute),
//!     //     Some(TimeFormat::Hour24),
//!     //     Some(salts), Some(kdf), None,
//!     // )?;
//!     Ok(enc_key)
//! }
//!
//! // Decryption — re-derive from a stored header.
//! fn decrypt(header: TimeLockParams) -> Result<TimeLockKey, TimeLockError> {
//!     #[timelock(params = header)]
//!     fn dec_key() {}
//!     // let dec_key = timelock(None, None, None, None, None, None, Some(header))?;
//!     Ok(dec_key)
//! }
//!
//! // Async encryption with a calendar cadence (Tuesdays only).
//! async fn async_encrypt() -> Result<TimeLockKey, TimeLockError> {
//!     let salts = TimeLockSalts::generate();
//!     let kdf   = KdfPreset::BalancedMac.params();
//!
//!     #[timelock(async,
//!                precision = Minute, format = Hour24, time(14, 37),
//!                cadence = DayOfWeek(Tuesday),
//!                salts = salts, kdf = kdf)]
//!     fn enc_key() {}
//!     Ok(enc_key)
//! }
//! ```
//!
//! ---
//!
//! # `#[dependencies]` — build-time fingerprint capture
//!
//! Embeds the `fingerprint.json` produced by `generate_fingerprint()` (feature
//! `dependency-graph-build`) into the binary and binds either the parsed
//! [`BuildTimeFingerprintData`](toolkit_zero::dependency_graph::capture::BuildTimeFingerprintData)
//! or the raw `&'static [u8]` JSON bytes.
//!
//! Apply the attribute to an **empty `fn`** inside a function body; the
//! function name becomes the `let` binding name. Requires the
//! `dependency-graph-capture` feature.
//!
//! ## Syntax
//!
//! ```text
//! #[dependencies]           // parse mode  → BuildTimeFingerprintData (propagates ?)
//! #[dependencies(bytes)]    // bytes mode  → &'static [u8]  (infallible)
//! ```
//!
//! ## Expansion
//!
//! Both modes expand to a `const` embedding followed by a `let` binding:
//!
//! ```rust,ignore
//! // Parse mode:
//! // const __TOOLKIT_ZERO_BUILD_TIME_FINGERPRINT__: &str =
//! //     include_str!(concat!(env!("OUT_DIR"), "/fingerprint.json"));
//! // let <binding> = capture::parse(__TOOLKIT_ZERO_BUILD_TIME_FINGERPRINT__)?;
//!
//! // Bytes mode:
//! // const __TOOLKIT_ZERO_BUILD_TIME_FINGERPRINT__: &str =
//! //     include_str!(concat!(env!("OUT_DIR"), "/fingerprint.json"));
//! // let <binding>: &'static [u8] = __TOOLKIT_ZERO_BUILD_TIME_FINGERPRINT__.as_bytes();
//! ```
//!
//! ## Examples
//!
//! ```rust,ignore
//! use toolkit_zero::dependency_graph::capture::dependencies;
//!
//! fn show_info() -> Result<(), Box<dyn std::error::Error>> {
//!     #[dependencies]
//!     fn data() {}
//!     println!("{} v{}", data.package.name, data.package.version);
//!     println!("target  : {}", data.build.target);
//!     println!("lock    : {}", data.cargo_lock_sha256);
//!     Ok(())
//! }
//!
//! fn raw_bytes() -> &'static [u8] {
//!     #[dependencies(bytes)]
//!     fn raw() {}
//!     raw
//! }
//! ```

#[allow(unused)]
use proc_macro::TokenStream;

#[cfg(feature = "socket-server")]
mod mechanism;
#[cfg(feature = "socket-client")]
mod request_macro;
#[cfg(feature = "serialization")]
mod serialization_macro;

// ─── socket-server ────────────────────────────────────────────────────────────

/// Declare a server-side route.
///
/// Available when the `socket-server` feature is enabled.
/// Re-exported as `toolkit_zero::socket::server::mechanism`.
///
/// Full documentation, parameter table, and worked examples are in the
/// [crate-level `#[mechanism]` section](self#mechanism--server-side-route-declaration).
#[cfg(feature = "socket-server")]
#[proc_macro_attribute]
pub fn mechanism(attr: TokenStream, item: TokenStream) -> TokenStream {
    mechanism::expand(attr, item)
}

// ─── socket-client ────────────────────────────────────────────────────────────

/// Emit an inline HTTP request and bind the response.
///
/// Available when the `socket-client` feature is enabled.
/// Re-exported as `toolkit_zero::socket::client::request`.
///
/// Full documentation, parameter table, and worked examples are in the
/// [crate-level `#[request]` section](self#request--client-side-request-shorthand).
#[cfg(feature = "socket-client")]
#[proc_macro_attribute]
pub fn request(attr: TokenStream, item: TokenStream) -> TokenStream {
    request_macro::expand(attr, item)
}

// ─── serialization ───────────────────────────────────────────────────────────

/// Derive `bincode::Encode + bincode::Decode` and inject `seal` / `open` methods.
///
/// Available when the `serialization` feature is enabled.
/// Re-exported as `toolkit_zero::serialization::serializable`.
///
/// Applies to structs and enums. Named struct fields annotated with
/// `#[serializable(key = "literal")]` additionally receive `seal_<field>` /
/// `open_<field>` helpers with the key baked in. Keys are moved in and
/// wrapped in `Zeroizing<String>`, wiping memory on drop.
///
/// Full documentation, expansion details, and examples are in the
/// [crate-level `#[serializable]` section](self#serializable--derive--inject-sealopen).
#[cfg(feature = "serialization")]
#[proc_macro_attribute]
pub fn serializable(attr: TokenStream, item: TokenStream) -> TokenStream {
    serialization_macro::expand_serializable(attr, item)
}

/// Emit an inline `seal()` call, binding the result or writing it to a file.
///
/// Available when the `serialization` feature is enabled.
/// Re-exported as `toolkit_zero::serialization::serialize`.
///
/// - **Variable mode** — the function name becomes the binding name; the
///   return type annotation (required) becomes the type of the `let` binding.
///   The function body is discarded.
///   ```text
///   #[serialize(source, key = my_key)]  fn blob() -> Vec<u8> {}
///   // expands to:  let blob: Vec<u8> = seal(&source, Some(my_key))?;
///   ```
///
/// - **File write mode** — triggered by `path = "..."`. Emits `fs::write(path, seal(…)?)?"`.
///   The function name and return type are ignored.
///   ```text
///   #[serialize(source, path = "out.bin")]  fn _() {}
///   ```
///
/// Full documentation and examples are in the
/// [crate-level `#[serialize]` section](self#serialize--inline-seal-statement).
#[cfg(feature = "serialization")]
#[proc_macro_attribute]
pub fn serialize(attr: TokenStream, item: TokenStream) -> TokenStream {
    serialization_macro::expand_serialize(attr, item)
}

/// Emit an inline `open()` call, decoding a blob or reading from a file.
///
/// Available when the `serialization` feature is enabled.
/// Re-exported as `toolkit_zero::serialization::deserialize`.
///
/// - **Variable mode** — `blob_expr` must be in scope; the function name
///   becomes the binding name; the return type (required) is used as the
///   turbofish type `T` in `open::<T>(…)`. The function body is discarded.
///   ```text
///   #[deserialize(blob)]  fn config() -> Config {}
///   // expands to:  let config: Config = open::<Config>(&blob, None)?;
///   ```
///
/// - **File read mode** — triggered by `path = "..."`. Reads the file first,
///   then passes the bytes to `open::<T>`. Return type still required.
///   ```text
///   #[deserialize(path = "config.bin")]  fn config() -> Config {}
///   ```
///
/// Full documentation and examples are in the
/// [crate-level `#[deserialize]` section](self#deserialize--inline-open-statement).
#[cfg(feature = "serialization")]
#[proc_macro_attribute]
pub fn deserialize(attr: TokenStream, item: TokenStream) -> TokenStream {
    serialization_macro::expand_deserialize(attr, item)
}

// ─── location-browser ────────────────────────────────────────────────────────

#[cfg(feature = "location-browser")]
mod browser_macro;

/// Replace a decorated `fn` with an inline location-capture statement.
///
/// Available when the `location` (or `location-browser`) feature is enabled.
/// Re-exported as `toolkit_zero::location::browser`.
///
/// The macro wraps either [`__location__`] (with `sync`) or
/// [`__location_async__`] (default) and builds the [`PageTemplate`] for you.
///
/// [`__location__`]: toolkit_zero::location::browser::__location__
/// [`__location_async__`]: toolkit_zero::location::browser::__location_async__
/// [`PageTemplate`]: toolkit_zero::location::browser::PageTemplate
///
/// ## Syntax
///
/// ```text
/// #[browser]                                        // async, Default template
/// #[browser(sync)]                                  // blocking, Default template
/// #[browser(title = "My App")]                      // async, custom title
/// #[browser(title = "T", body = "B")]               // async, title + body
/// #[browser(tickbox)]                               // async, Tickbox template
/// #[browser(tickbox, title = "T", consent = "C")]   // async, Tickbox with args
/// #[browser(html = "<html>…</html>")]               // async, Custom template
/// #[browser(sync, title = "T")]                     // sync + any variant
/// ```
///
/// All arguments are optional and may appear in **any order**.
///
/// ## Arguments
///
/// | Argument | Type | Notes |
/// |---|---|---|
/// | `sync` | flag | Use the blocking `__location__` function; default uses `__location_async__().await` |
/// | `tickbox` | flag | Use `PageTemplate::Tickbox`; default is `PageTemplate::Default` |
/// | `title = "…"` | string literal | Sets the `title` field on Default or Tickbox |
/// | `body = "…"` | string literal | Sets the `body_text` field on Default or Tickbox |
/// | `consent = "…"` | string literal | Sets the `consent_text` field on Tickbox only |
/// | `html = "…"` | string literal | Use `PageTemplate::Custom`; **mutually exclusive** with tickbox/title/body/consent |
///
/// ## What the macro expands to
///
/// The function's **name** becomes the binding; the body is discarded.
/// A `?` propagates any [`LocationError`](toolkit_zero::location::browser::LocationError).
///
/// ```rust,ignore
/// // Input:
/// #[browser(title = "My App")]
/// fn loc() -> LocationData {}
///
/// // Expanded to:
/// let loc = ::toolkit_zero::location::browser::__location_async__(
///     ::toolkit_zero::location::browser::PageTemplate::Default {
///         title:     ::std::option::Option::Some("My App".to_string()),
///         body_text: ::std::option::Option::None,
///     }
/// ).await?;
/// ```
///
/// Full documentation and examples are in the
/// [crate-level `#[browser]` section](self#browser--inline-location-capture).
#[cfg(feature = "location-browser")]
#[proc_macro_attribute]
pub fn browser(attr: TokenStream, item: TokenStream) -> TokenStream {
    browser_macro::expand_browser(attr, item)
}

// ─── enc-timelock-* ──────────────────────────────────────────────────────────

#[cfg(any(
    feature = "enc-timelock-keygen-now",
    feature = "enc-timelock-keygen-input",
    feature = "enc-timelock-async-keygen-now",
    feature = "enc-timelock-async-keygen-input",
))]
mod timelock_macro;

#[cfg(feature = "dep-graph-capture")]
mod dependencies_macro;

/// Replace a decorated `fn` with an inline time-locked key derivation call.
///
/// Available when any `enc-timelock-*` feature is enabled.
/// Re-exported as `toolkit_zero::encryption::timelock::timelock` (the macro).
///
/// Routes to either [`timelock`] (sync) or [`timelock_async`] (async — add
/// the `async` flag) and builds the positional `Option<…>` arguments for you.
///
/// [`timelock`]: toolkit_zero::encryption::timelock::timelock
/// [`timelock_async`]: toolkit_zero::encryption::timelock::timelock_async
///
/// ## Two paths
///
/// | Path | When to use | Required args |
/// |---|---|---|
/// | **Encryption** | Generate a key from an explicit time | `precision`, `format`, `time`, `salts`, `kdf` |
/// | **Decryption** | Re-derive a key from a stored header | `params` |
///
/// ## Syntax
///
/// ```text
/// // Encryption path
/// #[timelock(precision = Minute, format = Hour24, time(14, 37), salts = s, kdf = k)]
/// #[timelock(precision = Minute, format = Hour24, time(14, 37), salts = s, kdf = k,
///            cadence = DayOfWeek(Tuesday))]
/// #[timelock(async, precision = Minute, format = Hour24, time(14, 37), salts = s, kdf = k)]
///
/// // Decryption path
/// #[timelock(params = header)]
/// #[timelock(async, params = header)]
/// ```
///
/// ## Arguments
///
/// | Argument | Type | Notes |
/// |---|---|---|
/// | `async` | flag | Use `timelock_async().await?`; default uses `timelock()?` |
/// | `params = expr` | [`TimeLockParams`] | **Decryption path**. Mutually exclusive with all other args |
/// | `precision = …` | `Hour` \| `Quarter` \| `Minute` | Encryption path. Time quantisation level |
/// | `format = …` | `Hour12` \| `Hour24` | Encryption path. Clock representation |
/// | `time(h, m)` | two int literals | Encryption path. Target time (24-hour `h`, `m`) |
/// | `cadence = …` | variant or `None` | Optional; defaults to `None` (`TimeLockCadence::None`) |
/// | `salts = expr` | [`TimeLockSalts`] | Encryption path. Three 32-byte KDF salts |
/// | `kdf = expr` | [`KdfParams`] | Encryption path. KDF work-factor parameters |
///
/// [`TimeLockParams`]: toolkit_zero::encryption::timelock::TimeLockParams
/// [`TimeLockSalts`]:  toolkit_zero::encryption::timelock::TimeLockSalts
/// [`KdfParams`]:      toolkit_zero::encryption::timelock::KdfParams
///
/// ## Cadence variants
///
/// ```text
/// cadence = None
/// cadence = DayOfWeek(Tuesday)
/// cadence = DayOfMonth(15)
/// cadence = MonthOfYear(January)
/// cadence = DayOfWeekInMonth(Tuesday, January)
/// cadence = DayOfMonthInMonth(15, January)
/// cadence = DayOfWeekAndDayOfMonth(Tuesday, 15)
/// ```
///
/// ## What the macro expands to
///
/// ```rust,ignore
/// // Encryption path:
/// #[timelock(precision = Minute, format = Hour24, time(14, 37), salts = s, kdf = k)]
/// fn enc_key() {}
/// // expands to:
/// // let enc_key = ::toolkit_zero::encryption::timelock::timelock(
/// //     Some(TimeLockCadence::None),
/// //     Some(TimeLockTime::new(14, 37).unwrap()),
/// //     Some(TimePrecision::Minute),
/// //     Some(TimeFormat::Hour24),
/// //     Some(s), Some(k), None,
/// // )?;
///
/// // Decryption path:
/// #[timelock(params = header)]
/// fn dec_key() {}
/// // expands to:
/// // let dec_key = ::toolkit_zero::encryption::timelock::timelock(
/// //     None, None, None, None, None, None,
/// //     Some(header),
/// // )?;
/// ```
///
/// Full documentation and examples are in the
/// [crate-level `#[timelock]` section](self#timelock--inline-key-derivation).
#[cfg(any(
    feature = "enc-timelock-keygen-now",
    feature = "enc-timelock-keygen-input",
    feature = "enc-timelock-async-keygen-now",
    feature = "enc-timelock-async-keygen-input",
))]
#[proc_macro_attribute]
pub fn timelock(attr: TokenStream, item: TokenStream) -> TokenStream {
    timelock_macro::expand_timelock(attr, item)
}

// ─── #[dependencies] ──────────────────────────────────────────────────────────

/// Embed and parse (or read the raw bytes of) the build-time
/// `fingerprint.json` fingerprint in one expression.
///
/// Apply to an empty `fn`; the function name becomes the `let` binding in
/// the expansion. Requires the `dependency-graph-capture` feature.
///
/// ## Parse mode (default)
///
/// ```rust,ignore
/// use toolkit_zero::dependency_graph::capture::{dependencies, BuildTimeFingerprintData};
///
/// fn show() -> Result<(), Box<dyn std::error::Error>> {
///     #[dependencies]
///     fn data() {}
///     // expands to:
///     // const __TOOLKIT_ZERO_BUILD_TIME_FINGERPRINT__: &str =
///     //     include_str!(concat!(env!("OUT_DIR"), "/fingerprint.json"));
///     // let data = capture::parse(__TOOLKIT_ZERO_BUILD_TIME_FINGERPRINT__)?;
///
///     println!("{} v{}", data.package.name, data.package.version);
///     Ok(())
/// }
/// ```
///
/// ## Bytes mode
///
/// ```rust,ignore
/// fn raw_bytes() -> &'static [u8] {
///     #[dependencies(bytes)]
///     fn raw() {}
///     // expands to:
///     // const __TOOLKIT_ZERO_BUILD_TIME_FINGERPRINT__: &str =
///     //     include_str!(concat!(env!("OUT_DIR"), "/fingerprint.json"));
///     // let raw: &'static [u8] = __TOOLKIT_ZERO_BUILD_TIME_FINGERPRINT__.as_bytes();
///     raw
/// }
/// ```
///
/// Full documentation is in the
/// [crate-level `#[dependencies]` section](self#dependencies--build-time-fingerprint-capture).
#[cfg(feature = "dep-graph-capture")]
#[proc_macro_attribute]
pub fn dependencies(attr: TokenStream, item: TokenStream) -> TokenStream {
    dependencies_macro::expand_dependencies(attr, item)
}
