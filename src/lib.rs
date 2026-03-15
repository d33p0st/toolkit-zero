//! # toolkit-zero
//!
//! A feature-selective Rust utility crate. Declare only the functionality your
//! project requires via Cargo feature flags; each feature compiles exclusively
//! the code it depends on, with no extraneous overhead.
//!
//! ---
//!
//! ## Table of Contents
//!
//! 1. [Feature flags](#feature-flags)
//! 2. [Serialization](#serialization)
//! 3. [Socket — server](#socket--server)
//! 4. [Socket — client](#socket--client)
//! 5. [Location](#location)
//! 6. [Encryption — Timelock](#encryption--timelock)
//! 7. [Dependency Graph — BuildTimeFingerprint](#dependency-graph--buildtimefingerprint)
//! 8. [Backend deps](#backend-deps-1)
//!
//! ---
//!
//! ## Feature flags
//!
//! | Feature | Enables | Exposes |
//! |---|---|---|
//! | `serialization` | ChaCha20-Poly1305 authenticated encryption (seal / open) | [`serialization`] |
//! | `socket-server` | Authenticated encryption + typed HTTP server builder | [`socket::server`] |
//! | `socket-client` | Authenticated encryption + typed HTTP client builder | [`socket::client`] |
//! | `socket` | Both `socket-server` and `socket-client` | both |
//! | `location-browser` | Browser-based geolocation | [`location::browser`] |
//! | `location` | Alias for `location-browser` | [`location`] |
//! | `enc-timelock-keygen-now` | Time-lock key derivation from the system clock | [`encryption::timelock::derive_key_now`] |
//! | `enc-timelock-keygen-input` | Time-lock key derivation from a caller-supplied time | [`encryption::timelock::derive_key_at`] |
//! | `enc-timelock-async-keygen-now` | Async variant of `enc-timelock-keygen-now` | [`encryption::timelock::derive_key_now_async`] |
//! | `enc-timelock-async-keygen-input` | Async variant of `enc-timelock-keygen-input` | [`encryption::timelock::derive_key_at_async`] |
//! | `encryption` | All four `enc-timelock-*` features | [`encryption::timelock`] |
//! | `dependency-graph-build` | Attach a normalised dependency-graph snapshot (`fingerprint.json`) at build time | [`dependency_graph::build`] |
//! | `dependency-graph-capture` | Read the embedded `fingerprint.json` snapshot at runtime | [`dependency_graph::capture`] |
//! | `backend-deps` | Re-exports all third-party deps used by each active module | `*::backend_deps` |
//!
//! ```toml
//! [dependencies]
//! # ChaCha20-Poly1305 authenticated encryption (seal / open)
//! toolkit-zero = { version = "4", features = ["serialization"] }
//!
//! # HTTP server only
//! toolkit-zero = { version = "4", features = ["socket-server"] }
//!
//! # HTTP client only
//! toolkit-zero = { version = "4", features = ["socket-client"] }
//!
//! # Both sides of the socket
//! toolkit-zero = { version = "4", features = ["socket"] }
//!
//! # Geolocation (bundles socket-server automatically)
//! toolkit-zero = { version = "4", features = ["location"] }
//!
//! # Full time-lock encryption suite
//! toolkit-zero = { version = "4", features = ["encryption"] }
//!
//! # Attach build-time fingerprint in build.rs
//! # [build-dependencies]
//! toolkit-zero = { version = "4", features = ["dependency-graph-build"] }
//!
//! # Read build-time fingerprint at runtime
//! # [dependencies]
//! toolkit-zero = { version = "4", features = ["dependency-graph-capture"] }
//!
//! # Re-export deps alongside socket-server
//! toolkit-zero = { version = "4", features = ["socket-server", "backend-deps"] }
//! ```
//!
//! ---
//!
//! ## Serialization
//!
//! The `serialization` feature exposes **ChaCha20-Poly1305 authenticated encryption**
//! (IETF AEAD): [`serialization::seal`] encodes any [`bincode`]-encodable value and
//! encrypts it with a random 12-byte nonce; [`serialization::open`] verifies the
//! Poly1305 tag and decodes it back. A tampered ciphertext or wrong key is always
//! detected and rejected.
//!
//! Keys implement `AsRef<str>` — plain `&str` literals and `String` both work.
//! Key material is stored in `Zeroizing<String>` internally and wiped on drop.
//!
//! The two entry points are [`serialization::seal`] and [`serialization::open`].
//! Because a fresh nonce is generated per call, encrypting the same value twice
//! produces different ciphertexts (semantic security).
//!
//! Three attribute macros are also available via the `serialization` feature:
//!
//! | Macro | Purpose |
//! |---|---|
//! | [`serialization::serializable`] | derive `Encode+Decode` + inject `seal`/`open` methods |
//! | [`serialization::serialize`] | inline seal to a variable or a file |
//! | [`serialization::deserialize`] | inline open from a variable blob or a file |
//!
//! ```rust,ignore
//! use toolkit_zero::serialization::{seal, open, Encode, Decode};
//!
//! #[derive(Encode, Decode, Debug, PartialEq)]
//! struct Point { x: f64, y: f64 }
//!
//! let p = Point { x: 1.0, y: -2.0 };
//! let blob = seal(&p, None::<&str>).unwrap();      // default key
//! let back: Point = open(&blob, None::<&str>).unwrap();
//! assert_eq!(p, back);
//!
//! let blob2 = seal(&p, Some("my-key")).unwrap();   // &str key — no .to_string() needed
//! let back2: Point = open(&blob2, Some("my-key")).unwrap();
//! assert_eq!(p, back2);
//! ```
//!
//! ---
//!
//! ## Socket — server
//!
//! The `socket-server` feature exposes a fluent, type-safe builder API for
//! declaring and serving HTTP routes. Begin each route with
//! [`socket::server::ServerMechanism`], optionally attach a JSON body expectation,
//! URL query parameters, or shared state, then finalise with `.onconnect(handler)`.
//! Register routes on a [`socket::server::Server`] and serve them with a single
//! call to `.serve(addr).await`.
//!
//! The [`socket::server::reply!`] macro is the primary way to construct responses.
//!
//! ```rust,ignore
//! use toolkit_zero::socket::server::{Server, ServerMechanism, reply, Status};
//! use serde::{Deserialize, Serialize};
//! use std::sync::{Arc, Mutex};
//!
//! #[derive(Deserialize, Serialize, Clone)]
//! struct Item { id: u32, name: String }
//!
//! #[derive(Deserialize)]
//! struct NewItem { name: String }
//!
//! #[derive(Deserialize)]
//! struct Filter { page: u32 }
//!
//! # async fn run() {
//! let store: Arc<Mutex<Vec<Item>>> = Arc::new(Mutex::new(vec![]));
//!
//! let mut server = Server::default();
//! server
//!     // Plain GET — no body, no state
//!     .mechanism(
//!         ServerMechanism::get("/health")
//!             .onconnect(|| async { reply!() })
//!     )
//!     // POST with a JSON body
//!     .mechanism(
//!         ServerMechanism::post("/items")
//!             .json::<NewItem>()
//!             .onconnect(|body: NewItem| async move {
//!                 reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
//!             })
//!     )
//!     // GET with shared state
//!     .mechanism(
//!         ServerMechanism::get("/items")
//!             .state(store.clone())
//!             .onconnect(|state: Arc<Mutex<Vec<Item>>>| async move {
//!                 let items = state.lock().unwrap().clone();
//!                 reply!(json => items)
//!             })
//!     )
//!     // GET with URL query parameters
//!     .mechanism(
//!         ServerMechanism::get("/items/search")
//!             .query::<Filter>()
//!             .onconnect(|f: Filter| async move {
//!                 let _ = f.page;
//!                 reply!()
//!             })
//!     );
//!
//! server.serve(([127, 0, 0, 1], 8080)).await;
//! # }
//! ```
//!
//! Authenticated-encrypted routes are also supported via
//! [`socket::server::ServerMechanism::encryption`] and
//! [`socket::server::ServerMechanism::encrypted_query`].
//! The body or query is decrypted (ChaCha20-Poly1305) before the handler is called;
//! a wrong key or corrupt payload returns `403 Forbidden` automatically.
//!
//! ### Background server
//!
//! Call [`socket::server::Server::serve_managed`] to receive a
//! [`socket::server::BackgroundServer`] handle.  The server starts immediately;
//! the handle exposes [`addr()`](socket::server::BackgroundServer::addr),
//! [`rebind(addr)`](socket::server::BackgroundServer::rebind) (graceful restart on a
//! new port, all routes preserved),
//! [`mechanism(route)`](socket::server::BackgroundServer::mechanism) (hot-plug a new
//! route with no restart), and [`stop()`](socket::server::BackgroundServer::stop).
//!
//! ### `#[mechanism]` attribute macro
//!
//! The [`socket::server::mechanism`] attribute macro is a concise alternative to
//! the builder calls above. It replaces the decorated `async fn` in-place with the
//! equivalent `server.mechanism(...)` statement — no separate registration step
//! required. All 10 builder combinations are supported: plain, `json`, `query`,
//! `state`, `encrypted`, `encrypted_query`, and every `state + …` combination.
//!
//! ```rust,ignore
//! use toolkit_zero::socket::server::{Server, mechanism, reply, Status};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Deserialize)]
//! struct NewItem { name: String }
//!
//! #[derive(Serialize, Clone)]
//! struct Item { id: u32, name: String }
//!
//! # async fn run() {
//! let mut server = Server::default();
//!
//! #[mechanism(server, GET, "/health")]
//! async fn health() { reply!() }
//!
//! #[mechanism(server, POST, "/items", json)]
//! async fn create_item(body: NewItem) {
//!     reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
//! }
//!
//! server.serve(([127, 0, 0, 1], 8080)).await;
//! # }
//! ```
//!
//! See [`socket::server::mechanism`] for the full syntax reference.
//!
//! ---
//!
//! ## Socket — client
//!
//! The `socket-client` feature exposes a fluent [`socket::client::Client`] for
//! issuing HTTP requests. Construct a client from a
//! [`socket::client::Target`] (a localhost port or a remote URL), select an HTTP
//! method, optionally attach a body or query parameters, and call `.send().await`
//! (async) or `.send_sync()` (blocking).
//!
//! ```rust,ignore
//! use toolkit_zero::socket::client::{Client, Target};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Deserialize, Serialize, Clone)]
//! struct Item { id: u32, name: String }
//!
//! #[derive(Serialize)]
//! struct NewItem { name: String }
//!
//! #[derive(Serialize)]
//! struct Filter { page: u32 }
//!
//! # async fn run() -> Result<(), reqwest::Error> {
//! // Async-only client with a 5-second timeout — safe inside #[tokio::main]
//! use std::time::Duration;
//! use toolkit_zero::socket::client::ClientBuilder;
//! let client = ClientBuilder::new(Target::Localhost(8080))
//!     .timeout(Duration::from_secs(5))
//!     .build_async();
//!
//! // Plain GET
//! let items: Vec<Item> = client.get("/items").send().await?;
//!
//! // POST with JSON body
//! let created: Item = client
//!     .post("/items")
//!     .json(NewItem { name: "widget".into() })
//!     .send()
//!     .await?;
//!
//! // GET with query params
//! let page: Vec<Item> = client
//!     .get("/items")
//!     .query(Filter { page: 2 })
//!     .send()
//!     .await?;
//!
//! // Synchronous client — must be built outside any async runtime
//! let sync_client = ClientBuilder::new(Target::Localhost(8080)).build_sync();
//! let _: Item = sync_client.delete("/items/1").send_sync()?;
//! # Ok(())
//! # }
//! ```
//!
//! Authenticated-encrypted requests are available via
//! [`socket::client::RequestBuilder::encryption`] and
//! [`socket::client::RequestBuilder::encrypted_query`].
//! The body or query parameters are sealed (ChaCha20-Poly1305) before the wire send;
//! the sealed response is opened automatically.
//!
//! ### `#[request]` attribute macro
//!
//! The [`socket::client::request`] attribute macro is a concise alternative to
//! the builder calls above. It replaces the decorated `fn` in-place with a `let`
//! binding that performs the HTTP request. The **function name** becomes the
//! binding name; the **return type** becomes `R` in the `.send::<R>()` turbofish.
//! The function body is discarded. A return type annotation is **required**.
//!
//! All five builder modes are supported: plain, `json`, `query`, `encrypted`,
//! and `encrypted_query`. Each mode accepts either `async` (`.send::<R>().await?`)
//! or `sync` (`.send_sync::<R>()?`).
//!
//! ```rust,ignore
//! use toolkit_zero::socket::client::{ClientBuilder, Target, request};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Deserialize, Serialize, Clone)]
//! struct Item { id: u32, name: String }
//!
//! #[derive(Serialize)]
//! struct NewItem { name: String }
//!
//! # async fn run() -> Result<(), reqwest::Error> {
//! use std::time::Duration;
//! let client = ClientBuilder::new(Target::Localhost(8080))
//!     .timeout(Duration::from_secs(5))
//!     .build_async();
//!
//! // Plain async GET
//! #[request(client, GET, "/items", async)]
//! async fn items() -> Vec<Item> {}
//!
//! // POST with JSON body
//! #[request(client, POST, "/items", json(NewItem { name: "widget".into() }), async)]
//! async fn created() -> Item {}
//!
//! // Synchronous DELETE
//! #[request(client, DELETE, "/items/1", sync)]
//! fn deleted() -> Item {}
//! # Ok(())
//! # }
//! ```
//!
//! See [`socket::client::request`] for the full syntax reference.
//!
//! ---
//!
//! ## Location
//!
//! The `location` (or `location-browser`) feature provides browser-based geographic
//! coordinate acquisition. A temporary HTTP server is bound on a randomly assigned
//! local port, the system default browser is directed to a consent page, and the
//! coordinates are submitted via the standard Web Geolocation API. The server
//! shuts itself down upon receiving a result.
//!
//! Two entry points are available in [`location::browser`]:
//!
//! | Function | Context |
//! |---|---|
//! | [`location::browser::__location__`] | Blocking — safe from sync or async |
//! | [`location::browser::__location_async__`] | Async — preferred inside `#[tokio::main]` |
//!
//! ```rust,ignore
//! use toolkit_zero::location::browser::{__location__, __location_async__, PageTemplate};
//!
//! // Blocking — works from sync main or from inside a Tokio runtime
//! match __location__(PageTemplate::default()) {
//!     Ok(data) => println!("lat={:.6}  lon={:.6}  ±{:.0}m",
//!                          data.latitude, data.longitude, data.accuracy),
//!     Err(e)   => eprintln!("location error: {e}"),
//! }
//!
//! // Async — preferred when already inside #[tokio::main]
//! # async fn run() {
//! match __location_async__(PageTemplate::default()).await {
//!     Ok(data) => println!("lat={:.6}  lon={:.6}", data.latitude, data.longitude),
//!     Err(e)   => eprintln!("location error: {e}"),
//! }
//! # }
//! ```
//!
//! The [`location::browser::PageTemplate`] enum controls what the user sees:
//! a plain single-button page, a checkbox-gated variant, or a fully custom HTML
//! document.
//!
//! ### `#[browser]` attribute macro
//!
//! The [`location::browser::browser`] attribute macro is a concise alternative
//! to calling `__location__` / `__location_async__` directly. It replaces the
//! decorated `fn` item with an inline location-capture statement; the function
//! **name** becomes the binding that holds the resulting
//! [`location::browser::LocationData`], and the [`location::browser::PageTemplate`]
//! is built from the macro arguments.
//!
//! ```rust,ignore
//! use toolkit_zero::location::browser::{browser, LocationData, LocationError};
//!
//! async fn get_location() -> Result<LocationData, LocationError> {
//!     // async, plain Default template
//!     #[browser]
//!     fn loc() {}
//!     Ok(loc)
//! }
//!
//! async fn get_location_tickbox() -> Result<LocationData, LocationError> {
//!     // async, Tickbox with consent text
//!     #[browser(tickbox, title = "Verify Location", consent = "I agree")]
//!     fn loc() {}
//!     Ok(loc)
//! }
//!
//! fn get_location_sync() -> Result<LocationData, LocationError> {
//!     // blocking, custom title
//!     #[browser(sync, title = "My App")]
//!     fn loc() {}
//!     Ok(loc)
//! }
//! ```
//!
//! See [`location::browser::browser`] for the full argument reference.
//!
//! ---
//!
//! ## Encryption — Timelock
//!
//! The `encryption` feature (or any `enc-timelock-*` sub-feature) exposes a
//! **time-locked key derivation** scheme.  A 32-byte key is derived from a
//! time string through a three-pass KDF chain:
//!
//! > **Argon2id** (pass 1) → **scrypt** (pass 2) → **Argon2id** (pass 3)
//!
//! The key is reproducible only when the same time value, precision, format,
//! and salts are supplied. An additional passphrase may be incorporated for a
//! combined time × passphrase security model.
//!
//! **Features:**
//!
//! | Feature | Enables |
//! |---|---|
//! | `enc-timelock-keygen-now` | [`encryption::timelock::timelock`]`(None)` — decryption path (key from system clock) |
//! | `enc-timelock-keygen-input` | [`encryption::timelock::timelock`]`(Some(t))` — encryption path (key from explicit time) |
//! | `enc-timelock-async-keygen-now` | [`encryption::timelock::timelock_async`]`(None)` — async decryption path |
//! | `enc-timelock-async-keygen-input` | [`encryption::timelock::timelock_async`]`(Some(t))` — async encryption path |
//! | `encryption` | All four of the above |
//!
//! **Presets:** [`encryption::timelock::KdfPreset`] provides named parameter sets
//! tuned per platform: `Balanced`, `Paranoid`, `BalancedMac`, `ParanoidMac`,
//! `BalancedX86`, `ParanoidX86`, `BalancedArm`, `ParanoidArm`, and `Custom(KdfParams)`.
//!
//! ```rust,ignore
//! use toolkit_zero::encryption::timelock::*;
//!
//! // Encryption side — caller sets the unlock time
//! let salts = TimeLockSalts::generate();
//! let kdf   = KdfPreset::BalancedMac.params();
//! let at    = TimeLockTime::new(14, 30).unwrap();
//! // params = None → _at (encryption) path
//! let enc_key = timelock(
//!     Some(TimeLockCadence::None),
//!     Some(at),
//!     Some(TimePrecision::Minute),
//!     Some(TimeFormat::Hour24),
//!     Some(salts.clone()),
//!     Some(kdf),
//!     None,
//! ).unwrap();
//!
//! // Pack all settings (incl. salts + KDF params) into a self-contained header;
//! // store it in the ciphertext — salts and KDF params are not secret.
//! let header = pack(TimePrecision::Minute, TimeFormat::Hour24,
//!                   &TimeLockCadence::None, salts, kdf);
//!
//! // Decryption side — load header from ciphertext; call at 14:30 local time.
//! // params = Some(header) → _now (decryption) path
//! let dec_key = timelock(
//!     None, None, None, None, None, None,
//!     Some(header),
//! ).unwrap();
//! // enc_key.as_bytes() == dec_key.as_bytes() when called at 14:30 local time
//! ```
//!
//! ---
//!
//! ## Dependency Graph — BuildTimeFingerprint
//!
//! Two features; one for each side of the boundary.
//!
//! **`dependency-graph-build`** (goes in `[build-dependencies]`):
//! [`dependency_graph::build::generate_fingerprint`] runs `cargo metadata`, hashes
//! `Cargo.lock` and every `.rs` file under `src/`, captures the profile, target
//! triple, rustc version, and active features, then writes a compact, normalised
//! JSON document to `$OUT_DIR/fingerprint.json`. Pass `true` to also export a
//! pretty-printed copy alongside `Cargo.toml`.
//! [`dependency_graph::build::export`] optionally writes a pretty-printed copy
//! alongside `Cargo.toml` as a standalone call (useful when you want to combine it
//! with a separate `generate_fingerprint(false)` invocation).
//!
//! **`dependency-graph-capture`** (goes in `[dependencies]`):
//! [`dependency_graph::capture::parse`] deserialises the embedded snapshot into a
//! typed [`dependency_graph::capture::BuildTimeFingerprintData`] struct.
//!
//! ### `#[dependencies]` attribute macro
//!
//! The [`dependency_graph::capture::dependencies`] attribute macro is a concise
//! alternative to the manual `include_str!` + `parse()` boilerplate. Apply it to
//! an empty `fn`; the function name becomes the binding.
//!
//! ```rust,ignore
//! use toolkit_zero::dependency_graph::capture::dependencies;
//!
//! fn show() -> Result<(), Box<dyn std::error::Error>> {
//!     #[dependencies]             // → let data: BuildTimeFingerprintData = parse(...)?;
//!     fn data() {}
//!     println!("{} v{}", data.package.name, data.package.version);
//!     Ok(())
//! }
//!
//! fn raw() -> &'static [u8] {
//!     #[dependencies(bytes)]      // → let raw: &'static [u8] = include_str!(...).as_bytes();
//!     fn raw() {}
//!     raw
//! }
//! ```
//!
//! See [`dependency_graph::capture::dependencies`] for the full syntax reference.
//!
//! ### Sections captured in `fingerprint.json`
//!
//! | Section | Contents |
//! |---|---|
//! | `package` | crate name + version |
//! | `build` | profile, opt-level, target triple, rustc version, active feature flags |
//! | `deps` | full normalised `cargo metadata` graph (sorted, no absolute paths) |
//! | `cargo_lock_sha256` | SHA-256 of `Cargo.lock` (comment lines stripped) |
//! | `source` | SHA-256 of every `.rs` file under `src/` |
//!
//! ### Setup
//!
//! ```toml
//! [dependencies]
//! toolkit-zero = { version = "4", features = ["dependency-graph-capture"] }
//!
//! [build-dependencies]
//! toolkit-zero = { version = "4", features = ["dependency-graph-build"] }
//! ```
//!
//! `build.rs`:
//!
//! ```rust,ignore
//! fn main() {
//!     // Pass true to also export a pretty-printed copy alongside Cargo.toml.
//!     toolkit_zero::dependency_graph::build::generate_fingerprint(cfg!(debug_assertions))
//!         .expect("fingerprint generation failed");
//! }
//! ```
//!
//! `src/main.rs` (or any binary):
//!
//! ```rust,ignore
//! use toolkit_zero::dependency_graph::capture;
//!
//! const BUILD_TIME_FINGERPRINT: &str = include_str!(concat!(env!("OUT_DIR"), "/fingerprint.json"));
//!
//! fn main() {
//!     let data = capture::parse(BUILD_TIME_FINGERPRINT).expect("failed to parse fingerprint");
//!     println!("{} v{}", data.package.name, data.package.version);
//!     println!("target : {}", data.build.target);
//!     println!("lock   : {}", data.cargo_lock_sha256);
//!
//!     let raw: &[u8] = BUILD_TIME_FINGERPRINT.as_bytes();
//!     println!("{} bytes", raw.len());
//! }
//! ```
//!
//! ### Risks and considerations
//!
//! * **Not tamper-proof** — the fingerprint is embedded as plain text in the
//!   binary's read-only data section and is readable by anyone with access to
//!   the binary. It is informational in nature; it does not constitute a
//!   security boundary.
//! * **Export file** — `export(true)` writes `fingerprint.json` to the crate root.
//!   Add it to `.gitignore` to prevent accidental commits.
//! * **Build-time overhead** — `cargo metadata` runs on every rebuild triggered
//!   by the `cargo:rerun-if-changed` directives (changes to `src/`, `Cargo.toml`,
//!   or `Cargo.lock`).
//! * **Feature scope** — `build.features` captures active features of the crate
//!   being built, not toolkit-zero's own features.
//! * **Path stripping** — absolute and machine-specific paths are removed from
//!   `cargo metadata` output so the fingerprint is stable across machines.
//! * **Compile-time only** — the snapshot reflects the build environment at
//!   compile time; it does not change at runtime.
//!
//! ---
//!
//! ## Backend deps
//!
//! The `backend-deps` feature appends a `backend_deps` sub-module to each active
//! module. Every such sub-module re-exports via `pub use` all third-party crates
//! used internally by the parent module, allowing downstream crates to access
//! those dependencies without separate `Cargo.toml` declarations.
//!
//! | Module | Path | Re-exports |
//! |---|---|---|
//! | serialization | [`serialization::backend_deps`] | `bincode`, `base64`, `zeroize` |
//! | socket (server) | [`socket::backend_deps`] | `bincode`, `base64`, `serde`, `tokio`, `log`, `bytes`, `serde_urlencoded`, `hyper`, `hyper_util`, `http`, `http_body_util` |
//! | socket (client) | [`socket::backend_deps`] | `bincode`, `base64`, `serde`, `tokio`, `log`, `reqwest` |
//! | location | [`location::backend_deps`] | `tokio`, `serde`, `webbrowser`, `rand` |
//! | encryption (timelock) | [`encryption::timelock::backend_deps`] | `argon2`, `scrypt`, `zeroize`, `chrono`, `rand`; `tokio` (async variants only) |
//! | dependency_graph | [`dependency_graph::backend_deps`] | `serde_json`; `sha2` (build side only) |
//!
//! Enabling `backend-deps` without any other feature compiles successfully but
//! exposes no symbols; every re-export within `backend_deps` is individually
//! gated on the corresponding parent feature.

#[cfg(any(feature = "socket", feature = "socket-server", feature = "socket-client"))]
pub mod socket;

#[cfg(any(feature = "location", feature = "location-browser"))]
pub mod location;

#[cfg(feature = "serialization")]
pub mod serialization;

#[cfg(any(feature = "encryption", feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub mod encryption;

#[cfg(any(feature = "dependency-graph-build", feature = "dependency-graph-capture"))]
#[path = "dependency-graph/mod.rs"]
pub mod dependency_graph;