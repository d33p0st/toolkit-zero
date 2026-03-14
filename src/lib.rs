//! # toolkit-zero
//!
//! A feature-selective Rust utility toolkit.  Pull in only what you need via Cargo
//! feature flags — each feature compiles exactly the modules it requires and nothing
//! more.
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
//! 7. [Backend deps](#backend-deps-1)
//!
//! ---
//!
//! ## Feature flags
//!
//! | Feature | Enables | Exposes |
//! |---|---||---|
//! | `serialization` | VEIL cipher (seal / open) | [`serialization`] |
//! | `socket-server` | VEIL + typed HTTP server builder | [`socket::server`] |
//! | `socket-client` | VEIL + typed HTTP client builder | [`socket::client`] |
//! | `socket` | Both `socket-server` and `socket-client` | both |
//! | `location-native` | Browser-based geolocation | [`location::browser`] |
//! | `location` | Alias for `location-native` | [`location`] |
//! | `enc-timelock-keygen-now` | Time-lock key derivation from the system clock | [`encryption::timelock::derive_key_now`] |
//! | `enc-timelock-keygen-input` | Time-lock key derivation from a caller-supplied time | [`encryption::timelock::derive_key_at`] |
//! | `enc-timelock-async-keygen-now` | Async variant of `enc-timelock-keygen-now` | [`encryption::timelock::derive_key_now_async`] |
//! | `enc-timelock-async-keygen-input` | Async variant of `enc-timelock-keygen-input` | [`encryption::timelock::derive_key_at_async`] |
//! | `encryption` | All four `enc-timelock-*` features | [`encryption::timelock`] |
//! | `backend-deps` | Re-exports all third-party deps used by each active module | `*::backend_deps` |
//!
//! ```toml
//! [dependencies]
//! # Only the VEIL cipher
//! toolkit-zero = { version = "3", features = ["serialization"] }
//!
//! # HTTP server only
//! toolkit-zero = { version = "3", features = ["socket-server"] }
//!
//! # HTTP client only
//! toolkit-zero = { version = "3", features = ["socket-client"] }
//!
//! # Both sides of the socket
//! toolkit-zero = { version = "3", features = ["socket"] }
//!
//! # Geolocation (bundles socket-server automatically)
//! toolkit-zero = { version = "3", features = ["location"] }
//!
//! # Full time-lock encryption suite
//! toolkit-zero = { version = "3", features = ["encryption"] }
//!
//! # Re-export deps alongside socket-server
//! toolkit-zero = { version = "3", features = ["socket-server", "backend-deps"] }
//! ```
//!
//! ---
//!
//! ## Serialization
//!
//! The `serialization` feature exposes the **VEIL cipher** — a custom,
//! key-dependent binary codec that converts any [`bincode`]-encodable value into
//! an opaque byte sequence and back.
//!
//! The two entry points are [`serialization::seal`] and [`serialization::open`].
//! Every output byte depends on the full message and the key; without the exact
//! key, the output cannot be inverted.
//!
//! ```rust,ignore
//! use toolkit_zero::serialization::{seal, open, Encode, Decode};
//!
//! #[derive(Encode, Decode, Debug, PartialEq)]
//! struct Point { x: f64, y: f64 }
//!
//! let p = Point { x: 1.0, y: -2.0 };
//! let blob = seal(&p, None).unwrap();                          // default key
//! let back: Point = open(&blob, None).unwrap();
//! assert_eq!(p, back);
//!
//! let blob2 = seal(&p, Some("my-key")).unwrap();              // custom key
//! let back2: Point = open(&blob2, Some("my-key")).unwrap();
//! assert_eq!(p, back2);
//! ```
//!
//! ---
//!
//! ## Socket — server
//!
//! The `socket-server` feature exposes a fluent builder API for declaring typed
//! HTTP routes and serving them.  Start every route with [`socket::server::ServerMechanism`],
//! optionally add a JSON body expectation, URL query parameters, or shared state,
//! then finalise with `.onconnect(async_handler)`.  Register all routes on a
//! [`socket::server::Server`] and call `.serve(addr).await`.
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
//! VEIL-encrypted routes are also supported via
//! [`socket::server::ServerMechanism::encryption`] and
//! [`socket::server::ServerMechanism::encrypted_query`].
//! The body or query is decrypted before the handler is called; a wrong key or
//! corrupt payload returns `403 Forbidden` automatically.
//!
//! ---
//!
//! ## Socket — client
//!
//! The `socket-client` feature exposes a fluent [`socket::client::Client`] for
//! issuing typed HTTP requests.  Construct a client from a
//! [`socket::client::Target`] (a `localhost` port or a remote URL), pick an HTTP
//! method, optionally attach a body or query, and call `.send().await` (async) or
//! `.send_sync()` (blocking).
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
//! // Async-only client — safe inside #[tokio::main]
//! let client = Client::new_async(Target::Localhost(8080));
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
//! // Synchronous DELETE (Client::new_sync must be called outside any async runtime)
//! let _: Item = client.delete("/items/1").send_sync()?;
//! # Ok(())
//! # }
//! ```
//!
//! VEIL-encrypted requests are available via
//! [`socket::client::RequestBuilder::encryption`] and
//! [`socket::client::RequestBuilder::encrypted_query`].
//! The body or query parameters are sealed before the wire send; the response is
//! opened automatically.
//!
//! ---
//!
//! ## Location
//!
//! The `location` (or `location-native`) feature exposes browser-based geographic
//! coordinate acquisition.  A temporary local HTTP server is bound on a random
//! port, the system's default browser is opened to a consent page, and the
//! standard browser Geolocation API POSTs the coordinates back.  The server shuts
//! itself down once a result arrives.
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
//! The key is only reproducible when the same time value, precision, format,
//! and salts are provided.  Pair with an additional secret for a joint
//! time ✕ passphrase security model.
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
//! ```rust,no_run
//! use toolkit_zero::encryption::timelock::{
//!     timelock, TimeLockCadence,
//!     KdfPreset, TimeLockSalts, TimeLockTime,
//!     TimePrecision, TimeFormat,
//! };
//!
//! // Encryption side — caller picks the unlock time
//! let salts = TimeLockSalts::generate();
//! let at    = TimeLockTime::new(14, 30).unwrap();
//! let enc_key = timelock(
//!     TimeLockCadence::None,
//!     Some(at),
//!     TimePrecision::Minute,
//!     TimeFormat::Hour24,
//!     &salts,
//!     &KdfPreset::BalancedMac.params(),
//! ).unwrap();
//!
//! // Decryption side — re-derives from the current clock at 14:30 local time
//! let dec_key = timelock(
//!     TimeLockCadence::None,
//!     None,
//!     TimePrecision::Minute,
//!     TimeFormat::Hour24,
//!     &salts,
//!     &KdfPreset::BalancedMac.params(),
//! ).unwrap();
//! // enc_key.as_bytes() == dec_key.as_bytes() when called at 14:30 local time
//! ```
//!
//! ---
//!
//! ## Backend deps
//!
//! The `backend-deps` feature adds a `backend_deps` sub-module to every active
//! module.  Each `backend_deps` module re-exports with `pub use` every
//! third-party crate that its parent module uses internally.
//!
//! This lets downstream crates access those dependencies without declaring them
//! separately in their own `Cargo.toml`.
//!
//! | Module | Path | Re-exports |
//! |---|---|---|
//! | serialization | [`serialization::backend_deps`] | `bincode`, `base64` |
//! | socket (server) | [`socket::backend_deps`] | `bincode`, `base64`, `serde`, `tokio`, `log`, `bytes`, `serde_urlencoded`, `warp` |
//! | socket (client) | [`socket::backend_deps`] | `bincode`, `base64`, `serde`, `tokio`, `log`, `reqwest` |
//! | location | [`location::backend_deps`] | `tokio`, `serde`, `webbrowser`, `rand` |
//! | encryption (timelock) | [`encryption::timelock::backend_deps`] | `argon2`, `scrypt`, `zeroize`, `chrono`, `rand`; `tokio` (async variants only) |
//!
//! `backend-deps` on its own (without any other feature) compiles but exposes
//! nothing — the re-exports inside each `backend_deps` module are individually
//! gated on their parent feature.

#[cfg(any(feature = "socket", feature = "socket-server", feature = "socket-client"))]
pub mod socket;

#[cfg(any(feature = "location", feature = "location-native"))]
pub mod location;

#[cfg(feature = "serialization")]
pub mod serialization;

#[cfg(any(feature = "encryption", feature = "enc-timelock-keygen-now", feature = "enc-timelock-keygen-input", feature = "enc-timelock-async-keygen-now", feature = "enc-timelock-async-keygen-input"))]
pub mod encryption;