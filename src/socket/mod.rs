//! HTTP server and client utilities, selectively compiled via Cargo features.
//!
//! This module exposes two sub-modules behind feature flags:
//!
//! | Sub-module | Feature flag(s) |
//! |---|---|
//! | [`server`] | `socket` or `socket-server` |
//! | [`client`] | `socket` or `socket-client` |
//!
//! Enable `socket` to get both, or opt into only one side with `socket-server` / `socket-client`.
//!
//! # Server
//!
//! Build typed HTTP routes using a fluent builder chain starting from [`server::ServerMechanism`].
//! Routes are registered on a [`server::Server`] and served with a single `.await`.
//!
//! The chain supports:
//! - **No extras** — handler receives no arguments
//! - **JSON body** — via `.json::<T>()`, handler receives `T: DeserializeOwned`
//! - **Query params** — via `.query::<T>()`, handler receives `T: DeserializeOwned`
//! - **Shared state** — via `.state(s)`, handler receives a clone of `S`
//! - **State + JSON / State + query** — combinations of the above
//!
//! Each branch finalises with `.onconnect(async handler)` or the unsafe `.onconnect_sync(sync handler)`.
//! Use the [`reply!`] macro (or standalone helpers) to construct the response.
//!
//! ```rust,no_run
//! # use toolkit_zero::socket::server::*;
//! # use serde::{Deserialize, Serialize};
//! # #[derive(Deserialize, Serialize)] struct Item { id: u32, name: String }
//! # #[derive(Deserialize)] struct NewItem { name: String }
//! # #[derive(Deserialize)] struct Filter { page: u32 }
//! # use std::sync::{Arc, Mutex};
//!
//! let store: Arc<Mutex<Vec<Item>>> = Arc::new(Mutex::new(vec![]));
//!
//! let mut server = Server::default();
//! server
//!     .mechanism(
//!         ServerMechanism::get("/health")
//!             .onconnect(|| async { reply!() })
//!     )
//!     .mechanism(
//!         ServerMechanism::post("/items")
//!             .json::<NewItem>()
//!             .onconnect(|body| async move {
//!                 let item = Item { id: 1, name: body.name };
//!                 reply!(json => item, status => Status::Created)
//!             })
//!     )
//!     .mechanism(
//!         ServerMechanism::get("/items")
//!             .state(store.clone())
//!             .onconnect(|state| async move {
//!                 let items = state.lock().unwrap().clone();
//!                 reply!(json => items)
//!             })
//!     )
//!     .mechanism(
//!         ServerMechanism::get("/items/search")
//!             .query::<Filter>()
//!             .onconnect(|filter| async move {
//!                 let _ = filter.page;
//!                 reply!()
//!             })
//!     );
//!
//! // server.serve(([0, 0, 0, 0], 8080)).await;
//! ```
//!
//! # Client
//!
//! Make typed HTTP requests using a fluent builder chain starting from [`client::Client`].
//! The full URL is constructed automatically from a [`client::Target`] (localhost port or remote URL)
//! and the endpoint string. Both async (`.send()`) and sync (`.send_sync()`) are supported.
//!
//! The chain supports:
//! - **Plain** — no body, no query
//! - **JSON body** — via `.json(value)`, serialises with `serde`
//! - **Query params** — via `.query(value)`, serialised into the URL query string
//!
//! All seven HTTP methods are available: `get`, `post`, `put`, `delete`, `patch`, `head`, `options`.
//!
//! ```rust,no_run
//! # use toolkit_zero::socket::client::*;
//! # use toolkit_zero::socket::server::*;
//! # use serde::{Deserialize, Serialize};
//! # #[derive(Deserialize, Serialize, Clone)] struct Item { id: u32, name: String }
//! # #[derive(Deserialize, Serialize)] struct NewItem { name: String }
//! # #[derive(Deserialize, Serialize)] struct Filter { page: u32 }
//! # async fn example() -> Result<(), reqwest::Error> {
//!
//! let client = Client::new(Target::Localhost(8080));
//!
//! // ── GET /items ───────────────────────────────────────────────────────────
//! // Server:
//! //   ServerMechanism::get("/items")
//! //       .onconnect(|| async {
//! //           let items: Vec<Item> = vec![];
//! //           reply!(json => items)
//! //       })
//! let items: Vec<Item> = client.get("/items").send().await?;
//!
//! // ── POST /items  (JSON body) ──────────────────────────────────────────────
//! // Server:
//! //   ServerMechanism::post("/items")
//! //       .json::<NewItem>()
//! //       .onconnect(|body| async move {
//! //           let item = Item { id: 1, name: body.name };
//! //           reply!(json => item, status => Status::Created)
//! //       })
//! let created: Item = client
//!     .post("/items")
//!     .json(NewItem { name: "widget".to_string() })
//!     .send()
//!     .await?;
//!
//! // ── GET /items  (query params) ────────────────────────────────────────────
//! // Server:
//! //   ServerMechanism::get("/items")
//! //       .query::<Filter>()
//! //       .onconnect(|filter| async move {
//! //           let _ = filter.page;
//! //           reply!(json => Vec::<Item>::new())
//! //       })
//! let page: Vec<Item> = client
//!     .get("/items")
//!     .query(Filter { page: 2 })
//!     .send()
//!     .await?;
//!
//! // ── DELETE /items/1  (sync) ───────────────────────────────────────────────
//! // Server:
//! //   ServerMechanism::delete("/items/1")
//! //       .onconnect(|| async {
//! //           reply!(message => warp::reply(), status => Status::NoContent)
//! //       })
//! let _: Item = client.delete("/items/1").send_sync()?;
//!
//! # Ok(())
//! # }
//! ```

// ─── Serialization key (shared by server and client) ────────────────────────

/// Controls which VEIL key is used when the body or query parameters are sealed.
///
/// Pass this to [`server::ServerMechanism::encryption`], [`server::ServerMechanism::encrypted_query`],
/// [`client::RequestBuilder::encryption`], and [`client::RequestBuilder::encrypted_query`].
/// For plain-JSON routes use the existing `.json()` / `.query()` builder methods instead.
///
/// | Variant | Wire format | Trait requirements on `T` |
/// |---|---|---|
/// | `Default` | VEIL-sealed bytes (`application/octet-stream`) | `bincode::Encode` / `Decode<()>` |
/// | `Value(key)` | VEIL-sealed bytes with a custom key | `bincode::Encode` / `Decode<()>` |
#[derive(Clone)]
pub enum SerializationKey {
    /// Use the built-in default VEIL key (`"serialization/deserialization"`).
    Default,
    /// Use a custom VEIL key shared by both client and server.
    Value(String),
}

impl SerializationKey {
    #[doc(hidden)]
    pub fn veil_key(&self) -> Option<&str> {
        match self {
            Self::Default => None,
            Self::Value(k) => Some(k.as_str()),
        }
    }
}

#[cfg(feature = "socket-server")]
pub mod server;

#[cfg(feature = "socket-client")]
pub mod client;

#[cfg(any(feature = "socket-server", feature = "socket-client"))]
pub mod prelude;

#[cfg(feature = "backend-deps")]
pub mod backend_deps;