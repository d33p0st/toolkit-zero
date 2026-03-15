
//! Typed, fluent HTTP client.
//!
//! This module provides a builder-oriented API for issuing HTTP requests
//! against a configurable [`Target`] — a `localhost` port or an arbitrary
//! remote base URL — and deserialising the response body into a concrete Rust
//! type via [`serde`].
//!
//! The entry point is [`Client`]. Call any method constructor
//! ([`get`](Client::get), [`post`](Client::post), etc.) to obtain a
//! [`RequestBuilder`]. Optionally attach a JSON body via
//! [`json`](RequestBuilder::json) or URL query parameters via
//! [`query`](RequestBuilder::query), then finalise with
//! [`send`](RequestBuilder::send) (async) or
//! [`send_sync`](RequestBuilder::send_sync) (blocking).
//! All seven standard HTTP methods are supported.
//!
//! # Builder chains at a glance
//!
//! | Chain | Sends |
//! |---|---|
//! | `client.method(endpoint).send().await` | plain request |
//! | `.json(value).send().await` | `Content-Type: application/json` body |
//! | `.query(params).send().await` | serialised query string |
//!
//! # Example
//!
//! ```rust,no_run
//! use toolkit_zero::socket::client::{Client, Target};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Deserialize, Serialize)] struct Item { id: u32, name: String }
//! #[derive(Serialize)] struct NewItem { name: String }
//! #[derive(Serialize)] struct Filter { page: u32 }
//!
//! # async fn run() -> Result<(), reqwest::Error> {
//! let client = Client::new_async(Target::Localhost(8080));
//!
//! // Plain async GET
//! let items: Vec<Item> = client.get("/items").send().await?;
//!
//! // POST with a JSON body
//! let created: Item = client
//!     .post("/items")
//!     .json(NewItem { name: "widget".into() })
//!     .send()
//!     .await?;
//!
//! // GET with query parameters
//! let page: Vec<Item> = client
//!     .get("/items")
//!     .query(Filter { page: 2 })
//!     .send()
//!     .await?;
//!
//! // Synchronous DELETE
//! let _: Item = client.delete("/items/1").send_sync()?;
//! # Ok(())
//! # }
//! ```

use reqwest::{Client as AsyncClient, blocking::Client as BlockingClient};
use serde::{Serialize, de::DeserializeOwned};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crate::socket::SerializationKey;
use crate::serialization::SerializationError;

pub use toolkit_zero_macros::request;

fn build_url(base: &str, endpoint: &str) -> String {
    let ep = endpoint.trim_start_matches('/');
    if ep.is_empty() {
        base.trim_end_matches('/').to_owned()
    } else {
        format!("{}/{}", base.trim_end_matches('/'), ep)
    }
}

#[derive(Clone, Copy, Debug)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl HttpMethod {
    fn apply_async(&self, client: &AsyncClient, url: &str) -> reqwest::RequestBuilder {
        match self {
            HttpMethod::Get     => client.get(url),
            HttpMethod::Post    => client.post(url),
            HttpMethod::Put     => client.put(url),
            HttpMethod::Delete  => client.delete(url),
            HttpMethod::Patch   => client.patch(url),
            HttpMethod::Head    => client.head(url),
            HttpMethod::Options => client.request(reqwest::Method::OPTIONS, url),
        }
    }

    fn apply_sync(&self, client: &BlockingClient, url: &str) -> reqwest::blocking::RequestBuilder {
        match self {
            HttpMethod::Get     => client.get(url),
            HttpMethod::Post    => client.post(url),
            HttpMethod::Put     => client.put(url),
            HttpMethod::Delete  => client.delete(url),
            HttpMethod::Patch   => client.patch(url),
            HttpMethod::Head    => client.head(url),
            HttpMethod::Options => client.request(reqwest::Method::OPTIONS, url),
        }
    }
}

/// The target server for a [`Client`].
#[derive(Clone)]
pub enum Target {
    /// A locally running server. Provide the port number.
    Localhost(u16),
    /// A remote server. Provide the full base URL (e.g. `"https://example.com"`).
    Remote(String),
}

/// HTTP client for making typed requests against a [`Target`] server.
///
/// A `Client` is created in one of three modes depending on which send variants you need:
///
/// | Constructor | `send()` (async) | `send_sync()` (blocking) | Safe in async context |
/// |---|---|---|---|
/// | [`Client::new_async`] | ✓ | ✗ | ✓ |
/// | [`Client::new_sync`] | ✗ | ✓ | ✓ |
/// | [`Client::new`] | ✓ | ✓ | ✗ — panics if called inside a tokio runtime |
///
/// `reqwest::blocking::Client` internally creates its own single-threaded tokio runtime. If
/// you call `Client::new()` (or `Client::new_sync()`) from within an existing async context
/// (e.g. inside `#[tokio::main]`) it will panic. Use `Client::new_async()` when your program
/// is async-first and only call `Client::new_sync()` / `Client::new()` before entering any
/// async runtime.
///
/// # Example
/// ```rust,no_run
/// # use toolkit_zero::socket::client::{Client, Target};
/// # use serde::{Deserialize, Serialize};
/// # #[derive(Deserialize)] struct Item { id: u32, name: String }
/// # #[derive(Serialize)] struct NewItem { name: String }
/// # async fn example() -> Result<(), reqwest::Error> {
/// // Async-only client — safe inside #[tokio::main]
/// let client = Client::new_async(Target::Localhost(8080));
///
/// let items: Vec<Item> = client.get("/items").send().await?;
/// let created: Item = client.post("/items").json(NewItem { name: "w".into() }).send().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Client {
    target: Target,
    async_client: Option<AsyncClient>,
    sync_client: Option<BlockingClient>,
}

impl Client {
    /// Creates an **async-only** client. Safe to call from any context, including inside
    /// `#[tokio::main]`. Calling `.send_sync()` on builders from this client will panic.
    pub fn new_async(target: Target) -> Self {
        log::debug!("Creating async-only client");
        Self { target, async_client: Some(AsyncClient::new()), sync_client: None }
    }

    /// Creates a **sync-only** client. **Must not** be called from within an async context
    /// (inside `#[tokio::main]` or similar) — doing so panics. Calling `.send()` on builders
    /// from this client will panic with a message pointing to [`Client::new_async`].
    ///
    /// # Panics
    ///
    /// Panics at construction time if called inside a tokio runtime (same restriction as
    /// `reqwest::blocking::Client`). Prefer [`Client::new_async`] for async contexts.
    pub fn new_sync(target: Target) -> Self {
        log::debug!("Creating sync-only client");
        Self { target, async_client: None, sync_client: Some(BlockingClient::new()) }
    }

    /// Creates a client supporting **both** async and blocking sends.
    ///
    /// # Panics
    ///
    /// **Panics immediately if called from within an async context** (e.g. inside
    /// `#[tokio::main]`, `tokio::spawn`, or any `.await` call chain). This happens because
    /// `reqwest::blocking::Client` creates its own internal tokio runtime, and Rust/tokio
    /// forbids nesting two runtimes in the same thread.
    ///
    /// If you are in an async context, use [`Client::new_async`] instead.
    /// If you only need blocking calls, use [`Client::new_sync`] **before** entering any runtime.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::client::{Client, Target};
    /// // Correct — called from synchronous main before any async runtime starts
    /// fn main() {
    ///     let client = Client::new(Target::Localhost(8080));
    ///     // ... use client.send_sync() and client.send() via manual runtime
    /// }
    ///
    /// // WRONG — will panic at runtime:
    /// // #[tokio::main]
    /// // async fn main() { let client = Client::new(...); }  // panics!
    /// ```
    pub fn new(target: Target) -> Self {
        // Detect async context early: tokio sets a thread-local when a runtime is active.
        // try_current() succeeds only if we are already inside a tokio runtime — exactly
        // the forbidden case for BlockingClient, so we panic with an actionable message.
        if tokio::runtime::Handle::try_current().is_ok() {
            panic!(
                "Client::new() called inside an async context (tokio runtime detected). \
                 BlockingClient cannot be created inside an existing runtime.\n\
                 → Use Client::new_async(target) if you only need .send() (async).\n\
                 → Use Client::new_sync(target) called before entering any async runtime if you only need .send_sync()."
            );
        }
        log::debug!("Creating dual async+sync client");
        Self {
            target,
            async_client: Some(AsyncClient::new()),
            sync_client: Some(BlockingClient::new()),
        }
    }

    fn async_client(&self) -> &AsyncClient {
        self.async_client.as_ref()
            .expect("Client was created with new_sync() — call new_async() or new() to use async sends")
    }

    fn sync_client(&self) -> &BlockingClient {
        self.sync_client.as_ref()
            .expect("Client was created with new_async() — call new_sync() or new() to use sync sends")
    }

    /// Returns the base URL derived from the configured [`Target`].
    pub fn base_url(&self) -> String {
        match &self.target {
            Target::Localhost(port) => format!("http://localhost:{}", port),
            Target::Remote(url) => url.clone(),
        }
    }

    fn builder(&self, method: HttpMethod, endpoint: impl Into<String>) -> RequestBuilder<'_> {
        RequestBuilder::new(self, method, endpoint)
    }

    /// Starts a `GET` request builder for `endpoint`.
    pub fn get(&self, endpoint: impl Into<String>) -> RequestBuilder<'_> {
        self.builder(HttpMethod::Get, endpoint)
    }

    /// Starts a `POST` request builder for `endpoint`.
    pub fn post(&self, endpoint: impl Into<String>) -> RequestBuilder<'_> {
        self.builder(HttpMethod::Post, endpoint)
    }

    /// Starts a `PUT` request builder for `endpoint`.
    pub fn put(&self, endpoint: impl Into<String>) -> RequestBuilder<'_> {
        self.builder(HttpMethod::Put, endpoint)
    }

    /// Starts a `DELETE` request builder for `endpoint`.
    pub fn delete(&self, endpoint: impl Into<String>) -> RequestBuilder<'_> {
        self.builder(HttpMethod::Delete, endpoint)
    }

    /// Starts a `PATCH` request builder for `endpoint`.
    pub fn patch(&self, endpoint: impl Into<String>) -> RequestBuilder<'_> {
        self.builder(HttpMethod::Patch, endpoint)
    }

    /// Starts a `HEAD` request builder for `endpoint`.
    pub fn head(&self, endpoint: impl Into<String>) -> RequestBuilder<'_> {
        self.builder(HttpMethod::Head, endpoint)
    }

    /// Starts an `OPTIONS` request builder for `endpoint`.
    pub fn options(&self, endpoint: impl Into<String>) -> RequestBuilder<'_> {
        self.builder(HttpMethod::Options, endpoint)
    }
}

/// A request builder with no body or query parameters attached.
///
/// Obtained from any [`Client`] method constructor. Attach a JSON body via
/// [`json`](RequestBuilder::json) or query parameters via [`query`](RequestBuilder::query),
/// or finalise directly with [`send`](RequestBuilder::send) /
/// [`send_sync`](RequestBuilder::send_sync).
pub struct RequestBuilder<'a> {
    client: &'a Client,
    method: HttpMethod,
    endpoint: String,
}

impl<'a> RequestBuilder<'a> {
    fn new(client: &'a Client, method: HttpMethod, endpoint: impl Into<String>) -> Self {
        let endpoint = endpoint.into();
        log::debug!("Building {:?} request for endpoint '{}'", method, endpoint);
        Self { client, method, endpoint }
    }

    /// Attaches a JSON-serialisable body, transitioning to [`JsonRequestBuilder`].
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::client::Client;
    /// # use serde::{Deserialize, Serialize};
    /// # #[derive(Serialize)] struct NewItem { name: String }
    /// # #[derive(Deserialize)] struct Item { id: u32, name: String }
    /// # async fn example(client: &Client) -> Result<(), reqwest::Error> {
    /// let item: Item = client
    ///     .post("/items")
    ///     .json(NewItem { name: "widget".to_string() })
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn json<T: Serialize>(self, body: T) -> JsonRequestBuilder<'a, T> {
        log::trace!("Attaching JSON body to {:?} request for '{}'", self.method, self.endpoint);
        JsonRequestBuilder { client: self.client, method: self.method, endpoint: self.endpoint, body }
    }

    /// Attaches query parameters that serialise into the URL query string, transitioning to
    /// [`QueryRequestBuilder`].
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::client::Client;
    /// # use serde::{Deserialize, Serialize};
    /// # #[derive(Serialize)] struct SearchParams { q: String, page: u32 }
    /// # #[derive(Deserialize)] struct SearchResult { items: Vec<String> }
    /// # async fn example(client: &Client) -> Result<(), reqwest::Error> {
    /// let results: SearchResult = client
    ///     .get("/search")
    ///     .query(SearchParams { q: "rust".to_string(), page: 1 })
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn query<T: Serialize>(self, params: T) -> QueryRequestBuilder<'a, T> {
        log::trace!("Attaching query params to {:?} request for '{}'", self.method, self.endpoint);
        QueryRequestBuilder { client: self.client, method: self.method, endpoint: self.endpoint, params }
    }

    /// Sends the request asynchronously and deserialises the response body as `R`.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::client::Client;
    /// # use serde::Deserialize;
    /// # #[derive(Deserialize)] struct User { id: u32, name: String }
    /// # async fn example(client: &Client) -> Result<(), reqwest::Error> {
    /// let user: User = client.get("/users/1").send().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send<R: DeserializeOwned>(self) -> Result<R, reqwest::Error> {
        let url = build_url(&self.client.base_url(), &self.endpoint);
        log::info!("Sending async {:?} to '{}'", self.method, url);
        let resp = self.method.apply_async(&self.client.async_client(), &url)
            .send().await?;
        log::debug!("Response status: {}", resp.status());
        resp.json::<R>().await
    }

    /// Sends the request synchronously and deserialises the response body as `R`.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::client::Client;
    /// # use serde::Deserialize;
    /// # #[derive(Deserialize)] struct User { id: u32, name: String }
    /// # fn example(client: &Client) -> Result<(), reqwest::Error> {
    /// let user: User = client.get("/users/1").send_sync()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send_sync<R: DeserializeOwned>(self) -> Result<R, reqwest::Error> {
        let url = build_url(&self.client.base_url(), &self.endpoint);
        log::info!("Sending sync {:?} to '{}'", self.method, url);
        let resp = self.method.apply_sync(&self.client.sync_client(), &url)
            .send()?;
        log::debug!("Response status: {}", resp.status());
        resp.json::<R>()
    }

    /// Attaches an authenticated-encrypted body (ChaCha20-Poly1305), transitioning to
    /// [`EncryptedBodyRequestBuilder`].
    ///
    /// The body is sealed with the given [`SerializationKey`] and sent as
    /// `application/octet-stream`; the response is opened with the same key.
    /// For plain-JSON routes use `.json(body)` instead.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::client::Client;
    /// # use bincode::{Encode, Decode};
    /// # #[derive(Encode)] struct Req { value: i32 }
    /// # #[derive(Decode)] struct Resp { result: i32 }
    /// # async fn example(client: &Client) -> Result<(), toolkit_zero::socket::client::ClientError> {
    /// use toolkit_zero::socket::SerializationKey;
    /// let resp: Resp = client
    ///     .post("/compute")
    ///     .encryption(Req { value: 42 }, SerializationKey::Default)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn encryption<T: bincode::Encode>(self, body: T, key: SerializationKey) -> EncryptedBodyRequestBuilder<'a, T> {
        log::trace!("Attaching encrypted body to {:?} request for '{}'", self.method, self.endpoint);
        EncryptedBodyRequestBuilder { client: self.client, method: self.method, endpoint: self.endpoint, body, key }
    }

    /// Attaches authenticated-encrypted query parameters (ChaCha20-Poly1305), transitioning
    /// to [`EncryptedQueryRequestBuilder`].
    ///
    /// The params are sealed and sent as `?data=<base64url>`; the response is opened
    /// with the same key. For plain query-string routes use `.query(params)` instead.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::client::Client;
    /// # use bincode::{Encode, Decode};
    /// # #[derive(Encode)] struct Filter { page: u32 }
    /// # #[derive(Decode)] struct Page { items: Vec<String> }
    /// # async fn example(client: &Client) -> Result<(), toolkit_zero::socket::client::ClientError> {
    /// use toolkit_zero::socket::SerializationKey;
    /// let page: Page = client
    ///     .get("/items")
    ///     .encrypted_query(Filter { page: 1 }, SerializationKey::Default)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn encrypted_query<T: bincode::Encode>(self, params: T, key: SerializationKey) -> EncryptedQueryRequestBuilder<'a, T> {
        log::trace!("Attaching encrypted query to {:?} request for '{}'", self.method, self.endpoint);
        EncryptedQueryRequestBuilder { client: self.client, method: self.method, endpoint: self.endpoint, params, key }
    }
}

/// A request builder that will send a JSON-serialised body.
///
/// Obtained from [`RequestBuilder::json`]. Finalise with [`send`](JsonRequestBuilder::send)
/// (async) or [`send_sync`](JsonRequestBuilder::send_sync) (sync).
///
/// # Example
/// ```rust,no_run
/// # use toolkit_zero::socket::client::Client;
/// # use serde::{Deserialize, Serialize};
/// # #[derive(Serialize)] struct UpdateItem { name: String }
/// # #[derive(Deserialize)] struct Item { id: u32, name: String }
/// # async fn example(client: &Client) -> Result<(), reqwest::Error> {
/// // Async PUT
/// let updated: Item = client
///     .put("/items/42")
///     .json(UpdateItem { name: "new name".to_string() })
///     .send()
///     .await?;
///
/// // Sync PATCH
/// let patched: Item = client
///     .patch("/items/42")
///     .json(UpdateItem { name: "new name".to_string() })
///     .send_sync()?;
/// # Ok(())
/// # }
/// ```
pub struct JsonRequestBuilder<'a, T> {
    client: &'a Client,
    method: HttpMethod,
    endpoint: String,
    body: T,
}

impl<'a, T: Serialize> JsonRequestBuilder<'a, T> {
    /// Sends the request asynchronously with the JSON body and deserialises the response as `R`.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::client::Client;
    /// # use serde::{Deserialize, Serialize};
    /// # #[derive(Serialize)] struct Payload { value: i32 }
    /// # #[derive(Deserialize)] struct Ack { received: bool }
    /// # async fn example(client: &Client) -> Result<(), reqwest::Error> {
    /// let ack: Ack = client
    ///     .post("/process")
    ///     .json(Payload { value: 42 })
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send<R: DeserializeOwned>(self) -> Result<R, reqwest::Error> {
        let url = build_url(&self.client.base_url(), &self.endpoint);
        log::info!("Sending async {:?} with JSON body to '{}'", self.method, url);
        let resp = self.method.apply_async(&self.client.async_client(), &url)
            .json(&self.body)
            .send().await?;
        log::debug!("Response status: {}", resp.status());
        resp.json::<R>().await
    }

    /// Sends the request synchronously with the JSON body and deserialises the response as `R`.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::client::Client;
    /// # use serde::{Deserialize, Serialize};
    /// # #[derive(Serialize)] struct Payload { value: i32 }
    /// # #[derive(Deserialize)] struct Ack { received: bool }
    /// # fn example(client: &Client) -> Result<(), reqwest::Error> {
    /// let ack: Ack = client
    ///     .post("/process")
    ///     .json(Payload { value: 42 })
    ///     .send_sync()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send_sync<R: DeserializeOwned>(self) -> Result<R, reqwest::Error> {
        let url = build_url(&self.client.base_url(), &self.endpoint);
        log::info!("Sending sync {:?} with JSON body to '{}'", self.method, url);
        let resp = self.method.apply_sync(&self.client.sync_client(), &url)
            .json(&self.body)
            .send()?;
        log::debug!("Response status: {}", resp.status());
        resp.json::<R>()
    }
}

/// A request builder that will append serialisable query parameters to the URL.
///
/// Obtained from [`RequestBuilder::query`]. Finalise with [`send`](QueryRequestBuilder::send)
/// (async) or [`send_sync`](QueryRequestBuilder::send_sync) (sync).
///
/// # Example
/// ```rust,no_run
/// # use toolkit_zero::socket::client::Client;
/// # use serde::{Deserialize, Serialize};
/// # #[derive(Serialize)] struct Filters { status: String, limit: u32 }
/// # #[derive(Deserialize)] struct Item { id: u32, name: String }
/// # async fn example(client: &Client) -> Result<(), reqwest::Error> {
/// // Async GET with query params
/// let items: Vec<Item> = client
///     .get("/items")
///     .query(Filters { status: "active".to_string(), limit: 20 })
///     .send()
///     .await?;
///
/// // Sync variant
/// let items: Vec<Item> = client
///     .get("/items")
///     .query(Filters { status: "active".to_string(), limit: 20 })
///     .send_sync()?;
/// # Ok(())
/// # }
/// ```
pub struct QueryRequestBuilder<'a, T> {
    client: &'a Client,
    method: HttpMethod,
    endpoint: String,
    params: T,
}

impl<'a, T: Serialize> QueryRequestBuilder<'a, T> {
    /// Sends the request asynchronously with query parameters and deserialises the response as `R`.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::client::Client;
    /// # use serde::{Deserialize, Serialize};
    /// # #[derive(Serialize)] struct Params { page: u32 }
    /// # #[derive(Deserialize)] struct Page { items: Vec<String> }
    /// # async fn example(client: &Client) -> Result<(), reqwest::Error> {
    /// let page: Page = client
    ///     .get("/feed")
    ///     .query(Params { page: 2 })
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send<R: DeserializeOwned>(self) -> Result<R, reqwest::Error> {
        let url = build_url(&self.client.base_url(), &self.endpoint);
        log::info!("Sending async {:?} with query params to '{}'", self.method, url);
        let resp = self.method.apply_async(&self.client.async_client(), &url)
            .query(&self.params)
            .send().await?;
        log::debug!("Response status: {}", resp.status());
        resp.json::<R>().await
    }

    /// Sends the request synchronously with query parameters and deserialises the response as `R`.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::client::Client;
    /// # use serde::{Deserialize, Serialize};
    /// # #[derive(Serialize)] struct Params { page: u32 }
    /// # #[derive(Deserialize)] struct Page { items: Vec<String> }
    /// # fn example(client: &Client) -> Result<(), reqwest::Error> {
    /// let page: Page = client
    ///     .get("/feed")
    ///     .query(Params { page: 2 })
    ///     .send_sync()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send_sync<R: DeserializeOwned>(self) -> Result<R, reqwest::Error> {
        let url = build_url(&self.client.base_url(), &self.endpoint);
        log::info!("Sending sync {:?} with query params to '{}'", self.method, url);
        let resp = self.method.apply_sync(&self.client.sync_client(), &url)
            .query(&self.params)
            .send()?;
        log::debug!("Response status: {}", resp.status());
        resp.json::<R>()
    }
}

// ─── ClientError ─────────────────────────────────────────────────────────────

/// Error returned by [`EncryptedBodyRequestBuilder`] and [`EncryptedQueryRequestBuilder`].
///
/// Wraps either a transport-level [`reqwest::Error`] or a cipher failure.
#[derive(Debug)]
pub enum ClientError {
    /// The underlying HTTP transport failed (connection refused, timeout, etc.).
    Transport(reqwest::Error),
    /// Sealing or opening failed (wrong key, corrupted bytes, etc.).
    Serialization(SerializationError),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e)      => write!(f, "transport error: {e}"),
            Self::Serialization(e)  => write!(f, "serialization error: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self { Self::Transport(e) }
}

impl From<SerializationError> for ClientError {
    fn from(e: SerializationError) -> Self { Self::Serialization(e) }
}

// ─── EncryptedBodyRequestBuilder ─────────────────────────────────────────────

/// A request builder that seals the body (ChaCha20-Poly1305) before sending.
///
/// Obtained from [`RequestBuilder::encryption`]. Finalise with
/// [`send`](EncryptedBodyRequestBuilder::send) (async) or
/// [`send_sync`](EncryptedBodyRequestBuilder::send_sync) (sync).
///
/// The expected response is also sealed and is opened transparently.
pub struct EncryptedBodyRequestBuilder<'a, T> {
    client: &'a Client,
    method: HttpMethod,
    endpoint: String,
    body: T,
    key: SerializationKey,
}

impl<'a, T: bincode::Encode> EncryptedBodyRequestBuilder<'a, T> {
    /// Sends the request asynchronously.
    ///
    /// Before the request leaves, the body is sealed using the [`SerializationKey`]
    /// supplied to [`.encryption()`](RequestBuilder::encryption).  The server receives a
    /// raw `application/octet-stream` payload.  When the response arrives, its bytes are
    /// opened with the same key to produce `R`.  If either sealing or opening fails
    /// the error is wrapped in [`ClientError::Serialization`].
    pub async fn send<R>(self) -> Result<R, ClientError>
    where
        R: bincode::Decode<()>,
    {
        let url = build_url(&self.client.base_url(), &self.endpoint);
        log::info!("Sending async {:?} with encrypted body to '{}'", self.method, url);
        let sealed = crate::serialization::seal(&self.body, self.key.veil_key())?;
        let resp = self.method.apply_async(&self.client.async_client(), &url)
            .header("content-type", "application/octet-stream")
            .body(sealed)
            .send().await?;
        log::debug!("Response status: {}", resp.status());
        let bytes = resp.bytes().await?;
        Ok(crate::serialization::open::<R, _>(&bytes, self.key.veil_key())?)
    }

    /// Sends the request synchronously.
    ///
    /// The body is sealed with the configured [`SerializationKey`] before the wire
    /// send.  The response bytes, once received, are opened with the same key to
    /// produce `R`.  Any cipher failure is wrapped in [`ClientError::Serialization`].
    pub fn send_sync<R>(self) -> Result<R, ClientError>
    where
        R: bincode::Decode<()>,
    {
        let url = build_url(&self.client.base_url(), &self.endpoint);
        log::info!("Sending sync {:?} with encrypted body to '{}'", self.method, url);
        let sealed = crate::serialization::seal(&self.body, self.key.veil_key())?;
        let resp = self.method.apply_sync(&self.client.sync_client(), &url)
            .header("content-type", "application/octet-stream")
            .body(sealed)
            .send()?;
        log::debug!("Response status: {}", resp.status());
        let bytes = resp.bytes()?;
        Ok(crate::serialization::open::<R, _>(&bytes, self.key.veil_key())?)
    }
}

// ─── EncryptedQueryRequestBuilder ────────────────────────────────────────────

/// A request builder that seals query params (ChaCha20-Poly1305) and sends them as
/// `?data=<base64url>`.
///
/// Obtained from [`RequestBuilder::encrypted_query`]. Finalise with
/// [`send`](EncryptedQueryRequestBuilder::send) (async) or
/// [`send_sync`](EncryptedQueryRequestBuilder::send_sync) (sync).
///
/// The expected response is also sealed and is opened transparently.
pub struct EncryptedQueryRequestBuilder<'a, T> {
    client: &'a Client,
    method: HttpMethod,
    endpoint: String,
    params: T,
    key: SerializationKey,
}

impl<'a, T: bincode::Encode> EncryptedQueryRequestBuilder<'a, T> {
    /// Sends the request asynchronously.
    ///
    /// The params are sealed with the configured [`SerializationKey`] and
    /// base64url-encoded, then appended to the URL as `?data=<base64url>`.  When the
    /// response arrives, its bytes are opened with the same key to produce `R`.
    /// Any cipher failure is wrapped in [`ClientError::Serialization`].
    pub async fn send<R>(self) -> Result<R, ClientError>
    where
        R: bincode::Decode<()>,
    {
        let url = build_url(&self.client.base_url(), &self.endpoint);
        log::info!("Sending async {:?} with encrypted query to '{}'", self.method, url);
        let sealed = crate::serialization::seal(&self.params, self.key.veil_key())?;
        let b64 = URL_SAFE_NO_PAD.encode(&sealed);
        let resp = self.method.apply_async(&self.client.async_client(), &url)
            .query(&[("data", &b64)])
            .send().await?;
        log::debug!("Response status: {}", resp.status());
        let bytes = resp.bytes().await?;
        Ok(crate::serialization::open::<R, _>(&bytes, self.key.veil_key())?)
    }

    /// Sends the request synchronously.
    ///
    /// Same behaviour as [`send`](Self::send) — params are sealed and base64url-encoded
    /// as `?data=<value>`, and the sealed response bytes are opened to `R` — but the
    /// network call blocks the current thread.  Any cipher failure is wrapped in
    /// [`ClientError::Serialization`].
    pub fn send_sync<R>(self) -> Result<R, ClientError>
    where
        R: bincode::Decode<()>,
    {
        let url = build_url(&self.client.base_url(), &self.endpoint);
        log::info!("Sending sync {:?} with encrypted query to '{}'", self.method, url);
        let sealed = crate::serialization::seal(&self.params, self.key.veil_key())?;
        let b64 = URL_SAFE_NO_PAD.encode(&sealed);
        let resp = self.method.apply_sync(&self.client.sync_client(), &url)
            .query(&[("data", &b64)])
            .send()?;
        log::debug!("Response status: {}", resp.status());
        let bytes = resp.bytes()?;
        Ok(crate::serialization::open::<R, _>(&bytes, self.key.veil_key())?)
    }
}

// ─── ClientBuilder ────────────────────────────────────────────────────────────

/// Fluent builder for [`Client`] with optional timeout and other configuration.
///
/// Use this instead of the bare `Client::new_*` constructors when you need to
/// configure a request timeout.
///
/// # Example
///
/// ```rust,no_run
/// use std::time::Duration;
/// use toolkit_zero::socket::client::{ClientBuilder, Target};
///
/// // Async client with a 10-second timeout
/// let client = ClientBuilder::new(Target::Localhost(8080))
///     .timeout(Duration::from_secs(10))
///     .build_async();
///
/// // Sync client with a 30-second timeout
/// let client = ClientBuilder::new(Target::Remote("https://api.example.com".to_string()))
///     .timeout(Duration::from_secs(30))
///     .build_sync();
/// ```
pub struct ClientBuilder {
    target:  Target,
    timeout: Option<std::time::Duration>,
}

impl ClientBuilder {
    /// Create a new builder for the given [`Target`].
    pub fn new(target: Target) -> Self {
        Self { target, timeout: None }
    }

    /// Set a request timeout.
    ///
    /// Both the async and blocking reqwest clients will respect this duration.
    /// Requests that do not complete within the timeout are cancelled and return
    /// a [`reqwest::Error`] with `is_timeout()` = `true`.
    pub fn timeout(mut self, duration: std::time::Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    /// Build an **async-only** [`Client`]. Safe to call from any context,
    /// including inside `#[tokio::main]`.
    pub fn build_async(self) -> Client {
        log::debug!("Building async-only client (timeout={:?})", self.timeout);
        let mut builder = AsyncClient::builder();
        if let Some(t) = self.timeout {
            builder = builder.timeout(t);
        }
        Client {
            target:       self.target,
            async_client: Some(builder.build().expect("failed to build reqwest async client")),
            sync_client:  None,
        }
    }

    /// Build a **sync-only** [`Client`].
    ///
    /// # Panics
    ///
    /// Panics if called from within an async context (same restriction as
    /// `reqwest::blocking::Client`). See [`Client::new_sync`] for details.
    pub fn build_sync(self) -> Client {
        log::debug!("Building sync-only client (timeout={:?})", self.timeout);
        let mut builder = BlockingClient::builder();
        if let Some(t) = self.timeout {
            builder = builder.timeout(t);
        }
        Client {
            target:       self.target,
            async_client: None,
            sync_client:  Some(builder.build().expect("failed to build reqwest blocking client")),
        }
    }

    /// Build a client that supports **both** async and blocking sends.
    ///
    /// # Panics
    ///
    /// Panics if called from within an async context. See [`Client::new`] for details.
    pub fn build(self) -> Client {
        if tokio::runtime::Handle::try_current().is_ok() {
            panic!(
                "ClientBuilder::build() called inside an async context. \
                 Use ClientBuilder::build_async() for async-only clients."
            );
        }
        log::debug!("Building dual async+sync client (timeout={:?})", self.timeout);
        let mut async_builder   = AsyncClient::builder();
        let mut sync_builder    = BlockingClient::builder();
        if let Some(t) = self.timeout {
            async_builder = async_builder.timeout(t);
            sync_builder  = sync_builder.timeout(t);
        }
        Client {
            target:       self.target,
            async_client: Some(async_builder.build().expect("failed to build reqwest async client")),
            sync_client:  Some(sync_builder.build().expect("failed to build reqwest blocking client")),
        }
    }
}