//! Typed, fluent HTTP server construction.
//!
//! This module provides a builder-oriented API for declaring HTTP routes and
//! serving them with a built-in hyper-based HTTP engine.  The entry point for every
//! route is [`ServerMechanism`], which pairs an HTTP method with a URL path and
//! supports incremental enrichment — attaching a JSON body expectation, URL
//! query parameter deserialisation, or shared state — before being finalised
//! into a [`SocketType`] route handle via `onconnect`.
//!
//! Completed routes are registered on a [`Server`] and served via one of the
//! `serve*` methods, each of which returns a [`ServerFuture`].  A `ServerFuture`
//! can be `.await`'d to run the server inline **or** called `.background()` on to
//! spawn it as a background Tokio task and get a [`tokio::task::JoinHandle`] back.
//! Graceful shutdown is available via
//! [`Server::serve_with_graceful_shutdown`] and [`Server::serve_from_listener`].
//!
//! For **runtime address migration**, use [`Server::serve_managed`]: it starts
//! the server immediately and returns a [`BackgroundServer`] handle that supports
//! [`BackgroundServer::rebind`] (graceful shutdown + restart on a new address,
//! all existing routes preserved) and [`BackgroundServer::stop`].
//!
//! # Hot-reloading routes
//!
//! [`BackgroundServer::mechanism`] pushes a new route into the running
//! server's shared route table **without any restart or port gap**.  Because
//! routes are stored in an `Arc<RwLock<Vec<SocketType>>>` shared between the
//! caller and the server loop, the new route becomes visible to the next
//! incoming request immediately.
//!
//! # Builder chains at a glance
//!
//! | Chain | Handler receives |
//! |---|---|
//! | `ServerMechanism::method(path).onconnect(f)` | nothing |
//! | `.json::<T>().onconnect(f)` | `T: DeserializeOwned` |
//! | `.query::<T>().onconnect(f)` | `T: DeserializeOwned` |
//! | `.encryption::<T>(key).onconnect(f)` | `T: bincode::Decode<()>` (decrypted body) |
//! | `.encrypted_query::<T>(key).onconnect(f)` | `T: bincode::Decode<()>` (decrypted query) |
//! | `.state(s).onconnect(f)` | `S: Clone + Send + Sync` |
//! | `.state(s).json::<T>().onconnect(f)` | `(S, T)` |
//! | `.state(s).query::<T>().onconnect(f)` | `(S, T)` |
//! | `.state(s).encryption::<T>(key).onconnect(f)` | `(S, T)` — decrypted body |
//! | `.state(s).encrypted_query::<T>(key).onconnect(f)` | `(S, T)` — decrypted query |
//!
//! For blocking handlers (not recommended in production) every finaliser also
//! has an unsafe `onconnect_sync` counterpart.
//!
//! # `#[mechanism]` attribute macro
//!
//! As an alternative to spelling out the builder chain by hand, the
//! [`mechanism`] attribute macro collapses the entire
//! `server.mechanism(ServerMechanism::method(path) … .onconnect(handler))` call
//! into a single decorated `async fn`.
//!
//! # Response helpers
//!
//! Use the [`reply!`] macro as the most concise way to build a response:
//!
//! ```rust,no_run
//! # use toolkit_zero::socket::server::*;
//! # use serde::Serialize;
//! # #[derive(Serialize)] struct Item { id: u32 }
//! # let item = Item { id: 1 };
//! // 200 OK, empty body
//! // reply!()
//! // 200 OK, JSON body
//! // reply!(json => item)
//! // 201 Created, JSON body
//! // reply!(json => item, status => Status::Created)
//! ```

use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
};
use serde::{de::DeserializeOwned, Serialize};

pub use super::SerializationKey;
pub use toolkit_zero_macros::mechanism;

// ─── Internal future / handler types ─────────────────────────────────────────

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
type HandlerFn = Arc<dyn Fn(IncomingRequest) -> BoxFuture<http::Response<bytes::Bytes>> + Send + Sync>;

/// Raw data extracted from an incoming HTTP request, passed to every route handler.
pub(crate) struct IncomingRequest {
    /// Raw body bytes (empty for GET / HEAD / etc.).
    body: bytes::Bytes,
    /// Raw query string — everything after `?`; empty string when absent.
    query: String,
    /// Request headers.
    #[allow(dead_code)]
    headers: http::HeaderMap,
}

// ─── Rejection ────────────────────────────────────────────────────────────────

/// An HTTP-level error value returned from route handlers.
///
/// Returning `Err(rejection)` from an `onconnect` closure sends the corresponding
/// HTTP status code with an empty body to the client.
///
/// The most common source is [`forbidden()`] (produces `403 Forbidden`).
pub struct Rejection {
    status: http::StatusCode,
}

impl Rejection {
    fn new(status: http::StatusCode) -> Self {
        Self { status }
    }

    /// Builds a `403 Forbidden` rejection.
    pub fn forbidden() -> Self {
        Self::new(http::StatusCode::FORBIDDEN)
    }

    /// Builds a `400 Bad Request` rejection.
    pub fn bad_request() -> Self {
        Self::new(http::StatusCode::BAD_REQUEST)
    }

    /// Builds a `500 Internal Server Error` rejection.
    pub fn internal() -> Self {
        Self::new(http::StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn into_response(self) -> http::Response<bytes::Bytes> {
        http::Response::builder()
            .status(self.status)
            .body(bytes::Bytes::new())
            .unwrap()
    }
}

// ─── Reply ────────────────────────────────────────────────────────────────────

/// A value that can be converted into a fully-formed HTTP response.
///
/// Implemented for all types returned by the [`reply!`] macro and the standalone
/// reply helpers.  You may also implement it for your own types.
pub trait Reply: Send {
    /// Consumes `self` and returns a complete HTTP response.
    fn into_response(self) -> http::Response<bytes::Bytes>;
}

/// An empty `200 OK` reply — returned by `reply!()`.
pub struct EmptyReply;

impl Reply for EmptyReply {
    fn into_response(self) -> http::Response<bytes::Bytes> {
        http::Response::builder()
            .status(http::StatusCode::OK)
            .body(bytes::Bytes::new())
            .unwrap()
    }
}

/// An HTML body reply — returned by [`html_reply`].
pub struct HtmlReply {
    body: String,
}

impl Reply for HtmlReply {
    fn into_response(self) -> http::Response<bytes::Bytes> {
        http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(bytes::Bytes::from(self.body.into_bytes()))
            .unwrap()
    }
}

/// Wraps `content` into a `200 OK` HTML response.
pub fn html_reply(content: impl Into<String>) -> HtmlReply {
    HtmlReply { body: content.into() }
}

// Internal JSON reply — used by reply_with_json / reply_with_status_and_json.
struct JsonReply {
    body: bytes::Bytes,
    status: http::StatusCode,
}

impl Reply for JsonReply {
    fn into_response(self) -> http::Response<bytes::Bytes> {
        http::Response::builder()
            .status(self.status)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(self.body)
            .unwrap()
    }
}

// Passthrough — allows `http::Response<bytes::Bytes>` to satisfy the Reply bound directly.
impl Reply for http::Response<bytes::Bytes> {
    fn into_response(self) -> http::Response<bytes::Bytes> {
        self
    }
}

// ─── SocketType ───────────────────────────────────────────────────────────────

/// A fully assembled, type-erased HTTP route ready to be registered on a [`Server`].
///
/// This is the final product of every builder chain.  Pass it to [`Server::mechanism`]
/// to mount it.  Internally stores the HTTP method, the path pattern, and a
/// reference-counted async handler closure — cloning a `SocketType` is cheap
/// (just an `Arc` clone of the handler).
pub struct SocketType {
    pub(crate) method: http::Method,
    pub(crate) path:   String,
    pub(crate) handler: HandlerFn,
}

impl Clone for SocketType {
    fn clone(&self) -> Self {
        Self {
            method:  self.method.clone(),
            path:    self.path.clone(),
            handler: Arc::clone(&self.handler),
        }
    }
}

// ─── HttpMethod ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum HttpMethod {
    Get, Post, Put, Delete, Patch, Head, Options,
}

impl HttpMethod {
    fn to_http(self) -> http::Method {
        match self {
            HttpMethod::Get     => http::Method::GET,
            HttpMethod::Post    => http::Method::POST,
            HttpMethod::Put     => http::Method::PUT,
            HttpMethod::Delete  => http::Method::DELETE,
            HttpMethod::Patch   => http::Method::PATCH,
            HttpMethod::Head    => http::Method::HEAD,
            HttpMethod::Options => http::Method::OPTIONS,
        }
    }
}

// ─── Path matching ────────────────────────────────────────────────────────────

fn path_matches(pattern: &str, actual_path: &str) -> bool {
    let pat: Vec<&str> = pattern
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let act: Vec<&str> = actual_path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    pat == act
}

// ─── ServerMechanism ──────────────────────────────────────────────────────────

/// Entry point for building an HTTP route.
///
/// Pairs an HTTP method with a URL path and acts as the root of a fluent builder chain.
/// Optionally attach shared state, a JSON body expectation, or URL query parameter
/// deserialisation — then finalise with [`onconnect`](ServerMechanism::onconnect) (async)
/// or [`onconnect_sync`](ServerMechanism::onconnect_sync) (sync) to produce a
/// [`SocketType`] ready to be mounted on a [`Server`].
///
/// # Example
/// ```rust,no_run
/// # use toolkit_zero::socket::server::{ServerMechanism, Status};
/// # use toolkit_zero::socket::server::reply;
/// # use serde::{Deserialize, Serialize};
/// # use std::sync::{Arc, Mutex};
/// # #[derive(Deserialize, Serialize)] struct Item { id: u32, name: String }
/// # #[derive(Deserialize)] struct CreateItem { name: String }
/// # #[derive(Deserialize)] struct SearchQuery { q: String }
///
/// // Plain GET — no body, no state
/// let health = ServerMechanism::get("/health")
///     .onconnect(|| async { reply!() });
///
/// // POST — JSON body deserialised into `CreateItem`
/// let create = ServerMechanism::post("/items")
///     .json::<CreateItem>()
///     .onconnect(|body| async move {
///         let item = Item { id: 1, name: body.name };
///         reply!(json => item, status => Status::Created)
///     });
///
/// // GET — shared counter state injected on every request
/// let counter: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
/// let count_route = ServerMechanism::get("/count")
///     .state(counter.clone())
///     .onconnect(|state| async move {
///         let n = *state.lock().unwrap();
///         reply!(json => n)
///     });
/// ```
pub struct ServerMechanism {
    method: HttpMethod,
    path: String,
}

impl ServerMechanism {
    fn instance(method: HttpMethod, path: impl Into<String>) -> Self {
        let path = path.into();
        log::debug!("Creating {:?} route at '{}'", method, path);
        Self { method, path }
    }

    /// Creates a route matching HTTP `GET` requests at `path`.
    pub fn get(path: impl Into<String>) -> Self { Self::instance(HttpMethod::Get, path) }

    /// Creates a route matching HTTP `POST` requests at `path`.
    pub fn post(path: impl Into<String>) -> Self { Self::instance(HttpMethod::Post, path) }

    /// Creates a route matching HTTP `PUT` requests at `path`.
    pub fn put(path: impl Into<String>) -> Self { Self::instance(HttpMethod::Put, path) }

    /// Creates a route matching HTTP `DELETE` requests at `path`.
    pub fn delete(path: impl Into<String>) -> Self { Self::instance(HttpMethod::Delete, path) }

    /// Creates a route matching HTTP `PATCH` requests at `path`.
    pub fn patch(path: impl Into<String>) -> Self { Self::instance(HttpMethod::Patch, path) }

    /// Creates a route matching HTTP `HEAD` requests at `path`.
    pub fn head(path: impl Into<String>) -> Self { Self::instance(HttpMethod::Head, path) }

    /// Creates a route matching HTTP `OPTIONS` requests at `path`.
    pub fn options(path: impl Into<String>) -> Self { Self::instance(HttpMethod::Options, path) }

    /// Attaches shared state `S` to this route, transitioning to [`StatefulSocketBuilder`].
    ///
    /// A fresh clone of `S` is injected into the handler on every request.
    pub fn state<S: Clone + Send + Sync + 'static>(self, state: S) -> StatefulSocketBuilder<S> {
        log::trace!("Attaching state to {:?} route at '{}'", self.method, self.path);
        StatefulSocketBuilder { base: self, state }
    }

    /// Declares that this route expects a JSON-encoded request body, transitioning to
    /// [`JsonSocketBuilder`].
    pub fn json<T: DeserializeOwned + Send>(self) -> JsonSocketBuilder<T> {
        log::trace!("Attaching JSON body expectation to {:?} route at '{}'", self.method, self.path);
        JsonSocketBuilder { base: self, _phantom: std::marker::PhantomData }
    }

    /// Declares that this route extracts its input from URL query parameters, transitioning
    /// to [`QuerySocketBuilder`].
    pub fn query<T: DeserializeOwned + Send>(self) -> QuerySocketBuilder<T> {
        log::trace!("Attaching query parameter expectation to {:?} route at '{}'", self.method, self.path);
        QuerySocketBuilder { base: self, _phantom: std::marker::PhantomData }
    }

    /// Declares that this route expects an authenticated-encrypted request body
    /// (ChaCha20-Poly1305), transitioning to [`EncryptedBodyBuilder`].
    pub fn encryption<T>(self, key: SerializationKey) -> EncryptedBodyBuilder<T> {
        log::trace!("Attaching encrypted body to {:?} route at '{}'", self.method, self.path);
        EncryptedBodyBuilder { base: self, key, _phantom: std::marker::PhantomData }
    }

    /// Declares that this route expects authenticated-encrypted URL query parameters
    /// (ChaCha20-Poly1305), transitioning to [`EncryptedQueryBuilder`].
    pub fn encrypted_query<T>(self, key: SerializationKey) -> EncryptedQueryBuilder<T> {
        log::trace!("Attaching encrypted query to {:?} route at '{}'", self.method, self.path);
        EncryptedQueryBuilder { base: self, key, _phantom: std::marker::PhantomData }
    }

    /// Finalises this route with an async handler that receives no arguments.
    ///
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::server::ServerMechanism;
    /// # use toolkit_zero::socket::server::reply;
    /// # use serde::Serialize;
    /// # #[derive(Serialize)] struct Pong { ok: bool }
    ///
    /// let route = ServerMechanism::get("/ping")
    ///     .onconnect(|| async {
    ///         reply!(json => Pong { ok: true })
    ///     });
    /// ```
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn() -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!("Finalising async {:?} route at '{}' (no args)", self.method, self.path);
        let method = self.method.to_http();
        let path   = self.path.clone();
        SocketType {
            method,
            path,
            handler: Arc::new(move |_req: IncomingRequest| {
                let h = handler.clone();
                Box::pin(async move {
                    match h().await {
                        Ok(r)  => r.into_response(),
                        Err(e) => e.into_response(),
                    }
                })
            }),
        }
    }

    /// Finalises this route with a **synchronous** handler that receives no arguments.
    ///
    /// # Safety
    ///
    /// Every incoming request spawns an independent task on Tokio's blocking thread pool.
    /// The pool caps the number of live OS threads (default 512), but the queue of waiting
    /// tasks is unbounded — under a traffic surge, tasks accumulate without limit, consuming
    /// unbounded memory and causing severe latency spikes or OOM crashes. Additionally, any
    /// panic inside the handler is silently converted into a 500 response, masking runtime
    /// errors. Callers must ensure the handler completes quickly and that adequate
    /// backpressure or rate limiting is applied externally.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn() -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!(
            "Registering sync handler on {:?} '{}' — ensure rate-limiting is applied externally",
            self.method, self.path
        );
        let method = self.method.to_http();
        let path   = self.path.clone();
        SocketType {
            method,
            path,
            handler: Arc::new(move |_req: IncomingRequest| {
                let h = handler.clone();
                Box::pin(async move {
                    match tokio::task::spawn_blocking(move || h()).await {
                        Ok(Ok(r))  => r.into_response(),
                        Ok(Err(e)) => e.into_response(),
                        Err(_) => {
                            log::warn!("Sync handler panicked; returning 500");
                            Rejection::internal().into_response()
                        }
                    }
                })
            }),
        }
    }
}

// ─── JsonSocketBuilder ────────────────────────────────────────────────────────

/// Route builder that expects and deserialises a JSON request body of type `T`.
///
/// Obtained from [`ServerMechanism::json`]. Optionally attach shared state via
/// [`state`](JsonSocketBuilder::state), or finalise immediately with
/// [`onconnect`](JsonSocketBuilder::onconnect) /
/// [`onconnect_sync`](JsonSocketBuilder::onconnect_sync).
pub struct JsonSocketBuilder<T> {
    base: ServerMechanism,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: DeserializeOwned + Send + 'static> JsonSocketBuilder<T> {
    /// Finalises this route with an async handler that receives the deserialised JSON body.
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!(
            "Finalising async {:?} route at '{}' (JSON body)",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        SocketType {
            method,
            path,
            handler: Arc::new(move |req: IncomingRequest| {
                let h = handler.clone();
                Box::pin(async move {
                    let body: T = match serde_json::from_slice(&req.body) {
                        Ok(v)  => v,
                        Err(e) => {
                            log::debug!("JSON body parse failed: {}", e);
                            return Rejection::bad_request().into_response();
                        }
                    };
                    match h(body).await {
                        Ok(r)  => r.into_response(),
                        Err(e) => e.into_response(),
                    }
                })
            }),
        }
    }

    /// Finalises this route with a **synchronous** handler that receives the deserialised
    /// JSON body.
    ///
    /// # Safety
    /// See [`ServerMechanism::onconnect_sync`] for the thread-pool safety notes.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn(T) -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!(
            "Registering sync handler on {:?} '{}' (JSON body) — ensure rate-limiting is applied externally",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        SocketType {
            method,
            path,
            handler: Arc::new(move |req: IncomingRequest| {
                let h = handler.clone();
                Box::pin(async move {
                    let body: T = match serde_json::from_slice(&req.body) {
                        Ok(v)  => v,
                        Err(e) => {
                            log::debug!("JSON body parse failed (sync): {}", e);
                            return Rejection::bad_request().into_response();
                        }
                    };
                    match tokio::task::spawn_blocking(move || h(body)).await {
                        Ok(Ok(r))  => r.into_response(),
                        Ok(Err(e)) => e.into_response(),
                        Err(_) => {
                            log::warn!("Sync handler (JSON body) panicked; returning 500");
                            Rejection::internal().into_response()
                        }
                    }
                })
            }),
        }
    }

    /// Attaches shared state `S`, transitioning to [`StatefulJsonSocketBuilder`].
    pub fn state<S: Clone + Send + Sync + 'static>(
        self, state: S,
    ) -> StatefulJsonSocketBuilder<T, S> {
        StatefulJsonSocketBuilder {
            base: self.base,
            state,
            _phantom: std::marker::PhantomData,
        }
    }
}

// ─── QuerySocketBuilder ───────────────────────────────────────────────────────

/// Route builder that expects and deserialises URL query parameters of type `T`.
///
/// Obtained from [`ServerMechanism::query`]. Optionally attach shared state via
/// [`state`](QuerySocketBuilder::state), or finalise immediately with
/// [`onconnect`](QuerySocketBuilder::onconnect) /
/// [`onconnect_sync`](QuerySocketBuilder::onconnect_sync).
pub struct QuerySocketBuilder<T> {
    base: ServerMechanism,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: DeserializeOwned + Send + 'static> QuerySocketBuilder<T> {
    /// Finalises this route with an async handler that receives the deserialised query
    /// parameters.
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!(
            "Finalising async {:?} route at '{}' (query params)",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        SocketType {
            method,
            path,
            handler: Arc::new(move |req: IncomingRequest| {
                let h = handler.clone();
                Box::pin(async move {
                    let params: T = match serde_urlencoded::from_str(&req.query) {
                        Ok(v)  => v,
                        Err(e) => {
                            log::debug!("query param parse failed: {}", e);
                            return Rejection::bad_request().into_response();
                        }
                    };
                    match h(params).await {
                        Ok(r)  => r.into_response(),
                        Err(e) => e.into_response(),
                    }
                })
            }),
        }
    }

    /// Finalises this route with a **synchronous** handler that receives the deserialised
    /// query parameters.
    ///
    /// # Safety
    /// See [`ServerMechanism::onconnect_sync`] for the thread-pool safety notes.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn(T) -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!(
            "Registering sync handler on {:?} '{}' (query params) — ensure rate-limiting is applied externally",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        SocketType {
            method,
            path,
            handler: Arc::new(move |req: IncomingRequest| {
                let h = handler.clone();
                Box::pin(async move {
                    let params: T = match serde_urlencoded::from_str(&req.query) {
                        Ok(v)  => v,
                        Err(e) => {
                            log::debug!("query param parse failed (sync): {}", e);
                            return Rejection::bad_request().into_response();
                        }
                    };
                    match tokio::task::spawn_blocking(move || h(params)).await {
                        Ok(Ok(r))  => r.into_response(),
                        Ok(Err(e)) => e.into_response(),
                        Err(_) => {
                            log::warn!("Sync handler (query params) panicked; returning 500");
                            Rejection::internal().into_response()
                        }
                    }
                })
            }),
        }
    }

    /// Attaches shared state `S`, transitioning to [`StatefulQuerySocketBuilder`].
    pub fn state<S: Clone + Send + Sync + 'static>(
        self, state: S,
    ) -> StatefulQuerySocketBuilder<T, S> {
        StatefulQuerySocketBuilder {
            base: self.base,
            state,
            _phantom: std::marker::PhantomData,
        }
    }
}

// ─── StatefulSocketBuilder ────────────────────────────────────────────────────

/// Route builder that carries shared state `S` with no body or query expectation.
///
/// Obtained from [`ServerMechanism::state`]. `S` must be `Clone + Send + Sync + 'static`.
pub struct StatefulSocketBuilder<S> {
    base: ServerMechanism,
    state: S,
}

impl<S: Clone + Send + Sync + 'static> StatefulSocketBuilder<S> {
    /// Adds a JSON body expectation, transitioning to [`StatefulJsonSocketBuilder`].
    pub fn json<T: DeserializeOwned + Send>(self) -> StatefulJsonSocketBuilder<T, S> {
        StatefulJsonSocketBuilder {
            base: self.base,
            state: self.state,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Adds a query parameter expectation, transitioning to [`StatefulQuerySocketBuilder`].
    pub fn query<T: DeserializeOwned + Send>(self) -> StatefulQuerySocketBuilder<T, S> {
        StatefulQuerySocketBuilder {
            base: self.base,
            state: self.state,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Adds an encrypted body expectation, transitioning to [`StatefulEncryptedBodyBuilder`].
    pub fn encryption<T>(self, key: SerializationKey) -> StatefulEncryptedBodyBuilder<T, S> {
        StatefulEncryptedBodyBuilder {
            base: self.base,
            key,
            state: self.state,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Adds an encrypted query expectation, transitioning to [`StatefulEncryptedQueryBuilder`].
    pub fn encrypted_query<T>(self, key: SerializationKey) -> StatefulEncryptedQueryBuilder<T, S> {
        StatefulEncryptedQueryBuilder {
            base: self.base,
            key,
            state: self.state,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Finalises this route with an async handler that receives only the shared state.
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!(
            "Finalising async {:?} route at '{}' (state)",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        let state  = self.state;
        SocketType {
            method,
            path,
            handler: Arc::new(move |_req: IncomingRequest| {
                let h = handler.clone();
                let s = state.clone();
                Box::pin(async move {
                    match h(s).await {
                        Ok(r)  => r.into_response(),
                        Err(e) => e.into_response(),
                    }
                })
            }),
        }
    }

    /// Finalises this route with a **synchronous** handler that receives only the shared
    /// state.
    ///
    /// # Safety
    /// See [`ServerMechanism::onconnect_sync`] for the thread-pool safety notes.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S) -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!(
            "Registering sync handler on {:?} '{}' (state) — ensure rate-limiting and lock-free state are in place",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        let state  = self.state;
        SocketType {
            method,
            path,
            handler: Arc::new(move |_req: IncomingRequest| {
                let h = handler.clone();
                let s = state.clone();
                Box::pin(async move {
                    match tokio::task::spawn_blocking(move || h(s)).await {
                        Ok(Ok(r))  => r.into_response(),
                        Ok(Err(e)) => e.into_response(),
                        Err(_) => {
                            log::warn!("Sync handler (state) panicked; returning 500");
                            Rejection::internal().into_response()
                        }
                    }
                })
            }),
        }
    }
}

// ─── StatefulJsonSocketBuilder ────────────────────────────────────────────────

/// Route builder that carries shared state `S` and expects a JSON body of type `T`.
///
/// Obtained from [`JsonSocketBuilder::state`] or [`StatefulSocketBuilder::json`].
pub struct StatefulJsonSocketBuilder<T, S> {
    base:     ServerMechanism,
    state:    S,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: DeserializeOwned + Send + 'static, S: Clone + Send + Sync + 'static>
    StatefulJsonSocketBuilder<T, S>
{
    /// Finalises this route with an async handler that receives `(state: S, body: T)`.
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S, T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!(
            "Finalising async {:?} route at '{}' (state + JSON body)",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        let state  = self.state;
        SocketType {
            method,
            path,
            handler: Arc::new(move |req: IncomingRequest| {
                let h = handler.clone();
                let s = state.clone();
                Box::pin(async move {
                    let body: T = match serde_json::from_slice(&req.body) {
                        Ok(v)  => v,
                        Err(e) => {
                            log::debug!("JSON body parse failed (state): {}", e);
                            return Rejection::bad_request().into_response();
                        }
                    };
                    match h(s, body).await {
                        Ok(r)  => r.into_response(),
                        Err(e) => e.into_response(),
                    }
                })
            }),
        }
    }

    /// Finalises this route with a **synchronous** handler that receives `(state: S, body: T)`.
    ///
    /// # Safety
    /// See [`ServerMechanism::onconnect_sync`] for the thread-pool safety notes.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S, T) -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!(
            "Registering sync handler on {:?} '{}' (state + JSON body) — ensure rate-limiting and lock-free state are in place",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        let state  = self.state;
        SocketType {
            method,
            path,
            handler: Arc::new(move |req: IncomingRequest| {
                let h = handler.clone();
                let s = state.clone();
                Box::pin(async move {
                    let body: T = match serde_json::from_slice(&req.body) {
                        Ok(v)  => v,
                        Err(e) => {
                            log::debug!("JSON body parse failed (state+sync): {}", e);
                            return Rejection::bad_request().into_response();
                        }
                    };
                    match tokio::task::spawn_blocking(move || h(s, body)).await {
                        Ok(Ok(r))  => r.into_response(),
                        Ok(Err(e)) => e.into_response(),
                        Err(_) => {
                            log::warn!("Sync handler (state + JSON body) panicked; returning 500");
                            Rejection::internal().into_response()
                        }
                    }
                })
            }),
        }
    }
}

// ─── StatefulQuerySocketBuilder ───────────────────────────────────────────────

/// Route builder that carries shared state `S` and expects URL query parameters of type `T`.
///
/// Obtained from [`QuerySocketBuilder::state`] or [`StatefulSocketBuilder::query`].
pub struct StatefulQuerySocketBuilder<T, S> {
    base:     ServerMechanism,
    state:    S,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: DeserializeOwned + Send + 'static, S: Clone + Send + Sync + 'static>
    StatefulQuerySocketBuilder<T, S>
{
    /// Finalises this route with an async handler that receives `(state: S, query: T)`.
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S, T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!(
            "Finalising async {:?} route at '{}' (state + query params)",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        let state  = self.state;
        SocketType {
            method,
            path,
            handler: Arc::new(move |req: IncomingRequest| {
                let h = handler.clone();
                let s = state.clone();
                Box::pin(async move {
                    let params: T = match serde_urlencoded::from_str(&req.query) {
                        Ok(v)  => v,
                        Err(e) => {
                            log::debug!("query param parse failed (state): {}", e);
                            return Rejection::bad_request().into_response();
                        }
                    };
                    match h(s, params).await {
                        Ok(r)  => r.into_response(),
                        Err(e) => e.into_response(),
                    }
                })
            }),
        }
    }

    /// Finalises this route with a **synchronous** handler that receives `(state: S, query: T)`.
    ///
    /// # Safety
    /// See [`ServerMechanism::onconnect_sync`] for the thread-pool safety notes.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S, T) -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!(
            "Registering sync handler on {:?} '{}' (state + query params) — ensure rate-limiting and lock-free state are in place",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        let state  = self.state;
        SocketType {
            method,
            path,
            handler: Arc::new(move |req: IncomingRequest| {
                let h = handler.clone();
                let s = state.clone();
                Box::pin(async move {
                    let params: T = match serde_urlencoded::from_str(&req.query) {
                        Ok(v)  => v,
                        Err(e) => {
                            log::debug!("query param parse failed (state+sync): {}", e);
                            return Rejection::bad_request().into_response();
                        }
                    };
                    match tokio::task::spawn_blocking(move || h(s, params)).await {
                        Ok(Ok(r))  => r.into_response(),
                        Ok(Err(e)) => e.into_response(),
                        Err(_) => {
                            log::warn!("Sync handler (state + query params) panicked; returning 500");
                            Rejection::internal().into_response()
                        }
                    }
                })
            }),
        }
    }
}

// ─── EncryptedBodyBuilder ────────────────────────────────────────────────────

/// Route builder that expects an authenticated-encrypted request body of type `T`
/// (ChaCha20-Poly1305).
///
/// Obtained from [`ServerMechanism::encryption`].  On each matching request the raw
/// body bytes are decrypted using the [`SerializationKey`] supplied there.  If
/// decryption fails the route immediately returns `403 Forbidden`.
///
/// Optionally attach shared state via [`state`](EncryptedBodyBuilder::state) before
/// finalising with [`onconnect`](EncryptedBodyBuilder::onconnect) /
/// [`onconnect_sync`](EncryptedBodyBuilder::onconnect_sync).
pub struct EncryptedBodyBuilder<T> {
    base:     ServerMechanism,
    key:      SerializationKey,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> EncryptedBodyBuilder<T>
where
    T: bincode::Decode<()> + Send + 'static,
{
    /// Finalises this route with an async handler that receives the decrypted body as `T`.
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!(
            "Finalising async {:?} route at '{}' (encrypted body)",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        let key    = self.key;
        SocketType {
            method,
            path,
            handler: Arc::new(move |req: IncomingRequest| {
                let h   = handler.clone();
                let key = key.clone();
                Box::pin(async move {
                    let value: T = match decode_body(&req.body, &key) {
                        Ok(v)  => v,
                        Err(e) => return e.into_response(),
                    };
                    match h(value).await {
                        Ok(r)  => r.into_response(),
                        Err(e) => e.into_response(),
                    }
                })
            }),
        }
    }

    /// Finalises this route with a **synchronous** handler that receives the decrypted
    /// body as `T`.
    ///
    /// # Safety
    /// See [`ServerMechanism::onconnect_sync`] for the thread-pool safety notes.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn(T) -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!(
            "Registering sync handler on {:?} '{}' (encrypted body) — ensure rate-limiting is applied externally",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        let key    = self.key;
        SocketType {
            method,
            path,
            handler: Arc::new(move |req: IncomingRequest| {
                let h   = handler.clone();
                let key = key.clone();
                Box::pin(async move {
                    let value: T = match decode_body(&req.body, &key) {
                        Ok(v)  => v,
                        Err(e) => return e.into_response(),
                    };
                    match tokio::task::spawn_blocking(move || h(value)).await {
                        Ok(Ok(r))  => r.into_response(),
                        Ok(Err(e)) => e.into_response(),
                        Err(_) => {
                            log::warn!("Sync encrypted handler panicked; returning 500");
                            Rejection::internal().into_response()
                        }
                    }
                })
            }),
        }
    }

    /// Attaches shared state `S`, transitioning to [`StatefulEncryptedBodyBuilder`].
    pub fn state<S: Clone + Send + Sync + 'static>(
        self, state: S,
    ) -> StatefulEncryptedBodyBuilder<T, S> {
        StatefulEncryptedBodyBuilder {
            base: self.base,
            key: self.key,
            state,
            _phantom: std::marker::PhantomData,
        }
    }
}

// ─── EncryptedQueryBuilder ────────────────────────────────────────────────────

/// Route builder that expects authenticated-encrypted URL query parameters of type `T`
/// (ChaCha20-Poly1305).
///
/// Obtained from [`ServerMechanism::encrypted_query`].  The client must send a single
/// `?data=<base64url>` query parameter.  Any failure returns `403 Forbidden`.
///
/// Optionally attach shared state via [`state`](EncryptedQueryBuilder::state) before
/// finalising with [`onconnect`](EncryptedQueryBuilder::onconnect).
pub struct EncryptedQueryBuilder<T> {
    base:     ServerMechanism,
    key:      SerializationKey,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> EncryptedQueryBuilder<T>
where
    T: bincode::Decode<()> + Send + 'static,
{
    /// Finalises this route with an async handler that receives the decrypted query
    /// parameters as `T`.
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!(
            "Finalising async {:?} route at '{}' (encrypted query)",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        let key    = self.key;
        SocketType {
            method,
            path,
            handler: Arc::new(move |req: IncomingRequest| {
                let h   = handler.clone();
                let key = key.clone();
                Box::pin(async move {
                    let value: T = match decode_query(&req.query, &key) {
                        Ok(v)  => v,
                        Err(e) => return e.into_response(),
                    };
                    match h(value).await {
                        Ok(r)  => r.into_response(),
                        Err(e) => e.into_response(),
                    }
                })
            }),
        }
    }

    /// Attaches shared state `S`, transitioning to [`StatefulEncryptedQueryBuilder`].
    pub fn state<S: Clone + Send + Sync + 'static>(
        self, state: S,
    ) -> StatefulEncryptedQueryBuilder<T, S> {
        StatefulEncryptedQueryBuilder {
            base: self.base,
            key: self.key,
            state,
            _phantom: std::marker::PhantomData,
        }
    }
}

// ─── StatefulEncryptedBodyBuilder ────────────────────────────────────────────

/// Route builder carrying shared state `S` and an authenticated-encrypted request body
/// of type `T` (ChaCha20-Poly1305).
///
/// Obtained from [`EncryptedBodyBuilder::state`] or [`StatefulSocketBuilder::encryption`].
pub struct StatefulEncryptedBodyBuilder<T, S> {
    base:     ServerMechanism,
    key:      SerializationKey,
    state:    S,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, S> StatefulEncryptedBodyBuilder<T, S>
where
    T: bincode::Decode<()> + Send + 'static,
    S: Clone + Send + Sync + 'static,
{
    /// Finalises this route with an async handler that receives `(state: S, body: T)`.
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S, T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!(
            "Finalising async {:?} route at '{}' (state + encrypted body)",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        let key    = self.key;
        let state  = self.state;
        SocketType {
            method,
            path,
            handler: Arc::new(move |req: IncomingRequest| {
                let h   = handler.clone();
                let key = key.clone();
                let s   = state.clone();
                Box::pin(async move {
                    let value: T = match decode_body(&req.body, &key) {
                        Ok(v)  => v,
                        Err(e) => return e.into_response(),
                    };
                    match h(s, value).await {
                        Ok(r)  => r.into_response(),
                        Err(e) => e.into_response(),
                    }
                })
            }),
        }
    }
}

// ─── StatefulEncryptedQueryBuilder ───────────────────────────────────────────

/// Route builder carrying shared state `S` and authenticated-encrypted query parameters
/// of type `T` (ChaCha20-Poly1305).
///
/// Obtained from [`EncryptedQueryBuilder::state`] or
/// [`StatefulSocketBuilder::encrypted_query`].
pub struct StatefulEncryptedQueryBuilder<T, S> {
    base:     ServerMechanism,
    key:      SerializationKey,
    state:    S,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, S> StatefulEncryptedQueryBuilder<T, S>
where
    T: bincode::Decode<()> + Send + 'static,
    S: Clone + Send + Sync + 'static,
{
    /// Finalises this route with an async handler that receives `(state: S, query: T)`.
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S, T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!(
            "Finalising async {:?} route at '{}' (state + encrypted query)",
            self.base.method, self.base.path
        );
        let method = self.base.method.to_http();
        let path   = self.base.path.clone();
        let key    = self.key;
        let state  = self.state;
        SocketType {
            method,
            path,
            handler: Arc::new(move |req: IncomingRequest| {
                let h   = handler.clone();
                let key = key.clone();
                let s   = state.clone();
                Box::pin(async move {
                    let value: T = match decode_query(&req.query, &key) {
                        Ok(v)  => v,
                        Err(e) => return e.into_response(),
                    };
                    match h(s, value).await {
                        Ok(r)  => r.into_response(),
                        Err(e) => e.into_response(),
                    }
                })
            }),
        }
    }
}

// ─── Internal decode helpers ─────────────────────────────────────────────────

/// Decrypt an authenticated-encrypted request body into `T`, returning 403 on failure.
fn decode_body<T: bincode::Decode<()>>(
    raw: &bytes::Bytes,
    key: &SerializationKey,
) -> Result<T, Rejection> {
    crate::serialization::open(raw, key.veil_key()).map_err(|e| {
        log::debug!("body decryption failed (key mismatch or corrupt body): {}", e);
        Rejection::forbidden()
    })
}

/// Decrypt an authenticated-encrypted `?data=<base64url>` query into `T`, returning 403 on failure.
fn decode_query<T: bincode::Decode<()>>(
    raw_query: &str,
    key: &SerializationKey,
) -> Result<T, Rejection> {
    use base64::Engine;

    #[derive(serde::Deserialize)]
    struct DataParam { data: String }

    let q: DataParam = serde_urlencoded::from_str(raw_query).map_err(|_| {
        log::debug!("encrypted query missing `data` parameter");
        Rejection::forbidden()
    })?;

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&q.data)
        .map_err(|e| {
            log::debug!("base64url decode failed: {}", e);
            Rejection::forbidden()
        })?;

    crate::serialization::open(&bytes, key.veil_key()).map_err(|e| {
        log::debug!("query decryption failed: {}", e);
        Rejection::forbidden()
    })
}

/// Returns a `403 Forbidden` rejection.
///
/// Use in route handlers to deny access:
/// ```rust,no_run
/// # use toolkit_zero::socket::server::*;
/// # let _ = ServerMechanism::post("/secure")
/// #     .onconnect(|| async { Err::<EmptyReply, _>(forbidden()) });
/// ```
pub fn forbidden() -> Rejection {
    Rejection::forbidden()
}

// ─── Status ───────────────────────────────────────────────────────────────────

/// A collection of common HTTP status codes used with the reply helpers.
///
/// Converts into `http::StatusCode` via [`From`] and is accepted by
/// [`reply_with_status`] and [`reply_with_status_and_json`].  Also usable directly
/// in the [`reply!`] macro via the `status => Status::X` argument.
#[derive(Clone, Copy, Debug)]
pub enum Status {
    // 2xx
    Ok,
    Created,
    Accepted,
    NoContent,
    // 3xx
    MovedPermanently,
    Found,
    NotModified,
    TemporaryRedirect,
    PermanentRedirect,
    // 4xx
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    Conflict,
    Gone,
    UnprocessableEntity,
    TooManyRequests,
    // 5xx
    InternalServerError,
    NotImplemented,
    BadGateway,
    ServiceUnavailable,
    GatewayTimeout,
}

impl From<Status> for http::StatusCode {
    fn from(s: Status) -> Self {
        match s {
            Status::Ok                  => http::StatusCode::OK,
            Status::Created             => http::StatusCode::CREATED,
            Status::Accepted            => http::StatusCode::ACCEPTED,
            Status::NoContent           => http::StatusCode::NO_CONTENT,
            Status::MovedPermanently    => http::StatusCode::MOVED_PERMANENTLY,
            Status::Found               => http::StatusCode::FOUND,
            Status::NotModified         => http::StatusCode::NOT_MODIFIED,
            Status::TemporaryRedirect   => http::StatusCode::TEMPORARY_REDIRECT,
            Status::PermanentRedirect   => http::StatusCode::PERMANENT_REDIRECT,
            Status::BadRequest          => http::StatusCode::BAD_REQUEST,
            Status::Unauthorized        => http::StatusCode::UNAUTHORIZED,
            Status::Forbidden           => http::StatusCode::FORBIDDEN,
            Status::NotFound            => http::StatusCode::NOT_FOUND,
            Status::MethodNotAllowed    => http::StatusCode::METHOD_NOT_ALLOWED,
            Status::Conflict            => http::StatusCode::CONFLICT,
            Status::Gone                => http::StatusCode::GONE,
            Status::UnprocessableEntity => http::StatusCode::UNPROCESSABLE_ENTITY,
            Status::TooManyRequests     => http::StatusCode::TOO_MANY_REQUESTS,
            Status::InternalServerError => http::StatusCode::INTERNAL_SERVER_ERROR,
            Status::NotImplemented      => http::StatusCode::NOT_IMPLEMENTED,
            Status::BadGateway          => http::StatusCode::BAD_GATEWAY,
            Status::ServiceUnavailable  => http::StatusCode::SERVICE_UNAVAILABLE,
            Status::GatewayTimeout      => http::StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

// ─── Server ───────────────────────────────────────────────────────────────────

/// The HTTP server that owns and dispatches a collection of [`SocketType`] routes.
///
/// Build routes through the [`ServerMechanism`] builder chain, register each with
/// [`mechanism`](Server::mechanism), then start the server with [`serve`](Server::serve).
///
/// # Example
/// ```rust,no_run
/// # use toolkit_zero::socket::server::{Server, ServerMechanism, Status};
/// # use toolkit_zero::socket::server::reply;
/// # use serde::Serialize;
/// # #[derive(Serialize)] struct Pong { ok: bool }
///
/// let mut server = Server::default();
///
/// server
///     .mechanism(
///         ServerMechanism::get("/ping")
///             .onconnect(|| async { reply!(json => Pong { ok: true }) })
///     )
///     .mechanism(
///         ServerMechanism::delete("/session")
///             .onconnect(|| async { reply!() })
///     );
///
/// // Blocks forever — call only to actually run the server:
/// // server.serve(([0, 0, 0, 0], 8080)).await;
/// ```
///
/// # Caution
/// Calling [`serve`](Server::serve) with no routes registered will **panic**.
pub struct Server {
    mechanisms: Vec<SocketType>,
    /// Default bind address, set by [`rebind`](Server::rebind).
    bind_addr: Option<std::net::SocketAddr>,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    fn new() -> Self {
        Self { mechanisms: Vec::new(), bind_addr: None }
    }

    /// Registers a [`SocketType`] route on this server.
    ///
    /// Routes are evaluated in registration order.  Returns `&mut Self` for chaining.
    pub fn mechanism(&mut self, mech: SocketType) -> &mut Self {
        self.mechanisms.push(mech);
        log::debug!("Route registered (total: {})", self.mechanisms.len());
        self
    }

    /// Binds to `addr` and starts serving all registered routes.
    ///
    /// Returns a [`ServerFuture`] that can be:
    /// - **`.await`'d** — runs the server in the current task (infinite loop)
    /// - **`.background()`'d** — spawns the server as a Tokio background task
    ///
    /// # Panics
    /// Panics if no routes have been registered or if the address cannot be bound.
    pub fn serve(self, addr: impl Into<SocketAddr>) -> ServerFuture {
        let addr   = addr.into();
        let routes = Arc::new(tokio::sync::RwLock::new(self.mechanisms));
        ServerFuture::new(async move {
            log::info!("Server binding to {}", addr);
            run_hyper_server(routes, addr, std::future::pending::<()>()).await;
        })
    }

    /// Binds to `addr`, serves all registered routes, and shuts down gracefully when
    /// `shutdown` resolves.
    ///
    /// Returns a [`ServerFuture`] that can be `.await`'d or `.background()`'d.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use tokio::sync::oneshot;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let (tx, rx) = oneshot::channel::<()>();
    /// # let mut server = toolkit_zero::socket::server::Server::default();
    ///
    /// let handle = server.serve_with_graceful_shutdown(
    ///     ([127, 0, 0, 1], 8080),
    ///     async move { rx.await.ok(); },
    /// ).background();
    /// tx.send(()).ok();
    /// handle.await.ok();
    /// # }
    /// ```
    pub fn serve_with_graceful_shutdown(
        self,
        addr: impl Into<std::net::SocketAddr>,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> ServerFuture {
        let addr   = addr.into();
        let routes = Arc::new(tokio::sync::RwLock::new(self.mechanisms));
        ServerFuture::new(async move {
            log::info!("Server binding to {} (graceful shutdown enabled)", addr);
            run_hyper_server(routes, addr, shutdown).await;
        })
    }

    /// Serves all registered routes from an already-bound `listener`, shutting down
    /// gracefully when `shutdown` resolves.
    ///
    /// Returns a [`ServerFuture`] that can be `.await`'d or `.background()`'d.
    ///
    /// Use this when port `0` is passed to `TcpListener::bind` and you need to know
    /// the actual OS-assigned port before the server starts.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use tokio::net::TcpListener;
    /// use tokio::sync::oneshot;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> std::io::Result<()> {
    /// let listener = TcpListener::bind("127.0.0.1:0").await?;
    /// let port = listener.local_addr()?.port();
    ///
    /// let (tx, rx) = oneshot::channel::<()>();
    /// # let mut server = toolkit_zero::socket::server::Server::default();
    ///
    /// let handle = server
    ///     .serve_from_listener(listener, async move { rx.await.ok(); })
    ///     .background();
    /// tx.send(()).ok();
    /// handle.await.ok();
    /// # Ok(())
    /// # }
    /// ```
    pub fn serve_from_listener(
        self,
        listener: tokio::net::TcpListener,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> ServerFuture {
        let routes = Arc::new(tokio::sync::RwLock::new(self.mechanisms));
        ServerFuture::new(async move {
            log::info!(
                "Server running on {} (graceful shutdown enabled)",
                listener.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into())
            );
            run_hyper_server_inner(routes, listener, shutdown).await;
        })
    }

    /// Stores `addr` as this server's default bind address.
    ///
    /// This is a pre-serve convenience setter.  Call it before
    /// [`serve_managed`](Server::serve_managed) or any other `serve*` variant to
    /// record the initial address without starting the server.
    ///
    /// Returns `&mut Self` for method chaining.
    pub fn rebind(&mut self, addr: impl Into<std::net::SocketAddr>) -> &mut Self {
        self.bind_addr = Some(addr.into());
        log::debug!("Default bind address updated to {:?}", self.bind_addr);
        self
    }

    /// Starts all registered routes in a background Tokio task and returns a
    /// [`BackgroundServer`] handle.
    ///
    /// Unlike `serve*` + `.background()`, this method keeps a live route table
    /// inside the handle, enabling:
    ///
    /// - [`BackgroundServer::rebind`]     — graceful stop + restart on a new address
    /// - [`BackgroundServer::mechanism`]   — add routes **without restarting**
    /// - [`BackgroundServer::addr`]        — query the current bind address
    /// - [`BackgroundServer::stop`]        — shut down and await completion
    ///
    /// # Panics
    /// Panics if no routes have been registered.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::server::Server;
    /// # use serde::Serialize;
    /// # use toolkit_zero::socket::server::reply;
    /// # #[derive(Serialize)] struct Pong { ok: bool }
    /// # #[tokio::main]
    /// # async fn main() {
    /// let mut server = Server::default();
    /// server.mechanism(
    ///     toolkit_zero::socket::server::ServerMechanism::get("/ping")
    ///         .onconnect(|| async { reply!(json => Pong { ok: true }) })
    /// );
    ///
    /// let mut bg = server.serve_managed(([127, 0, 0, 1], 8080));
    /// println!("Running on {}", bg.addr());
    ///
    /// bg.rebind(([127, 0, 0, 1], 9090)).await;
    /// println!("Rebound to {}", bg.addr());
    ///
    /// bg.stop().await;
    /// # }
    /// ```
    pub fn serve_managed(self, addr: impl Into<std::net::SocketAddr>) -> BackgroundServer {
        let addr   = addr.into();
        let routes = Arc::new(tokio::sync::RwLock::new(self.mechanisms));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let routes_ref = Arc::clone(&routes);
        let handle = tokio::spawn(run_hyper_server(
            routes_ref,
            addr,
            async { rx.await.ok(); },
        ));
        BackgroundServer {
            routes,
            addr,
            shutdown_tx: Some(tx),
            handle: Some(handle),
        }
    }
}

// ─── ServerFuture ────────────────────────────────────────────────────────────

/// Opaque future returned by [`Server::serve`], [`Server::serve_with_graceful_shutdown`],
/// and [`Server::serve_from_listener`].
///
/// A `ServerFuture` can be used in two ways:
///
/// - **`.await`** — drives the server inline in the current task.
/// - **`.background()`** — spawns the server on a new Tokio task and returns a
///   [`tokio::task::JoinHandle<()>`] immediately.
pub struct ServerFuture(Pin<Box<dyn Future<Output = ()> + Send + 'static>>);

impl ServerFuture {
    fn new(fut: impl Future<Output = ()> + Send + 'static) -> Self {
        Self(Box::pin(fut))
    }

    /// Spawns the server on a new Tokio background task and returns a `JoinHandle<()>`.
    ///
    /// # Panics
    /// Panics if called outside a Tokio runtime.
    pub fn background(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.0)
    }
}

impl std::future::IntoFuture for ServerFuture {
    type Output     = ();
    type IntoFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
    fn into_future(self) -> Self::IntoFuture {
        self.0
    }
}

// ─── Internal: dispatch + server loop ────────────────────────────────────────

/// Dispatch a single hyper request to the matching route handler.
async fn dispatch(
    routes: &Arc<tokio::sync::RwLock<Vec<SocketType>>>,
    req: hyper::Request<hyper::body::Incoming>,
) -> http::Response<bytes::Bytes> {
    use http_body_util::BodyExt;

    let (parts, body) = req.into_parts();
    let path    = parts.uri.path().to_owned();
    let query   = parts.uri.query().unwrap_or("").to_owned();
    let method  = parts.method.clone();
    let headers = parts.headers.clone();

    // Collect body bytes before acquiring the route lock.
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            log::debug!("failed to read request body: {}", e);
            return http::Response::builder()
                .status(http::StatusCode::BAD_REQUEST)
                .body(bytes::Bytes::new())
                .unwrap();
        }
    };

    // Hold lock only long enough to clone the matching handler Arc.
    let handler = {
        let guard = routes.read().await;
        guard
            .iter()
            .find(|s| s.method == method && path_matches(&s.path, &path))
            .map(|s| Arc::clone(&s.handler))
    };

    match handler {
        Some(h) => {
            h(IncomingRequest { body: body_bytes, query, headers }).await
        }
        None => {
            log::debug!("No route matched {} {}", method, path);
            http::Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(bytes::Bytes::new())
                .unwrap()
        }
    }
}

/// Core server loop — drives an already-bound listener with graceful shutdown.
///
/// Uses `hyper::server::conn::http1::Builder` (HTTP/1.1) whose `Connection<IO, S>`
/// has no lifetime tied to the builder, making it `'static` and compatible with
/// `tokio::spawn` and `GracefulShutdown::watch`.
async fn run_hyper_server_inner(
    routes:   Arc<tokio::sync::RwLock<Vec<SocketType>>>,
    listener: tokio::net::TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) {
    use hyper_util::server::graceful::GracefulShutdown;
    use hyper_util::rt::TokioIo;
    use hyper::server::conn::http1;

    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, remote) = match result {
                    Ok(pair) => pair,
                    Err(e) => {
                        log::warn!("accept error: {}", e);
                        continue;
                    }
                };
                log::trace!("accepted connection from {}", remote);

                let routes_ref = Arc::clone(&routes);
                // http1::Builder::serve_connection returns Connection<IO, S> with no
                // builder-lifetime, so it is 'static when IO + S are 'static.
                let conn = http1::Builder::new().serve_connection(
                    TokioIo::new(stream),
                    hyper::service::service_fn(move |req| {
                        let r = Arc::clone(&routes_ref);
                        async move {
                            let resp = dispatch(&r, req).await;
                            let (parts, body) = resp.into_parts();
                            Ok::<_, std::convert::Infallible>(
                                http::Response::from_parts(
                                    parts,
                                    http_body_util::Full::new(body),
                                )
                            )
                        }
                    }),
                );
                let fut = graceful.watch(conn);
                tokio::spawn(async move {
                    if let Err(e) = fut.await {
                        log::debug!("connection error: {}", e);
                    }
                });
            }
            _ = &mut shutdown => {
                log::info!("shutdown signal received — draining in-flight connections");
                break;
            }
        }
    }

    // Free the TCP port so a rebound server can bind immediately.
    drop(listener);

    // Block until every in-flight request completes.
    graceful.shutdown().await;
    log::info!("all connections drained");
}

/// Bind to `addr` then delegate to [`run_hyper_server_inner`].
async fn run_hyper_server(
    routes:   Arc<tokio::sync::RwLock<Vec<SocketType>>>,
    addr:     SocketAddr,
    shutdown: impl Future<Output = ()> + Send + 'static,
) {
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => {
            log::info!("server bound to {}", addr);
            l
        }
        Err(e) => {
            log::error!("failed to bind {}: {}", addr, e);
            panic!("server bind failed: {}", e);
        }
    };
    run_hyper_server_inner(routes, listener, shutdown).await;
}

// ─── BackgroundServer ─────────────────────────────────────────────────────────

/// A managed, background HTTP server returned by [`Server::serve_managed`].
///
/// The server starts as soon as `serve_managed` is called.  Use this handle to:
///
/// - [`addr`](BackgroundServer::addr) — query the current bind address
/// - [`rebind`](BackgroundServer::rebind) — gracefully migrate to a new address
/// - [`mechanism`](BackgroundServer::mechanism) — add a route live, **no restart**
/// - [`stop`](BackgroundServer::stop) — shut down and await the task
///
/// # Routes are preserved across `rebind`
/// All routes registered before [`serve_managed`](Server::serve_managed), plus any
/// added via [`mechanism`](BackgroundServer::mechanism), are automatically carried over when
/// [`rebind`](BackgroundServer::rebind) restarts the server.
///
/// # Ownership
/// Dropping a `BackgroundServer` without calling [`stop`](BackgroundServer::stop)
/// leaves the background task running until the Tokio runtime exits.
///
/// # Example
/// ```rust,no_run
/// # use toolkit_zero::socket::server::Server;
/// # use serde::Serialize;
/// # use toolkit_zero::socket::server::reply;
/// # #[derive(Serialize)] struct Pong { ok: bool }
/// # #[tokio::main]
/// # async fn main() {
/// let mut server = Server::default();
/// server.mechanism(
///     toolkit_zero::socket::server::ServerMechanism::get("/ping")
///         .onconnect(|| async { reply!(json => Pong { ok: true }) })
/// );
/// let mut bg = server.serve_managed(([127, 0, 0, 1], 8080));
/// assert_eq!(bg.addr().port(), 8080);
///
/// bg.rebind(([127, 0, 0, 1], 9090)).await;
/// assert_eq!(bg.addr().port(), 9090);
///
/// bg.stop().await;
/// # }
/// ```
pub struct BackgroundServer {
    /// Shared mutable route table — written by [`mechanism`](BackgroundServer::mechanism), read by the server loop.
    routes:      Arc<tokio::sync::RwLock<Vec<SocketType>>>,
    addr:        std::net::SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    handle:      Option<tokio::task::JoinHandle<()>>,
}

impl BackgroundServer {
    /// Returns the address the server is currently bound to.
    pub fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    /// Shuts the server down gracefully and awaits the background task.
    ///
    /// In-flight requests complete before the server stops.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }

    /// Migrates the server to `addr` with zero route loss:
    ///
    /// 1. Sends a graceful shutdown signal to the current instance.
    /// 2. Waits for all in-flight requests to complete.
    /// 3. Spawns a fresh server task on the new address with the same routes.
    ///
    /// After this method returns, [`addr`](BackgroundServer::addr) reflects the
    /// new address and the server is accepting connections.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use toolkit_zero::socket::server::Server;
    /// # use serde::Serialize;
    /// # use toolkit_zero::socket::server::reply;
    /// # #[derive(Serialize)] struct Pong { ok: bool }
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let mut server = Server::default();
    /// # server.mechanism(
    /// #     toolkit_zero::socket::server::ServerMechanism::get("/ping")
    /// #         .onconnect(|| async { reply!(json => Pong { ok: true }) })
    /// # );
    /// let mut bg = server.serve_managed(([127, 0, 0, 1], 8080));
    ///
    /// bg.rebind(([127, 0, 0, 1], 9090)).await;
    /// assert_eq!(bg.addr().port(), 9090);
    ///
    /// bg.stop().await;
    /// # }
    /// ```
    pub async fn rebind(&mut self, addr: impl Into<std::net::SocketAddr>) {
        // 1. Graceful shutdown of the current server.
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        // 2. Wait for all in-flight requests to drain.
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
        // 3. Start on the new address, sharing the existing route table.
        let new_addr = addr.into();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        self.shutdown_tx = Some(tx);
        self.addr        = new_addr;
        let routes = Arc::clone(&self.routes);
        self.handle = Some(tokio::spawn(run_hyper_server(
            routes,
            new_addr,
            async { rx.await.ok(); },
        )));
        log::info!("Server rebound to {}", new_addr);
    }

    /// Registers a new route on the **running** server without any restart.
    ///
    /// Because routes are stored in an `Arc<RwLock<Vec<SocketType>>>` shared between
    /// this handle and the server's dispatch loop, writing through the lock makes the
    /// new route visible to the next incoming request immediately — no TCP port gap,
    /// no in-flight request interruption.
    ///
    /// Returns `&mut Self` for chaining.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use toolkit_zero::socket::server::{Server, ServerMechanism, reply};
    /// use serde::Serialize;
    ///
    /// #[derive(Serialize)] struct Pong   { ok:  bool   }
    /// #[derive(Serialize)] struct Status { msg: String }
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let mut server = Server::default();
    /// server.mechanism(
    ///     ServerMechanism::get("/ping")
    ///         .onconnect(|| async { reply!(json => Pong { ok: true }) })
    /// );
    ///
    /// let mut bg = server.serve_managed(([127, 0, 0, 1], 8080));
    ///
    /// bg.mechanism(
    ///     ServerMechanism::get("/status")
    ///         .onconnect(|| async { reply!(json => Status { msg: "enabled".into() }) })
    /// ).await;
    ///
    /// // /status is now live alongside /ping — no restart.
    /// bg.stop().await;
    /// # }
    /// ```
    pub async fn mechanism(&mut self, mech: SocketType) -> &mut Self {
        self.routes.write().await.push(mech);
        log::debug!(
            "mechanism: live route added (total = {})",
            self.routes.read().await.len()
        );
        self
    }
}

// ─── Reply helpers ────────────────────────────────────────────────────────────

/// Wraps `reply` with the given HTTP `status` code and returns it as a result.
///
/// Pairs with the [`reply!`] macro form `reply!(message => ..., status => ...)`.
pub fn reply_with_status(
    status: Status,
    reply: impl Reply,
) -> Result<http::Response<bytes::Bytes>, Rejection> {
    let mut resp = reply.into_response();
    *resp.status_mut() = status.into();
    Ok(resp)
}

/// Returns an empty `200 OK` reply result.
///
/// Equivalent to `reply!()`.
pub fn reply() -> Result<impl Reply, Rejection> {
    Ok::<_, Rejection>(EmptyReply)
}

/// Serialises `json` as a JSON body and returns it as a `200 OK` reply result.
///
/// `T` must implement `serde::Serialize`.  Equivalent to `reply!(json => ...)`.
pub fn reply_with_json<T: Serialize>(
    json: &T,
) -> Result<impl Reply + use<T>, Rejection> {
    let bytes = serde_json::to_vec(json).map_err(|_| Rejection::internal())?;
    Ok::<_, Rejection>(JsonReply {
        body:   bytes::Bytes::from(bytes),
        status: http::StatusCode::OK,
    })
}

/// Serialises `json` as a JSON body, attaches the given HTTP `status`, and returns a result.
///
/// `T` must implement `serde::Serialize`.  Equivalent to `reply!(json => ..., status => ...)`.
pub fn reply_with_status_and_json<T: Serialize>(
    status: Status,
    json: &T,
) -> Result<impl Reply + use<T>, Rejection> {
    let bytes = serde_json::to_vec(json).map_err(|_| Rejection::internal())?;
    Ok::<_, Rejection>(JsonReply {
        body:   bytes::Bytes::from(bytes),
        status: status.into(),
    })
}

/// Seals `value` with `key` and returns it as an `application/octet-stream` response (`200 OK`).
///
/// `T` must implement `bincode::Encode`.
/// Equivalent to `reply!(sealed => value, key => key)`.
pub fn reply_sealed<T: bincode::Encode>(
    value: &T,
    key: SerializationKey,
) -> Result<http::Response<bytes::Bytes>, Rejection> {
    sealed_response(value, key, None)
}

/// Seals `value` with `key`, attaches the given HTTP `status`, and returns it as a result.
///
/// Equivalent to `reply!(sealed => value, key => key, status => Status::X)`.
pub fn reply_sealed_with_status<T: bincode::Encode>(
    value: &T,
    key: SerializationKey,
    status: Status,
) -> Result<http::Response<bytes::Bytes>, Rejection> {
    sealed_response(value, key, Some(status))
}

fn sealed_response<T: bincode::Encode>(
    value: &T,
    key: SerializationKey,
    status: Option<Status>,
) -> Result<http::Response<bytes::Bytes>, Rejection> {
    let code: http::StatusCode = status.map(Into::into).unwrap_or(http::StatusCode::OK);
    let sealed = crate::serialization::seal(value, key.veil_key())
        .map_err(|_| Rejection::internal())?;
    Ok(http::Response::builder()
        .status(code)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .body(bytes::Bytes::from(sealed))
        .unwrap())
}

// ─── reply! macro ─────────────────────────────────────────────────────────────

/// Convenience macro for constructing reply results inside route handlers.
///
/// | Syntax | Equivalent | Description |
/// |---|---|---|
/// | `reply!()` | [`reply()`] | Empty `200 OK` response. |
/// | `reply!(message => expr, status => Status::X)` | [`reply_with_status`] | Any `Reply` with a status code. |
/// | `reply!(json => expr)` | [`reply_with_json`] | JSON body with `200 OK`. |
/// | `reply!(json => expr, status => Status::X)` | [`reply_with_status_and_json`] | JSON body with a status code. |
/// | `reply!(sealed => expr, key => key)` | [`reply_sealed`] | Encrypted body, `200 OK`. |
/// | `reply!(sealed => expr, key => key, status => Status::X)` | [`reply_sealed_with_status`] | Encrypted body with status. |
///
/// # Example
/// ```rust,no_run
/// # use toolkit_zero::socket::server::{ServerMechanism, Status};
/// # use toolkit_zero::socket::server::reply;
/// # use serde::{Deserialize, Serialize};
/// # #[derive(Deserialize, Serialize)] struct Item { id: u32, name: String }
///
/// // Empty 200 OK
/// let ping = ServerMechanism::get("/ping")
///     .onconnect(|| async { reply!() });
///
/// // JSON body, 200 OK
/// let list = ServerMechanism::get("/items")
///     .onconnect(|| async {
///         let items: Vec<Item> = vec![];
///         reply!(json => items)
///     });
///
/// // JSON body with a custom status
/// let create = ServerMechanism::post("/items")
///     .json::<Item>()
///     .onconnect(|item| async move {
///         reply!(json => item, status => Status::Created)
///     });
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! reply {
    () => {{
        $crate::socket::server::reply()
    }};

    (message => $message: expr, status => $status: expr) => {{
        $crate::socket::server::reply_with_status($status, $message)
    }};

    (json => $json: expr) => {{
        $crate::socket::server::reply_with_json(&$json)
    }};

    (json => $json: expr, status => $status: expr) => {{
        $crate::socket::server::reply_with_status_and_json($status, &$json)
    }};

    (sealed => $val: expr, key => $key: expr) => {{
        $crate::socket::server::reply_sealed(&$val, $key)
    }};

    (sealed => $val: expr, key => $key: expr, status => $status: expr) => {{
        $crate::socket::server::reply_sealed_with_status(&$val, $key, $status)
    }};
}

/// Re-export the [`reply!`] macro so it is accessible as
/// `toolkit_zero::socket::server::reply` and included in glob imports.
pub use crate::reply;
