
//! Typed, fluent HTTP server construction.
//!
//! This module provides a builder-oriented API for declaring HTTP routes and
//! serving them with [`warp`] under the hood. The entry point for every route
//! is [`ServerMechanism`], which pairs an HTTP method with a URL path and
//! supports incremental enrichment — attaching a JSON body expectation, URL
//! query parameter deserialisation, or shared state — before being finalised
//! into a [`SocketType`] route handle via `onconnect`.
//!
//! Completed routes are registered on a [`Server`] and served with a single
//! `.await`. Graceful shutdown is available via
//! [`Server::serve_with_graceful_shutdown`] and [`Server::serve_from_listener`].
//!
//! # Builder chains at a glance
//!
//! | Chain | Handler receives |
//! |---|---|
//! | `ServerMechanism::method(path).onconnect(f)` | nothing |
//! | `.json::<T>().onconnect(f)` | `T: DeserializeOwned` |
//! | `.query::<T>().onconnect(f)` | `T: DeserializeOwned` |
//! | `.encryption::<T>(key).onconnect(f)` | `T: bincode::Decode<()>` (VEIL-decrypted body) |
//! | `.encrypted_query::<T>(key).onconnect(f)` | `T: bincode::Decode<()>` (VEIL-decrypted query) |
//! | `.state(s).onconnect(f)` | `S: Clone + Send + Sync` |
//! | `.state(s).json::<T>().onconnect(f)` | `(S, T)` |
//! | `.state(s).query::<T>().onconnect(f)` | `(S, T)` |
//! | `.state(s).encryption::<T>(key).onconnect(f)` | `(S, T)` — VEIL-decrypted body |
//! | `.state(s).encrypted_query::<T>(key).onconnect(f)` | `(S, T)` — VEIL-decrypted query |
//!
//! For blocking handlers (not recommended in production) every finaliser also
//! has an unsafe `onconnect_sync` counterpart.
//!
//! # `#[mechanism]` attribute macro
//!
//! As an alternative to spelling out the builder chain by hand, the
//! [`mechanism`] attribute macro collapses the entire
//! `server.mechanism(ServerMechanism::method(path) … .onconnect(handler))` call
//! into a single decorated `async fn`:
//!
//! ```rust,no_run
//! # use toolkit_zero::socket::server::{Server, mechanism, reply, Status};
//! # use serde::Deserialize;
//! # #[derive(Deserialize)] struct NewItem { name: String }
//! # #[derive(serde::Serialize)] struct Item { id: u32, name: String }
//! # let mut server = Server::default();
//! // Fluent form:
//! // server.mechanism(
//! //     ServerMechanism::post("/items")
//! //         .json::<NewItem>()
//! //         .onconnect(|body: NewItem| async move {
//! //             reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
//! //         })
//! // );
//!
//! // Equivalent attribute form:
//! #[mechanism(server, POST, "/items", json)]
//! async fn create(body: NewItem) {
//!     reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
//! }
//! ```
//!
//! See the [`mechanism`] item for the full syntax reference.
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
//!
//! // 200 OK, JSON body
//! // reply!(json => item)
//!
//! // 201 Created, JSON body
//! // reply!(json => item, status => Status::Created)
//! ```

use std::{future::Future, net::SocketAddr};
use serde::{de::DeserializeOwned, Serialize};
use warp::{Filter, Rejection, Reply, filters::BoxedFilter};

pub use super::SerializationKey;
pub use toolkit_zero_macros::mechanism;

/// A fully assembled, type-erased HTTP route ready to be registered on a [`Server`].
///
/// This is the final product of every builder chain. Pass it to [`Server::mechanism`] to mount it.
pub type SocketType = BoxedFilter<(warp::reply::Response, )>;

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
    fn filter(&self) -> BoxedFilter<()> {
        match self {
            HttpMethod::Get     => warp::get().boxed(),
            HttpMethod::Post    => warp::post().boxed(),
            HttpMethod::Put     => warp::put().boxed(),
            HttpMethod::Delete  => warp::delete().boxed(),
            HttpMethod::Patch   => warp::patch().boxed(),
            HttpMethod::Head    => warp::head().boxed(),
            HttpMethod::Options => warp::options().boxed(),
        }
    }
}


fn path_filter(path: &str) -> BoxedFilter<()> {
    log::trace!("Building path filter for: '{}'", path);
    let segs: Vec<&'static str> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| -> &'static str { Box::leak(s.to_owned().into_boxed_str()) })
        .collect();

    if segs.is_empty() {
        return warp::path::end().boxed();
    }

    // Start with the first segment, then and-chain the rest.
    let mut f: BoxedFilter<()> = warp::path(segs[0]).boxed();
    for seg in &segs[1..] {
        f = f.and(warp::path(*seg)).boxed();
    }
    f.and(warp::path::end()).boxed()
}

/// Entry point for building an HTTP route.
///
/// Pairs an HTTP method with a URL path and acts as the root of a fluent builder chain.
/// Optionally attach shared state, a JSON body expectation, or URL query parameter
/// deserialisation — then finalise with [`onconnect`](ServerMechanism::onconnect) (async) or
/// [`onconnect_sync`](ServerMechanism::onconnect_sync) (sync) to produce a [`SocketType`]
/// ready to be mounted on a [`Server`].
///
/// # Example
/// ```rust,no_run
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
/// // GET — URL query params deserialised into `SearchQuery`
/// let search = ServerMechanism::get("/search")
///     .query::<SearchQuery>()
///     .onconnect(|params| async move {
///         let _q = params.q;
///         reply!()
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
    /// A fresh clone of `S` is injected into the handler on every request.  For mutable
    /// shared state, wrap the inner value in `Arc<Mutex<_>>` or `Arc<RwLock<_>>` before
    /// passing it here — only the outer `Arc` is cloned per request; the inner data stays
    /// shared across all requests.
    ///
    /// `S` must be `Clone + Send + Sync + 'static`.
    ///
    /// From [`StatefulSocketBuilder`] you can further add a JSON body (`.json`), query
    /// parameters (`.query`), or encryption (`.encryption` / `.encrypted_query`) before
    /// finalising with `onconnect`.
    ///
    /// # Example
    /// ```rust,no_run
    /// use std::sync::{Arc, Mutex};
    ///
    /// let db: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    ///
    /// let route = ServerMechanism::get("/list")
    ///     .state(db.clone())
    ///     .onconnect(|state| async move {
    ///         let items = state.lock().unwrap().clone();
    ///         reply!(json => items)
    ///     });
    /// ```
    pub fn state<S: Clone + Send + Sync + 'static>(self, state: S) -> StatefulSocketBuilder<S> {
        log::trace!("Attaching state to {:?} route at '{}'", self.method, self.path);
        StatefulSocketBuilder { base: self, state }
    }

    /// Declares that this route expects a JSON-encoded request body, transitioning to
    /// [`JsonSocketBuilder`].
    ///
    /// On each incoming request the body is parsed as `Content-Type: application/json`
    /// and deserialised into `T`.  If the body is absent, malformed, or fails to
    /// deserialise, the request is rejected before the handler is ever called.
    /// When you subsequently call [`onconnect`](JsonSocketBuilder::onconnect), the handler
    /// receives a fully-deserialised, ready-to-use `T`.
    ///
    /// `T` must implement `serde::de::DeserializeOwned`.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use serde::Deserialize;
    /// # #[derive(Deserialize)] struct Payload { value: i32 }
    ///
    /// let route = ServerMechanism::post("/submit")
    ///     .json::<Payload>()
    ///     .onconnect(|body| async move {
    ///         reply!(json => body.value)
    ///     });
    /// ```
    pub fn json<T: DeserializeOwned + Send>(self) -> JsonSocketBuilder<T> {
        log::trace!("Attaching JSON body expectation to {:?} route at '{}'", self.method, self.path);
        JsonSocketBuilder { base: self, _phantom: std::marker::PhantomData }
    }

    /// Declares that this route extracts its input from URL query parameters, transitioning
    /// to [`QuerySocketBuilder`].
    ///
    /// On each incoming request the query string (`?field=value&...`) is deserialised into
    /// `T`.  A missing or malformed query string is rejected before the handler is called.
    /// When you subsequently call [`onconnect`](QuerySocketBuilder::onconnect), the handler
    /// receives a fully-deserialised, ready-to-use `T`.
    ///
    /// `T` must implement `serde::de::DeserializeOwned`.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use serde::Deserialize;
    /// # #[derive(Deserialize)] struct Filter { page: u32, per_page: u32 }
    ///
    /// let route = ServerMechanism::get("/items")
    ///     .query::<Filter>()
    ///     .onconnect(|filter| async move {
    ///         let _ = (filter.page, filter.per_page);
    ///         reply!()
    ///     });
    /// ```
    pub fn query<T: DeserializeOwned + Send>(self) -> QuerySocketBuilder<T> {
        log::trace!("Attaching query parameter expectation to {:?} route at '{}'", self.method, self.path);
        QuerySocketBuilder { base: self, _phantom: std::marker::PhantomData }
    }

    /// Declares that this route expects a VEIL-encrypted request body, transitioning to
    /// [`EncryptedBodyBuilder`].
    ///
    /// On each incoming request the raw body bytes are decrypted using the provided
    /// [`SerializationKey`] before the handler is called.  If the key does not match or
    /// the body is corrupt, the route responds with `403 Forbidden` and the handler is
    /// never invoked — meaning the `T` your handler receives is always a legitimate,
    /// trusted, fully-decrypted value.
    ///
    /// Use `SerializationKey::Default` when both client and server share the built-in key,
    /// or `SerializationKey::Value("your-key")` for a custom shared secret.
    /// For plain-JSON routes (no encryption) use [`.json::<T>()`](ServerMechanism::json)
    /// instead.
    ///
    /// `T` must implement `bincode::Decode<()>`.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use bincode::{Encode, Decode};
    /// # #[derive(Encode, Decode)] struct Payload { value: i32 }
    ///
    /// let route = ServerMechanism::post("/submit")
    ///     .encryption::<Payload>(SerializationKey::Default)
    ///     .onconnect(|body| async move {
    ///         // `body` is already decrypted and deserialised — use it directly.
    ///         reply!(json => body.value)
    ///     });
    /// ```
    pub fn encryption<T>(self, key: SerializationKey) -> EncryptedBodyBuilder<T> {
        log::trace!("Attaching encrypted body to {:?} route at '{}'", self.method, self.path);
        EncryptedBodyBuilder { base: self, key, _phantom: std::marker::PhantomData }
    }

    /// Declares that this route expects VEIL-encrypted URL query parameters, transitioning
    /// to [`EncryptedQueryBuilder`].
    ///
    /// The client must send a single `?data=<base64url>` query parameter whose value is
    /// the URL-safe base64 encoding of the VEIL-encrypted struct bytes.  On each request
    /// the server base64-decodes then decrypts the payload using the provided
    /// [`SerializationKey`].  If the `data` parameter is missing, the encoding is invalid,
    /// the key does not match, or the bytes are corrupt, the route responds with
    /// `403 Forbidden` and the handler is never invoked — meaning the `T` your handler
    /// receives is always a legitimate, trusted, fully-decrypted value.
    ///
    /// Use `SerializationKey::Default` or `SerializationKey::Value("your-key")`.  For
    /// plain query-string routes (no encryption) use
    /// [`.query::<T>()`](ServerMechanism::query) instead.
    ///
    /// `T` must implement `bincode::Decode<()>`.
    pub fn encrypted_query<T>(self, key: SerializationKey) -> EncryptedQueryBuilder<T> {
        log::trace!("Attaching encrypted query to {:?} route at '{}'", self.method, self.path);
        EncryptedQueryBuilder { base: self, key, _phantom: std::marker::PhantomData }
    }

    /// Finalises this route with an async handler that receives no arguments.
    ///
    /// Neither a request body nor query parameters are read.  The handler runs on every
    /// matching request and must return `Result<impl Reply, Rejection>`.  Use the
    /// [`reply!`] macro or the standalone reply helpers ([`reply_with_json`],
    /// [`reply_with_status`], etc.) to construct a response.
    ///
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    ///
    /// # Example
    /// ```rust,no_run
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
        let m = self.method.filter();
        let p = path_filter(&self.path);
        m.and(p)
            .and_then(handler)
            .map(|r: Re| r.into_response())
            .boxed()
    }

    /// Finalises this route with a **synchronous** handler that receives no arguments.
    ///
    /// Behaviour and contract are identical to the async variant — neither a body nor
    /// query parameters are read — but the closure may block.  Each request is dispatched
    /// to the blocking thread pool, so the handler must complete quickly to avoid starving
    /// other requests.
    ///
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    ///
    /// # Safety
    ///
    /// Every incoming request spawns an independent task on Tokio's blocking thread pool.
    /// The pool caps the number of live OS threads (default 512), but the **queue of waiting
    /// tasks is unbounded** — under a traffic surge, tasks accumulate without limit, consuming
    /// unbounded memory and causing severe latency spikes or OOM crashes before any queued task
    /// gets a chance to run. Additionally, any panic inside the handler is silently converted
    /// into a `Rejection`, masking runtime errors. Callers must ensure the handler completes
    /// quickly and that adequate backpressure or rate limiting is applied externally.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn() -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!("Registering sync handler on {:?} '{}' — ensure rate-limiting is applied externally", self.method, self.path);
        let m = self.method.filter();
        let p = path_filter(&self.path);
        m.and(p)
            .and_then(move || {
                let handler = handler.clone();
                async move {
                    tokio::task::spawn_blocking(move || handler())
                        .await
                        .unwrap_or_else(|_| {
                            log::warn!("Sync handler panicked; converting to Rejection");
                            Err(warp::reject())
                        })
                }
            })
            .map(|r: Re| r.into_response())
            .boxed()
    }
}


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
    ///
    /// Before the handler is called, the incoming request body is parsed as
    /// `Content-Type: application/json` and deserialised into `T`.  The handler receives
    /// a ready-to-use `T` — no manual parsing is needed.  If the body is absent or cannot
    /// be decoded the request is rejected before the handler is ever invoked.
    ///
    /// The handler must return `Result<impl Reply, Rejection>`.
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where 
        F: Fn(T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!("Finalising async {:?} route at '{}' (JSON body)", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        m.and(p)
            .and(warp::body::json::<T>())
            .and_then(handler)
            .map(|r: Re| r.into_response())
            .boxed()
    }

    /// Finalises this route with a **synchronous** handler that receives the deserialised
    /// JSON body.
    ///
    /// The body is decoded into `T` before the handler is dispatched, identical to the
    /// async variant.  The closure may block but must complete quickly to avoid exhausting
    /// the blocking thread pool.
    ///
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    ///
    /// # Safety
    ///
    /// Every incoming request spawns an independent task on Tokio's blocking thread pool.
    /// The pool caps the number of live OS threads (default 512), but the **queue of waiting
    /// tasks is unbounded** — under a traffic surge, tasks accumulate without limit, consuming
    /// unbounded memory and causing severe latency spikes or OOM crashes before any queued task
    /// gets a chance to run. Additionally, any panic inside the handler is silently converted
    /// into a `Rejection`, masking runtime errors. Callers must ensure the handler completes
    /// quickly and that adequate backpressure or rate limiting is applied externally.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn(T) -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!("Registering sync handler on {:?} '{}' (JSON body) — ensure rate-limiting is applied externally", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        m.and(p)
            .and(warp::body::json::<T>())
            .and_then(move |body: T| {
                let handler = handler.clone();
                async move {
                    tokio::task::spawn_blocking(move || handler(body))
                        .await
                        .unwrap_or_else(|_| {
                            log::warn!("Sync handler (JSON body) panicked; converting to Rejection");
                            Err(warp::reject())
                        })
                }
            })
            .map(|r: Re| r.into_response())
            .boxed()
    }

    /// Attaches shared state `S`, transitioning to [`StatefulJsonSocketBuilder`].
    ///
    /// Alternative ordering to `.state(s).json::<T>()` — both produce the same route.
    /// A fresh clone of `S` is injected alongside the JSON-decoded `T` on every request.
    /// The handler will receive `(state: S, body: T)`.
    ///
    /// `S` must be `Clone + Send + Sync + 'static`.
    pub fn state<S: Clone + Send + Sync + 'static>(self, state: S) -> StatefulJsonSocketBuilder<T, S> {
        StatefulJsonSocketBuilder { base: self.base, state, _phantom: std::marker::PhantomData }
    }

}

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
    ///
    /// Before the handler is called, the URL query string (`?field=value&...`) is parsed
    /// and deserialised into `T`.  The handler receives a ready-to-use `T` — no manual
    /// parsing is needed.  A missing or malformed query string is rejected before the
    /// handler is ever invoked.
    ///
    /// The handler must return `Result<impl Reply, Rejection>`.
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!("Finalising async {:?} route at '{}' (query params)", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        m.and(p)
            .and(warp::filters::query::query::<T>())
            .and_then(handler)
            .map(|r: Re| r.into_response())
            .boxed()
    }

    /// Finalises this route with a **synchronous** handler that receives the deserialised
    /// query parameters.
    ///
    /// The query string is decoded into `T` before the handler is dispatched, identical to
    /// the async variant.  The closure may block but must complete quickly.
    ///
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    ///
    /// # Safety
    ///
    /// Every incoming request spawns an independent task on Tokio's blocking thread pool.
    /// The pool caps the number of live OS threads (default 512), but the **queue of waiting
    /// tasks is unbounded** — under a traffic surge, tasks accumulate without limit, consuming
    /// unbounded memory and causing severe latency spikes or OOM crashes before any queued task
    /// gets a chance to run. Additionally, any panic inside the handler is silently converted
    /// into a `Rejection`, masking runtime errors. Callers must ensure the handler completes
    /// quickly and that adequate backpressure or rate limiting is applied externally.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn(T) -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!("Registering sync handler on {:?} '{}' (query params) — ensure rate-limiting is applied externally", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        m.and(p)
            .and(warp::filters::query::query::<T>())
            .and_then(move |query: T| {
                let handler = handler.clone();
                async move {
                    tokio::task::spawn_blocking(move || handler(query))
                        .await
                        .unwrap_or_else(|_| {
                            log::warn!("Sync handler (query params) panicked; converting to Rejection");
                            Err(warp::reject())
                        })
                }
            })
            .map(|r: Re| r.into_response())
            .boxed()
    }

    /// Attaches shared state `S`, transitioning to [`StatefulQuerySocketBuilder`].
    ///
    /// Alternative ordering to `.state(s).query::<T>()` — both produce the same route.
    /// A fresh clone of `S` is injected alongside the query-decoded `T` on every request.
    /// The handler will receive `(state: S, query: T)`.
    ///
    /// `S` must be `Clone + Send + Sync + 'static`.
    pub fn state<S: Clone + Send + Sync + 'static>(self, state: S) -> StatefulQuerySocketBuilder<T, S> {
        StatefulQuerySocketBuilder { base: self.base, state, _phantom: std::marker::PhantomData }
    }

}


/// Route builder that carries shared state `S` with no body or query expectation.
///
/// Obtained from [`ServerMechanism::state`]. `S` must be `Clone + Send + Sync + 'static`.
/// For mutable shared state, wrap it in `Arc<Mutex<_>>` or `Arc<RwLock<_>>` before passing
/// it here. Finalise with [`onconnect`](StatefulSocketBuilder::onconnect) /
/// [`onconnect_sync`](StatefulSocketBuilder::onconnect_sync).
pub struct StatefulSocketBuilder<S> {
    base: ServerMechanism,
    state: S,
}


impl<S: Clone + Send + Sync + 'static> StatefulSocketBuilder<S> {
    /// Adds a JSON body expectation, transitioning to [`StatefulJsonSocketBuilder`].
    ///
    /// Alternative ordering to `.json::<T>().state(s)` — both produce the same route.
    /// On each request the incoming JSON body is deserialised into `T` and a fresh clone
    /// of `S` is prepared; both are handed to the handler together as `(state: S, body: T)`.
    ///
    /// Allows `.state(s).json::<T>()` as an alternative ordering to `.json::<T>().state(s)`.
    pub fn json<T: DeserializeOwned + Send>(self) -> StatefulJsonSocketBuilder<T, S> {
        log::trace!("Attaching JSON body expectation (after state) to {:?} route at '{}'", self.base.method, self.base.path);
        StatefulJsonSocketBuilder { base: self.base, state: self.state, _phantom: std::marker::PhantomData }
    }

    /// Adds a query parameter expectation, transitioning to [`StatefulQuerySocketBuilder`].
    ///
    /// Alternative ordering to `.query::<T>().state(s)` — both produce the same route.
    /// On each request the URL query string is deserialised into `T` and a fresh clone
    /// of `S` is prepared; both are handed to the handler together as `(state: S, query: T)`.
    ///
    /// Allows `.state(s).query::<T>()` as an alternative ordering to `.query::<T>().state(s)`.
    pub fn query<T: DeserializeOwned + Send>(self) -> StatefulQuerySocketBuilder<T, S> {
        log::trace!("Attaching query param expectation (after state) to {:?} route at '{}'", self.base.method, self.base.path);
        StatefulQuerySocketBuilder { base: self.base, state: self.state, _phantom: std::marker::PhantomData }
    }

    /// Adds an encrypted body expectation, transitioning to [`StatefulEncryptedBodyBuilder`].
    ///
    /// Alternative ordering to `.encryption::<T>(key).state(s)` — both produce the same
    /// route.  On each request the raw body bytes are VEIL-decrypted using `key` before
    /// the handler runs; a wrong key or corrupt body returns `403 Forbidden` without
    /// invoking the handler.  The handler will receive `(state: S, body: T)` where `T` is
    /// always a trusted, fully-decrypted value.
    ///
    /// Allows `.state(s).encryption::<T>(key)` as an alternative ordering to
    /// `.encryption::<T>(key).state(s)`.
    pub fn encryption<T>(self, key: SerializationKey) -> StatefulEncryptedBodyBuilder<T, S> {
        log::trace!("Attaching encrypted body (after state) to {:?} route at '{}'", self.base.method, self.base.path);
        StatefulEncryptedBodyBuilder { base: self.base, key, state: self.state, _phantom: std::marker::PhantomData }
    }

    /// Adds an encrypted query expectation, transitioning to [`StatefulEncryptedQueryBuilder`].
    ///
    /// Alternative ordering to `.encrypted_query::<T>(key).state(s)` — both produce the
    /// same route.  On each request the `?data=<base64url>` query parameter is
    /// base64-decoded then VEIL-decrypted using `key`; a missing, malformed, or
    /// undecryptable payload returns `403 Forbidden` without invoking the handler.  The
    /// handler will receive `(state: S, query: T)` where `T` is always a trusted,
    /// fully-decrypted value.
    ///
    /// Allows `.state(s).encrypted_query::<T>(key)` as an alternative ordering to
    /// `.encrypted_query::<T>(key).state(s)`.
    pub fn encrypted_query<T>(self, key: SerializationKey) -> StatefulEncryptedQueryBuilder<T, S> {
        log::trace!("Attaching encrypted query (after state) to {:?} route at '{}'", self.base.method, self.base.path);
        StatefulEncryptedQueryBuilder { base: self.base, key, state: self.state, _phantom: std::marker::PhantomData }
    }

    /// Finalises this route with an async handler that receives only the shared state.
    ///
    /// On each request a fresh clone of `S` is injected into the handler.  No request body
    /// or query parameters are read.  The handler must return `Result<impl Reply, Rejection>`.
    ///
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!("Finalising async {:?} route at '{}' (state)", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        let state = self.state;
        let state_filter = warp::any().map(move || state.clone());
        m.and(p)
            .and(state_filter)
            .and_then(handler)
            .map(|r: Re| r.into_response())
            .boxed()
    }

    /// Finalises this route with a **synchronous** handler that receives only the shared
    /// state.
    ///
    /// On each request a fresh clone of `S` is passed to the handler.  If `S` wraps a mutex
    /// or lock, contention across concurrent requests can stall the thread pool — ensure the
    /// lock is held only briefly.  The closure may block but must complete quickly.
    ///
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    ///
    /// # Safety
    ///
    /// Every incoming request spawns an independent task on Tokio's blocking thread pool.
    /// The pool caps the number of live OS threads (default 512), but the **queue of waiting
    /// tasks is unbounded** — under a traffic surge, tasks accumulate without limit, consuming
    /// unbounded memory and causing severe latency spikes or OOM crashes before any queued task
    /// gets a chance to run. When the handler acquires a lock on `S` (e.g. `Arc<Mutex<_>>`),
    /// concurrent blocking tasks contending on the same lock can stall indefinitely, causing the
    /// thread pool queue to grow without bound and compounding the exhaustion risk. Additionally,
    /// any panic inside the handler is silently converted into a `Rejection`, masking runtime
    /// errors. Callers must ensure the handler completes quickly, that lock contention on `S`
    /// cannot produce indefinite stalls, and that adequate backpressure or rate limiting is
    /// applied externally.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S) -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!("Registering sync handler on {:?} '{}' (state) — ensure rate-limiting and lock-free state are in place", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        let state = self.state;
        let state_filter = warp::any().map(move || state.clone());
        m.and(p)
            .and(state_filter)
            .and_then(move |s: S| {
                let handler = handler.clone();
                async move {
                    tokio::task::spawn_blocking(move || handler(s))
                        .await
                        .unwrap_or_else(|_| {
                            log::warn!("Sync handler (state) panicked; converting to Rejection");
                            Err(warp::reject())
                        })
                }
            })
            .map(|r: Re| r.into_response())
            .boxed()
    }
}


/// Route builder that carries shared state `S` and expects a JSON body of type `T`.
///
/// Obtained from [`JsonSocketBuilder::state`]. `S` must be `Clone + Send + Sync + 'static`.
/// `T` must implement `serde::de::DeserializeOwned`. Finalise with
/// [`onconnect`](StatefulJsonSocketBuilder::onconnect) /
/// [`onconnect_sync`](StatefulJsonSocketBuilder::onconnect_sync).
pub struct StatefulJsonSocketBuilder<T, S> {
    base: ServerMechanism,
    state: S,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: DeserializeOwned + Send + 'static, S: Clone + Send + Sync + 'static>
    StatefulJsonSocketBuilder<T, S>
{
    /// Finalises this route with an async handler that receives `(state: S, body: T)`.
    ///
    /// On each request the incoming JSON body is deserialised into `T` and a fresh clone
    /// of `S` is prepared — both are handed to the handler together.  The handler is only
    /// called when the body can be decoded; a missing or malformed body is rejected first.
    ///
    /// The handler must return `Result<impl Reply, Rejection>`.
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S, T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!("Finalising async {:?} route at '{}' (state + JSON body)", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        let state = self.state;
        let state_filter = warp::any().map(move || state.clone());
        m.and(p)
            .and(state_filter)
            .and(warp::body::json::<T>())
            .and_then(handler)
            .map(|r: Re| r.into_response())
            .boxed()
    }

    /// Finalises this route with a **synchronous** handler that receives
    /// `(state: S, body: T)`.
    ///
    /// The body is decoded into `T` and a clone of `S` is prepared before the blocking
    /// handler is dispatched.  If `S` wraps a lock, keep it held only briefly.  See
    /// [`ServerMechanism::onconnect_sync`] for the full thread-pool safety notes.
    ///
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    ///
    /// # Safety
    ///
    /// Every incoming request spawns an independent task on Tokio's blocking thread pool.
    /// The pool caps the number of live OS threads (default 512), but the **queue of waiting
    /// tasks is unbounded** — under a traffic surge, tasks accumulate without limit, consuming
    /// unbounded memory and causing severe latency spikes or OOM crashes before any queued task
    /// gets a chance to run. When the handler acquires a lock on `S` (e.g. `Arc<Mutex<_>>`),
    /// concurrent blocking tasks contending on the same lock can stall indefinitely, causing the
    /// thread pool queue to grow without bound and compounding the exhaustion risk. Additionally,
    /// any panic inside the handler is silently converted into a `Rejection`, masking runtime
    /// errors. Callers must ensure the handler completes quickly, that lock contention on `S`
    /// cannot produce indefinite stalls, and that adequate backpressure or rate limiting is
    /// applied externally.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S, T) -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!("Registering sync handler on {:?} '{}' (state + JSON body) — ensure rate-limiting and lock-free state are in place", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        let state = self.state;
        let state_filter = warp::any().map(move || state.clone());
        m.and(p)
            .and(state_filter)
            .and(warp::body::json::<T>())
            .and_then(move |s: S, body: T| {
                let handler = handler.clone();
                async move {
                    tokio::task::spawn_blocking(move || handler(s, body))
                        .await
                        .unwrap_or_else(|_| {
                            log::warn!("Sync handler (state + JSON body) panicked; converting to Rejection");
                            Err(warp::reject())
                        })
                }
            })
            .map(|r: Re| r.into_response())
            .boxed()
    }
}

/// Route builder that carries shared state `S` and expects URL query parameters of type `T`.
///
/// Obtained from [`QuerySocketBuilder::state`]. `S` must be `Clone + Send + Sync + 'static`.
/// `T` must implement `serde::de::DeserializeOwned`. Finalise with
/// [`onconnect`](StatefulQuerySocketBuilder::onconnect) /
/// [`onconnect_sync`](StatefulQuerySocketBuilder::onconnect_sync).
pub struct StatefulQuerySocketBuilder<T, S> {
    base: ServerMechanism,
    state: S,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: DeserializeOwned + Send + 'static, S: Clone + Send + Sync + 'static>
    StatefulQuerySocketBuilder<T, S>
{
    /// Finalises this route with an async handler that receives `(state: S, query: T)`.
    ///
    /// On each request the URL query string is deserialised into `T` and a fresh clone of
    /// `S` is prepared — both are handed to the handler together.  A missing or malformed
    /// query string is rejected before the handler is ever invoked.
    ///
    /// The handler must return `Result<impl Reply, Rejection>`.
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S, T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!("Finalising async {:?} route at '{}' (state + query params)", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        let state = self.state;
        let state_filter = warp::any().map(move || state.clone());
        m.and(p)
            .and(state_filter)
            .and(warp::filters::query::query::<T>())
            .and_then(handler)
            .map(|r: Re| r.into_response())
            .boxed()
    }

    /// Finalises this route with a **synchronous** handler that receives
    /// `(state: S, query: T)`.
    ///
    /// The query string is decoded into `T` and a clone of `S` is prepared before the
    /// blocking handler is dispatched.  If `S` wraps a lock, keep it held only briefly.
    /// See [`ServerMechanism::onconnect_sync`] for the full thread-pool safety notes.
    ///
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    ///
    /// # Safety
    ///
    /// Every incoming request spawns an independent task on Tokio's blocking thread pool.
    /// The pool caps the number of live OS threads (default 512), but the **queue of waiting
    /// tasks is unbounded** — under a traffic surge, tasks accumulate without limit, consuming
    /// unbounded memory and causing severe latency spikes or OOM crashes before any queued task
    /// gets a chance to run. When the handler acquires a lock on `S` (e.g. `Arc<Mutex<_>>`),
    /// concurrent blocking tasks contending on the same lock can stall indefinitely, causing the
    /// thread pool queue to grow without bound and compounding the exhaustion risk. Additionally,
    /// any panic inside the handler is silently converted into a `Rejection`, masking runtime
    /// errors. Callers must ensure the handler completes quickly, that lock contention on `S`
    /// cannot produce indefinite stalls, and that adequate backpressure or rate limiting is
    /// applied externally.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S, T) -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!("Registering sync handler on {:?} '{}' (state + query params) — ensure rate-limiting and lock-free state are in place", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        let state = self.state;
        let state_filter = warp::any().map(move || state.clone());
        m.and(p)
            .and(state_filter)
            .and(warp::filters::query::query::<T>())
            .and_then(move |s: S, query: T| {
                let handler = handler.clone();
                async move {
                    tokio::task::spawn_blocking(move || handler(s, query))
                        .await
                        .unwrap_or_else(|_| {
                            log::warn!("Sync handler (state + query params) panicked; converting to Rejection");
                            Err(warp::reject())
                        })
                }
            })
            .map(|r: Re| r.into_response())
            .boxed()
    }
}

// ─── EncryptedBodyBuilder ────────────────────────────────────────────────────

/// Route builder that expects a VEIL-encrypted request body of type `T`.
///
/// Obtained from [`ServerMechanism::encryption`].  On each matching request the raw
/// body bytes are decrypted using the [`SerializationKey`] supplied there.  If
/// decryption fails for any reason (wrong key, mismatched secret, corrupted payload)
/// the route immediately returns `403 Forbidden` — the handler is never invoked.
///
/// Optionally attach shared state via [`state`](EncryptedBodyBuilder::state) before
/// finalising with [`onconnect`](EncryptedBodyBuilder::onconnect) /
/// [`onconnect_sync`](EncryptedBodyBuilder::onconnect_sync).
pub struct EncryptedBodyBuilder<T> {
    base: ServerMechanism,
    key: SerializationKey,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> EncryptedBodyBuilder<T>
where
    T: bincode::Decode<()> + Send + 'static,
{
    /// Finalises this route with an async handler that receives the decrypted body as `T`.
    ///
    /// On each request the raw body bytes are VEIL-decrypted using the [`SerializationKey`]
    /// configured on this builder.  The handler is only invoked when decryption succeeds —
    /// a wrong key, mismatched secret, or corrupted body causes the route to return
    /// `403 Forbidden` without ever reaching the handler.  The `T` the closure receives is
    /// therefore always a trusted, fully-decrypted value ready to use.
    ///
    /// The handler must return `Result<impl Reply, Rejection>`.
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!("Finalising async {:?} route at '{}' (encrypted body)", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        let key = self.key;
        m.and(p)
            .and(warp::body::bytes())
            .and_then(move |raw: bytes::Bytes| {
                let key = key.clone();
                let handler = handler.clone();
                async move {
                    let value: T = decode_body(&raw, &key)?;
                    handler(value).await.map(|r| r.into_response())
                }
            })
            .boxed()
    }

    /// Finalises this route with a **synchronous** handler that receives the decrypted
    /// body as `T`.
    ///
    /// Decryption happens before the handler is dispatched to the thread pool: if the key
    /// is wrong or the body is corrupt the request is rejected with `403 Forbidden` and
    /// the thread pool is not touched at all.  The `T` handed to the closure is always a
    /// trusted, fully-decrypted value.  The closure may block but must complete quickly.
    ///
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    ///
    /// # Safety
    /// See [`ServerMechanism::onconnect_sync`] for the thread-pool safety notes.
    pub unsafe fn onconnect_sync<F, Re>(self, handler: F) -> SocketType
    where
        F: Fn(T) -> Result<Re, Rejection> + Clone + Send + Sync + 'static,
        Re: Reply + Send + 'static,
    {
        log::warn!("Registering sync handler on {:?} '{}' (encrypted body) — ensure rate-limiting is applied externally", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        let key = self.key;
        m.and(p)
            .and(warp::body::bytes())
            .and_then(move |raw: bytes::Bytes| {
                let key = key.clone();
                let handler = handler.clone();
                async move {
                    let value: T = decode_body(&raw, &key)?;
                    tokio::task::spawn_blocking(move || handler(value))
                        .await
                        .unwrap_or_else(|_| {
                            log::warn!("Sync encrypted handler panicked; converting to Rejection");
                            Err(warp::reject())
                        })
                        .map(|r| r.into_response())
                }
            })
            .boxed()
    }

    /// Attaches shared state `S`, transitioning to [`StatefulEncryptedBodyBuilder`].
    ///
    /// A fresh clone of `S` is injected alongside the decrypted `T` on every request.
    /// The handler will receive `(state: S, body: T)`.
    ///
    /// `S` must be `Clone + Send + Sync + 'static`.
    pub fn state<S: Clone + Send + Sync + 'static>(self, state: S) -> StatefulEncryptedBodyBuilder<T, S> {
        StatefulEncryptedBodyBuilder { base: self.base, key: self.key, state, _phantom: std::marker::PhantomData }
    }
}

// ─── EncryptedQueryBuilder ────────────────────────────────────────────────────

/// Route builder that expects VEIL-encrypted URL query parameters of type `T`.
///
/// Obtained from [`ServerMechanism::encrypted_query`].  The client must send a single
/// `?data=<base64url>` query parameter whose value is the URL-safe base64 encoding of
/// the VEIL-encrypted struct bytes.  On each matching request the server base64-decodes
/// then decrypts the value using the configured [`SerializationKey`].  If any step fails
/// (missing `data` parameter, invalid base64, wrong key, corrupt bytes) the route
/// returns `403 Forbidden` — the handler is never invoked.
///
/// Optionally attach shared state via [`state`](EncryptedQueryBuilder::state) before
/// finalising with [`onconnect`](EncryptedQueryBuilder::onconnect).
pub struct EncryptedQueryBuilder<T> {
    base: ServerMechanism,
    key: SerializationKey,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> EncryptedQueryBuilder<T>
where
    T: bincode::Decode<()> + Send + 'static,
{
    /// Finalises this route with an async handler that receives the decrypted query
    /// parameters as `T`.
    ///
    /// On each request the `?data=<base64url>` query parameter is base64-decoded then
    /// VEIL-decrypted using the [`SerializationKey`] on this builder.  The handler is only
    /// invoked when every step succeeds — a missing `data` parameter, invalid base64,
    /// wrong key, or corrupt payload causes the route to return `403 Forbidden` without
    /// ever reaching the handler.  The `T` the closure receives is therefore always a
    /// trusted, fully-decrypted value ready to use.
    ///
    /// The handler must return `Result<impl Reply, Rejection>`.
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!("Finalising async {:?} route at '{}' (encrypted query)", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        let key = self.key;
        m.and(p)
            .and(warp::filters::query::raw())
            .and_then(move |raw_query: String| {
                let key = key.clone();
                let handler = handler.clone();
                async move {
                    let value: T = decode_query(&raw_query, &key)?;
                    handler(value).await.map(|r| r.into_response())
                }
            })
            .boxed()
    }

    /// Attaches shared state `S`, transitioning to [`StatefulEncryptedQueryBuilder`].
    ///
    /// A fresh clone of `S` is injected alongside the decrypted `T` on every request.
    /// The handler will receive `(state: S, query: T)`.
    ///
    /// `S` must be `Clone + Send + Sync + 'static`.
    pub fn state<S: Clone + Send + Sync + 'static>(self, state: S) -> StatefulEncryptedQueryBuilder<T, S> {
        StatefulEncryptedQueryBuilder { base: self.base, key: self.key, state, _phantom: std::marker::PhantomData }
    }
}

// ─── StatefulEncryptedBodyBuilder ────────────────────────────────────────────

/// Route builder carrying shared state `S` and a VEIL-encrypted request body of type `T`.
///
/// Obtained from [`EncryptedBodyBuilder::state`] or [`StatefulSocketBuilder::encryption`].
/// On each matching request the body is VEIL-decrypted and a fresh clone of `S` is
/// prepared before the handler is called.  A wrong key or corrupt body returns
/// `403 Forbidden` without ever invoking the handler.
///
/// Finalise with [`onconnect`](StatefulEncryptedBodyBuilder::onconnect).
pub struct StatefulEncryptedBodyBuilder<T, S> {
    base: ServerMechanism,
    key: SerializationKey,
    state: S,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, S> StatefulEncryptedBodyBuilder<T, S>
where
    T: bincode::Decode<()> + Send + 'static,
    S: Clone + Send + Sync + 'static,
{
    /// Finalises this route with an async handler that receives `(state: S, body: T)`.
    ///
    /// On each request the raw body bytes are VEIL-decrypted using the configured
    /// [`SerializationKey`] and a fresh clone of `S` is prepared — both are handed to the
    /// handler together.  If decryption fails (wrong key or corrupt body) the route returns
    /// `403 Forbidden` and the handler is never invoked.  The `T` the closure receives is
    /// always a trusted, fully-decrypted value ready to use.
    ///
    /// The handler must return `Result<impl Reply, Rejection>`.
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S, T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!("Finalising async {:?} route at '{}' (state + encrypted body)", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        let key = self.key;
        let state = self.state;
        let state_filter = warp::any().map(move || state.clone());
        m.and(p)
            .and(state_filter)
            .and(warp::body::bytes())
            .and_then(move |s: S, raw: bytes::Bytes| {
                let key = key.clone();
                let handler = handler.clone();
                async move {
                    let value: T = decode_body(&raw, &key)?;
                    handler(s, value).await.map(|r| r.into_response())
                }
            })
            .boxed()
    }
}

// ─── StatefulEncryptedQueryBuilder ───────────────────────────────────────────

/// Route builder carrying shared state `S` and VEIL-encrypted query parameters of
/// type `T`.
///
/// Obtained from [`EncryptedQueryBuilder::state`] or
/// [`StatefulSocketBuilder::encrypted_query`].  On each matching request the
/// `?data=<base64url>` parameter is base64-decoded then VEIL-decrypted and a fresh
/// clone of `S` is prepared before the handler is called.  Any decode or decryption
/// failure returns `403 Forbidden` without ever invoking the handler.
///
/// Finalise with [`onconnect`](StatefulEncryptedQueryBuilder::onconnect).
pub struct StatefulEncryptedQueryBuilder<T, S> {
    base: ServerMechanism,
    key: SerializationKey,
    state: S,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, S> StatefulEncryptedQueryBuilder<T, S>
where
    T: bincode::Decode<()> + Send + 'static,
    S: Clone + Send + Sync + 'static,
{
    /// Finalises this route with an async handler that receives `(state: S, query: T)`.
    ///
    /// On each request the `?data=<base64url>` query parameter is base64-decoded then
    /// VEIL-decrypted using the configured [`SerializationKey`] and a fresh clone of `S`
    /// is prepared — both are handed to the handler together.  If any step fails (missing
    /// parameter, bad encoding, wrong key, or corrupt data) the route returns
    /// `403 Forbidden` and the handler is never invoked.  The `T` the closure receives is
    /// always a trusted, fully-decrypted value ready to use.
    ///
    /// The handler must return `Result<impl Reply, Rejection>`.
    /// Returns a [`SocketType`] ready to be passed to [`Server::mechanism`].
    pub fn onconnect<F, Fut, Re>(self, handler: F) -> SocketType
    where
        F: Fn(S, T) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Re, Rejection>> + Send,
        Re: Reply + Send,
    {
        log::debug!("Finalising async {:?} route at '{}' (state + encrypted query)", self.base.method, self.base.path);
        let m = self.base.method.filter();
        let p = path_filter(&self.base.path);
        let key = self.key;
        let state = self.state;
        let state_filter = warp::any().map(move || state.clone());
        m.and(p)
            .and(state_filter)
            .and(warp::filters::query::raw())
            .and_then(move |s: S, raw_query: String| {
                let key = key.clone();
                let handler = handler.clone();
                async move {
                    let value: T = decode_query(&raw_query, &key)?;
                    handler(s, value).await.map(|r| r.into_response())
                }
            })
            .boxed()
    }
}

// ─── Internal decode helpers ─────────────────────────────────────────────────

/// Decode a VEIL-sealed request body into `T`, returning `403 Forbidden` on any failure.
fn decode_body<T: bincode::Decode<()>>(raw: &bytes::Bytes, key: &SerializationKey) -> Result<T, Rejection> {
    crate::serialization::open(raw, key.veil_key()).map_err(|e| {
        log::debug!("VEIL open failed (key mismatch or corrupt body): {e}");
        forbidden()
    })
}

/// Decode a VEIL-sealed query parameter (`?data=<base64url>`) into `T`,
/// returning `403 Forbidden` on any failure.
fn decode_query<T: bincode::Decode<()>>(raw_query: &str, key: &SerializationKey) -> Result<T, Rejection> {
    // Extract the `data` parameter value from the raw query string.
    let data_value = serde_urlencoded::from_str::<std::collections::HashMap<String, String>>(raw_query)
        .ok()
        .and_then(|mut m| m.remove("data"));

    let b64 = data_value.ok_or_else(|| {
        log::debug!("Encrypted query missing `data` parameter");
        forbidden()
    })?;

    let bytes = base64::engine::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        b64.trim_end_matches('='),
    )
    .map_err(|e| {
        log::debug!("base64url decode failed: {e}");
        forbidden()
    })?;

    crate::serialization::open(&bytes, key.veil_key()).map_err(|e| {
        log::debug!("VEIL open (query) failed: {e}");
        forbidden()
    })
}

/// Builds a `403 Forbidden` rejection response.
fn forbidden() -> Rejection {
    // Warp doesn't expose a built-in 403 rejection, so we use a custom one.
    warp::reject::custom(ForbiddenError)
}

#[derive(Debug)]
struct ForbiddenError;

impl warp::reject::Reject for ForbiddenError {}

/// A collection of common HTTP status codes used with the reply helpers.
///
/// Covers 2xx success, 3xx redirect, 4xx client error, and 5xx server error ranges.
/// Converts into `warp::http::StatusCode` via [`From`] and is accepted by
/// [`reply_with_status`] and [`reply_with_status_and_json`]. Also usable directly in the
/// [`reply!`] macro via the `status => Status::X` argument.
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

impl From<Status> for warp::http::StatusCode {
    fn from(s: Status) -> Self {
        match s {
            Status::Ok                  => warp::http::StatusCode::OK,
            Status::Created             => warp::http::StatusCode::CREATED,
            Status::Accepted            => warp::http::StatusCode::ACCEPTED,
            Status::NoContent           => warp::http::StatusCode::NO_CONTENT,
            Status::MovedPermanently    => warp::http::StatusCode::MOVED_PERMANENTLY,
            Status::Found               => warp::http::StatusCode::FOUND,
            Status::NotModified         => warp::http::StatusCode::NOT_MODIFIED,
            Status::TemporaryRedirect   => warp::http::StatusCode::TEMPORARY_REDIRECT,
            Status::PermanentRedirect   => warp::http::StatusCode::PERMANENT_REDIRECT,
            Status::BadRequest          => warp::http::StatusCode::BAD_REQUEST,
            Status::Unauthorized        => warp::http::StatusCode::UNAUTHORIZED,
            Status::Forbidden           => warp::http::StatusCode::FORBIDDEN,
            Status::NotFound            => warp::http::StatusCode::NOT_FOUND,
            Status::MethodNotAllowed    => warp::http::StatusCode::METHOD_NOT_ALLOWED,
            Status::Conflict            => warp::http::StatusCode::CONFLICT,
            Status::Gone                => warp::http::StatusCode::GONE,
            Status::UnprocessableEntity => warp::http::StatusCode::UNPROCESSABLE_ENTITY,
            Status::TooManyRequests     => warp::http::StatusCode::TOO_MANY_REQUESTS,
            Status::InternalServerError => warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            Status::NotImplemented      => warp::http::StatusCode::NOT_IMPLEMENTED,
            Status::BadGateway          => warp::http::StatusCode::BAD_GATEWAY,
            Status::ServiceUnavailable  => warp::http::StatusCode::SERVICE_UNAVAILABLE,
            Status::GatewayTimeout      => warp::http::StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

/// The HTTP server that owns and dispatches a collection of [`SocketType`] routes.
///
/// Build routes through the [`ServerMechanism`] builder chain, register each with
/// [`mechanism`](Server::mechanism), then start the server with [`serve`](Server::serve).
///
/// # Example
/// ```rust,no_run
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
///             .onconnect(|| async { reply!(message => warp::reply(), status => Status::NoContent) })
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
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    fn new() -> Self {
        Self { mechanisms: Vec::new() }
    }

    /// Registers a [`SocketType`] route on this server.
    ///
    /// Routes are evaluated in registration order. Returns `&mut Self` for method chaining.
    pub fn mechanism(&mut self, mech: SocketType) -> &mut Self {
        self.mechanisms.push(mech);
        log::debug!("Route registered (total: {})", self.mechanisms.len());
        self
    }

    /// Binds to `addr` and starts serving all registered routes.
    ///
    /// This is an infinite async loop — it never returns under normal operation.
    ///
    /// # Panics
    /// Panics immediately if no routes have been registered via [`mechanism`](Server::mechanism).
    pub async fn serve(self, addr: impl Into<SocketAddr>) {
        let addr = addr.into();
        log::info!("Server binding to {}", addr);
        let mut iter = self.mechanisms.into_iter();
        let first = iter.next().unwrap_or_else(|| {
            log::trace!("No mechanisms are defined on the server, this will result in a panic!");
            log::error!("The server contains no mechanisms to follow through");
            panic!();
        });

        let combined = iter.fold(first.boxed(), |acc, next| {
            acc.or(next).unify().boxed()
        });

        log::info!("Server running on {}", addr);
        warp::serve(combined).run(addr).await;
    }

    /// Binds to `addr`, serves all registered routes, and shuts down gracefully when
    /// `shutdown` resolves.
    ///
    /// Equivalent to calling [`serve_from_listener`](Server::serve_from_listener) with an
    /// address instead of a pre-bound listener.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use tokio::sync::oneshot;
    ///
    /// # async fn run() {
    /// let (tx, rx) = oneshot::channel::<()>();
    /// // ... build server and mount routes ...
    /// // trigger shutdown later by calling tx.send(())
    /// server.serve_with_graceful_shutdown(([127, 0, 0, 1], 8080), async move {
    ///     rx.await.ok();
    /// }).await;
    /// # }
    /// ```
    pub async fn serve_with_graceful_shutdown(
        self,
        addr: impl Into<std::net::SocketAddr>,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        let addr = addr.into();
        log::info!("Server binding to {} (graceful shutdown enabled)", addr);
        let mut iter = self.mechanisms.into_iter();
        let first = iter.next().unwrap_or_else(|| {
            log::error!("The server contains no mechanisms to follow through");
            panic!("serve_with_graceful_shutdown called with no routes registered");
        });
        let combined = iter.fold(first.boxed(), |acc, next| acc.or(next).unify().boxed());
        log::info!("Server running on {} (graceful shutdown enabled)", addr);
        warp::serve(combined)
            .bind(addr)
            .await
            .graceful(shutdown)
            .run()
            .await;
    }

    /// Serves all registered routes from an already-bound `listener`, shutting down gracefully
    /// when `shutdown` resolves.
    ///
    /// Use this when port `0` is passed to `TcpListener::bind` and you need to know the actual
    /// OS-assigned port before the server starts (e.g. to open a browser to the correct URL).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use tokio::net::TcpListener;
    /// use tokio::sync::oneshot;
    ///
    /// # async fn run() -> std::io::Result<()> {
    /// let listener = TcpListener::bind("127.0.0.1:0").await?;
    /// let port = listener.local_addr()?.port();
    /// println!("Will listen on port {port}");
    ///
    /// let (tx, rx) = oneshot::channel::<()>();
    /// // ... build server and mount routes ...
    /// server.serve_from_listener(listener, async move { rx.await.ok(); }).await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn serve_from_listener(
        self,
        listener: tokio::net::TcpListener,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        log::info!("Server running on {} (graceful shutdown enabled)",
            listener.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into()));
        let mut iter = self.mechanisms.into_iter();
        let first = iter.next().unwrap_or_else(|| {
            log::error!("The server contains no mechanisms to follow through");
            panic!("serve_from_listener called with no routes registered");
        });
        let combined = iter.fold(first.boxed(), |acc, next| acc.or(next).unify().boxed());
        warp::serve(combined)
            .incoming(listener)
            .graceful(shutdown)
            .run()
            .await;
    }
}

/// Wraps `reply` with the given HTTP `status` code and returns it as a warp result.
///
/// Use when an endpoint needs to respond with a specific status alongside a plain message.
/// Pairs with the [`reply!`] macro form `reply!(message => ..., status => ...)`.
pub fn reply_with_status(status: Status, reply: impl Reply) -> Result<impl Reply, Rejection> {
    Ok::<_, Rejection>(warp::reply::with_status(reply, status.into()))
}

/// Returns an empty `200 OK` warp reply result.
///
/// Useful for endpoints that need only to acknowledge a request with no body.
/// Equivalent to `reply!()`.
pub fn reply() -> Result<impl Reply, Rejection> {
    Ok::<_, Rejection>(warp::reply())
}

/// Serialises `json` as a JSON body and returns it as a `200 OK` warp reply result.
///
/// `T` must implement `serde::Serialize`. Equivalent to `reply!(json => ...)`.
pub fn reply_with_json<T: Serialize>(json: &T) -> Result<impl Reply + use<T>, Rejection> {
    Ok::<_, Rejection>(warp::reply::json(json))
}

/// Serialises `json` as a JSON body, attaches the given HTTP `status`, and returns a warp result.
///
/// `T` must implement `serde::Serialize`. Equivalent to `reply!(json => ..., status => ...)`.
pub fn reply_with_status_and_json<T: Serialize>(status: Status, json: &T) -> Result<impl Reply + use<T>, Rejection> {
    Ok::<_, Rejection>(warp::reply::with_status(warp::reply::json(json), status.into()))
}

/// Seals `value` with `key` and returns it as an `application/octet-stream` response (`200 OK`).
///
/// `T` must implement `bincode::Encode`.
/// Equivalent to `reply!(sealed => value, key => key)`.
pub fn reply_sealed<T: bincode::Encode>(
    value: &T,
    key: SerializationKey,
) -> Result<warp::reply::Response, Rejection> {
    sealed_response(value, key, None)
}

/// Seals `value` with `key`, attaches the given HTTP `status`, and returns it as a warp result.
///
/// Equivalent to `reply!(sealed => value, key => key, status => Status::X)`.
pub fn reply_sealed_with_status<T: bincode::Encode>(
    value: &T,
    key: SerializationKey,
    status: Status,
) -> Result<warp::reply::Response, Rejection> {
    sealed_response(value, key, Some(status))
}

fn sealed_response<T: bincode::Encode>(
    value: &T,
    key: SerializationKey,
    status: Option<Status>,
) -> Result<warp::reply::Response, Rejection> {
    use warp::http::StatusCode;
    use warp::Reply;
    let code: StatusCode = status.map(Into::into).unwrap_or(StatusCode::OK);
    let sealed = crate::serialization::seal(value, key.veil_key()).map_err(|_| warp::reject())?;
    Ok(warp::reply::with_status(sealed, code).into_response())
}

/// Convenience macro for constructing warp reply results inside route handlers.
///
/// | Syntax | Equivalent | Description |
/// |---|---|---|
/// | `reply!()` | [`reply()`] | Empty `200 OK` response. |
/// | `reply!(message => expr, status => Status::X)` | [`reply_with_status`] | Plain reply with a status code. |
/// | `reply!(json => expr)` | [`reply_with_json`] | JSON body with `200 OK`. |
/// | `reply!(json => expr, status => Status::X)` | [`reply_with_status_and_json`] | JSON body with a status code. |
/// | `reply!(sealed => expr, key => key)` | [`reply_sealed`] | VEIL-sealed (or JSON for `Plain`) body, `200 OK`. |
/// | `reply!(sealed => expr, key => key, status => Status::X)` | [`reply_sealed_with_status`] | VEIL-sealed (or JSON for `Plain`) body with status. |
///
/// # Example
/// ```rust,no_run
/// # use serde::{Deserialize, Serialize};
/// # #[derive(Deserialize, Serialize)] struct Item { id: u32, name: String }
///
/// // Empty 200 OK
/// let ping = ServerMechanism::get("/ping")
///     .onconnect(|| async { reply!() });
///
/// // Plain reply with a custom status
/// let gone = ServerMechanism::delete("/v1")
///     .onconnect(|| async {
///         reply!(message => warp::reply::html("endpoint deprecated"), status => Status::Gone)
///     });
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

