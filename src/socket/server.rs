
use std::{future::Future, net::SocketAddr};
use serde::{de::DeserializeOwned, Serialize};
use warp::{Filter, Rejection, Reply, filters::BoxedFilter};

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

    /// Attaches shared state `S`, transitioning to [`StatefulSocketBuilder`].
    ///
    /// `S` must be `Clone + Send + Sync + 'static`. Wrap mutable state in `Arc<Mutex<_>>` or similar.
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

    /// Expects a JSON-encoded request body of type `T`, transitioning to [`JsonSocketBuilder`].
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

    /// Expects URL query parameters deserialising into `T`, transitioning to [`QuerySocketBuilder`].
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

    /// Attaches an async handler and returns the finished [`SocketType`].
    ///
    /// The handler receives no arguments and must return
    /// `impl Future<Output = Result<impl Reply, Rejection>>`. Use the [`reply!`] macro or the
    /// standalone reply helpers to construct the return value.
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

    /// Attaches a **synchronous** handler and returns the finished [`SocketType`].
    ///
    /// The handler receives no arguments and must return `Result<impl Reply, Rejection>`.
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

    /// Attaches an async handler that receives the deserialised JSON body as `T`.
    ///
    /// `handler` must be `Fn(T) -> impl Future<Output = Result<impl Reply, Rejection>>`.
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

    /// Attaches a **synchronous** handler that receives the deserialised JSON body as `T`.
    ///
    /// `handler` must be `Fn(T) -> Result<impl Reply, Rejection>`.
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
    /// Attaches an async handler that receives the deserialised query parameters as `T`.
    ///
    /// `handler` must be `Fn(T) -> impl Future<Output = Result<impl Reply, Rejection>>`.
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

    /// Attaches a **synchronous** handler that receives the deserialised query parameters as `T`.
    ///
    /// `handler` must be `Fn(T) -> Result<impl Reply, Rejection>`.
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
    /// Attaches an async handler that receives the shared state as its only argument.
    ///
    /// `handler` must be `Fn(S) -> impl Future<Output = Result<impl Reply, Rejection>>`.
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

    /// Attaches a **synchronous** handler that receives the shared state as its only argument.
    ///
    /// `handler` must be `Fn(S) -> Result<impl Reply, Rejection>`.
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
    /// Attaches an async handler that receives `(state: S, body: T)`.
    ///
    /// `handler` must be `Fn(S, T) -> impl Future<Output = Result<impl Reply, Rejection>>`.
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

    /// Attaches a **synchronous** handler that receives `(state: S, body: T)`.
    ///
    /// `handler` must be `Fn(S, T) -> Result<impl Reply, Rejection>`.
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
    /// Attaches an async handler that receives `(state: S, query: T)`.
    ///
    /// `handler` must be `Fn(S, T) -> impl Future<Output = Result<impl Reply, Rejection>>`.
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

    /// Attaches a **synchronous** handler that receives `(state: S, query: T)`.
    ///
    /// `handler` must be `Fn(S, T) -> Result<impl Reply, Rejection>`.
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
pub fn reply_with_json<T: Serialize>(json: &T) -> Result<impl Reply, Rejection> {
    Ok::<_, Rejection>(warp::reply::json(json))
}

/// Serialises `json` as a JSON body, attaches the given HTTP `status`, and returns a warp result.
///
/// `T` must implement `serde::Serialize`. Equivalent to `reply!(json => ..., status => ...)`.
pub fn reply_with_status_and_json<T: Serialize>(status: Status, json: &T) -> Result<impl Reply, Rejection> {
    Ok::<_, Rejection>(warp::reply::with_status(warp::reply::json(json), status.into()))
}

/// Convenience macro for constructing warp reply results inside route handlers.
///
/// | Syntax | Equivalent | Description |
/// |---|---|---|
/// | `reply!()` | [`reply()`] | Empty `200 OK` response. |
/// | `reply!(message => expr, status => Status::X)` | [`reply_with_status`] | Plain reply with a status code. |
/// | `reply!(json => expr)` | [`reply_with_json`] | JSON body with `200 OK`. |
/// | `reply!(json => expr, status => Status::X)` | [`reply_with_status_and_json`] | JSON body with a status code. |
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
}