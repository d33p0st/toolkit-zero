
use reqwest::{Client as AsyncClient, blocking::Client as BlockingClient};
use serde::{Serialize, de::DeserializeOwned};

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
/// Use the method constructors ([`get`](Client::get), [`post`](Client::post), etc.) to start a
/// fluent builder chain. Optionally attach a JSON body via
/// [`json`](RequestBuilder::json) or query parameters via [`query`](RequestBuilder::query),
/// then finalise with [`send`](RequestBuilder::send) (async) or
/// [`send_sync`](RequestBuilder::send_sync) (sync) to execute the request and deserialise the
/// response into a concrete type.
///
/// The full URL is constructed automatically from the configured [`Target`] and the endpoint
/// passed to the method constructor — no manual URL assembly required.
///
/// # Example
/// ```rust,no_run
/// # use serde::{Deserialize, Serialize};
/// # #[derive(Deserialize)] struct Item { id: u32, name: String }
/// # #[derive(Serialize)] struct NewItem { name: String }
/// # #[derive(Serialize)] struct SearchParams { q: String }
/// # async fn example() -> Result<(), reqwest::Error> {
/// let client = Client::new(Target::Localhost(8080));
///
/// // Async GET — response deserialised into Vec<Item>
/// let items: Vec<Item> = client.get("/items").send().await?;
///
/// // Async POST with a JSON body
/// let created: Item = client
///     .post("/items")
///     .json(NewItem { name: "widget".to_string() })
///     .send()
///     .await?;
///
/// // Async GET with query parameters
/// let results: Vec<Item> = client
///     .get("/search")
///     .query(SearchParams { q: "rust".to_string() })
///     .send()
///     .await?;
///
/// // Sync DELETE
/// let _: Item = client.delete("/items/1").send_sync()?;
///
/// // All seven methods work identically: get, post, put, delete, patch, head, options
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Client {
    target: Target,
    async_client: AsyncClient,
    sync_client: BlockingClient,
}

impl Client {
    /// Creates a new `Client` pointed at `target`.
    pub fn new(target: Target) -> Self {
        log::debug!("Creating client");
        Self {
            target,
            async_client: AsyncClient::new(),
            sync_client: BlockingClient::new(),
        }
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
///
/// # Example
/// ```rust,no_run
/// # use serde::Deserialize;
/// # #[derive(Deserialize)] struct Status { ok: bool }
/// # async fn example(client: &Client) -> Result<(), reqwest::Error> {
/// // Async plain GET
/// let status: Status = client.get("/health").send().await?;
///
/// // Sync plain DELETE
/// let _: Status = client.delete("/session").send_sync()?;
/// # Ok(())
/// # }
/// ```
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
        let resp = self.method.apply_async(&self.client.async_client, &url)
            .send().await?;
        log::debug!("Response status: {}", resp.status());
        resp.json::<R>().await
    }

    /// Sends the request synchronously and deserialises the response body as `R`.
    ///
    /// # Example
    /// ```rust,no_run
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
        let resp = self.method.apply_sync(&self.client.sync_client, &url)
            .send()?;
        log::debug!("Response status: {}", resp.status());
        resp.json::<R>()
    }
}

/// A request builder that will send a JSON-serialised body.
///
/// Obtained from [`RequestBuilder::json`]. Finalise with [`send`](JsonRequestBuilder::send)
/// (async) or [`send_sync`](JsonRequestBuilder::send_sync) (sync).
///
/// # Example
/// ```rust,no_run
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
        let resp = self.method.apply_async(&self.client.async_client, &url)
            .json(&self.body)
            .send().await?;
        log::debug!("Response status: {}", resp.status());
        resp.json::<R>().await
    }

    /// Sends the request synchronously with the JSON body and deserialises the response as `R`.
    ///
    /// # Example
    /// ```rust,no_run
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
        let resp = self.method.apply_sync(&self.client.sync_client, &url)
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
        let resp = self.method.apply_async(&self.client.async_client, &url)
            .query(&self.params)
            .send().await?;
        log::debug!("Response status: {}", resp.status());
        resp.json::<R>().await
    }

    /// Sends the request synchronously with query parameters and deserialises the response as `R`.
    ///
    /// # Example
    /// ```rust,no_run
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
        let resp = self.method.apply_sync(&self.client.sync_client, &url)
            .query(&self.params)
            .send()?;
        log::debug!("Response status: {}", resp.status());
        resp.json::<R>()
    }
}