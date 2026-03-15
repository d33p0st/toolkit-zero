//! Procedural macros for `toolkit-zero`.
//!
//! This crate is an internal implementation detail of `toolkit-zero`.
//! Do not depend on it directly. Use the re-exported attribute macros:
//!
//! - [`mechanism`] — server-side route declaration, via `toolkit_zero::socket::server`
//! - [`request`]   — client-side request shorthand, via `toolkit_zero::socket::client`

#[cfg(any(feature = "socket-server", feature = "socket-client"))]
use proc_macro::TokenStream;
#[cfg(any(feature = "socket-server", feature = "socket-client"))]
use quote::quote;
#[cfg(any(feature = "socket-server", feature = "socket-client"))]
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Expr, Ident, ItemFn, LitStr, Token,
};

// ─── Argument types ───────────────────────────────────────────────────────────

#[cfg(feature = "socket-server")]
/// The body/query mode keyword extracted from the attribute arguments.
enum BodyMode {
    None,
    Json,
    Query,
    Encrypted(Expr),
    EncryptedQuery(Expr),
}

#[cfg(feature = "socket-server")]
/// Fully parsed attribute arguments.
struct MechanismArgs {
    /// The `Server` variable identifier in the enclosing scope.
    server: Ident,
    /// HTTP method identifier (GET, POST, …).
    method: Ident,
    /// Route path string literal.
    path: LitStr,
    /// Optional `state(expr)` argument.
    state: Option<Expr>,
    /// How the request body / query is processed.
    body_mode: BodyMode,
}

#[cfg(feature = "socket-server")]
impl Parse for MechanismArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // ── Positional: server_ident, METHOD, "/path" ─────────────────────
        let server: Ident = input.parse()?;
        input.parse::<Token![,]>()?;

        let method: Ident = input.parse()?;
        input.parse::<Token![,]>()?;

        let path: LitStr = input.parse()?;

        // ── Named (order-independent) keywords ────────────────────────────
        let mut state: Option<Expr> = None;
        let mut body_mode = BodyMode::None;

        while input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }

            let kw: Ident = input.parse()?;
            match kw.to_string().as_str() {
                "json" => {
                    if !matches!(body_mode, BodyMode::None) {
                        return Err(syn::Error::new(
                            kw.span(),
                            "#[mechanism]: only one of `json`, `query`, \
                             `encrypted(…)`, or `encrypted_query(…)` may be \
                             specified per route",
                        ));
                    }
                    body_mode = BodyMode::Json;
                }
                "query" => {
                    if !matches!(body_mode, BodyMode::None) {
                        return Err(syn::Error::new(
                            kw.span(),
                            "#[mechanism]: only one of `json`, `query`, \
                             `encrypted(…)`, or `encrypted_query(…)` may be \
                             specified per route",
                        ));
                    }
                    body_mode = BodyMode::Query;
                }
                "state" => {
                    if state.is_some() {
                        return Err(syn::Error::new(
                            kw.span(),
                            "#[mechanism]: `state(…)` may only be specified once",
                        ));
                    }
                    let content;
                    syn::parenthesized!(content in input);
                    state = Some(content.parse::<Expr>()?);
                }
                "encrypted" => {
                    if !matches!(body_mode, BodyMode::None) {
                        return Err(syn::Error::new(
                            kw.span(),
                            "#[mechanism]: only one of `json`, `query`, \
                             `encrypted(…)`, or `encrypted_query(…)` may be \
                             specified per route",
                        ));
                    }
                    let content;
                    syn::parenthesized!(content in input);
                    body_mode = BodyMode::Encrypted(content.parse::<Expr>()?);
                }
                "encrypted_query" => {
                    if !matches!(body_mode, BodyMode::None) {
                        return Err(syn::Error::new(
                            kw.span(),
                            "#[mechanism]: only one of `json`, `query`, \
                             `encrypted(…)`, or `encrypted_query(…)` may be \
                             specified per route",
                        ));
                    }
                    let content;
                    syn::parenthesized!(content in input);
                    body_mode = BodyMode::EncryptedQuery(content.parse::<Expr>()?);
                }
                other => {
                    return Err(syn::Error::new(
                        kw.span(),
                        format!(
                            "#[mechanism]: unknown keyword `{other}`. \
                             Valid keywords: json, query, state(<expr>), \
                             encrypted(<key>), encrypted_query(<key>)"
                        ),
                    ));
                }
            }
        }

        Ok(MechanismArgs { server, method, path, state, body_mode })
    }
}

// ─── Helper ───────────────────────────────────────────────────────────────────

#[cfg(feature = "socket-server")]
/// Extract `(&Pat, &Type)` from a `FnArg::Typed`. Emits a proper error for
/// `FnArg::Receiver` (i.e. `self`).
fn extract_pat_ty<'a>(
    arg: &'a syn::FnArg,
    position: &str,
) -> syn::Result<(&'a syn::Pat, &'a syn::Type)> {
    match arg {
        syn::FnArg::Typed(pt) => Ok((&pt.pat, &pt.ty)),
        syn::FnArg::Receiver(r) => Err(syn::Error::new_spanned(
            &r.self_token,
            format!(
                "#[mechanism]: unexpected `self` in the {position} parameter position"
            ),
        )),
    }
}

// ─── Attribute macro ──────────────────────────────────────────────────────────

#[cfg(feature = "socket-server")]
/// Concise route declaration for `toolkit-zero` socket-server routes.
///
/// Replaces an `async fn` item with a `server.mechanism(…)` statement at the
/// point of declaration. The function body is transplanted verbatim into the
/// `.onconnect(…)` closure; all variables from the enclosing scope are
/// accessible via `move` capture.
///
/// # Syntax
///
/// ```text
/// #[mechanism(server, METHOD, "/path")]
/// #[mechanism(server, METHOD, "/path", json)]
/// #[mechanism(server, METHOD, "/path", query)]
/// #[mechanism(server, METHOD, "/path", encrypted(key_expr))]
/// #[mechanism(server, METHOD, "/path", encrypted_query(key_expr))]
/// #[mechanism(server, METHOD, "/path", state(state_expr))]
/// #[mechanism(server, METHOD, "/path", state(state_expr), json)]
/// #[mechanism(server, METHOD, "/path", state(state_expr), query)]
/// #[mechanism(server, METHOD, "/path", state(state_expr), encrypted(key_expr))]
/// #[mechanism(server, METHOD, "/path", state(state_expr), encrypted_query(key_expr))]
/// ```
///
/// The first three arguments (`server`, `METHOD`, `"/path"`) are positional.
/// `json`, `query`, `state(…)`, `encrypted(…)`, and `encrypted_query(…)` may
/// appear in any order after the path.
///
/// # Parameters
///
/// | Argument | Meaning |
/// |---|---|
/// | `server` | Identifier of the `Server` variable in the enclosing scope |
/// | `METHOD` | HTTP method: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS` |
/// | `"/path"` | Route path string literal |
/// | `json` | JSON-deserialised body; fn has one param `(body: T)` |
/// | `query` | URL query params; fn has one param `(params: T)` |
/// | `encrypted(key)` | VEIL-encrypted body; fn has one param `(body: T)` |
/// | `encrypted_query(key)` | VEIL-encrypted query; fn has one param `(params: T)` |
/// | `state(expr)` | State injection; fn first param is `(state: S)` |
///
/// When `state` is combined with a body mode the function receives two
/// parameters: the state clone first, the body or query second.
///
/// # Function signature
///
/// The decorated function:
/// - May be `async` or non-async — it is always wrapped in `async move { … }`.
/// - May carry a return type annotation or none — it is ignored; Rust infers
///   the return type from the `reply!` macro inside the body.
/// - Must have exactly the number of parameters described in the table above.
///
/// # Example
///
/// ```rust,ignore
/// use toolkit_zero::socket::server::{Server, mechanism, reply, Status, SerializationKey};
/// use serde::{Deserialize, Serialize};
/// use std::sync::{Arc, Mutex};
///
/// #[derive(Deserialize, Serialize, Clone)] struct Item { id: u32, name: String }
/// #[derive(Deserialize)]                  struct NewItem { name: String }
/// #[derive(Deserialize)]                  struct Filter { page: u32 }
///
/// #[tokio::main]
/// async fn main() {
///     let mut server = Server::default();
///     let db: Arc<Mutex<Vec<Item>>> = Arc::new(Mutex::new(vec![]));
///
///     // Plain GET — no body, no state
///     #[mechanism(server, GET, "/health")]
///     async fn health() { reply!() }
///
///     // POST — JSON body
///     #[mechanism(server, POST, "/items", json)]
///     async fn create_item(body: NewItem) {
///         reply!(json => Item { id: 1, name: body.name }, status => Status::Created)
///     }
///
///     // GET — query params
///     #[mechanism(server, GET, "/items", query)]
///     async fn list_items(filter: Filter) {
///         let _ = filter.page;
///         reply!()
///     }
///
///     // GET — state + query
///     #[mechanism(server, GET, "/items/all", state(db.clone()), query)]
///     async fn list_all(db: Arc<Mutex<Vec<Item>>>, filter: Filter) {
///         let items = db.lock().unwrap().clone();
///         reply!(json => items)
///     }
///
///     // POST — state + JSON body
///     #[mechanism(server, POST, "/items/add", state(db.clone()), json)]
///     async fn add_item(db: Arc<Mutex<Vec<Item>>>, body: NewItem) {
///         let id = db.lock().unwrap().len() as u32 + 1;
///         let item = Item { id, name: body.name };
///         db.lock().unwrap().push(item.clone());
///         reply!(json => item, status => Status::Created)
///     }
///
///     // POST — VEIL-encrypted body
///     #[mechanism(server, POST, "/secure", encrypted(SerializationKey::Default))]
///     async fn secure_post(body: NewItem) {
///         reply!(json => Item { id: 99, name: body.name })
///     }
///
///     server.serve(([127, 0, 0, 1], 8080)).await;
/// }
/// ```
#[cfg(feature = "socket-server")]
#[proc_macro_attribute]
pub fn mechanism(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as MechanismArgs);
    let func = parse_macro_input!(item as ItemFn);

    // ── Validate and normalise the HTTP method ────────────────────────────
    let method_str = args.method.to_string().to_lowercase();
    let method_ident = Ident::new(&method_str, args.method.span());

    match method_str.as_str() {
        "get" | "post" | "put" | "delete" | "patch" | "head" | "options" => {}
        other => {
            return syn::Error::new(
                args.method.span(),
                format!(
                    "#[mechanism]: `{other}` is not a valid HTTP method. \
                     Expected GET, POST, PUT, DELETE, PATCH, HEAD, or OPTIONS."
                ),
            )
            .to_compile_error()
            .into();
        }
    }

    let server = &args.server;
    let path   = &args.path;
    let body   = &func.block;
    let params: Vec<&syn::FnArg> = func.sig.inputs.iter().collect();

    // ── Convenience macro: emit a compile error and return ────────────────
    macro_rules! bail {
        ($span:expr, $msg:literal) => {{
            return syn::Error::new($span, $msg)
                .to_compile_error()
                .into();
        }};
    }

    // ── Build the builder-chain expression ────────────────────────────────
    let route_expr = match (&args.state, &args.body_mode) {

        // ── Plain ─────────────────────────────────────────────────────────
        (None, BodyMode::None) => {
            quote! {
                toolkit_zero::socket::server::ServerMechanism::#method_ident(#path)
                    .onconnect(|| async move #body)
            }
        }

        // ── JSON body, no state ───────────────────────────────────────────
        (None, BodyMode::Json) => {
            if params.is_empty() {
                bail!(
                    func.sig.ident.span(),
                    "#[mechanism]: `json` mode requires one function parameter — `(body: YourType)`"
                );
            }
            let (name, ty) = match extract_pat_ty(params[0], "body") {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            quote! {
                toolkit_zero::socket::server::ServerMechanism::#method_ident(#path)
                    .json::<#ty>()
                    .onconnect(|#name: #ty| async move #body)
            }
        }

        // ── Query params, no state ────────────────────────────────────────
        (None, BodyMode::Query) => {
            if params.is_empty() {
                bail!(
                    func.sig.ident.span(),
                    "#[mechanism]: `query` mode requires one function parameter — `(params: YourType)`"
                );
            }
            let (name, ty) = match extract_pat_ty(params[0], "query") {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            quote! {
                toolkit_zero::socket::server::ServerMechanism::#method_ident(#path)
                    .query::<#ty>()
                    .onconnect(|#name: #ty| async move #body)
            }
        }

        // ── VEIL-encrypted body, no state ─────────────────────────────────
        (None, BodyMode::Encrypted(key_expr)) => {
            if params.is_empty() {
                bail!(
                    func.sig.ident.span(),
                    "#[mechanism]: `encrypted(key)` mode requires one function parameter — `(body: YourType)`"
                );
            }
            let (name, ty) = match extract_pat_ty(params[0], "body") {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            quote! {
                toolkit_zero::socket::server::ServerMechanism::#method_ident(#path)
                    .encryption::<#ty>(#key_expr)
                    .onconnect(|#name: #ty| async move #body)
            }
        }

        // ── VEIL-encrypted query, no state ────────────────────────────────
        (None, BodyMode::EncryptedQuery(key_expr)) => {
            if params.is_empty() {
                bail!(
                    func.sig.ident.span(),
                    "#[mechanism]: `encrypted_query(key)` mode requires one function parameter — `(params: YourType)`"
                );
            }
            let (name, ty) = match extract_pat_ty(params[0], "params") {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            quote! {
                toolkit_zero::socket::server::ServerMechanism::#method_ident(#path)
                    .encrypted_query::<#ty>(#key_expr)
                    .onconnect(|#name: #ty| async move #body)
            }
        }

        // ── State only ────────────────────────────────────────────────────
        (Some(state_expr), BodyMode::None) => {
            if params.is_empty() {
                bail!(
                    func.sig.ident.span(),
                    "#[mechanism]: `state(expr)` mode requires one function parameter — `(state: YourStateType)`"
                );
            }
            let (name, ty) = match extract_pat_ty(params[0], "state") {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            quote! {
                toolkit_zero::socket::server::ServerMechanism::#method_ident(#path)
                    .state(#state_expr)
                    .onconnect(|#name: #ty| async move #body)
            }
        }

        // ── State + JSON body ─────────────────────────────────────────────
        (Some(state_expr), BodyMode::Json) => {
            if params.len() < 2 {
                bail!(
                    func.sig.ident.span(),
                    "#[mechanism]: `state(expr), json` mode requires two function parameters — `(state: S, body: T)`"
                );
            }
            let (s_name, s_ty) = match extract_pat_ty(params[0], "state") {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            let (b_name, b_ty) = match extract_pat_ty(params[1], "body") {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            quote! {
                toolkit_zero::socket::server::ServerMechanism::#method_ident(#path)
                    .state(#state_expr)
                    .json::<#b_ty>()
                    .onconnect(|#s_name: #s_ty, #b_name: #b_ty| async move #body)
            }
        }

        // ── State + Query params ──────────────────────────────────────────
        (Some(state_expr), BodyMode::Query) => {
            if params.len() < 2 {
                bail!(
                    func.sig.ident.span(),
                    "#[mechanism]: `state(expr), query` mode requires two function parameters — `(state: S, params: T)`"
                );
            }
            let (s_name, s_ty) = match extract_pat_ty(params[0], "state") {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            let (q_name, q_ty) = match extract_pat_ty(params[1], "query") {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            quote! {
                toolkit_zero::socket::server::ServerMechanism::#method_ident(#path)
                    .state(#state_expr)
                    .query::<#q_ty>()
                    .onconnect(|#s_name: #s_ty, #q_name: #q_ty| async move #body)
            }
        }

        // ── State + VEIL-encrypted body ───────────────────────────────────
        (Some(state_expr), BodyMode::Encrypted(key_expr)) => {
            if params.len() < 2 {
                bail!(
                    func.sig.ident.span(),
                    "#[mechanism]: `state(expr), encrypted(key)` mode requires two function parameters — `(state: S, body: T)`"
                );
            }
            let (s_name, s_ty) = match extract_pat_ty(params[0], "state") {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            let (b_name, b_ty) = match extract_pat_ty(params[1], "body") {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            quote! {
                toolkit_zero::socket::server::ServerMechanism::#method_ident(#path)
                    .state(#state_expr)
                    .encryption::<#b_ty>(#key_expr)
                    .onconnect(|#s_name: #s_ty, #b_name: #b_ty| async move #body)
            }
        }

        // ── State + VEIL-encrypted query ──────────────────────────────────
        (Some(state_expr), BodyMode::EncryptedQuery(key_expr)) => {
            if params.len() < 2 {
                bail!(
                    func.sig.ident.span(),
                    "#[mechanism]: `state(expr), encrypted_query(key)` mode requires two function parameters — `(state: S, params: T)`"
                );
            }
            let (s_name, s_ty) = match extract_pat_ty(params[0], "state") {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            let (q_name, q_ty) = match extract_pat_ty(params[1], "query") {
                Ok(v) => v,
                Err(e) => return e.to_compile_error().into(),
            };
            quote! {
                toolkit_zero::socket::server::ServerMechanism::#method_ident(#path)
                    .state(#state_expr)
                    .encrypted_query::<#q_ty>(#key_expr)
                    .onconnect(|#s_name: #s_ty, #q_name: #q_ty| async move #body)
            }
        }
    };

    // ── Final expansion: server.mechanism(<route_expr>); ──────────────────
    quote! {
        #server.mechanism(#route_expr);
    }
    .into()
}

// ─── Client-side: #[request] ─────────────────────────────────────────────────

#[cfg(feature = "socket-client")]
/// Body/query attachment mode for a client request.
enum RequestBodyMode {
    None,
    Json(Expr),
    Query(Expr),
    Encrypted(Expr, Expr),
    EncryptedQuery(Expr, Expr),
}

#[cfg(feature = "socket-client")]
/// Whether to call `.send().await?` or `.send_sync()?`.
enum SendMode {
    Async,
    Sync,
}

#[cfg(feature = "socket-client")]
/// Fully parsed `#[request]` attribute arguments.
struct RequestArgs {
    client: Ident,
    method: Ident,
    path:   LitStr,
    mode:   RequestBodyMode,
    send:   SendMode,
}

#[cfg(feature = "socket-client")]
/// Parse the mandatory final `, async` or `, sync` keyword.
fn parse_send_mode(input: ParseStream) -> syn::Result<SendMode> {
    input.parse::<Token![,]>()?;
    if input.peek(Token![async]) {
        input.parse::<Token![async]>()?;
        Ok(SendMode::Async)
    } else {
        let kw: Ident = input.parse()?;
        match kw.to_string().as_str() {
            "sync" => Ok(SendMode::Sync),
            _ => Err(syn::Error::new(
                kw.span(),
                "#[request]: expected `async` or `sync` as the final argument",
            )),
        }
    }
}

#[cfg(feature = "socket-client")]
impl Parse for RequestArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // ── Positional: client_ident, METHOD, "/path" ─────────────────────
        let client: Ident = input.parse()?;
        input.parse::<Token![,]>()?;

        let method: Ident = input.parse()?;
        input.parse::<Token![,]>()?;

        let path: LitStr = input.parse()?;
        input.parse::<Token![,]>()?;

        // ── Optional mode keyword + mandatory send mode ───────────────────
        let (mode, send) = if input.peek(Token![async]) {
            input.parse::<Token![async]>()?;
            (RequestBodyMode::None, SendMode::Async)
        } else {
            let kw: Ident = input.parse()?;
            match kw.to_string().as_str() {
                "sync" => (RequestBodyMode::None, SendMode::Sync),
                "json" => {
                    let content;
                    syn::parenthesized!(content in input);
                    let expr: Expr = content.parse()?;
                    let send = parse_send_mode(input)?;
                    (RequestBodyMode::Json(expr), send)
                }
                "query" => {
                    let content;
                    syn::parenthesized!(content in input);
                    let expr: Expr = content.parse()?;
                    let send = parse_send_mode(input)?;
                    (RequestBodyMode::Query(expr), send)
                }
                "encrypted" => {
                    let content;
                    syn::parenthesized!(content in input);
                    let body: Expr = content.parse()?;
                    content.parse::<Token![,]>()?;
                    let key: Expr = content.parse()?;
                    let send = parse_send_mode(input)?;
                    (RequestBodyMode::Encrypted(body, key), send)
                }
                "encrypted_query" => {
                    let content;
                    syn::parenthesized!(content in input);
                    let params: Expr = content.parse()?;
                    content.parse::<Token![,]>()?;
                    let key: Expr = content.parse()?;
                    let send = parse_send_mode(input)?;
                    (RequestBodyMode::EncryptedQuery(params, key), send)
                }
                other => {
                    return Err(syn::Error::new(
                        kw.span(),
                        format!(
                            "#[request]: unknown keyword `{other}`. \
                             Valid modes: json(<expr>), query(<expr>), \
                             encrypted(<body>, <key>), encrypted_query(<params>, <key>). \
                             Final argument must be `async` or `sync`."
                        ),
                    ));
                }
            }
        };

        Ok(RequestArgs { client, method, path, mode, send })
    }
}

/// Concise HTTP client request for `toolkit-zero` socket-client routes.
///
/// Replaces a decorated `fn` item with a `let` binding statement that performs
/// the HTTP request inline.  The function name becomes the binding name; the
/// return type annotation is used as the response type `R` in `.send::<R>()`.
/// The function body is discarded entirely.
///
/// # Syntax
///
/// ```text
/// #[request(client, METHOD, "/path", async|sync)]
/// #[request(client, METHOD, "/path", json(<body_expr>), async|sync)]
/// #[request(client, METHOD, "/path", query(<params_expr>), async|sync)]
/// #[request(client, METHOD, "/path", encrypted(<body_expr>, <key_expr>), async|sync)]
/// #[request(client, METHOD, "/path", encrypted_query(<params_expr>, <key_expr>), async|sync)]
/// ```
///
/// # Parameters
///
/// | Argument | Meaning |
/// |---|---|
/// | `client` | The [`Client`](toolkit_zero::socket::client::Client) variable in the enclosing scope |
/// | `METHOD` | HTTP method: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS` |
/// | `"/path"` | Endpoint path string literal |
/// | `json(expr)` | Serialise `expr` as a JSON body (`Content-Type: application/json`) |
/// | `query(expr)` | Serialise `expr` as URL query parameters |
/// | `encrypted(body, key)` | VEIL-seal `body` with a [`SerializationKey`](toolkit_zero::socket::SerializationKey) |
/// | `encrypted_query(params, key)` | VEIL-seal `params`, send as `?data=<base64url>` |
/// | `async` | Finalise with `.send::<R>().await?` |
/// | `sync`  | Finalise with `.send_sync::<R>()?` |
///
/// The function **must** carry an explicit return type — it becomes `R` in the turbofish.
/// The enclosing function must return a `Result<_, E>` where `E` implements the relevant
/// `From` for `?` to propagate: `reqwest::Error` for plain/json/query, or
/// `ClientError` for encrypted variants.
///
/// # Example
///
/// ```rust,ignore
/// use toolkit_zero::socket::client::{Client, Target, request};
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Deserialize, Serialize, Clone)] struct Item   { id: u32, name: String }
/// #[derive(Serialize)]                     struct NewItem { name: String }
/// #[derive(Serialize)]                     struct Filter  { page: u32 }
///
/// async fn example() -> Result<(), reqwest::Error> {
///     let client = Client::new_async(Target::Localhost(8080));
///
///     // Plain async GET → let items: Vec<Item> = client.get("/items").send::<Vec<Item>>().await?
///     #[request(client, GET, "/items", async)]
///     async fn items() -> Vec<Item> {}
///
///     // POST with JSON body
///     #[request(client, POST, "/items", json(NewItem { name: "widget".into() }), async)]
///     async fn created() -> Item {}
///
///     // GET with query params
///     #[request(client, GET, "/items", query(Filter { page: 2 }), async)]
///     async fn page() -> Vec<Item> {}
///
///     // Sync DELETE
///     #[request(client, DELETE, "/items/1", sync)]
///     fn deleted() -> Item {}
///
///     Ok(())
/// }
/// ```
#[cfg(feature = "socket-client")]
#[proc_macro_attribute]
pub fn request(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as RequestArgs);
    let func = parse_macro_input!(item as ItemFn);

    // ── Validate HTTP method ──────────────────────────────────────────────
    let method_str = args.method.to_string().to_lowercase();
    let method_ident = Ident::new(&method_str, args.method.span());

    match method_str.as_str() {
        "get" | "post" | "put" | "delete" | "patch" | "head" | "options" => {}
        other => {
            return syn::Error::new(
                args.method.span(),
                format!(
                    "#[request]: `{other}` is not a valid HTTP method. \
                     Expected GET, POST, PUT, DELETE, PATCH, HEAD, or OPTIONS."
                ),
            )
            .to_compile_error()
            .into();
        }
    }

    let client   = &args.client;
    let path     = &args.path;
    let var_name = &func.sig.ident;

    // ── Return type — required; used as turbofish argument ────────────────
    let ret_ty = match &func.sig.output {
        syn::ReturnType::Type(_, ty) => ty.as_ref(),
        syn::ReturnType::Default => {
            return syn::Error::new(
                func.sig.ident.span(),
                "#[request]: a return type is required — it specifies the response type `R` \
                 in `.send::<R>()`. Example: `async fn my_var() -> Vec<MyType> {}`",
            )
            .to_compile_error()
            .into();
        }
    };

    // ── Build the partial builder chain (without the send call) ──────────
    let chain = match &args.mode {
        RequestBodyMode::None => quote! {
            #client.#method_ident(#path)
        },
        RequestBodyMode::Json(expr) => quote! {
            #client.#method_ident(#path).json(#expr)
        },
        RequestBodyMode::Query(expr) => quote! {
            #client.#method_ident(#path).query(#expr)
        },
        RequestBodyMode::Encrypted(body_expr, key_expr) => quote! {
            #client.#method_ident(#path).encryption(#body_expr, #key_expr)
        },
        RequestBodyMode::EncryptedQuery(params_expr, key_expr) => quote! {
            #client.#method_ident(#path).encrypted_query(#params_expr, #key_expr)
        },
    };

    // ── Final let-binding statement ───────────────────────────────────────
    match &args.send {
        SendMode::Async => quote! {
            let #var_name: #ret_ty = #chain.send::<#ret_ty>().await?;
        },
        SendMode::Sync => quote! {
            let #var_name: #ret_ty = #chain.send_sync::<#ret_ty>()?;
        },
    }
    .into()
}
