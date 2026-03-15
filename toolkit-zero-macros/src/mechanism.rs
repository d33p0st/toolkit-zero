// ─── socket-server: #[mechanism] ────────────────────────────────────────────

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Expr, Ident, ItemFn, LitStr, Token,
};

// ─── Argument types ───────────────────────────────────────────────────────────

/// The body/query mode keyword extracted from the attribute arguments.
enum BodyMode {
    None,
    Json,
    Query,
    Encrypted(Expr),
    EncryptedQuery(Expr),
}

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

// ─── Entry point ─────────────────────────────────────────────────────────────

pub fn expand(attr: TokenStream, item: TokenStream) -> TokenStream {
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
