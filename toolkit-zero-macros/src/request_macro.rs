// ─── socket-client: #[request] ───────────────────────────────────────────────

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Expr, Ident, ItemFn, LitStr, Token,
};

// ─── Argument types ───────────────────────────────────────────────────────────

/// Body/query attachment mode for a client request.
enum RequestBodyMode {
    None,
    Json(Expr),
    Query(Expr),
    Encrypted(Expr, Expr),
    EncryptedQuery(Expr, Expr),
}

/// Whether to call `.send().await?` or `.send_sync()?`.
enum SendMode {
    Async,
    Sync,
}

/// Fully parsed `#[request]` attribute arguments.
struct RequestArgs {
    client: Ident,
    method: Ident,
    path:   LitStr,
    mode:   RequestBodyMode,
    send:   SendMode,
}

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

// ─── Entry point ─────────────────────────────────────────────────────────────

pub fn expand(attr: TokenStream, item: TokenStream) -> TokenStream {
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
