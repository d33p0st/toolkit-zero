// ─── #[browser] ──────────────────────────────────────────────────────────────
//
// Attribute macro that replaces a decorated `fn` with an inline
// `__location__` / `__location_async__` call.
//
// Syntax:
//   #[browser]
//   #[browser(sync)]
//   #[browser(title = "…")]
//   #[browser(body = "…")]
//   #[browser(tickbox)]
//   #[browser(tickbox, title = "…", body = "…", consent = "…")]
//   #[browser(html = "…")]
//   #[browser(sync, html = "…")]
//   — any combination of `sync` + one template spec.

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    Ident, ItemFn, LitStr, Token,
};

// ─── Argument struct ─────────────────────────────────────────────────────────

struct BrowserArgs {
    sync:    bool,
    tickbox: bool,
    title:   Option<LitStr>,
    body:    Option<LitStr>,
    consent: Option<LitStr>,
    html:    Option<LitStr>,
}

impl Parse for BrowserArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut sync    = false;
        let mut tickbox = false;
        let mut title   = None::<LitStr>;
        let mut body    = None::<LitStr>;
        let mut consent = None::<LitStr>;
        let mut html    = None::<LitStr>;

        while !input.is_empty() {
            // Peek at an identifier to determine which argument follows.
            if input.peek(Ident) {
                let ident: Ident = input.parse()?;
                match ident.to_string().as_str() {
                    "sync" => {
                        sync = true;
                    }
                    "tickbox" => {
                        tickbox = true;
                    }
                    "title" => {
                        let _eq: Token![=] = input.parse()?;
                        title = Some(input.parse()?);
                    }
                    "body" => {
                        let _eq: Token![=] = input.parse()?;
                        body = Some(input.parse()?);
                    }
                    "consent" => {
                        let _eq: Token![=] = input.parse()?;
                        consent = Some(input.parse()?);
                    }
                    "html" => {
                        let _eq: Token![=] = input.parse()?;
                        html = Some(input.parse()?);
                    }
                    other => {
                        return Err(syn::Error::new(
                            ident.span(),
                            format!(
                                "#[browser]: unknown argument `{other}`. \
                                 Expected: sync, tickbox, title, body, consent, html"
                            ),
                        ));
                    }
                }
            }

            // Consume trailing comma, if present.
            if input.peek(Token![,]) {
                let _: Token![,] = input.parse()?;
            }
        }

        Ok(BrowserArgs { sync, tickbox, title, body, consent, html })
    }
}

// ─── Expansion ───────────────────────────────────────────────────────────────

pub fn expand_browser(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = match syn::parse::<BrowserArgs>(attr) {
        Ok(a)  => a,
        Err(e) => return e.to_compile_error().into(),
    };

    let func = match syn::parse::<ItemFn>(item) {
        Ok(f)  => f,
        Err(e) => return e.to_compile_error().into(),
    };

    // Validate: `html` is mutually exclusive with tickbox / title / body / consent.
    if args.html.is_some()
        && (args.tickbox
            || args.title.is_some()
            || args.body.is_some()
            || args.consent.is_some())
    {
        return syn::Error::new_spanned(
            &func.sig.ident,
            "#[browser]: `html` is mutually exclusive with `tickbox`, `title`, `body`, and `consent`",
        )
        .to_compile_error()
        .into();
    }

    let binding = &func.sig.ident;

    // ── Build the PageTemplate token stream ──────────────────────────────────
    let template_tokens = build_template(&args);

    // ── Build the call expression ────────────────────────────────────────────
    let call_tokens = if args.sync {
        quote! {
            let #binding = ::toolkit_zero::location::browser::__location__(#template_tokens)?;
        }
    } else {
        quote! {
            let #binding = ::toolkit_zero::location::browser::__location_async__(#template_tokens).await?;
        }
    };

    call_tokens.into()
}

// ─── Template builder ────────────────────────────────────────────────────────

fn build_template(args: &BrowserArgs) -> proc_macro2::TokenStream {
    // Custom HTML variant.
    if let Some(ref html_lit) = args.html {
        return quote! {
            ::toolkit_zero::location::browser::PageTemplate::Custom(
                ::std::string::String::from(#html_lit)
            )
        };
    }

    // Title helper — Option<String> expression.
    let title_expr = match &args.title {
        Some(lit) => quote! { ::std::option::Option::Some(::std::string::String::from(#lit)) },
        None      => quote! { ::std::option::Option::None },
    };

    // Body helper.
    let body_expr = match &args.body {
        Some(lit) => quote! { ::std::option::Option::Some(::std::string::String::from(#lit)) },
        None      => quote! { ::std::option::Option::None },
    };

    if args.tickbox {
        let consent_expr = match &args.consent {
            Some(lit) => quote! { ::std::option::Option::Some(::std::string::String::from(#lit)) },
            None      => quote! { ::std::option::Option::None },
        };
        quote! {
            ::toolkit_zero::location::browser::PageTemplate::Tickbox {
                title:        #title_expr,
                body_text:    #body_expr,
                consent_text: #consent_expr,
            }
        }
    } else {
        quote! {
            ::toolkit_zero::location::browser::PageTemplate::Default {
                title:     #title_expr,
                body_text: #body_expr,
            }
        }
    }
}
