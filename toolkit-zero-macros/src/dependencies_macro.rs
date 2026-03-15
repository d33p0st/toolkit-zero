// ─── #[dependencies] ──────────────────────────────────────────────────────────
//
// Attribute macro that replaces a decorated empty `fn` with an inline
// `capture::parse(…)?` or `.as_bytes()` call, embedding the build-time
// fingerprint JSON via `include_str!`.
//
// The function name becomes the `let` binding name in the expansion.
//
// Parse mode (default — returns BuildTimeFingerprintData via `?`):
//   #[dependencies]
//   fn data() {}
//
// Bytes mode (returns &'static [u8], no `?`):
//   #[dependencies(bytes)]
//   fn raw() {}

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    Ident, ItemFn,
};

// ─── args ─────────────────────────────────────────────────────────────────────

struct DepsArgs {
    bytes_mode: bool,
}

impl Parse for DepsArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(DepsArgs { bytes_mode: false });
        }
        let ident: Ident = input.parse()?;
        match ident.to_string().as_str() {
            "bytes" => Ok(DepsArgs { bytes_mode: true }),
            other => Err(syn::Error::new(
                ident.span(),
                format!("#[dependencies]: unknown option `{other}`; expected `bytes`"),
            )),
        }
    }
}

// ─── expander ─────────────────────────────────────────────────────────────────

pub fn expand_dependencies(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = match syn::parse::<DepsArgs>(attr) {
        Ok(a)  => a,
        Err(e) => return e.to_compile_error().into(),
    };

    let func = match syn::parse::<ItemFn>(item) {
        Ok(f)  => f,
        Err(e) => return e.to_compile_error().into(),
    };

    let binding = &func.sig.ident;
    let cap = quote! { ::toolkit_zero::dependency_graph::capture };

    let expanded: TokenStream2 = if args.bytes_mode {
        quote! {
            const __TOOLKIT_ZERO_BUILD_TIME_FINGERPRINT__: &str =
                include_str!(concat!(env!("OUT_DIR"), "/fingerprint.json"));
            let #binding: &'static [u8] =
                __TOOLKIT_ZERO_BUILD_TIME_FINGERPRINT__.as_bytes();
        }
    } else {
        quote! {
            const __TOOLKIT_ZERO_BUILD_TIME_FINGERPRINT__: &str =
                include_str!(concat!(env!("OUT_DIR"), "/fingerprint.json"));
            let #binding = #cap::parse(__TOOLKIT_ZERO_BUILD_TIME_FINGERPRINT__)?;
        }
    };

    expanded.into()
}
