// ─── serialization macros ─────────────────────────────────────────────────────
//
// #[serializable]  — derives Encode+Decode and injects seal/open methods
// #[serialize]     — inline seal to variable or file
// #[deserialize]   — inline open from variable or file

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Data, DeriveInput, Expr, Fields, Ident, ItemFn, LitStr, Token,
};

// ─── #[serializable] ─────────────────────────────────────────────────────────

pub fn expand_serializable(attr: TokenStream, item: TokenStream) -> TokenStream {
    let _ = attr; // struct-level: no attribute args expected

    let mut input = parse_macro_input!(item as DeriveInput);

    let name = input.ident.clone();

    // Serialise generics to TokenStream2 early so we can later move `input`.
    let (impl_generics_ts, ty_generics_ts, where_clause_ts) = {
        let (i, t, w) = input.generics.split_for_impl();
        (quote!(#i), quote!(#t), quote!(#w))
    };

    let mut per_field_methods: Vec<TokenStream2> = vec![];

    // ── Process struct fields: strip helper #[serializable(key = "...")] ──
    if let Data::Struct(ref mut ds) = input.data {
        let fields_opt = match &mut ds.fields {
            Fields::Named(f)   => Some(&mut f.named),
            Fields::Unnamed(f) => Some(&mut f.unnamed),
            Fields::Unit       => None,
        };

        if let Some(fields) = fields_opt {
            for field in fields.iter_mut() {
                let field_name = match &field.ident {
                    Some(id) => id.clone(),
                    None     => continue, // unnamed fields don't get per-field helpers
                };
                let field_ty = field.ty.clone();

                let mut found_key: Option<LitStr> = None;

                // Strip #[serializable(key = "...")] and remember the key
                field.attrs.retain(|a| {
                    if a.path().is_ident("serializable") {
                        if let Ok(lit) = a.parse_args_with(|inp: ParseStream| {
                            let kw: Ident = inp.parse()?;
                            if kw != "key" {
                                return Err(syn::Error::new(
                                    kw.span(),
                                    "#[serializable]: field attribute syntax is \
                                     `#[serializable(key = \"your-key\")]`",
                                ));
                            }
                            inp.parse::<Token![=]>()?;
                            inp.parse::<LitStr>()
                        }) {
                            found_key = Some(lit);
                        }
                        false // remove the attr from field
                    } else {
                        true
                    }
                });

                if let Some(key_lit) = found_key {
                    let seal_fn = format_ident!("seal_{}", field_name);
                    let open_fn = format_ident!("open_{}", field_name);

                    per_field_methods.push(quote! {
                        /// Seal the `#field_name` field with its associated key.
                        pub fn #seal_fn(
                            &self,
                        ) -> ::std::result::Result<
                            ::std::vec::Vec<u8>,
                            ::toolkit_zero::serialization::SerializationError,
                        > {
                            ::toolkit_zero::serialization::seal(
                                &self.#field_name,
                                ::std::option::Option::Some(#key_lit.to_string()),
                            )
                        }

                        /// Open a blob sealed by `seal_#field_name`.
                        pub fn #open_fn(
                            bytes: &[u8],
                        ) -> ::std::result::Result<
                            #field_ty,
                            ::toolkit_zero::serialization::SerializationError,
                        > {
                            ::toolkit_zero::serialization::open::<#field_ty, ::std::string::String>(
                                bytes,
                                ::std::option::Option::Some(#key_lit.to_string()),
                            )
                        }
                    });
                }
            }
        }
    }

    quote! {
        #[derive(
            ::toolkit_zero::serialization::Encode,
            ::toolkit_zero::serialization::Decode,
        )]
        #[bincode(crate = "::toolkit_zero::serialization::bincode")]
        #input

        impl #impl_generics_ts #name #ty_generics_ts #where_clause_ts {
            /// Encode and seal this value into an encrypted byte blob.
            ///
            /// Pass `None` to use the default key (`"serialization/deserialization"`),
            /// or `Some(key)` for a custom key.  The key is moved in and zeroized on drop.
            pub fn seal(
                &self,
                key: ::std::option::Option<::std::string::String>,
            ) -> ::std::result::Result<
                ::std::vec::Vec<u8>,
                ::toolkit_zero::serialization::SerializationError,
            > {
                ::toolkit_zero::serialization::seal(self, key)
            }

            /// Open a byte blob produced by [`seal`] back into `Self`.
            ///
            /// Pass the same key that was used in [`seal`], or `None` for the
            /// default key.  The key is moved in and zeroized on drop.
            pub fn open(
                bytes: &[u8],
                key: ::std::option::Option<::std::string::String>,
            ) -> ::std::result::Result<
                Self,
                ::toolkit_zero::serialization::SerializationError,
            > {
                ::toolkit_zero::serialization::open::<Self, ::std::string::String>(bytes, key)
            }

            #(#per_field_methods)*
        }
    }
    .into()
}

// ─── #[serialize] ────────────────────────────────────────────────────────────

struct SerializeArgs {
    /// The expression to seal (e.g. `my_struct`).
    source: Expr,
    /// Present → file write mode; absent → variable binding mode.
    path: Option<LitStr>,
    /// Optional explicit key expression.
    key: Option<Expr>,
}

impl Parse for SerializeArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let source: Expr = input.parse()?;

        let mut path: Option<LitStr> = None;
        let mut key: Option<Expr> = None;

        while input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }

            let kw: Ident = input.parse()?;
            match kw.to_string().as_str() {
                "path" => {
                    input.parse::<Token![=]>()?;
                    path = Some(input.parse::<LitStr>()?);
                }
                "key" => {
                    input.parse::<Token![=]>()?;
                    key = Some(input.parse::<Expr>()?);
                }
                other => {
                    return Err(syn::Error::new(
                        kw.span(),
                        format!(
                            "#[serialize]: unknown keyword `{other}`. \
                             Valid keywords: path = \"file.bin\", key = <expr>"
                        ),
                    ));
                }
            }
        }

        Ok(SerializeArgs { source, path, key })
    }
}

pub fn expand_serialize(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as SerializeArgs);
    let func = parse_macro_input!(item as ItemFn);

    let key_arg = match &args.key {
        Some(k) => quote! { ::std::option::Option::Some(#k) },
        None    => quote! { ::std::option::Option::<::std::string::String>::None },
    };

    let source = &args.source;

    match &args.path {
        // ── File write mode ───────────────────────────────────────────────
        Some(path_lit) => quote! {
            ::std::fs::write(
                #path_lit,
                ::toolkit_zero::serialization::seal(&#source, #key_arg)?,
            )?;
        },

        // ── Variable binding mode ─────────────────────────────────────────
        None => {
            let var_name = &func.sig.ident;

            let ret_ty = match &func.sig.output {
                syn::ReturnType::Type(_, ty) => ty.as_ref(),
                syn::ReturnType::Default => {
                    return syn::Error::new(
                        func.sig.ident.span(),
                        "#[serialize]: a return type is required in variable mode. \
                         Example: `fn blob() -> Vec<u8> {}`",
                    )
                    .to_compile_error()
                    .into();
                }
            };

            quote! {
                let #var_name: #ret_ty =
                    ::toolkit_zero::serialization::seal(&#source, #key_arg)?;
            }
        }
    }
    .into()
}

// ─── #[deserialize] ──────────────────────────────────────────────────────────

enum DeserializeSource {
    Blob(Expr),
    Path(LitStr),
}

struct DeserializeArgs {
    source: DeserializeSource,
    key: Option<Expr>,
}

impl Parse for DeserializeArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Detect `path = "..."` vs a blob expression
        let source = if input.peek(Ident) {
            let fork = input.fork();
            let kw: Ident = fork.parse()?;
            if kw == "path" && fork.peek(Token![=]) {
                input.parse::<Ident>()?; // consume "path"
                input.parse::<Token![=]>()?;
                DeserializeSource::Path(input.parse::<LitStr>()?)
            } else {
                DeserializeSource::Blob(input.parse::<Expr>()?)
            }
        } else {
            DeserializeSource::Blob(input.parse::<Expr>()?)
        };

        let mut key: Option<Expr> = None;

        while input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }

            let kw: Ident = input.parse()?;
            match kw.to_string().as_str() {
                "key" => {
                    input.parse::<Token![=]>()?;
                    key = Some(input.parse::<Expr>()?);
                }
                other => {
                    return Err(syn::Error::new(
                        kw.span(),
                        format!(
                            "#[deserialize]: unknown keyword `{other}`. \
                             Valid keywords: key = <expr>"
                        ),
                    ));
                }
            }
        }

        Ok(DeserializeArgs { source, key })
    }
}

pub fn expand_deserialize(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as DeserializeArgs);
    let func = parse_macro_input!(item as ItemFn);

    let var_name = &func.sig.ident;

    let ret_ty = match &func.sig.output {
        syn::ReturnType::Type(_, ty) => ty.as_ref(),
        syn::ReturnType::Default => {
            return syn::Error::new(
                func.sig.ident.span(),
                "#[deserialize]: a return type is required. \
                 Example: `fn config() -> MyStruct {}`",
            )
            .to_compile_error()
            .into();
        }
    };

    let key_arg = match &args.key {
        Some(k) => quote! { ::std::option::Option::Some(#k) },
        None    => quote! { ::std::option::Option::<::std::string::String>::None },
    };

    let bytes_expr = match &args.source {
        DeserializeSource::Blob(expr) => quote! { &#expr },
        DeserializeSource::Path(lit)  => quote! { &::std::fs::read(#lit)? },
    };

    quote! {
        let #var_name: #ret_ty =
            ::toolkit_zero::serialization::open::<#ret_ty, _>(#bytes_expr, #key_arg)?;
    }
    .into()
}
