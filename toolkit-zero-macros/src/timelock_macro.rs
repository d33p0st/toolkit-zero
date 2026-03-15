// ─── #[timelock] ─────────────────────────────────────────────────────────────
//
// Attribute macro that replaces a decorated `fn` with an inline
// `timelock(…)?` / `timelock_async(…).await?` call.
//
// Encryption path (params = None):
//   #[timelock(precision = Minute, format = Hour24, time(14, 37), salts = s, kdf = k)]
//   #[timelock(precision = Hour,   format = Hour24, time(14, 0),  salts = s, kdf = k, cadence = DayOfWeek(Tuesday))]
//   #[timelock(async, precision = Minute, format = Hour24, time(14, 37), salts = s, kdf = k)]
//
// Decryption path (params = Some):
//   #[timelock(params = header)]
//   #[timelock(async, params = header)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    Expr, Ident, ItemFn, LitInt, Token,
};

// ─── Cadence value ────────────────────────────────────────────────────────────

enum CadenceArg {
    /// Not supplied (or explicit `None`) → `TimeLockCadence::None`
    Default,
    DayOfWeek(Ident),
    DayOfMonth(LitInt),
    MonthOfYear(Ident),
    DayOfWeekInMonth(Ident, Ident),
    DayOfMonthInMonth(LitInt, Ident),
    DayOfWeekAndDayOfMonth(Ident, LitInt),
}

impl CadenceArg {
    /// Parse after the `=` sign following the `cadence` keyword.
    fn parse_value(input: ParseStream) -> syn::Result<Self> {
        let ident: Ident = input.parse()?;
        match ident.to_string().as_str() {
            // explicit None → same as omitted
            "None" => Ok(CadenceArg::Default),

            "DayOfWeek" => {
                let content;
                syn::parenthesized!(content in input);
                let w: Ident = content.parse()?;
                validate_weekday(&w)?;
                Ok(CadenceArg::DayOfWeek(w))
            }
            "DayOfMonth" => {
                let content;
                syn::parenthesized!(content in input);
                let d: LitInt = content.parse()?;
                Ok(CadenceArg::DayOfMonth(d))
            }
            "MonthOfYear" => {
                let content;
                syn::parenthesized!(content in input);
                let m: Ident = content.parse()?;
                validate_month(&m)?;
                Ok(CadenceArg::MonthOfYear(m))
            }
            "DayOfWeekInMonth" => {
                let content;
                syn::parenthesized!(content in input);
                let w: Ident = content.parse()?;
                validate_weekday(&w)?;
                let _: Token![,] = content.parse()?;
                let m: Ident = content.parse()?;
                validate_month(&m)?;
                Ok(CadenceArg::DayOfWeekInMonth(w, m))
            }
            "DayOfMonthInMonth" => {
                let content;
                syn::parenthesized!(content in input);
                let d: LitInt = content.parse()?;
                let _: Token![,] = content.parse()?;
                let m: Ident = content.parse()?;
                validate_month(&m)?;
                Ok(CadenceArg::DayOfMonthInMonth(d, m))
            }
            "DayOfWeekAndDayOfMonth" => {
                let content;
                syn::parenthesized!(content in input);
                let w: Ident = content.parse()?;
                validate_weekday(&w)?;
                let _: Token![,] = content.parse()?;
                let d: LitInt = content.parse()?;
                Ok(CadenceArg::DayOfWeekAndDayOfMonth(w, d))
            }
            other => Err(syn::Error::new(
                ident.span(),
                format!(
                    "#[timelock]: unknown cadence variant `{other}`. \
                     Expected: None, DayOfWeek, DayOfMonth, MonthOfYear, \
                     DayOfWeekInMonth, DayOfMonthInMonth, DayOfWeekAndDayOfMonth"
                ),
            )),
        }
    }

    /// Produce the full `Option::Some(TimeLockCadence::…)` token stream for
    /// the encryption path.
    fn to_tokens(&self) -> TokenStream2 {
        let tl = quote! { ::toolkit_zero::encryption::timelock };
        match self {
            CadenceArg::Default => quote! {
                ::std::option::Option::Some(#tl::TimeLockCadence::None)
            },
            CadenceArg::DayOfWeek(w) => quote! {
                ::std::option::Option::Some(
                    #tl::TimeLockCadence::DayOfWeek(#tl::Weekday::#w)
                )
            },
            CadenceArg::DayOfMonth(d) => quote! {
                ::std::option::Option::Some(
                    #tl::TimeLockCadence::DayOfMonth(#d)
                )
            },
            CadenceArg::MonthOfYear(m) => quote! {
                ::std::option::Option::Some(
                    #tl::TimeLockCadence::MonthOfYear(#tl::Month::#m)
                )
            },
            CadenceArg::DayOfWeekInMonth(w, m) => quote! {
                ::std::option::Option::Some(
                    #tl::TimeLockCadence::DayOfWeekInMonth(
                        #tl::Weekday::#w,
                        #tl::Month::#m,
                    )
                )
            },
            CadenceArg::DayOfMonthInMonth(d, m) => quote! {
                ::std::option::Option::Some(
                    #tl::TimeLockCadence::DayOfMonthInMonth(#d, #tl::Month::#m)
                )
            },
            CadenceArg::DayOfWeekAndDayOfMonth(w, d) => quote! {
                ::std::option::Option::Some(
                    #tl::TimeLockCadence::DayOfWeekAndDayOfMonth(
                        #tl::Weekday::#w,
                        #d,
                    )
                )
            },
        }
    }
}

// ─── Argument struct ──────────────────────────────────────────────────────────

struct TimelockArgs {
    is_async:  bool,
    // ── decryption path ──────────────────────────────────────────────────────
    params:    Option<Expr>,
    // ── encryption path ──────────────────────────────────────────────────────
    precision: Option<Ident>,   // Hour | Quarter | Minute
    format:    Option<Ident>,   // Hour12 | Hour24
    time_h:    Option<LitInt>,
    time_m:    Option<LitInt>,
    cadence:   CadenceArg,      // defaults to None (→ TimeLockCadence::None)
    salts:     Option<Expr>,
    kdf:       Option<Expr>,
}

impl Parse for TimelockArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut is_async  = false;
        let mut params    = None::<Expr>;
        let mut precision = None::<Ident>;
        let mut format    = None::<Ident>;
        let mut time_h    = None::<LitInt>;
        let mut time_m    = None::<LitInt>;
        let mut cadence   = CadenceArg::Default;
        let mut salts     = None::<Expr>;
        let mut kdf       = None::<Expr>;

        while !input.is_empty() {
            // `async` is a keyword in Rust — handle it via Token![async].
            if input.peek(Token![async]) {
                let _: Token![async] = input.parse()?;
                is_async = true;
            } else if input.peek(Ident) {
                let ident: Ident = input.parse()?;
                match ident.to_string().as_str() {
                    "params" => {
                        let _: Token![=] = input.parse()?;
                        params = Some(input.parse()?);
                    }
                    "precision" => {
                        let _: Token![=] = input.parse()?;
                        precision = Some(input.parse()?);
                    }
                    "format" => {
                        let _: Token![=] = input.parse()?;
                        format = Some(input.parse()?);
                    }
                    "time" => {
                        let content;
                        syn::parenthesized!(content in input);
                        time_h = Some(content.parse()?);
                        let _: Token![,] = content.parse()?;
                        time_m = Some(content.parse()?);
                    }
                    "cadence" => {
                        let _: Token![=] = input.parse()?;
                        cadence = CadenceArg::parse_value(input)?;
                    }
                    "salts" => {
                        let _: Token![=] = input.parse()?;
                        salts = Some(input.parse()?);
                    }
                    "kdf" => {
                        let _: Token![=] = input.parse()?;
                        kdf = Some(input.parse()?);
                    }
                    other => {
                        return Err(syn::Error::new(
                            ident.span(),
                            format!(
                                "#[timelock]: unknown argument `{other}`. \
                                 Expected: async, params, precision, format, \
                                 time, cadence, salts, kdf"
                            ),
                        ));
                    }
                }
            }

            // Consume trailing comma.
            if input.peek(Token![,]) {
                let _: Token![,] = input.parse()?;
            }
        }

        Ok(TimelockArgs { is_async, params, precision, format, time_h, time_m, cadence, salts, kdf })
    }
}

// ─── Validators ───────────────────────────────────────────────────────────────

fn validate_weekday(w: &Ident) -> syn::Result<()> {
    match w.to_string().as_str() {
        "Monday" | "Tuesday" | "Wednesday" | "Thursday"
            | "Friday" | "Saturday" | "Sunday" => Ok(()),
        other => Err(syn::Error::new(
            w.span(),
            format!(
                "#[timelock]: unknown weekday `{other}`. \
                 Expected: Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday"
            ),
        )),
    }
}

fn validate_month(m: &Ident) -> syn::Result<()> {
    match m.to_string().as_str() {
        "January" | "February" | "March"     | "April"
            | "May"    | "June"     | "July"      | "August"
            | "September" | "October"  | "November" | "December" => Ok(()),
        other => Err(syn::Error::new(
            m.span(),
            format!(
                "#[timelock]: unknown month `{other}`. \
                 Expected: January, February, March, April, May, June, \
                 July, August, September, October, November, December"
            ),
        )),
    }
}

// ─── Expansion ───────────────────────────────────────────────────────────────

pub fn expand_timelock(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = match syn::parse::<TimelockArgs>(attr) {
        Ok(a)  => a,
        Err(e) => return e.to_compile_error().into(),
    };

    let func = match syn::parse::<ItemFn>(item) {
        Ok(f)  => f,
        Err(e) => return e.to_compile_error().into(),
    };

    let binding = &func.sig.ident;
    let tl = quote! { ::toolkit_zero::encryption::timelock };

    let call = if let Some(params_expr) = &args.params {
        // ── Decryption path ──────────────────────────────────────────────────
        // `params` is mutually exclusive with all encryption path arguments.
        if args.precision.is_some()
            || args.format.is_some()
            || args.time_h.is_some()
            || args.salts.is_some()
            || args.kdf.is_some()
        {
            return syn::Error::new_spanned(
                &func.sig.ident,
                "#[timelock]: `params` is mutually exclusive with \
                 precision, format, time, salts, and kdf",
            )
            .to_compile_error()
            .into();
        }

        if args.is_async {
            quote! {
                let #binding = #tl::timelock_async(
                    ::std::option::Option::None,
                    ::std::option::Option::None,
                    ::std::option::Option::None,
                    ::std::option::Option::None,
                    ::std::option::Option::None,
                    ::std::option::Option::None,
                    ::std::option::Option::Some(#params_expr),
                ).await?;
            }
        } else {
            quote! {
                let #binding = #tl::timelock(
                    ::std::option::Option::None,
                    ::std::option::Option::None,
                    ::std::option::Option::None,
                    ::std::option::Option::None,
                    ::std::option::Option::None,
                    ::std::option::Option::None,
                    ::std::option::Option::Some(#params_expr),
                )?;
            }
        }
    } else {
        // ── Encryption path ──────────────────────────────────────────────────
        let precision = match &args.precision {
            Some(p) => p,
            None => return syn::Error::new_spanned(
                &func.sig.ident,
                "#[timelock]: `precision = Hour|Quarter|Minute` is required",
            ).to_compile_error().into(),
        };

        let fmt = match &args.format {
            Some(f) => f,
            None => return syn::Error::new_spanned(
                &func.sig.ident,
                "#[timelock]: `format = Hour12|Hour24` is required",
            ).to_compile_error().into(),
        };

        let time_h = match &args.time_h {
            Some(h) => h,
            None => return syn::Error::new_spanned(
                &func.sig.ident,
                "#[timelock]: `time(hour, minute)` is required",
            ).to_compile_error().into(),
        };
        let time_m = args.time_m.as_ref().unwrap(); // always set with time_h

        let salts = match &args.salts {
            Some(s) => s,
            None => return syn::Error::new_spanned(
                &func.sig.ident,
                "#[timelock]: `salts = <TimeLockSalts expr>` is required",
            ).to_compile_error().into(),
        };

        let kdf = match &args.kdf {
            Some(k) => k,
            None => return syn::Error::new_spanned(
                &func.sig.ident,
                "#[timelock]: `kdf = <KdfParams expr>` is required",
            ).to_compile_error().into(),
        };

        // Validate precision ident.
        match precision.to_string().as_str() {
            "Hour" | "Quarter" | "Minute" => {}
            _ => return syn::Error::new_spanned(
                precision,
                "#[timelock]: `precision` must be Hour, Quarter, or Minute",
            ).to_compile_error().into(),
        }

        // Validate format ident.
        match fmt.to_string().as_str() {
            "Hour12" | "Hour24" => {}
            _ => return syn::Error::new_spanned(
                fmt,
                "#[timelock]: `format` must be Hour12 or Hour24",
            ).to_compile_error().into(),
        }

        let cadence_tokens = args.cadence.to_tokens();

        if args.is_async {
            quote! {
                let #binding = #tl::timelock_async(
                    #cadence_tokens,
                    ::std::option::Option::Some(
                        #tl::TimeLockTime::new(#time_h, #time_m)
                            .expect("#[timelock]: time() values out of range — hour must be 0–23, minute 0–59")
                    ),
                    ::std::option::Option::Some(#tl::TimePrecision::#precision),
                    ::std::option::Option::Some(#tl::TimeFormat::#fmt),
                    ::std::option::Option::Some(#salts),
                    ::std::option::Option::Some(#kdf),
                    ::std::option::Option::None,
                ).await?;
            }
        } else {
            quote! {
                let #binding = #tl::timelock(
                    #cadence_tokens,
                    ::std::option::Option::Some(
                        #tl::TimeLockTime::new(#time_h, #time_m)
                            .expect("#[timelock]: time() values out of range — hour must be 0–23, minute 0–59")
                    ),
                    ::std::option::Option::Some(#tl::TimePrecision::#precision),
                    ::std::option::Option::Some(#tl::TimeFormat::#fmt),
                    ::std::option::Option::Some(#salts),
                    ::std::option::Option::Some(#kdf),
                    ::std::option::Option::None,
                )?;
            }
        }
    };

    call.into()
}
