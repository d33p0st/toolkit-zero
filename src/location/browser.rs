//! The most simplest of location mechanism that uses the native browser to
//! fetch location info about current device. This module provides [`__location__`],
//! a versatile function that works with both sync and async contexts.
//! 
//! The browser will prompt the user for location permission upon acceptance,
//! the location data will be returned back.
//! 
//! 1. Binds a temporary HTTP server on a random `localhost` port using the
//!    [`socket-server`](crate::socket) module.
//! 2. Opens the system's default browser to a consent page served by that
//!    server (using the [`webbrowser`] crate — works on macOS, Windows, and
//!    Linux).
//! 3. The browser prompts the user for location permission via the standard
//!    [`navigator.geolocation.getCurrentPosition`][geo-api] Web API.
//! 4. On success the browser POSTs the coordinates back to the local server,
//!    which shuts itself down and returns the data to the caller.
//! 
//! [geo-api]: https://developer.mozilla.org/en-US/docs/Web/API/Geolocation/getCurrentPosition


use std::sync::Arc;
use tokio::sync::RwLock;
use serde::Deserialize;
use crate::socket::server::{Server, ServerMechanism, SerializationKey};


// ─────────────────────────────────────────────────────────────────────────────
// Page template
// ─────────────────────────────────────────────────────────────────────────────

/// Controls what the user sees in the browser when [`__location__`] is called.
///
/// # Variants at a glance
///
/// | Variant | Description |
/// |---|---|
/// | [`PageTemplate::Default`] | Clean single-button page. Title and body text are customisable. |
/// | [`PageTemplate::Tickbox`] | Same, but requires a checkbox tick before the button activates. Title, body text, and consent label are customisable. |
/// | [`PageTemplate::Custom`] | Fully custom HTML. Place `{}` where the capture button should appear; the required JavaScript is injected automatically. |
pub enum PageTemplate {
    /// A clean, single-button consent page.
    ///
    /// Both fields fall back to sensible built-in values when `None`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use toolkit_zero::location::browser::PageTemplate;
    /// // fully default
    /// let t = PageTemplate::default();
    ///
    /// // custom title only
    /// let t = PageTemplate::Default {
    ///     title:     Some("My App — Location".into()),
    ///     body_text: None,
    /// };
    /// ```
    Default {
        /// Browser tab title and `<h1>` heading text.
        /// Falls back to `"Location Access"` when `None`.
        title: Option<String>,
        /// Descriptive paragraph shown below the heading.
        /// Falls back to a generic description when `None`.
        body_text: Option<String>,
    },

    /// Like [`Default`](PageTemplate::Default) but adds a checkbox the user
    /// must tick before the capture button becomes active.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use toolkit_zero::location::browser::PageTemplate;
    /// let t = PageTemplate::Tickbox {
    ///     title:        Some("Verify Location".into()),
    ///     body_text:    None,
    ///     consent_text: Some("I agree to share my location with this application.".into()),
    /// };
    /// ```
    Tickbox {
        /// Browser tab title and `<h1>` heading text.
        /// Falls back to `"Location Access"` when `None`.
        title: Option<String>,
        /// Descriptive paragraph shown below the heading.
        /// Falls back to a generic description when `None`.
        body_text: Option<String>,
        /// Text label shown next to the checkbox.
        /// Falls back to `"I consent to sharing my location."` when `None`.
        consent_text: Option<String>,
    },

    /// A fully custom HTML document.
    ///
    /// Place exactly one `{}` in the string where the capture button should
    /// be injected. The required JavaScript (which POSTs to `/location` and
    /// `/location-error`) is injected automatically before `</body>`, so you
    /// do not need to write any geolocation JS yourself.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use toolkit_zero::location::browser::PageTemplate;
    /// let html = r#"<!DOCTYPE html>
    /// <html><body>
    ///   <h1>Where are you?</h1>
    ///   {}
    ///   <div id="status"></div>
    /// </body></html>"#;
    ///
    /// let t = PageTemplate::Custom(html.into());
    /// ```
    Custom(String),
}

impl Default for PageTemplate {
    /// Returns [`PageTemplate::Default`] with both fields set to `None`
    /// (all text falls back to built-in defaults).
    fn default() -> Self {
        PageTemplate::Default {
            title:     None,
            body_text: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public data types
// ─────────────────────────────────────────────────────────────────────────────

/// Geographic coordinates returned by the browser [Geolocation API].
///
/// Fields that are optional in the spec are `None` when the browser or device
/// did not supply them.
///
/// [Geolocation API]: https://developer.mozilla.org/en-US/docs/Web/API/GeolocationCoordinates
#[derive(Debug, Clone, PartialEq)]
pub struct LocationData {
    /// Latitude in decimal degrees (WGS 84).
    pub latitude: f64,
    /// Longitude in decimal degrees (WGS 84).
    pub longitude: f64,
    /// Horizontal accuracy radius in metres (95 % confidence).
    pub accuracy: f64,
    /// Altitude in metres above the WGS 84 ellipsoid, if provided by the device.
    pub altitude: Option<f64>,
    /// Accuracy of [`altitude`](Self::altitude) in metres, if provided.
    pub altitude_accuracy: Option<f64>,
    /// Direction of travel clockwise from true north in degrees `[0, 360)`,
    /// or `None` when the device is stationary or the sensor is unavailable.
    pub heading: Option<f64>,
    /// Ground speed in metres per second, or `None` when unavailable.
    pub speed: Option<f64>,
    /// Browser timestamp in milliseconds since the Unix epoch at which the
    /// position was acquired.
    pub timestamp_ms: f64,
}

/// Errors that can be returned by [`__location__`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocationError {
    /// The user denied the browser's location permission prompt
    /// (`GeolocationPositionError.PERMISSION_DENIED`, code 1).
    PermissionDenied,
    /// The device could not determine its position
    /// (`GeolocationPositionError.POSITION_UNAVAILABLE`, code 2).
    PositionUnavailable,
    /// The browser did not obtain a fix within its internal 30 s timeout
    /// (`GeolocationPositionError.TIMEOUT`, code 3).
    Timeout,
    /// The local HTTP server or the Tokio runtime could not be started.
    ServerError,
}

impl std::fmt::Display for LocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PermissionDenied    => write!(f, "location permission denied"),
            Self::PositionUnavailable => write!(f, "position unavailable"),
            Self::Timeout             => write!(f, "location request timed out"),
            Self::ServerError         => write!(f, "internal server error"),
        }
    }
}

impl std::error::Error for LocationError {}

#[derive(Deserialize, bincode::Encode, bincode::Decode)]
struct BrowserLocationBody {
    latitude:          f64,
    longitude:         f64,
    accuracy:          f64,
    altitude:          Option<f64>,
    altitude_accuracy: Option<f64>,
    heading:           Option<f64>,
    speed:             Option<f64>,
    timestamp:         f64,
}

#[derive(Deserialize, bincode::Encode, bincode::Decode)]
struct BrowserErrorBody {
    code: u32,
    #[allow(dead_code)]
    message: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared in-flight state between route handlers
// ─────────────────────────────────────────────────────────────────────────────

struct GeoState {
    result:   Option<Result<LocationData, LocationError>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}


/// Capture the user's geographic location by opening the browser to a local
/// consent page.
///
/// This is a **blocking** call. It:
///
/// 1. Binds a temporary HTTP server on a free `127.0.0.1` port.
/// 2. Opens `http://127.0.0.1:<port>/` in the system's default browser.
/// 3. Waits for the browser to POST location data (or an error) back.
/// 4. Shuts the server down and returns the result.
///
/// Pass a [`PageTemplate`] to control what the user sees in the browser.
/// Use [`PageTemplate::default()`] for the built-in single-button consent page.
///
/// # Errors
///
/// | Variant | Cause |
/// |---|---|
/// | [`LocationError::PermissionDenied`] | User denied the browser prompt. |
/// | [`LocationError::PositionUnavailable`] | Device cannot determine position. |
/// | [`LocationError::Timeout`] | No fix within the browser's 30 s timeout. |
/// | [`LocationError::ServerError`] | Failed to start the local HTTP server or runtime. |
///
/// # Example
///
/// ```no_run
/// use toolkit_zero::location::browser::{__location__, PageTemplate, LocationError};
///
/// // Default built-in page
/// match __location__(PageTemplate::default()) {
///     Ok(data) => println!("lat={:.6} lon={:.6} ±{:.0}m",
///                          data.latitude, data.longitude, data.accuracy),
///     Err(LocationError::PermissionDenied) => eprintln!("access denied"),
///     Err(e) => eprintln!("error: {e}"),
/// }
///
/// // Tickbox page with custom consent label
/// let _ = __location__(PageTemplate::Tickbox {
///     title:        None,
///     body_text:    None,
///     consent_text: Some("I agree to share my location.".into()),
/// });
/// ```
///
/// # Note on async callers
///
/// If you are already inside a Tokio async context (e.g. inside
/// `#[tokio::main]`), use [`__location_async__`] instead — it is the raw
/// `async fn` and avoids spawning an extra OS thread.
pub fn __location__(template: PageTemplate) -> Result<LocationData, LocationError> {
    // If called from within an existing Tokio runtime, calling `block_on` on
    // that same thread would panic with "Cannot start a runtime from within a
    // runtime". Detect this case and delegate to a dedicated OS thread that
    // owns its own single-threaded runtime, then join the result back.
    match tokio::runtime::Handle::try_current() {
        Ok(_) => {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| LocationError::ServerError)
                    .and_then(|rt| rt.block_on(capture(template)));
                let _ = tx.send(result);
            });
            rx.recv().unwrap_or(Err(LocationError::ServerError))
        }
        Err(_) => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| LocationError::ServerError)?
                .block_on(capture(template))
        }
    }
}

/// Async version of [`__location__`].
///
/// Directly awaits the capture future — preferred when you are already running
/// inside a Tokio async context so no extra OS thread needs to be spawned.
///
/// # Example
///
/// ```no_run
/// use toolkit_zero::location::browser::{__location_async__, PageTemplate, LocationError};
///
/// #[tokio::main]
/// async fn main() {
///     match __location_async__(PageTemplate::default()).await {
///         Ok(data) => println!("lat={:.6} lon={:.6}", data.latitude, data.longitude),
///         Err(e) => eprintln!("error: {e}"),
///     }
/// }
/// ```
pub async fn __location_async__(template: PageTemplate) -> Result<LocationData, LocationError> {
    capture(template).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Async core
// ─────────────────────────────────────────────────────────────────────────────

async fn capture(template: PageTemplate) -> Result<LocationData, LocationError> {
    // Bind to port 0 so the OS assigns a free port; pass the ready listener
    // directly to the server to avoid any TOCTOU race.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| LocationError::ServerError)?;

    let port = listener
        .local_addr()
        .map_err(|_| LocationError::ServerError)?
        .port();

    use rand::Rng as _;
    let mut rng = rand::rng();
    let key: String = (0..16).map(|_| format!("{:02x}", rng.random::<u8>())).collect();
    let skey = SerializationKey::Value(key.clone());

    let html = render_page(&template, &key);

    // Shared state written by POST handlers, read after the server exits.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let state: Arc<RwLock<GeoState>> = Arc::new(RwLock::new(GeoState {
        result:   None,
        shutdown: Some(shutdown_tx),
    }));

    // ── GET / — serve the consent page ────────────────────────────────────
    let get_route = ServerMechanism::get("/").onconnect(move || {
        let html = html.clone();
        async move { Ok::<_, warp::Rejection>(warp::reply::html(html)) }
    });

    // ── POST /location — browser geolocation success ───────────────────────
    let post_route = ServerMechanism::post("/location")
        .state(Arc::clone(&state))
        .encryption::<BrowserLocationBody>(skey.clone())
        .onconnect(
            |s: Arc<RwLock<GeoState>>, body: BrowserLocationBody| async move {
                let mut lock = s.write().await;
                if lock.result.is_none() {
                    lock.result = Some(Ok(LocationData {
                        latitude:          body.latitude,
                        longitude:         body.longitude,
                        accuracy:          body.accuracy,
                        altitude:          body.altitude,
                        altitude_accuracy: body.altitude_accuracy,
                        heading:           body.heading,
                        speed:             body.speed,
                        timestamp_ms:      body.timestamp,
                    }));
                    if let Some(tx) = lock.shutdown.take() {
                        let _ = tx.send(());
                    }
                }
                Ok::<_, warp::Rejection>(warp::reply())
            },
        );

    // ── POST /location-error — browser geolocation failure ────────────────
    let error_route = ServerMechanism::post("/location-error")
        .state(Arc::clone(&state))
        .encryption::<BrowserErrorBody>(skey)
        .onconnect(
            |s: Arc<RwLock<GeoState>>, body: BrowserErrorBody| async move {
                let mut lock = s.write().await;
                if lock.result.is_none() {
                    lock.result = Some(Err(match body.code {
                        1 => LocationError::PermissionDenied,
                        2 => LocationError::PositionUnavailable,
                        _ => LocationError::Timeout,
                    }));
                    if let Some(tx) = lock.shutdown.take() {
                        let _ = tx.send(());
                    }
                }
                Ok::<_, warp::Rejection>(warp::reply())
            },
        );

    let mut server = Server::default();
    server
        .mechanism(get_route)
        .mechanism(post_route)
        .mechanism(error_route);

    // Open the browser before blocking on the server.
    let url = format!("http://127.0.0.1:{port}");
    if webbrowser::open(&url).is_err() {
        eprintln!("Could not open browser automatically. Navigate to: {url}");
    } else {
        println!("Location capture page opened. If the browser did not appear, navigate to: {url}");
    }

    server
        .serve_from_listener(listener, async move {
            shutdown_rx.await.ok();
        })
        .await;

    state
        .write()
        .await
        .result
        .take()
        .unwrap_or(Err(LocationError::ServerError))
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML rendering
// ─────────────────────────────────────────────────────────────────────────────

/// The capture button element injected into every template.
const CAPTURE_BUTTON: &str =
    r#"<button id="btn" onclick="requestLocation()">Share My Location</button>"#;

/// JavaScript that handles geolocation and POSTs the VEIL-sealed result to
/// the local server. Injected into every template (including `Custom`).
/// Requires the VEIL cipher script (from [`veil_cipher_script`]) to be
/// present on the page so that `window.sealLocation` and
/// `window.sealLocationError` are available.
const CAPTURE_JS: &str = r#"<script>
  var done = false;
  function setStatus(msg) {
    var el = document.getElementById('status');
    if (el) el.textContent = msg;
  }
  function requestLocation() {
    if (done) return;
    document.getElementById('btn').disabled = true;
    setStatus('Requesting location\u2026');
    navigator.geolocation.getCurrentPosition(
      function(pos) {
        if (done) return; done = true;
        var c = pos.coords;
        fetch('/location', {
          method:  'POST',
          headers: { 'Content-Type': 'application/octet-stream' },
          body: window.sealLocation({
            latitude:          c.latitude,
            longitude:         c.longitude,
            accuracy:          c.accuracy,
            altitude:          c.altitude,
            altitude_accuracy: c.altitudeAccuracy,
            heading:           c.heading,
            speed:             c.speed,
            timestamp:         pos.timestamp
          })
        }).then(function() {
          setStatus('\u2705 Location captured \u2014 you may close this tab.');
        }).catch(function() {
          setStatus('\u26a0\ufe0f Captured but could not reach the app.');
        });
      },
      function(err) {
        if (done) return; done = true;
        fetch('/location-error', {
          method:  'POST',
          headers: { 'Content-Type': 'application/octet-stream' },
          body: window.sealLocationError({ code: err.code, message: err.message })
        }).then(function() {
          setStatus('\u274c ' + err.message + '. You may close this tab.');
        });
      },
      { enableHighAccuracy: true, timeout: 30000, maximumAge: 0 }
    );
  }
</script>"#;

/// Shared CSS used by the two built-in templates.
const SHARED_CSS: &str = r#"<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; background: #f5f5f7; color: #1d1d1f;
  }
  .card {
    background: #fff; border-radius: 18px; padding: 44px 52px;
    box-shadow: 0 4px 32px rgba(0,0,0,.10); max-width: 440px; width: 92%;
    text-align: center;
  }
  .icon  { font-size: 3rem; margin-bottom: 16px; }
  h1     { font-size: 1.55rem; font-weight: 600; margin-bottom: 10px; }
  p      { font-size: .95rem; color: #555; line-height: 1.6; margin-bottom: 30px; }
  button {
    background: #0071e3; color: #fff; border: none; border-radius: 980px;
    padding: 14px 34px; font-size: 1rem; cursor: pointer;
    transition: background .15s, opacity .15s;
  }
  button:hover:not(:disabled) { background: #0077ed; }
  button:disabled { opacity: .55; cursor: default; }
  #status { margin-top: 22px; font-size: .88rem; color: #444; min-height: 1.3em; }
  .consent-row {
    display: flex; align-items: center; justify-content: center;
    gap: 8px; margin-bottom: 24px; font-size: .92rem; color: #333;
  }
  .consent-row input[type="checkbox"] { width: 16px; height: 16px; cursor: pointer; }
</style>"#;

/// Helper for the tickbox template: a tiny inline script that enables /
/// disables the button based on whether the checkbox is checked.
const TICKBOX_TOGGLE_JS: &str = r#"<script>
  function toggleBtn() {
    document.getElementById('btn').disabled =
      !document.getElementById('consent').checked;
  }
</script>"#;

/// Generates a `<script>` block containing the full VEIL cipher JavaScript
/// port. The runtime `key` is embedded as an obfuscated char-code array so
/// it does not appear as a plain string in DevTools source view.
///
/// The script exposes two globals used by [`CAPTURE_JS`]:
/// - `window.sealLocation(data)` — encodes and seals a location payload.
/// - `window.sealLocationError(data)` — encodes and seals an error payload.
///
/// Both functions return a `Uint8Array` ready to POST as
/// `application/octet-stream`. The sealed bytes are identical to what
/// [`crate::serialization::seal`] produces with the same key, so the server
/// route's `.encryption::<T>(SerializationKey::Value(key))` can decrypt them
/// transparently.
fn veil_cipher_script(key: &str) -> String {
    let kc: String = key.bytes().map(|b| b.to_string()).collect::<Vec<_>>().join(",");
    format!(r#"<script>(function(){{
var _K=[{kc}].map(function(c){{return String.fromCharCode(c);}}).join('');
function _sm(x){{
  x=BigInt.asUintN(64,x+0x9e3779b97f4a7c15n);
  x=BigInt.asUintN(64,(x^(x>>30n))*0xbf58476d1ce4e5b9n);
  x=BigInt.asUintN(64,(x^(x>>27n))*0x94d049bb133111ebn);
  return x^(x>>31n);
}}
function _fnv(b){{
  var h=0xcbf29ce484222325n,P=0x100000001b3n;
  for(var i=0;i<b.length;i++) h=BigInt.asUintN(64,(h^BigInt(b[i]))*P);
  return h;}}
function _ks(k){{
  var kb=new TextEncoder().encode(k);
  var h0=_fnv(kb);
  var h1=_sm(BigInt.asUintN(64,h0^0xdeadbeefcafebaben));
  var sx=new Uint8Array(256);
  for(var i=0;i<256;i++) sx[i]=i;
  var r=h0;
  for(var i=255;i>=1;i--){{
    r=_sm(r);
    var j=Number(r%BigInt(i+1));
    var t=sx[i];sx[i]=sx[j];sx[j]=t;
  }}
  var ss=h1;
  var sh=_sm(BigInt.asUintN(64,h1^0x1234567890abcdefn));
  function sb(pos){{
    var s=BigInt.asUintN(64,BigInt.asUintN(64,ss+BigInt(pos))*0x9e3779b97f4a7c15n);
    var v=_sm(s);
    return Number((v>>32n)^(v&0xffffffffn))&0xff;
  }}
  function pm(bi,len){{
    var sd=BigInt.asUintN(64,BigInt.asUintN(64,sh+BigInt(bi))*0x6c62272e07bb0142n);
    var p=[];
    for(var i=0;i<len;i++) p.push(i);
    var rr=_sm(sd);
    for(var i=len-1;i>=1;i--){{
      rr=_sm(rr);
      var j=Number(rr%BigInt(i+1));
      var t=p[i];p[i]=p[j];p[j]=t;
    }}
    return p;
  }}
  return{{sx:sx,sb:sb,pm:pm}};
}}
function _enc(plain){{
  var ks=_ks(_K),b=new Uint8Array(plain.length);
  for(var i=0;i<plain.length;i++) b[i]=ks.sx[plain[i]];
  for(var i=0;i<b.length;i++) b[i]^=ks.sb(i);
  var prev=0xA7;
  for(var i=0;i<b.length;i++){{
    var orig=b[i];
    var mix=((((i&0xff)+prev)&0xff)*0x6b)&0xff;
    b[i]=(b[i]^mix)&0xff;
    prev=orig;
  }}
  var acc=0xB3;
  for(var i=0;i<b.length;i++){{
    var out=(b[i]^acc)&0xff;
    acc=(((acc<<3)|(acc>>5))^out)&0xff;
    b[i]=out;
  }}
  var BK=16,n=b.length,full=Math.floor(n/BK);
  for(var bi=0;bi<full;bi++){{
    var p=ks.pm(bi,BK),base=bi*BK,blk=b.slice(base,base+BK);
    for(var i=0;i<BK;i++) b[base+i]=blk[p[i]];
  }}
  var ts=full*BK,tl=n-ts;
  if(tl>1){{
    var p=ks.pm(full,tl),tail=b.slice(ts);
    for(var i=0;i<tl;i++) b[ts+i]=tail[p[i]];
  }}
  return b;
}}
var _f64b=new ArrayBuffer(8),_f64v=new DataView(_f64b);
function _f64(v){{_f64v.setFloat64(0,v,true);return new Uint8Array(_f64b.slice(0));}}
function _cat(arrays){{
  var len=0,off=0;
  for(var i=0;i<arrays.length;i++) len+=arrays[i].length;
  var out=new Uint8Array(len);
  for(var i=0;i<arrays.length;i++){{out.set(arrays[i],off);off+=arrays[i].length;}}
  return out;
}}
function _opt(v){{
  return(v===null||v===undefined)?new Uint8Array([0]):_cat([new Uint8Array([1]),_f64(v)]);
}}
function _vi(n){{
  if(n<251) return new Uint8Array([n]);
  if(n<65536) return new Uint8Array([251,n&0xff,(n>>8)&0xff]);
  if(n<4294967296) return new Uint8Array([252,n&0xff,(n>>8)&0xff,(n>>16)&0xff,(n>>24)&0xff]);
  var bn=BigInt(n);
  return new Uint8Array([253,Number(bn&0xffn),Number((bn>>8n)&0xffn),Number((bn>>16n)&0xffn),
    Number((bn>>24n)&0xffn),Number((bn>>32n)&0xffn),Number((bn>>40n)&0xffn),
    Number((bn>>48n)&0xffn),Number((bn>>56n)&0xffn)]);
}}
function _wrap(b){{return _cat([_vi(b.length),b]);}}
window.sealLocation=function(d){{
  return _wrap(_enc(_cat([
    _f64(d.latitude),_f64(d.longitude),_f64(d.accuracy),
    _opt(d.altitude),_opt(d.altitude_accuracy),_opt(d.heading),_opt(d.speed),
    _f64(d.timestamp)
  ])));
}};
window.sealLocationError=function(d){{
  var mb=new TextEncoder().encode(d.message);
  return _wrap(_enc(_cat([_vi(d.code),_vi(mb.length),mb])));
}};
}})();</script>"#, kc = kc)
}

fn render_page(template: &PageTemplate, key: &str) -> String {
    match template {
        PageTemplate::Default { title, body_text } => {
            let title = title.as_deref().unwrap_or("Location Access");
            let body  = body_text.as_deref().unwrap_or(
                "An application on this computer is requesting your geographic \
                 location. Click <strong>Share My Location</strong> and allow \
                 access when the browser asks.",
            );
            let veil_js = veil_cipher_script(key);
            format!(
                r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  {SHARED_CSS}
</head>
<body>
  <div class="card">
    <div class="icon">&#128205;</div>
    <h1>{title}</h1>
    <p>{body}</p>
    {CAPTURE_BUTTON}
    <div id="status"></div>
  </div>
  {veil_js}
  {CAPTURE_JS}
</body>
</html>"#
            )
        }

        PageTemplate::Tickbox { title, body_text, consent_text } => {
            let title   = title.as_deref().unwrap_or("Location Access");
            let body    = body_text.as_deref().unwrap_or(
                "An application on this computer is requesting your geographic \
                 location. Tick the box below, then click \
                 <strong>Share My Location</strong> to continue.",
            );
            let consent = consent_text.as_deref()
                .unwrap_or("I consent to sharing my location.");
            // The capture button is disabled by default; toggleBtn() enables it.
            let tickbox_button =
                r#"<button id="btn" onclick="requestLocation()" disabled>Share My Location</button>"#;
            let veil_js = veil_cipher_script(key);
            format!(
                r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  {SHARED_CSS}
</head>
<body>
  <div class="card">
    <div class="icon">&#128205;</div>
    <h1>{title}</h1>
    <p>{body}</p>
    <div class="consent-row">
      <input type="checkbox" id="consent" onchange="toggleBtn()">
      <label for="consent">{consent}</label>
    </div>
    {tickbox_button}
    <div id="status"></div>
  </div>
  {TICKBOX_TOGGLE_JS}
  {veil_js}
  {CAPTURE_JS}
</body>
</html>"#
            )
        }

        PageTemplate::Custom(html) => {
            // Replace the first {} with the capture button.
            let with_button = html.replacen("{}", CAPTURE_BUTTON, 1);
            // Inject the VEIL cipher script then CAPTURE_JS before </body>,
            // mirroring how the button is injected. The cipher script must
            // come first so that sealLocation / sealLocationError are defined
            // before the geolocation handler runs.
            let veil_js = veil_cipher_script(key);
            let inject = format!("{veil_js}\n{CAPTURE_JS}\n</body>");
            if with_button.contains("</body>") {
                with_button.replacen("</body>", &inject, 1)
            } else {
                format!("{with_button}\n{veil_js}\n{CAPTURE_JS}")
            }
        }
    }
}
