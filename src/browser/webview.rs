//! Thread-local WebView storage and management.
//!
//! wry's [`WebView`] must be created and accessed on the main thread.  iced's
//! `update` and `view` functions also run on the main thread, so storing the
//! WebView in a `thread_local!` is both safe and correct.

use std::cell::RefCell;

use wry::dpi::{LogicalPosition, LogicalSize};
use wry::{PageLoadEvent, Rect, WebView, WebViewBuilder};
#[cfg(any(target_os = "macos", target_os = "ios"))]
use wry::WebViewBuilderExtDarwin;

use super::BrowserEvent;

// ── thread-local storage ────────────────────────────────────────────────────

thread_local! {
    static WEBVIEW: RefCell<Option<WebView>> = const { RefCell::new(None) };
    /// Simple event queue populated by wry callbacks (main-thread only).
    static EVENT_QUEUE: RefCell<Vec<BrowserEvent>> = const { RefCell::new(Vec::new()) };
}

// ── keyboard-shortcut init script ────────────────────────────────────────────

/// Injected into every page so that Cmd/Ctrl + C/V/X/A/Z/Y work inside the
/// WebView even when iced has intercepted the window's key-event handling.
const KEYBOARD_INIT_SCRIPT: &str = r#"
(function() {
  // Early-exit on platforms where the native engine already handles these.
  var ua = navigator.userAgent;
  if (/Mac/.test(ua)) {
    // WKWebView on macOS does NOT need JS shims for edit commands.
    // We only need to make sure devtools is not eating shortcuts.
    return;
  }
  // Windows / Linux: dispatch execCommand for common edit shortcuts.
  document.addEventListener('keydown', function(e) {
    var ctrl = e.ctrlKey || e.metaKey;
    if (!ctrl) return;
    switch (e.key.toLowerCase()) {
      case 'c': document.execCommand('copy');      e.preventDefault(); break;
      case 'x': document.execCommand('cut');       e.preventDefault(); break;
      case 'v': document.execCommand('paste');     e.preventDefault(); break;
      case 'a': document.execCommand('selectAll'); e.preventDefault(); break;
      case 'z': document.execCommand('undo');      e.preventDefault(); break;
      case 'y': document.execCommand('redo');      e.preventDefault(); break;
    }
  }, true);
})();
"#;

/// Init script that injects a custom context-menu item on every non-homepage
/// page: "Add to Quick Links".
const CONTEXT_MENU_INIT_SCRIPT: &str = r#"
(function() {
  // Remove the native context menu and replace with a minimal one that
  // includes our "Add to Quick Links" action.
  document.addEventListener('contextmenu', function(e) {
    // Only add the custom menu item when we are NOT on the homepage.
    if (window.location.protocol === 'about:' || window.__TKZ_HOME__) return;
    // We can't inject a native menu from JS, but we CAN offer a quick-add via
    // a small floating overlay that appears at the cursor position.
    var existing = document.getElementById('__tkz_ctx__');
    if (existing) existing.remove();

    var menu = document.createElement('div');
    menu.id = '__tkz_ctx__';
    menu.style.cssText = [
      'position:fixed',
      'z-index:2147483647',
      'left:' + e.clientX + 'px',
      'top:' + e.clientY + 'px',
      'background:#1a1a24',
      'border:1px solid rgba(120,0,255,0.35)',
      'border-radius:6px',
      'padding:4px 0',
      'font:13px/1 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif',
      'color:#ddd',
      'box-shadow:0 4px 18px rgba(0,0,0,.6)',
      'min-width:180px',
      'user-select:none',
    ].join(';');

    var title = document.title || window.location.hostname;
    var url   = window.location.href;

    var item = document.createElement('div');
    item.textContent = '⚡ Add to Quick Links';
    item.style.cssText = 'padding:7px 14px;cursor:pointer;';
    item.onmouseenter = function() { item.style.background='rgba(120,0,255,.18)'; };
    item.onmouseleave = function() { item.style.background=''; };
    item.onclick = function() {
      window.ipc.postMessage(JSON.stringify({type:'add_quicklink',url:url,title:title}));
      menu.remove();
    };

    menu.appendChild(item);
    document.body.appendChild(menu);

    // Dismiss on any outside click.
    var dismiss = function(ev) {
      if (!menu.contains(ev.target)) { menu.remove(); document.removeEventListener('mousedown', dismiss, true); }
    };
    document.addEventListener('mousedown', dismiss, true);
  });
})();
"#;

// ── public helpers ───────────────────────────────────────────────────────────

/// Push an event into the queue so iced can drain it on the next tick.
pub(super) fn push_event(event: BrowserEvent) {
    EVENT_QUEUE.with(|q| q.borrow_mut().push(event));
}

/// Drain all queued events and return them.
pub(super) fn drain_events() -> Vec<BrowserEvent> {
    // Fast path: avoid Vec allocation on the common empty-queue case.
    if EVENT_QUEUE.with(|q| q.borrow().is_empty()) {
        return Vec::new();
    }
    EVENT_QUEUE.with(|q| q.borrow_mut().drain(..).collect())
}

/// Returns `true` if the WebView has been initialised.
pub(super) fn is_initialised() -> bool {
    WEBVIEW.with(|wv| wv.borrow().is_some())
}

// ── WebView creation (called from within `window::run` closure) ──────────────

/// Raw-handle wrapper so we can satisfy `HasWindowHandle` with a `RawWindowHandle`.
///
/// # Safety
/// The raw handle must remain valid for the duration of the builder call, which
/// it always is because we are inside `window::run`'s closure.
struct HandleBorrow(raw_window_handle::RawWindowHandle);

impl raw_window_handle::HasWindowHandle for HandleBorrow {
    fn window_handle(
        &self,
    ) -> Result<raw_window_handle::WindowHandle<'_>, raw_window_handle::HandleError> {
        // SAFETY: the raw handle came directly from the live iced window
        unsafe { Ok(raw_window_handle::WindowHandle::borrow_raw(self.0)) }
    }
}

/// Initialise the WebView.  Must be called from the main thread inside an
/// iced `window::run` closure.
///
/// * `raw_handle`   – the raw OS window handle obtained via `window::run`
/// * `initial_url`  – URL to navigate to immediately, or `None` to load blank
/// * `initial_html` – HTML string to load, takes precedence over `initial_url`
/// * `content_x/y/w/h` – WebView bounds (logical pixels)
pub(super) fn create(
    raw_handle: raw_window_handle::RawWindowHandle,
    initial_url: Option<String>,
    initial_html: Option<String>,
    content_x: f64,
    content_y: f64,
    content_w: f64,
    content_h: f64,
) {
    let borrow = HandleBorrow(raw_handle);

    let mut builder = WebViewBuilder::new()
        .with_bounds(Rect {
            position: LogicalPosition::new(content_x, content_y).into(),
            size: LogicalSize::new(content_w, content_h).into(),
        })
        // Use a proper Safari UA so that sites (e.g. GitHub) recognise this as
        // a full-capability WebKit browser and enable passkeys / WebAuthn fully.
        // WKWebView's default UA omits the trailing "Safari/NNN" token which
        // causes detection scripts to classify it as a limited embedded context.
        .with_user_agent(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
             AppleWebKit/605.1.15 (KHTML, like Gecko) \
             Version/17.6 Safari/605.1.15"
        )
        .with_clipboard(true)
        .with_back_forward_navigation_gestures(true)
        .with_initialization_script(KEYBOARD_INIT_SCRIPT)
        .with_initialization_script(CONTEXT_MENU_INIT_SCRIPT)
        .with_ipc_handler(|req: wry::http::Request<String>| {
            let body = req.into_body();
            push_event(BrowserEvent::Ipc(body));
        })
        .with_on_page_load_handler(|event, url| match event {
            PageLoadEvent::Started  => push_event(BrowserEvent::PageStarted(url)),
            PageLoadEvent::Finished => push_event(BrowserEvent::PageFinished(url)),
        })
        .with_document_title_changed_handler(|title| {
            push_event(BrowserEvent::TitleChanged(title));
        });

    // ── Persistent cookie / session storage (macOS >= 14 / iOS >= 17) ─────
    // WKWebView's default data store is ephemeral (in-memory only), which
    // means every restart requires the user to log in to websites again.
    // Passing a fixed 16-byte identifier creates a named persistent
    // WKWebsiteDataStore that survives across launches.  The identifier below
    // is fixed for this application so all windows share the same store.
    //
    // Identifier bytes: "tkzbrowser00001" (16 bytes, RFC 4122 v4 style UUID slot)
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        builder = builder.with_data_store_identifier([
            0x74, 0x6b, 0x7a, 0x62, 0x72, 0x6f, 0x77, 0x73,
            0x65, 0x72, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
        ]);
    }

    if let Some(html) = initial_html {
        builder = builder.with_html(html);
    } else if let Some(url) = initial_url {
        builder = builder.with_url(url);
    }

    // ── Download handlers ────────────────────────────────────────────────
    builder = builder.with_download_started_handler(|url: String, dest: &mut std::path::PathBuf| -> bool {
        // Rename "video.mp4" → "video.mp4.tkz" so the partial file cannot
        // be accidentally opened while the download is in progress.
        let final_dest = dest.clone();
        let temp_name = dest
            .file_name()
            .map(|n| format!("{}.tkz", n.to_string_lossy()))
            .unwrap_or_else(|| "download.tkz".to_string());
        let temp_dest = dest.with_file_name(temp_name);
        *dest = temp_dest.clone();
        push_event(BrowserEvent::DownloadStarted(url, temp_dest, final_dest));
        // Return false to cancel WebKit's built-in download; our parallel
        // reqwest engine in `downloader.rs` handles the actual transfer.
        // NOTE: We do NOT register a download_completed_handler — when we
        // return false here WebKit fires its completion callback immediately
        // with success=false, which would kill our reqwest download.
        false
    });

    match builder.build_as_child(&borrow) {
        Ok(wv) => WEBVIEW.with(|cell| *cell.borrow_mut() = Some(wv)),
        Err(e) => eprintln!("[browser] WebView creation failed: {e}"),
    }
}

// ── navigation helpers ───────────────────────────────────────────────────────

pub(super) fn navigate(url: &str) {
    WEBVIEW.with(|cell| {
        if let Some(wv) = cell.borrow().as_ref() {
            if let Err(e) = wv.load_url(url) {
                eprintln!("[browser] navigate error: {e}");
            }
        }
    });
}

pub(super) fn load_html(html: &str) {
    WEBVIEW.with(|cell| {
        if let Some(wv) = cell.borrow().as_ref() {
            if let Err(e) = wv.load_html(html) {
                eprintln!("[browser] load_html error: {e}");
            }
        }
    });
}

#[allow(dead_code)]
pub(super) fn back() {
    WEBVIEW.with(|cell| {
        if let Some(wv) = cell.borrow().as_ref() {
            let _ = wv.evaluate_script("window.history.back()");
        }
    });
}

#[allow(dead_code)]
pub(super) fn forward() {
    WEBVIEW.with(|cell| {
        if let Some(wv) = cell.borrow().as_ref() {
            let _ = wv.evaluate_script("window.history.forward()");
        }
    });
}

pub(super) fn reload() {
    WEBVIEW.with(|cell| {
        if let Some(wv) = cell.borrow().as_ref() {
            let _ = wv.reload();
        }
    });
}

/// Update the WebView bounds when the window resizes.
pub(super) fn set_bounds(x: f64, y: f64, w: f64, h: f64) {
    WEBVIEW.with(|cell| {
        if let Some(wv) = cell.borrow().as_ref() {
            let _ = wv.set_bounds(Rect {
                position: LogicalPosition::new(x, y).into(),
                size: LogicalSize::new(w, h).into(),
            });
        }
    });
}

/// Evaluate arbitrary JavaScript in the WebView context.
///
/// Used to push data (e.g. updated quick links) to the currently open page.
pub(super) fn eval_script(js: &str) {
    WEBVIEW.with(|cell| {
        if let Some(wv) = cell.borrow().as_ref() {
            let _ = wv.evaluate_script(js);
        }
    });
}
