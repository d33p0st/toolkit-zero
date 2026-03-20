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

/// Injected into every page so that:
///   1. Cmd/Ctrl + C/V/X/A/Z/Y work for clipboard / editing within the page.
///   2. Global browser shortcuts (Cmd+T, Cmd+W, …) are forwarded back to iced
///      via window.ipc.postMessage so they work even when the WKWebView has
///      focus (which prevents iced's own key-event subscription from firing).
const KEYBOARD_INIT_SCRIPT: &str = r#"
(function() {
  document.addEventListener('keydown', function(e) {
    var ctrl = e.ctrlKey || e.metaKey;

    // ── In-page editing shortcuts (handled locally, not forwarded) ───────────
    if (ctrl && !e.shiftKey) {
      switch (e.key.toLowerCase()) {
        case 'c': document.execCommand('copy');      e.preventDefault(); return;
        case 'x': document.execCommand('cut');       e.preventDefault(); return;
        case 'v': document.execCommand('paste');     e.preventDefault(); return;
        case 'a': document.execCommand('selectAll'); e.preventDefault(); return;
        case 'z': document.execCommand('undo');      e.preventDefault(); return;
      }
    }
    if (ctrl && e.shiftKey && e.key.toLowerCase() === 'z') {
      document.execCommand('redo'); e.preventDefault(); return;
    }
    if (ctrl && e.key === 'y') {
      document.execCommand('redo'); e.preventDefault(); return;
    }

    // ── Browser-level shortcuts — forward to iced via IPC ────────────────────
    if (!ctrl && e.key !== 'Escape' && e.key !== 'F5') return;

    var action = null;
    if (ctrl) {
      var k = e.key.toLowerCase();
      if (!e.shiftKey) {
        switch (k) {
          case 't': action = 'new_tab';           break;
          case 'w': action = 'close_tab';         break;
          case 'r': action = 'reload';            break;
          case 'l': action = 'focus_address_bar'; break;
          case '[': action = 'back';              break;
          case ']': action = 'forward';           break;
          case '-': action = 'zoom_out';          break;
          case '=':
          case '+': action = 'zoom_in';           break;
          case '0': action = 'zoom_reset';        break;
          case 'f': action = 'find';              break;
        }
      } else {
        switch (k) {
          case 's': action = 'screenshot';        break;
          case 'm': action = 'spatial_map';       break;
          case 'v': action = 'vault_fill';        break;
        }
      }
    } else if (e.key === 'F5') {
      action = 'reload';
    } else if (e.key === 'Escape') {
      action = 'close_find';
    }

    if (action) {
      e.preventDefault();
      e.stopPropagation();
      window.ipc.postMessage(JSON.stringify({type:'shortcut', action: action}));
    }
  }, true);
})();
"#;

/// Init script that injects a custom context-menu item on every non-homepage
/// page: "Add to Quick Links" and "Open in New Tab".
const CONTEXT_MENU_INIT_SCRIPT: &str = r#"
(function() {
  // Remove the native context menu and replace with a minimal one that
  // includes our "Add to Quick Links" action.
  document.addEventListener('contextmenu', function(e) {
    // Only add the custom menu item when we are NOT on the homepage.
    if (window.location.protocol === 'about:' || window.__TKZ_HOME__) return;
    e.preventDefault();
    e.stopPropagation();
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

    // Determine if the right-click target is a link.
    var linkEl = e.target;
    while (linkEl && linkEl.tagName !== 'A') linkEl = linkEl.parentElement;
    var linkUrl = linkEl ? (linkEl.href || '') : '';

    function makeItem(label, onclick) {
      var item = document.createElement('div');
      item.textContent = label;
      item.style.cssText = 'padding:7px 14px;cursor:pointer;';
      item.onmouseenter = function() { item.style.background='rgba(120,0,255,.18)'; };
      item.onmouseleave = function() { item.style.background=''; };
      item.onclick = function() { onclick(); menu.remove(); };
      return item;
    }

    menu.appendChild(makeItem('⚡ Add to Quick Links', function() {
      window.ipc.postMessage(JSON.stringify({type:'add_quicklink',url:url,title:title}));
    }));

    if (linkUrl) {
      menu.appendChild(makeItem('⬡ Open in New Tab', function() {
        window.ipc.postMessage(JSON.stringify({type:'open_in_new_tab',url:linkUrl}));
      }));
    }

    document.body.appendChild(menu);

    // Dismiss on any outside click.
    var dismiss = function(ev) {
      if (!menu.contains(ev.target)) { menu.remove(); document.removeEventListener('mousedown', dismiss, true); }
    };
    document.addEventListener('mousedown', dismiss, true);
  });
})();
"#;

/// Init script that polyfills the Fullscreen API for WKWebView contexts.
///
/// WKWebView disables `Element.requestFullscreen()` by default.  This script:
///   1. Falls back to the webkit-prefixed variants so sites like Netflix work.
///   2. Notifies the Rust side via IPC so we can adjust the WebView bounds and
///      call `WebView::set_fullscreen()` to invoke the OS-level fullscreen mode.
const FULLSCREEN_INIT_SCRIPT: &str = r#"
(function() {
  // -- event-driven fullscreen bridge for WKWebView -----------------------
  // We report enter/exit ONLY when the fullscreen change event fires and we
  // can confirm the state, which avoids false "exit" flashes when a video
  // player like Netflix requests fullscreen and WKWebView actually accepts it.

  var _origReqFS = HTMLElement.prototype.requestFullscreen;
  HTMLElement.prototype.requestFullscreen = function(options) {
    var el = this;
    if (_origReqFS) {
      try {
        var p = _origReqFS.call(el, options);
        if (p && typeof p.then === 'function') {
          p.catch(function() { _tryWebkit(el); });
          return p;
        }
      } catch(e) {}
    }
    _tryWebkit(el);
    return Promise.resolve();
  };

  function _tryWebkit(el) {
    if (el.webkitRequestFullscreen) el.webkitRequestFullscreen();
    else if (el.webkitRequestFullScreen) el.webkitRequestFullScreen();
  }

  // Report enter/exit based purely on whether an element is fullscreen.
  function _reportFS() {
    var active = !!(document.fullscreenElement || document.webkitFullscreenElement);
    window.ipc.postMessage(JSON.stringify({
      type: active ? 'enter_fullscreen' : 'exit_fullscreen'
    }));
  }

  document.addEventListener('fullscreenchange',       _reportFS);
  document.addEventListener('webkitfullscreenchange', _reportFS);

  // exitFullscreen polyfill
  document.exitFullscreen = function() {
    if (document.webkitExitFullscreen) { try { document.webkitExitFullscreen(); } catch(e) {} }
    return Promise.resolve();
  };

  // Escape key – WKWebView may not fire this natively.
  document.addEventListener('keydown', function(e) {
    if ((e.key === 'Escape' || e.key === 'Esc') &&
        (document.fullscreenElement || document.webkitFullscreenElement)) {
      window.ipc.postMessage(JSON.stringify({type:'exit_fullscreen'}));
    }
  });
})();
"#;

/// Init script that intercepts clicks on <a download href="blob:…"> / <a download href="data:…">
/// links, reads the binary data using fetch(), base64-encodes it, and forwards
/// it via IPC as a `blob_download` message so our Rust code can write the file
/// to the Downloads folder and track it in the downloads panel.
///
/// Without this, blob: URL downloads fail because reqwest cannot access
/// the browser's in-memory blob store.
const BLOB_DOWNLOAD_SCRIPT: &str = r#"
(function() {
  function tryBlobDownload(link) {
    var href = link.href;
    if (!href) return false;
    if (!href.startsWith('blob:') && !href.startsWith('data:')) return false;
    var filename = (link.getAttribute('download') || 'download').replace(/[\/\\\0]/g, '_');
    if (!filename) filename = 'download';
    fetch(href)
      .then(function(r) { return r.arrayBuffer(); })
      .then(function(buf) {
        var bytes = new Uint8Array(buf);
        // Build base64 in 8 KiB chunks to avoid stack overflow on large files.
        var CHUNK = 8192;
        var parts = [];
        for (var i = 0; i < bytes.length; i += CHUNK) {
          parts.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK)));
        }
        window.ipc.postMessage(JSON.stringify({
          type: 'blob_download',
          filename: filename,
          data: btoa(parts.join(''))
        }));
      })
      .catch(function(err) {
        console.error('[browser] blob download IPC failed:', err);
      });
    return true;
  }

  document.addEventListener('click', function(e) {
    // Walk up the DOM tree to find the nearest anchor element.
    var el = e.target;
    while (el && el.nodeName !== 'A') el = el.parentElement;
    if (!el || !el.hasAttribute('download')) return;
    if (tryBlobDownload(el)) {
      e.preventDefault();
      e.stopPropagation();
    }
  }, true);
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
        .with_initialization_script(FULLSCREEN_INIT_SCRIPT)
        .with_initialization_script(BLOB_DOWNLOAD_SCRIPT)
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
        // blob: and data: URLs are handled by the BLOB_DOWNLOAD_SCRIPT JS
        // interceptor which reads the binary data in-page and forwards it via
        // IPC. For any other non-HTTP URL we have no way to fetch it, so let
        // WebKit handle it natively (returns true = allow WebKit download).
        if !url.starts_with("http://") && !url.starts_with("https://") {
            // Leave *dest untouched so WebKit uses its own suggested path.
            return true;
        }

        // HTTP/HTTPS: cancel WebKit's built-in download; our parallel reqwest
        // engine in `downloader.rs` handles the actual transfer.
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

/// Engage or disengage OS-level fullscreen for the WebView.
///
/// On macOS this moves the window into its own fullscreen Space (same as
/// pressing the green traffic-light button), which gives the web content the
/// full display area.  On other platforms wry routes this to the native
/// fullscreen primitive.
pub(super) fn set_fullscreen(_fullscreen: bool) {
    // wry 0.54 does not expose set_fullscreen on WebView.
    // Fullscreen is handled by expanding/restoring the webview bounds
    // via set_bounds() in app.rs, combined with the JS polyfill that
    // calls the webkit-prefixed requestFullscreen API.
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

/// Set the page zoom level.  `1.0` = 100 %, range is roughly 0.3 – 3.0.
///
/// Uses the CSS `zoom` property on `:root`, which is non-standard but
/// universally supported in WebKit (WKWebView / Safari).
pub(super) fn set_zoom(level: f32) {
    eval_script(&format!(
        "document.documentElement.style.zoom = '{:.2}';",
        level
    ));
}

/// Find (and scroll to) the next or previous occurrence of `query` in the page.
///
/// Delegates to `window.find()` which, despite being non-standard, is fully
/// supported in WebKit/WKWebView and Blink.  Successive calls step through
/// matches; `backwards = true` moves to the previous match.
pub(super) fn find_text(query: &str, backwards: bool) {
    // Escape characters that would break the JS string literal.
    let escaped = query.replace('\\', "\\\\").replace('\'', "\\'");
    if escaped.is_empty() {
        if_let_webview(|wv| {
            let _ = wv.evaluate_script(
                "if(window.getSelection)window.getSelection().removeAllRanges();"
            );
        });
    } else {
        // window.find(string, caseSensitive, backwards, wrapAround,
        //             wholeWord, searchInFrames, showDialog)
        eval_script(&format!(
            "window.find('{}',false,{},true,false,true,false);",
            escaped, backwards,
        ));
    }
}

/// Remove the active find highlight / selection from the page.
pub(super) fn clear_find() {
    eval_script("if(window.getSelection)window.getSelection().removeAllRanges();");
}

/// Inject a CSS stylesheet for the current page.
///
/// The CSS is injected into the `<head>` via a dynamically created `<style>`
/// element tagged with `data-tkz-userstyle` so it can be de-duped on
/// subsequent calls for the same host.
pub(super) fn inject_userstyle(css: &str) {
    // Escape backticks and backslashes so the CSS can be passed inside a JS
    // template literal safely.
    let escaped = css.replace('\\', "\\\\").replace('`', "\\`");
    eval_script(&format!(
        "(function(){{ \
           var prev=document.querySelector('[data-tkz-userstyle]');\
           if(prev)prev.remove();\
           var s=document.createElement('style');\
           s.setAttribute('data-tkz-userstyle','1');\
           s.textContent=`{escaped}`;\
           (document.head||document.documentElement).appendChild(s);\
        }})();"
    ));
}

/// Trigger an interactive macOS area-select screenshot.
///
/// Launches `screencapture -i -x <dest>` in a background thread so the UI
/// remains responsive while the user drags the crosshair. The result PNG is
/// saved to `dest_path` (should be an absolute path on the Desktop).
pub(super) fn take_screenshot(dest_path: &str) {
    let path = dest_path.to_string();
    std::thread::spawn(move || {
        let _ = std::process::Command::new("screencapture")
            .args(["-i", "-x", &path])
            .status();
    });
}

// Shared helper so we don't repeat the borrow pattern everywhere.
#[inline]
fn if_let_webview(f: impl FnOnce(&WebView)) {
    WEBVIEW.with(|cell| {
        if let Some(wv) = cell.borrow().as_ref() {
            f(wv);
        }
    });
}
