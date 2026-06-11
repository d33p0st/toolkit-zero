//! iced application state, update, view and subscription for the browser.

use std::time::{Duration, Instant};

use iced::
    {Color, Element, Length, Point, Radians, Rectangle, Size, Subscription, Task, Theme,
    alignment,
    widget::{
        Button, Canvas, Column, Container, PickList, ProgressBar, Row, Scrollable, Slider,
        Space, Stack, Text, TextInput,
        button, container, progress_bar, text_input,
    },
    window,
};
use iced::widget::canvas::{self, Frame, Geometry, Path, Stroke};

use super::{
    BrowserEvent, Target,
    history,
    loader::BorderTrace,
    quicklinks,
    tab::{Tab, TabGroup, VerticalTabBar, GROUP_COLORS, PANEL_COLLAPSED_W, PANEL_EXPANDED_W},
    urlencoding,
    webview,
};

// ── reduce the visual height for a thin strip feel
const ADDR_BAR_H: f32 = 38.0;
pub const CHROME_H: f32 = ADDR_BAR_H;
const INSET: f32 = 1.5;
const LOAD_SPEED: f32 = 0.007;
const PANEL_SPEED: f32 = 14.0;

#[derive(Debug, Clone)]
pub enum Message {
    AddressChanged(String),
    Navigate,
    Back,
    Forward,
    Reload,
    NewTab,
    CloseTab(usize),
    SelectTab(usize),
    TabsHovered(bool),
    ToggleHistory,
    DeleteAllHistory,
    DeleteHistoryRange(u64),
    NavigateHistory(String),
    /// Async history load result.
    HistoryLoaded(Vec<history::HistoryEntry>),
    /// IPC message received from the WebView.
    IpcReceived(String),
    WindowOpened(window::Id),
    WindowResized(window::Id, Size),
    WebViewReady,
    PageStarted(String),
    PageFinished(String),
    TitleChanged(String),
    Tick(Instant),
    // ── tab groups ─────────────────────────────────────────────
    /// Create a new group containing the current active tab.
    CreateTabGroup,
    /// Cycle the tab at `idx` through all groups (right-click).
    CycleTabGroup(usize),
    /// Directly assign tab `idx` to `group_id` (None = ungroup).
    SetTabGroup(usize, Option<u64>),
    /// Delete a group; its members become ungrouped.
    DeleteTabGroup(u64),
    /// Begin inline rename of a group.
    BeginRenameGroup(u64),
    GroupRenameChanged(String),
    CommitGroupRename,
    /// Cycle through Light → Dark → Auto.
    CycleTheme,
    /// Toggle whether visited pages are appended to `history.hist`.
    ToggleHistoryRecording,
    /// Toggle the downloads side-panel.
    ToggleDownloads,
    /// Notify that a file download has started (url, temp path with .tkz, final path).
    DownloadStarted(String, std::path::PathBuf, std::path::PathBuf),
    /// Notify that a file download finished (success/failure).
    DownloadCompleted(String, bool),
    /// Clear completed/failed downloads from the list.
    ClearDoneDownloads,
    /// History deletion slider value changed.
    HistorySliderChanged(f32),
    /// History deletion time-unit (dropdown) changed.
    HistoryUnitChanged(TimeUnit),
    /// Delete history entries within the selected range.
    DeleteHistoryByUnit,
    /// Cancel an in-progress download and delete its partial `.tkz` file.
    CancelDownload(u64),
    /// Open a completed download with the system default application.
    OpenDownloadedFile(u64),
    /// Reveal a download in the system file manager.
    RevealDownload(u64),
    /// Progress update from the parallel downloader (id, bytes, total).
    DownloadProgress(u64, u64, Option<u64>),
    /// Download completed successfully (id); temp file already renamed.
    DownloadFinished(u64),
    /// Download failed (id).
    DownloadFailed(u64),
    // ── new UX features ──────────────────────────────────────────────────────
    /// Close the currently-active tab (Cmd+W shortcut path).
    CloseCurrentTab,
    /// Focus and select-all in the address bar (Cmd+L).
    FocusAddressBar,
    /// Zoom into the current page (Cmd++ / Cmd+=).
    ZoomIn,
    /// Zoom out of the current page (Cmd+-).
    ZoomOut,
    /// Reset page zoom to 100 % (Cmd+0).
    ZoomReset,
    /// Toggle the find-in-page toolbar (Cmd+F).
    ToggleFindBar,
    /// The find-query string changed.
    FindQueryChanged(String),
    /// Jump to the next find match.
    FindNext,
    /// Jump to the previous find match.
    FindPrev,
    /// Close the find toolbar and clear the active highlight.
    CloseFind,
    /// Navigate to a URL chosen from the address-bar autocomplete list.
    AutocompleteSelected(String),
    /// Dismiss the autocomplete dropdown without navigating.
    AutocompleteDismiss,
    /// Web content entered fullscreen (Netflix, YouTube, etc.).
    EnterFullscreen,
    /// Web content exited fullscreen.
    ExitFullscreen,
    // ── tab group redesign ─────────────────────────────────────────────────────
    /// Toggle collapsed/expanded state of a group in the tab panel.
    ToggleCollapseGroup(u64),
    /// Move the group with `group_id` to `new_index` in the groups Vec.
    MoveGroupToIndex(u64, usize),
    /// Move the tab at `from_idx` to `to_idx` (drag reorder) in the tabs Vec.
    ReorderTab(usize, usize),
    // ── Feature 10: smart auto-grouping ───────────────────────────────────────
    /// Open a URL in a new tab, inheriting the group of the current active tab.
    OpenInNewTab(String),
    // ── Feature 4: tab suspension ─────────────────────────────────────────────
    /// Suspend (hibernate) the background tab at `idx` to free resources.
    SuspendTab(usize),
    // ── Feature 7: screenshot ─────────────────────────────────────────────────
    /// Trigger the interactive macOS screenshot picker and save to Desktop.
    TakeScreenshot,
    // ── Feature 5: spatial tab map ────────────────────────────────────────────
    /// Toggle the force-directed spatial tab map overlay.
    ToggleSpatialMap,
    /// Drag a node in the spatial map — move tab `idx` by `(dx, dy)`.
    SpatialMoveNode(usize, f32, f32),
    /// Select a tab from the spatial map overlay.
    SpatialTabSelected(usize),

    // ── Credential vault ──────────────────────────────────────────────────────
    /// Open the vault panel.
    OpenVaultPanel,
    /// Close the vault panel (vault remains unlocked in memory).
    CloseVaultPanel,
    /// User is typing the master password.
    VaultPasswordChanged(String),
    /// Unlock (or create) the vault with the current `vault_password_draft`.
    VaultUnlock,
    /// Lock the vault, clearing in-memory key and entries.
    VaultLock,
    /// Add or update an entry: (domain, username, password).
    VaultUpsert(String, String, String),
    /// Delete an entry: (domain, username).
    VaultDelete(String, String),
    /// Inject credentials for the current page's domain.
    VaultFillPage,
    /// Toggle the "Actions" dropdown menu in the toolbar.
    ToggleActionsMenu,
    /// Add the currently-active page to Quick Links (from the Actions menu).
    AddQuickLink,
}

/// Determines which visual theme the browser uses.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThemeMode {
    /// Always use a light palette.
    Light,
    /// Always use a dark palette.
    Dark,
    /// Light 07:00–19:00 local time, dark otherwise.
    Auto,
}

/// Time unit for history deletion range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeUnit {
    Seconds,
    Minutes,
    Hours,
    Days,
    Months,
    Years,
}

impl std::fmt::Display for TimeUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimeUnit::Seconds => write!(f, "seconds"),
            TimeUnit::Minutes => write!(f, "minutes"),
            TimeUnit::Hours   => write!(f, "hours"),
            TimeUnit::Days    => write!(f, "days"),
            TimeUnit::Months  => write!(f, "months"),
            TimeUnit::Years   => write!(f, "years"),
        }
    }
}

const TIME_UNITS: &[TimeUnit] = &[
    TimeUnit::Seconds,
    TimeUnit::Minutes,
    TimeUnit::Hours,
    TimeUnit::Days,
    TimeUnit::Months,
    TimeUnit::Years,
];

// ── Download ring canvas widget ───────────────────────────────────────────────

/// Small circular-ring widget rendered in the address bar as the download button.
///
/// When downloads are active it shows a spinning blue arc.  
/// When all downloads are done (but not yet cleared) it shows a solid green ring.  
/// When idle it shows a thin gray ring with a ↓ glyph in the centre.
struct DownloadRing {
    /// Number of downloads currently in progress.
    active: usize,
    /// Number of completed-but-not-cleared downloads.
    done: usize,
    /// Animation phase (radians) advancing each Tick while downloads are active.
    phase: f32,
    dark: bool,
}

impl canvas::Program<Message> for DownloadRing {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &iced::Renderer,
        _theme: &iced::Theme,
        bounds: Rectangle,
        _cursor: iced::mouse::Cursor,
    ) -> Vec<Geometry<iced::Renderer>> {
        use std::f32::consts::PI;

        let mut frame = Frame::new(renderer, bounds.size());
        let sz = bounds.size();
        let center = Point::new(sz.width / 2.0, sz.height / 2.0);
        let radius = (sz.width.min(sz.height) / 2.0 - 2.5).max(2.0);

        // ── Background ring ───────────────────────────────────────────────
        let bg = if self.dark {
            Color::from_rgba(1.0, 1.0, 1.0, 0.18)
        } else {
            Color::from_rgba(0.0, 0.0, 0.0, 0.18)
        };
        frame.stroke(
            &Path::new(|b| b.arc(canvas::path::Arc {
                center,
                radius,
                start_angle: Radians(0.0),
                end_angle: Radians(2.0 * PI),
            })),
            Stroke::default().with_color(bg).with_width(2.0),
        );

        // ── Foreground arc / ring ─────────────────────────────────────────
        if self.active > 0 {
            // Spinning indeterminate arc ≈ 100°
            let span = PI * 0.56;
            frame.stroke(
                &Path::new(|b| b.arc(canvas::path::Arc {
                    center,
                    radius,
                    start_angle: Radians(self.phase),
                    end_angle:   Radians(self.phase + span),
                })),
                Stroke::default()
                    .with_color(Color::from_rgb(0.15, 0.55, 1.0))
                    .with_width(2.0),
            );
            // Count badge
            frame.fill_text(canvas::Text {
                content: format!("{}", self.active),
                position: Point::new(sz.width / 2.0 - 3.0, sz.height / 2.0 - 6.0),
                color: Color::from_rgb(0.15, 0.55, 1.0),
                size: iced::Pixels(10.0),
                ..canvas::Text::default()
            });
        } else if self.done > 0 {
            // Full green ring — all done
            frame.stroke(
                &Path::new(|b| b.arc(canvas::path::Arc {
                    center,
                    radius,
                    start_angle: Radians(-PI / 2.0),
                    end_angle:   Radians(-PI / 2.0 + 2.0 * PI),
                })),
                Stroke::default()
                    .with_color(Color::from_rgb(0.20, 0.78, 0.40))
                    .with_width(2.0),
            );
            let gc = if self.dark {
                Color::from_rgb(0.20, 0.78, 0.40)
            } else {
                Color::from_rgb(0.10, 0.60, 0.28)
            };
            frame.fill_text(canvas::Text {
                content: "\u{2713}".to_string(), // ✓
                position: Point::new(sz.width / 2.0 - 4.0, sz.height / 2.0 - 6.0),
                color: gc,
                size: iced::Pixels(10.0),
                ..canvas::Text::default()
            });
        } else {
            // Idle: ↓ glyph
            let ic = if self.dark {
                Color::from_rgba(0.60, 0.60, 0.70, 0.80)
            } else {
                Color::from_rgba(0.30, 0.30, 0.40, 0.80)
            };
            frame.fill_text(canvas::Text {
                content: "\u{2193}".to_string(), // ↓
                position: Point::new(sz.width / 2.0 - 3.5, sz.height / 2.0 - 6.0),
                color: ic,
                size: iced::Pixels(10.0),
                ..canvas::Text::default()
            });
        }

        vec![frame.into_geometry()]
    }
}

pub struct BrowserState {
    tabs: Vec<Tab>,
    active_tab: usize,
    address_input: String,
    window_size: Size,
    window_id: Option<window::Id>,
    is_loading: bool,
    load_progress: f32,
    load_alpha: f32,
    tabs_hovered: bool,
    tab_panel_w: f32,
    pending_target: Option<Target>,
    /// When `true`, the next `PageFinished` will NOT push to per-tab nav history
    /// (used for back/forward/reload/tab-switch where we initiate the navigation).
    suppress_next_push: bool,
    /// Whether the persistent history side-panel is visible.
    show_history: bool,
    /// Cached history entries shown in the panel (refreshed on open).
    history_entries: Vec<history::HistoryEntry>,
    /// Pending quicklinks injection into the active homepage tab.
    needs_quicklinks_inject: bool,
    /// All tab groups.
    tab_groups: Vec<TabGroup>,
    /// Monotonically increasing counter for group IDs.
    next_group_id: u64,
    /// Group currently being renamed (shows the rename overlay).
    renaming_group: Option<u64>,
    /// Text buffer for the rename input.
    group_rename_text: String,
    /// Current theme mode.
    theme_mode: ThemeMode,
    /// Whether page visits are recorded in the persistent history file.
    /// Does not affect the per-tab back/forward stack.
    history_recording: bool,
    /// Whether cookies/site-data survive across restarts (macOS only).
    /// Saved to disk for future UI; takes effect on the *next* app start.
    session_persistence_enabled: bool,
    /// Whether the downloads side-panel is open.
    show_downloads: bool,
    /// Active and recently completed downloads.
    downloads: Vec<super::downloads::DownloadEntry>,
    /// Sequential counter for assigning download IDs.
    next_download_id: u64,
    /// Slider value (1–100) for history deletion time range.
    history_delete_amount: f32,
    /// Unit for the history deletion slider.
    history_delete_unit: TimeUnit,
    /// Phase (radians) driving the animated download button pulse.
    download_anim_phase: f32,
    /// Tick counter used to rate-limit file-system polling to ~500 ms intervals.
    _poll_tick_counter: u32,
    /// Instant of the previous Tick, used to compute download speed per tick interval.
    last_tick: std::time::Instant,
    /// Tracks the last time each URL's download was started, used to debounce
    /// WKWebView double-fire events (which fire <50 ms apart) while still
    /// allowing genuine re-clicks of the same link.
    recent_download_starts: std::collections::HashMap<String, std::time::Instant>,
    /// When `Target::UrlFromHome` is used, holds the target URL while the
    /// homepage is loading. Once the homepage's `PageFinished` fires we
    /// navigate here so the webview back-stack contains the homepage.
    pending_url_after_home: Option<String>,
    /// Receiver for programmatic API commands from [`super::api::BrowserHandle`].
    /// `None` when the browser was launched without an API handle.
    api_rx: Option<tokio::sync::mpsc::UnboundedReceiver<super::api::ApiMessage>>,
    /// Current page zoom level.  1.0 = 100 %, range 0.3 – 3.0.
    zoom_level: f32,
    /// Whether the find-in-page toolbar is currently visible.
    find_bar_open: bool,
    /// The active text search query shown in the find toolbar.
    find_query: String,
    /// Whether the address-bar autocomplete dropdown is currently shown.
    autocomplete_visible: bool,
    /// Filtered history suggestions displayed in the autocomplete dropdown.
    autocomplete_suggestions: Vec<history::HistoryEntry>,
    /// All history entries kept in memory for instant autocomplete filtering.
    /// Loaded once at startup and updated as new pages are visited.
    history_cache: Vec<history::HistoryEntry>,
    /// Whether the webview is currently in OS-level fullscreen mode.
    /// When true the webview fills the entire window and the chrome is hidden.
    content_fullscreen: bool,
    /// Groups whose tab lists are currently collapsed in the panel.
    collapsed_groups: std::collections::HashSet<u64>,
    // ── Feature 5: spatial tab map ────────────────────────────────────────────
    /// Whether the spatial tab map overlay is visible.
    spatial_map_open: bool,
    /// (x, y) canvas positions for each tab node — parallel to `tabs`.
    /// Lazily initialised and updated by force-directed layout in `Tick`.
    node_positions: Vec<(f32, f32)>,
    // ── Credential vault ──────────────────────────────────────────────────────
    /// Unlocked vault (None when locked or not yet opened).
    vault: Option<super::vault::Vault>,
    /// Whether the vault panel is visible.
    vault_panel_open: bool,
    /// Staging area for the master-password input field.
    vault_password_draft: String,
    /// Last vault status message shown to the user.
    vault_status: String,
    /// Whether the "Actions" toolbar dropdown is currently open.
    actions_menu_open: bool,
}

impl BrowserState {
    pub fn new(target: Target) -> (Self, Task<Message>) {
        let initial_tab = match &target {
            Target::Default        => Tab::new_html(super::homepage_html_arc()),
            Target::Url(u)         => Tab::new(u.clone()),
            Target::File(p)        => Tab::new(format!("file://{}", p.display())),
            Target::Html(html)     => Tab::new_html(std::sync::Arc::from(html.as_str())),
            Target::UrlFromHome(u) => Tab::new(u.clone()),
        };
        let address_input = match &target {
            Target::Default        => String::new(),
            Target::Url(u)         => u.clone(),
            Target::File(p)        => format!("file://{}", p.display()),
            Target::Html(_)        => String::new(),
            Target::UrlFromHome(u) => u.clone(),
        };
        let saved = super::settings::load();
        let state = BrowserState {
            tabs: vec![initial_tab],
            active_tab: 0,
            address_input,
            window_size: Size::new(1280.0, 820.0),
            window_id: None,
            is_loading: false,
            load_progress: 0.0,
            load_alpha: 0.0,
            tabs_hovered: false,
            tab_panel_w: PANEL_COLLAPSED_W,
            pending_target: Some(target),
            suppress_next_push: false,
            show_history: false,
            history_entries: Vec::new(),
            needs_quicklinks_inject: false,
            tab_groups: Vec::new(),
            next_group_id: 0,
            renaming_group: None,
            group_rename_text: String::new(),
            theme_mode: ThemeMode::Auto,
            history_recording: saved.history_recording,
            session_persistence_enabled: saved.session_persistence,
            show_downloads: false,
            downloads: Vec::new(),
            next_download_id: 0,
            history_delete_amount: 24.0,
            history_delete_unit: TimeUnit::Hours,
            download_anim_phase: 0.0,
            _poll_tick_counter: 0,
            last_tick: std::time::Instant::now(),
            recent_download_starts: std::collections::HashMap::new(),
            pending_url_after_home: None,
            api_rx: super::api::take_receiver(),
            zoom_level: 1.0,
            find_bar_open: false,
            find_query: String::new(),
            autocomplete_visible: false,
            autocomplete_suggestions: Vec::new(),
            history_cache: history::load_history(),
            content_fullscreen: false,
            collapsed_groups: std::collections::HashSet::new(),
            spatial_map_open: false,
            node_positions: Vec::new(),
            vault: None,
            vault_panel_open: false,
            vault_password_draft: String::new(),
            vault_status: String::new(),
            actions_menu_open: false,
        };
        (state, Task::none())
    }
}

pub fn update(state: &mut BrowserState, message: Message) -> Task<Message> {
    match message {
        Message::AddressChanged(s) => {
            state.address_input = s.clone();
            if s.len() >= 2 {
                let lower = s.to_lowercase();
                state.autocomplete_suggestions = state.history_cache
                    .iter()
                    .rev() // most-recent-first
                    .filter(|e| {
                        e.url.to_lowercase().contains(&lower)
                            || e.title.to_lowercase().contains(&lower)
                    })
                    .take(8)
                    .cloned()
                    .collect();
                state.autocomplete_visible = !state.autocomplete_suggestions.is_empty();
            } else {
                state.autocomplete_visible = false;
                state.autocomplete_suggestions.clear();
            }
            Task::none()
        }
        Message::Navigate => {
            state.autocomplete_visible = false;
            state.autocomplete_suggestions.clear();
            if state.actions_menu_open {
                state.actions_menu_open = false;
                if !state.content_fullscreen {
                    let right_w = right_panel_w(state);
                    let (x, y, w, h) = content_bounds(
                        state.window_size, state.tab_panel_w, right_w, 0.0,
                    );
                    webview::set_bounds(x as f64, y as f64, w as f64, h as f64);
                }
            }
            let url = resolve_url(&state.address_input);
            navigate_current_tab(state, url);
            // Unfocus the address bar by focusing a nonexistent ID — the
            // operation traverses every focusable widget and calls unfocus()
            // on all that don't match, which means all of them.
            iced::widget::operation::focus::<Message>(iced::widget::Id::unique())
        }
        Message::Back => {
            if let Some(tab) = state.tabs.get_mut(state.active_tab) {
                if tab.can_go_back() {
                    tab.nav_pos -= 1;
                    let url = tab.nav_history[tab.nav_pos].clone();
                    tab.url = url.clone();
                    state.suppress_next_push = true;
                    if url == "tkz:home" {
                        webview::load_html(tab.home_html.as_deref().unwrap_or(super::HOMEPAGE_HTML));
                        state.address_input = String::new();
                        state.needs_quicklinks_inject = true;
                    } else {
                        state.address_input = url.clone();
                        webview::navigate(&url);
                    }
                }
            }
            iced::widget::operation::focus::<Message>(iced::widget::Id::unique())
        }
        Message::Forward => {
            if let Some(tab) = state.tabs.get_mut(state.active_tab) {
                if tab.can_go_forward() {
                    tab.nav_pos += 1;
                    let url = tab.nav_history[tab.nav_pos].clone();
                    tab.url = url.clone();
                    state.suppress_next_push = true;
                    if url == "tkz:home" {
                        webview::load_html(tab.home_html.as_deref().unwrap_or(super::HOMEPAGE_HTML));
                        state.address_input = String::new();
                        state.needs_quicklinks_inject = true;
                    } else {
                        state.address_input = url.clone();
                        webview::navigate(&url);
                    }
                }
            }
            iced::widget::operation::focus::<Message>(iced::widget::Id::unique())
        }
        Message::Reload  => {
            state.suppress_next_push = true;
            let tab = &state.tabs[state.active_tab];
            if tab.url == "tkz:home" || tab.home_html.is_some() {
                // WKWebView doesn't persist HTML loaded via load_html, so
                // direct reload would blank the page. Re-inject the HTML.
                webview::load_html(tab.home_html.as_deref().unwrap_or(super::HOMEPAGE_HTML));
                state.needs_quicklinks_inject = true;
            } else {
                webview::reload();
            }
            Task::none()
        }

        Message::TabsHovered(h) => {
            // Keep the panel expanded while a group rename is in progress so
            // the user can hover into the input box without the panel collapsing.
            if state.renaming_group.is_some() {
                state.tabs_hovered = true;
            } else {
                state.tabs_hovered = h;
            }
            Task::none()
        }

        Message::NewTab => {
            state.tabs.push(Tab::new_html(super::homepage_html_arc()));
            state.active_tab = state.tabs.len() - 1;
            state.address_input = String::new();
            state.needs_quicklinks_inject = true;
            webview::load_html(super::HOMEPAGE_HTML);
            Task::none()
        }
        Message::CloseTab(idx) => {
            if state.tabs.len() == 1 {
                return window::close(state.window_id.unwrap());
            }
            state.tabs.remove(idx);
            if state.active_tab >= state.tabs.len() {
                state.active_tab = state.tabs.len() - 1;
            }
            let (home_html, url) = {
                let tab = &state.tabs[state.active_tab];
                (tab.home_html.clone(), tab.url.clone())
            };
            state.suppress_next_push = true;
            if let Some(html) = &home_html {
                webview::load_html(html);
                state.address_input = String::new();
                state.needs_quicklinks_inject = true;
            } else {
                state.address_input = url.clone();
                webview::navigate(&url);
            }
            cleanup_empty_groups(state);
            Task::none()
        }
        Message::SelectTab(idx) => {
            if state.actions_menu_open {
                state.actions_menu_open = false;
                if !state.content_fullscreen {
                    let right_w = right_panel_w(state);
                    let (x, y, w, h) = content_bounds(
                        state.window_size, state.tab_panel_w, right_w, 0.0,
                    );
                    webview::set_bounds(x as f64, y as f64, w as f64, h as f64);
                }
            }
            // Record when the previously active tab is backgrounded.
            if let Some(prev) = state.tabs.get_mut(state.active_tab) {
                if state.active_tab != idx {
                    prev.last_active_time = Some(std::time::Instant::now());
                }
            }
            state.active_tab = idx;
            state.suppress_next_push = true;
            // Clear background-timer for the newly selected tab.
            if let Some(tab) = state.tabs.get_mut(idx) {
                tab.last_active_time = None;
            }
            let suspended = state.tabs.get(idx).map(|t| t.suspended).unwrap_or(false);
            if suspended {
                if let Some(tab) = state.tabs.get_mut(idx) {
                    tab.suspended = false;
                }
            }
            let (home_html, url) = {
                let tab = &state.tabs[idx];
                (tab.home_html.clone(), tab.url.clone())
            };
            if let Some(html) = &home_html {
                webview::load_html(html);
                state.address_input = String::new();
                state.needs_quicklinks_inject = true;
            } else {
                state.address_input = url.clone();
                webview::navigate(&url);
            }
            Task::none()
        }

        Message::WindowOpened(id) => {
            state.window_id = Some(id);

            // Restore any downloads that were in-flight when the browser last closed.
            for entry in super::stash::load_stash() {
                let dl_id = state.next_download_id;
                state.next_download_id += 1;
                let bytes_so_far = std::fs::metadata(&entry.temp_dest)
                    .ok()
                    .map(|m| m.len())
                    .unwrap_or(0);
                state.downloads.push(super::downloads::DownloadEntry {
                    id: dl_id,
                    url: entry.url.clone(),
                    filename: entry.filename.clone(),
                    temp_dest: entry.temp_dest.clone(),
                    final_dest: entry.final_dest.clone(),
                    bytes_downloaded: bytes_so_far,
                    total_bytes: None,
                    speed_bps: 0,
                    status: super::downloads::DownloadStatus::InProgress,
                });
                super::downloader::spawn_download(dl_id, entry.url, entry.temp_dest, entry.final_dest);
            }

            // Set macOS dock icon after NSApp is fully initialised.
            #[cfg(all(target_os = "macos", has_app_icon))]
            super::set_dock_icon();
            window::size(id)
                .then(move |actual_size| create_webview_task(id, actual_size, None, None))
                .map(|()| Message::WebViewReady)
        }
        Message::WindowResized(_, new_size) => {
            state.window_size = new_size;
            if state.content_fullscreen {
                // While in fullscreen the webview covers the entire window.
                webview::set_bounds(0.0, 0.0, new_size.width as f64, new_size.height as f64);
            } else {
                let right_w = right_panel_w(state);
                let (x, y, w, h) = content_bounds(new_size, state.tab_panel_w, right_w, actions_extra_h(state));
                webview::set_bounds(x as f64, y as f64, w as f64, h as f64);
            }
            Task::none()
        }
        Message::WebViewReady => {
            state.suppress_next_push = true;
            if let Some(target) = state.pending_target.take() {
                match &target {
                    Target::Default | Target::Html(_) => state.needs_quicklinks_inject = true,
                    _ => {}
                }
                match target {
                    Target::Default        => webview::load_html(super::HOMEPAGE_HTML),
                    Target::Url(url)       => webview::navigate(&url),
                    Target::File(path)     => webview::navigate(&format!("file://{}", path.display())),
                    Target::Html(html)     => webview::load_html(&html),
                    Target::UrlFromHome(url) => {
                        // Load the homepage first to seed the webview back-stack.
                        // Once the homepage's PageFinished fires we navigate to `url`.
                        webview::load_html(super::HOMEPAGE_HTML);
                        state.pending_url_after_home = Some(url);
                    }
                }
            }
            Task::none()
        }

        Message::PageStarted(url) => {
            state.is_loading = true;
            state.load_progress = 0.0;
            state.load_alpha = 1.0;
            if !url.is_empty() && url != "about:blank" {
                if let Some(tab) = state.tabs.get_mut(state.active_tab) {
                    tab.url = url.clone();
                }
                state.address_input = url;
            }
            // Unfocus the address bar when a page starts loading (e.g., link click in webview).
            iced::widget::operation::focus::<Message>(iced::widget::Id::unique())
        }
        Message::PageFinished(url) => {
            state.load_progress = 1.0;
            if !url.is_empty() && url != "about:blank" && !url.starts_with("tkz:") {
                let title = state.tabs.get(state.active_tab)
                    .map(|t| t.title.clone())
                    .unwrap_or_default();
                if state.suppress_next_push {
                    if let Some(tab) = state.tabs.get_mut(state.active_tab) {
                        tab.url = url.clone();
                        tab.home_html = None;
                    }
                } else {
                    if let Some(tab) = state.tabs.get_mut(state.active_tab) {
                        if tab.nav_history.get(tab.nav_pos) != Some(&url) {
                            tab.push_nav(url.clone());
                        }
                        tab.url = url.clone();
                        tab.home_html = None;
                    }
                    // Append synchronously — history.hist is a small append-only file;
                    // the write is a single buffered syscall (< 1 ms).
                    if state.history_recording {
                        history::append_entry(&title, &url);
                        // Keep the in-memory autocomplete cache in sync.
                        use std::time::{SystemTime, UNIX_EPOCH};
                        let ts = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        state.history_cache.push(super::history::HistoryEntry {
                            timestamp_ms: ts,
                            title: title.clone(),
                            url: url.clone(),
                        });
                    }
                }
                state.suppress_next_push = false;
                state.address_input = url.clone();
                // ── Feature 6: per-domain CSS injection ─────────────────────
                inject_userstyle_for_url(&url);
            } else {
                // about:blank or tkz: URL.
                if let Some(url) = state.pending_url_after_home.take() {
                    // Homepage finished loading — now navigate to the real target.
                    // The webview back-stack already has the homepage in it.
                    navigate_current_tab(state, url);
                } else if state.tabs.get(state.active_tab)
                    .map(|t| t.home_html.is_some() || t.url == "tkz:home")
                    .unwrap_or(false)
                {
                    // Normal home tab — inject quicklinks and theme.
                    inject_quicklinks();
                    inject_theme(effective_dark(state.theme_mode));
                }
                state.suppress_next_push = false;
            }
            Task::none()
        }
        Message::TitleChanged(title) => {
            if let Some(tab) = state.tabs.get_mut(state.active_tab) {
                tab.title = title;
            }
            Task::none()
        }

        Message::ToggleHistory => {
            state.show_downloads = false;
            state.show_history = !state.show_history;
            if state.show_history {
                state.history_entries = history::load_history();
            }
            // Shrink/restore webview so the iced history panel is not obscured
            // by the native OS webview layer sitting on top of iced.
            let right_w = right_panel_w(state);
            let (x, y, w, h) = content_bounds(state.window_size, state.tab_panel_w, right_w, actions_extra_h(state));
            webview::set_bounds(x as f64, y as f64, w as f64, h as f64);
            Task::none()
        }
        Message::HistoryLoaded(entries) => {
            state.history_entries = entries;
            Task::none()
        }
        Message::DeleteAllHistory => {
            history::delete_all();
            state.history_entries.clear();
            Task::none()
        }
        Message::DeleteHistoryRange(since_ms) => {
            state.history_entries = history::delete_since(since_ms);
            Task::none()
        }
        Message::NavigateHistory(url) => {
            state.show_history = false;
            state.show_downloads = false;
            // Restore full webview width when all panels close.
            let (x, y, w, h) = content_bounds(state.window_size, state.tab_panel_w, 0.0, actions_extra_h(state));
            webview::set_bounds(x as f64, y as f64, w as f64, h as f64);
            navigate_current_tab(state, url);
            Task::none()
        }

        Message::IpcReceived(msg) => {
            // Fast-path: fullscreen events are handled here without going
            // through handle_ipc() so we can return a Task.
            if msg.contains("\"enter_fullscreen\"") && !state.content_fullscreen {
                return Task::done(Message::EnterFullscreen);
            }
            if msg.contains("\"exit_fullscreen\"") && state.content_fullscreen {
                return Task::done(Message::ExitFullscreen);
            }
            // Blob/data-URL downloads forwarded from the in-page JS interceptor.
            // The bytes are base64-encoded in JS (where the blob store is
            // accessible) and written directly to ~/Downloads from here.
            if msg.contains("\"blob_download\"") {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&msg) {
                    if let (Some(raw_name), Some(b64)) = (
                        val["filename"].as_str(),
                        val["data"].as_str(),
                    ) {
                        use base64::Engine;
                        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                            // Sanitize filename.
                            let safe: String = raw_name.chars()
                                .filter(|c| !matches!(c, '/' | '\\' | '\0'))
                                .collect();
                            let safe = if safe.trim().is_empty() { "download".to_string() } else { safe };

                            let home = std::env::var("HOME").unwrap_or_default();
                            let downloads = std::path::PathBuf::from(home).join("Downloads");
                            let final_dest = unique_download_dest(&downloads.join(&safe), &state.downloads);

                            let id = state.next_download_id;
                            state.next_download_id += 1;
                            let name = final_dest.file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or(safe);
                            let size = bytes.len() as u64;

                            if let Ok(()) = std::fs::write(&final_dest, &bytes) {
                                state.downloads.push(super::downloads::DownloadEntry {
                                    id,
                                    url: String::from("blob:"),
                                    filename: name,
                                    temp_dest: final_dest.clone(),
                                    final_dest: final_dest.clone(),
                                    bytes_downloaded: size,
                                    total_bytes: Some(size),
                                    speed_bps: 0,
                                    status: super::downloads::DownloadStatus::Completed,
                                });
                                super::stash::save_stash(&state.downloads);
                            }
                        }
                    }
                }
                return Task::none();
            }
            // Global keyboard shortcuts forwarded from the webview JS.
            // The WKWebView captures all keyboard events when focused; this
            // IPC bridge re-emits them as Messages so shortcuts work everywhere.
            if msg.contains("\"shortcut\"") {
                let action = {
                    let needle = "\"action\":";
                    msg.find(needle).and_then(|p| {
                        let rest = msg[p + needle.len()..].trim_start();
                        if rest.starts_with('"') {
                            let inner = &rest[1..];
                            inner.find('"').map(|e| inner[..e].to_string())
                        } else { None }
                    })
                };
                return match action.as_deref() {
                    Some("new_tab")           => Task::done(Message::NewTab),
                    Some("close_tab")         => Task::done(Message::CloseCurrentTab),
                    Some("reload")            => Task::done(Message::Reload),
                    Some("focus_address_bar") => Task::done(Message::FocusAddressBar),
                    Some("back")              => Task::done(Message::Back),
                    Some("forward")           => Task::done(Message::Forward),
                    Some("zoom_in")           => Task::done(Message::ZoomIn),
                    Some("zoom_out")          => Task::done(Message::ZoomOut),
                    Some("zoom_reset")        => Task::done(Message::ZoomReset),
                    Some("find")              => Task::done(Message::ToggleFindBar),
                    Some("close_find")        => Task::done(Message::CloseFind),
                    Some("screenshot")        => Task::done(Message::TakeScreenshot),
                    Some("spatial_map")       => Task::done(Message::ToggleSpatialMap),
                    Some("vault_fill")        => Task::done(Message::VaultFillPage),
                    _ => Task::none(),
                };
            }
            handle_ipc(state, &msg);
            Task::none()
        }

        Message::CycleTheme => {
            state.theme_mode = match state.theme_mode {
                ThemeMode::Dark  => ThemeMode::Light,
                ThemeMode::Light => ThemeMode::Auto,
                ThemeMode::Auto  => ThemeMode::Dark,
            };
            inject_theme(effective_dark(state.theme_mode));
            Task::none()
        }

        Message::ToggleHistoryRecording => {
            state.history_recording = !state.history_recording;
            super::settings::save(&super::settings::BrowserSettings {
                history_recording:   state.history_recording,
                session_persistence: state.session_persistence_enabled,
            });
            Task::none()
        }

        Message::ToggleDownloads => {
            state.show_history = false;
            state.show_downloads = !state.show_downloads;
            let right_w = right_panel_w(state);
            let (x, y, w, h) = content_bounds(state.window_size, state.tab_panel_w, right_w, actions_extra_h(state));
            webview::set_bounds(x as f64, y as f64, w as f64, h as f64);
            Task::none()
        }

        Message::DownloadStarted(url, temp_dest, final_dest) => {
            // Debounce WKWebView double-fire: the same OS-level download intent
            // can fire the callback twice within ~50 ms. A genuine user re-click
            // always takes at least a few hundred ms, so 500 ms is a safe window.
            const DEBOUNCE_MS: u128 = 500;
            let is_double_fire = state
                .recent_download_starts
                .get(&url)
                .map(|t| t.elapsed().as_millis() < DEBOUNCE_MS)
                .unwrap_or(false);
            if is_double_fire {
                return Task::none();
            }
            state.recent_download_starts.insert(url.clone(), std::time::Instant::now());

            // Derive a unique final_dest by appending -2, -3, … to the stem
            // when a previous download (any status) already claimed this path
            // or the file already exists on disk.
            let unique_final = unique_download_dest(&final_dest, &state.downloads);
            let unique_temp = unique_final.with_file_name(
                format!(
                    "{}.tkz",
                    unique_final
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "download".to_string())
                )
            );

            let id = state.next_download_id;
            state.next_download_id += 1;
            let filename = unique_final
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| {
                    url.split('/').last().unwrap_or("download").to_string()
                });
            state.downloads.push(super::downloads::DownloadEntry {
                id,
                url: url.clone(),
                filename,
                temp_dest: unique_temp.clone(),
                final_dest: unique_final.clone(),
                bytes_downloaded: 0,
                total_bytes: None,
                speed_bps: 0,
                status: super::downloads::DownloadStatus::InProgress,
            });
            // Persist stash so the URL is remembered if the app closes.
            super::stash::save_stash(&state.downloads);
            // Spawn our parallel reqwest downloader instead of using WebKit's.
            super::downloader::spawn_download(id, url, unique_temp, unique_final);
            Task::none()
        }

        // DownloadCompleted is no longer emitted: we removed wry's
        // download_completed_handler because returning false from
        // download_started_handler causes WebKit to fire it immediately with
        // success=false, which would kill our reqwest download task. All
        // completion/failure signals now come from downloader::drain_progress().
        Message::DownloadCompleted(_url, _success) => Task::none(),

        Message::ClearDoneDownloads => {
            state.downloads.retain(|d| {
                d.status == super::downloads::DownloadStatus::InProgress
            });
            Task::none()
        }

        Message::CancelDownload(id) => {
            if let Some(dl) = state.downloads.iter_mut()
                .find(|d| d.id == id
                    && d.status == super::downloads::DownloadStatus::InProgress)
            {
                // Remove the partial .tkz file from disk.
                let _ = std::fs::remove_file(&dl.temp_dest);
                dl.status = super::downloads::DownloadStatus::Cancelled;
            }
            super::stash::save_stash(&state.downloads);
            Task::none()
        }

        Message::DownloadProgress(id, bytes, total) => {
            if let Some(dl) = state.downloads.iter_mut().find(|d| d.id == id) {
                dl.bytes_downloaded = bytes;
                if let Some(t) = total {
                    dl.total_bytes = Some(t);
                }
            }
            Task::none()
        }

        Message::DownloadFinished(id) => {
            if let Some(dl) = state.downloads.iter_mut().find(|d| d.id == id) {
                // The downloader already renamed the temp file to final_dest.
                if let Ok(m) = std::fs::metadata(&dl.final_dest) {
                    dl.bytes_downloaded = m.len();
                }
                dl.status = super::downloads::DownloadStatus::Completed;
            }
            super::stash::save_stash(&state.downloads);
            Task::none()
        }

        Message::DownloadFailed(id) => {
            if let Some(dl) = state.downloads.iter_mut().find(|d| d.id == id) {
                dl.status = super::downloads::DownloadStatus::Failed;
            }
            super::stash::save_stash(&state.downloads);
            Task::none()
        }

        Message::OpenDownloadedFile(id) => {
            if let Some(dl) = state.downloads.iter()
                .find(|d| d.id == id
                    && d.status == super::downloads::DownloadStatus::Completed)
            {
                let path = dl.final_dest.clone();
                open_path_with_system(&path, false);
            }
            Task::none()
        }

        Message::RevealDownload(id) => {
            if let Some(dl) = state.downloads.iter()
                .find(|d| d.id == id)
            {
                let path = if dl.status == super::downloads::DownloadStatus::Completed {
                    dl.final_dest.clone()
                } else {
                    dl.temp_dest.clone()
                };
                open_path_with_system(&path, true);
            }
            Task::none()
        }

        Message::HistorySliderChanged(v) => {
            state.history_delete_amount = v;
            Task::none()
        }

        Message::HistoryUnitChanged(unit) => {
            state.history_delete_unit = unit;
            Task::none()
        }

        Message::DeleteHistoryByUnit => {
            let since_ms = ms_ago(state.history_delete_amount, state.history_delete_unit);
            state.history_entries = history::delete_since(since_ms);
            Task::none()
        }

        Message::CreateTabGroup => {
            let id = state.next_group_id;
            state.next_group_id += 1;
            let color_idx = id as usize % GROUP_COLORS.len();
            let default_name = format!("Group {}", id + 1);
            state.tab_groups.push(TabGroup { id, name: default_name.clone(), color_idx });
            if let Some(t) = state.tabs.get_mut(state.active_tab) {
                t.group_id = Some(id);
            }
            state.renaming_group = Some(id);
            state.group_rename_text = default_name;
            iced::widget::operation::focus::<Message>(iced::widget::Id::new("group_rename"))
        }

        Message::CycleTabGroup(tab_idx) => {
            if let Some(t) = state.tabs.get_mut(tab_idx) {
                t.group_id = match t.group_id {
                    None => state.tab_groups.first().map(|g| g.id),
                    Some(gid) => {
                        let pos = state.tab_groups.iter().position(|g| g.id == gid);
                        match pos {
                            Some(p) if p + 1 < state.tab_groups.len() => Some(state.tab_groups[p + 1].id),
                            _ => None,
                        }
                    }
                };
            }
            cleanup_empty_groups(state);
            Task::none()
        }

        Message::SetTabGroup(tab_idx, group_id) => {
            if let Some(t) = state.tabs.get_mut(tab_idx) {
                t.group_id = group_id;
            }
            cleanup_empty_groups(state);
            Task::none()
        }

        Message::DeleteTabGroup(gid) => {
            state.tab_groups.retain(|g| g.id != gid);
            for t in state.tabs.iter_mut() {
                if t.group_id == Some(gid) { t.group_id = None; }
            }
            Task::none()
        }

        Message::BeginRenameGroup(gid) => {
            let name = state.tab_groups.iter()
                .find(|g| g.id == gid)
                .map(|g| g.name.clone())
                .unwrap_or_default();
            state.renaming_group = Some(gid);
            state.group_rename_text = name;
            iced::widget::operation::focus::<Message>(iced::widget::Id::new("group_rename"))
        }

        Message::GroupRenameChanged(s) => {
            state.group_rename_text = s;
            Task::none()
        }

        Message::CommitGroupRename => {
            if let Some(gid) = state.renaming_group.take() {
                if state.group_rename_text.trim().is_empty() {
                    state.tab_groups.retain(|g| g.id != gid);
                    for t in state.tabs.iter_mut() {
                        if t.group_id == Some(gid) { t.group_id = None; }
                    }
                } else if let Some(g) = state.tab_groups.iter_mut().find(|g| g.id == gid) {
                    g.name = state.group_rename_text.trim().to_string();
                }
                state.group_rename_text.clear();
            }
            // Release panel hover lock now that rename is done.
            state.tabs_hovered = false;
            Task::none()
        }

        // ── new UX features ────────────────────────────────────────────────

        Message::CloseCurrentTab => {
            // Route through the existing CloseTab handler so all cleanup logic
            // (group prune, window close when last tab, etc.) fires correctly.
            Task::done(Message::CloseTab(state.active_tab))
        }

        Message::FocusAddressBar => {
            state.autocomplete_visible = false;
            state.autocomplete_suggestions.clear();
            iced::widget::operation::focus::<Message>(iced::widget::Id::new("addr_bar"))
        }

        Message::ZoomIn => {
            state.zoom_level = (state.zoom_level + 0.1).min(3.0);
            webview::set_zoom(state.zoom_level);
            Task::none()
        }
        Message::ZoomOut => {
            state.zoom_level = (state.zoom_level - 0.1).max(0.3);
            webview::set_zoom(state.zoom_level);
            Task::none()
        }
        Message::ZoomReset => {
            state.zoom_level = 1.0;
            webview::set_zoom(1.0);
            Task::none()
        }

        Message::ToggleFindBar => {
            state.find_bar_open = !state.find_bar_open;
            if !state.find_bar_open {
                state.find_query.clear();
                webview::clear_find();
                Task::none()
            } else {
                iced::widget::operation::focus::<Message>(iced::widget::Id::new("find_input"))
            }
        }
        Message::FindQueryChanged(q) => {
            state.find_query = q.clone();
            if q.is_empty() {
                webview::clear_find();
            } else {
                webview::find_text(&q, false);
            }
            Task::none()
        }
        Message::FindNext => {
            if !state.find_query.is_empty() {
                webview::find_text(&state.find_query, false);
            }
            Task::none()
        }
        Message::FindPrev => {
            if !state.find_query.is_empty() {
                webview::find_text(&state.find_query, true);
            }
            Task::none()
        }
        Message::CloseFind => {
            state.find_bar_open = false;
            state.find_query.clear();
            webview::clear_find();
            state.autocomplete_visible = false;
            state.autocomplete_suggestions.clear();
            // Escape also exits fullscreen (mirrors native browser behaviour).
            if state.content_fullscreen {
                return Task::done(Message::ExitFullscreen);
            }
            Task::none()
        }

        Message::AutocompleteSelected(raw_url) => {
            let url = resolve_url(&raw_url);
            state.address_input = url.clone();
            state.autocomplete_visible = false;
            state.autocomplete_suggestions.clear();
            navigate_current_tab(state, url);
            iced::widget::operation::focus::<Message>(iced::widget::Id::unique())
        }
        Message::AutocompleteDismiss => {
            state.autocomplete_visible = false;
            state.autocomplete_suggestions.clear();
            Task::none()
        }

        Message::EnterFullscreen => {
            state.content_fullscreen = true;
            // Expand the webview to cover the entire window (hides iced chrome).
            webview::set_bounds(
                0.0, 0.0,
                state.window_size.width as f64,
                state.window_size.height as f64,
            );
            webview::set_fullscreen(true);
            // Also put the OS window into true fullscreen mode.
            if let Some(wid) = state.window_id {
                window::set_mode(wid, window::Mode::Fullscreen)
            } else {
                Task::none()
            }
        }
        Message::ExitFullscreen => {
            state.content_fullscreen = false;
            webview::set_fullscreen(false);
            // Exit OS fullscreen first; bounds are corrected in the resize event
            // that fires once the window returns to its previous size.
            if let Some(wid) = state.window_id {
                window::set_mode(wid, window::Mode::Windowed)
            } else {
                Task::none()
            }
        }

        Message::ToggleCollapseGroup(gid) => {
            if state.collapsed_groups.contains(&gid) {
                state.collapsed_groups.remove(&gid);
            } else {
                state.collapsed_groups.insert(gid);
            }
            Task::none()
        }
        Message::MoveGroupToIndex(gid, new_idx) => {
            if let Some(pos) = state.tab_groups.iter().position(|g| g.id == gid) {
                let group = state.tab_groups.remove(pos);
                let insert_at = new_idx.min(state.tab_groups.len());
                state.tab_groups.insert(insert_at, group);
            }
            Task::none()
        }
        Message::ReorderTab(from_idx, to_idx) => {
            if from_idx != to_idx && from_idx < state.tabs.len() && to_idx <= state.tabs.len() {
                let tab = state.tabs.remove(from_idx);
                let insert_at = if to_idx > from_idx { to_idx - 1 } else { to_idx };
                state.tabs.insert(insert_at, tab);
                // Keep active_tab pointing at the same tab.
                if state.active_tab == from_idx {
                    state.active_tab = insert_at;
                } else if from_idx < state.active_tab && to_idx > state.active_tab {
                    state.active_tab -= 1;
                } else if from_idx > state.active_tab && to_idx <= state.active_tab {
                    state.active_tab += 1;
                }
            }
            Task::none()
        }

        // ── Feature 10: open in new tab with auto-grouping ─────────────────
        Message::OpenInNewTab(url) => {
            // Inherit the group of the tab that spawned this one.
            let parent_group = state.tabs.get(state.active_tab).and_then(|t| t.group_id);
            let parent_idx   = state.active_tab;
            let mut new_tab  = Tab::new(url.clone());
            new_tab.opened_from = Some(parent_idx);
            new_tab.group_id    = parent_group;
            state.tabs.push(new_tab);
            let new_idx = state.tabs.len() - 1;
            state.active_tab = new_idx;
            state.address_input = url.clone();
            state.suppress_next_push = false;
            // Set last_active_time on the previous tab immediately.
            if let Some(prev) = state.tabs.get_mut(parent_idx) {
                prev.last_active_time = Some(std::time::Instant::now());
            }
            webview::navigate(&url);
            Task::none()
        }

        // ── Feature 4: tab suspension ──────────────────────────────────────
        Message::SuspendTab(idx) => {
            if let Some(tab) = state.tabs.get_mut(idx) {
                tab.suspended = true;
            }
            Task::none()
        }

        // ── Feature 7: screenshot ──────────────────────────────────────────
        Message::TakeScreenshot => {
            let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
            let home = std::env::var("HOME").unwrap_or_default();
            let path = format!("{home}/Desktop/duct-tape-{ts}.png");
            webview::take_screenshot(&path);
            Task::none()
        }

        // ── Feature 5: spatial tab map ─────────────────────────────────────
        Message::ToggleSpatialMap => {
            state.spatial_map_open = !state.spatial_map_open;
            if state.spatial_map_open {
                // Initialise or resize the node_positions Vec to match tabs.
                reinit_spatial_positions(state);
                // The webview is a native OS window layer that always renders on
                // top of iced canvases.  Collapse it to nothing so the spatial
                // map overlay (an iced Canvas) is fully visible.
                webview::set_bounds(0.0, 0.0, 0.0, 0.0);
            } else {
                // Restore the webview to its normal content area.
                let right_w = right_panel_w(state);
                let (x, y, w, h) = content_bounds(state.window_size, state.tab_panel_w, right_w, actions_extra_h(state));
                webview::set_bounds(x as f64, y as f64, w as f64, h as f64);
            }
            Task::none()
        }
        Message::SpatialMoveNode(idx, dx, dy) => {
            if let Some(pos) = state.node_positions.get_mut(idx) {
                pos.0 = (pos.0 + dx).clamp(
                    super::tab::PANEL_COLLAPSED_W + super::tab::PANEL_EXPANDED_W + 40.0,
                    state.window_size.width  - 40.0,
                );
                pos.1 = (pos.1 + dy).clamp(40.0, state.window_size.height - 40.0);
            }
            Task::none()
        }
        Message::SpatialTabSelected(idx) => {
            // Close the map, restore the webview, and switch to the selected tab.
            state.spatial_map_open = false;
            let right_w = right_panel_w(state);
            let (x, y, w, h) = content_bounds(state.window_size, state.tab_panel_w, right_w, actions_extra_h(state));
            webview::set_bounds(x as f64, y as f64, w as f64, h as f64);
            if idx < state.tabs.len() {
                return Task::done(Message::SelectTab(idx));
            }
            Task::none()
        }

        // ── Credential vault ──────────────────────────────────────────────────
        Message::OpenVaultPanel => {
            state.vault_panel_open = true;
            state.show_history = false;
            state.show_downloads = false;
            let right_w = right_panel_w(state);
            let (x, y, w, h) = content_bounds(state.window_size, state.tab_panel_w, right_w, actions_extra_h(state));
            webview::set_bounds(x as f64, y as f64, w as f64, h as f64);
            Task::none()
        }
        Message::CloseVaultPanel => {
            state.vault_panel_open = false;
            state.vault_password_draft.clear();
            let right_w = right_panel_w(state);
            let (x, y, w, h) = content_bounds(state.window_size, state.tab_panel_w, right_w, actions_extra_h(state));
            webview::set_bounds(x as f64, y as f64, w as f64, h as f64);
            Task::none()
        }
        Message::VaultPasswordChanged(s) => {
            state.vault_password_draft = s;
            Task::none()
        }
        Message::VaultUnlock => {
            let master = std::mem::take(&mut state.vault_password_draft);
            if master.is_empty() {
                state.vault_status = "Enter a master password.".into();
                return Task::none();
            }
            if super::vault::Vault::exists() {
                match super::vault::Vault::open(&master) {
                    Ok(v) => {
                        state.vault = Some(v);
                        state.vault_status = "Vault unlocked.".into();
                    }
                    Err(e) => {
                        state.vault_status = format!("Could not unlock: {e}");
                    }
                }
            } else {
                match super::vault::Vault::create(&master) {
                    Ok(v) => {
                        state.vault = Some(v);
                        state.vault_status = "New vault created and unlocked.".into();
                    }
                    Err(e) => {
                        state.vault_status = format!("Could not create vault: {e}");
                    }
                }
            }
            Task::none()
        }
        Message::VaultLock => {
            state.vault = None;
            state.vault_status = "Vault locked.".into();
            Task::none()
        }
        Message::VaultUpsert(domain, username, password) => {
            if let Some(v) = &mut state.vault {
                match v.upsert(domain, username, password) {
                    Ok(())  => state.vault_status = "Credential saved.".into(),
                    Err(e)  => state.vault_status = format!("Save failed: {e}"),
                }
            } else {
                state.vault_status = "Unlock the vault first.".into();
            }
            Task::none()
        }
        Message::VaultDelete(domain, username) => {
            if let Some(v) = &mut state.vault {
                match v.remove(&domain, &username) {
                    Ok(true)  => state.vault_status = "Credential deleted.".into(),
                    Ok(false) => state.vault_status = "Entry not found.".into(),
                    Err(e)    => state.vault_status = format!("Delete failed: {e}"),
                }
            }
            Task::none()
        }
        Message::ToggleActionsMenu => {
            state.actions_menu_open = !state.actions_menu_open;
            if !state.content_fullscreen {
                let right_w = right_panel_w(state);
                let (x, y, w, h) = content_bounds(
                    state.window_size, state.tab_panel_w, right_w, actions_extra_h(state),
                );
                webview::set_bounds(x as f64, y as f64, w as f64, h as f64);
            }
            Task::none()
        }

        Message::AddQuickLink => {
            state.actions_menu_open = false;
            // Restore WebView bounds (dropdown reserved space is no longer needed).
            if !state.content_fullscreen {
                let right_w = right_panel_w(state);
                let (x, y, w, h) = content_bounds(
                    state.window_size, state.tab_panel_w, right_w, 0.0,
                );
                webview::set_bounds(x as f64, y as f64, w as f64, h as f64);
            }
            if let Some(tab) = state.tabs.get(state.active_tab) {
                let url   = tab.url.clone();
                let title = tab.title.clone();
                if !url.is_empty() && url != "tkz:home" {
                    let links = quicklinks::add(url, title);
                    // Refresh homepage quicklinks if that tab is active.
                    if state.tabs.get(state.active_tab)
                        .map(|t| t.url == "tkz:home")
                        .unwrap_or(false)
                    {
                        inject_quicklinks_from(&links);
                    }
                }
            }
            Task::none()
        }

        Message::VaultFillPage => {
            if let Some(v) = &state.vault {
                let url = state.tabs.get(state.active_tab)
                    .map(|t| t.url.as_str())
                    .unwrap_or("");
                let host = url
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .trim_start_matches("www.");
                if let Some(js) = v.fill_js(host) {
                    webview::eval_script(&js);
                    state.vault_status = format!("Filled credentials for {host}.");
                } else {
                    state.vault_status = format!("No stored credentials for {host}.");
                }
            } else {
                state.vault_status = "Vault is locked. Open the vault panel first.".into();
            }
            Task::none()
        }

        Message::Tick(now) => {
            let elapsed_secs = now.duration_since(state.last_tick).as_secs_f64().max(0.001);
            state.last_tick = now;

            let mut tasks: Vec<Task<Message>> = webview::drain_events()
                .into_iter()
                .map(|ev| match ev {
                    BrowserEvent::PageStarted(u)        => Task::done(Message::PageStarted(u)),
                    BrowserEvent::PageFinished(u)       => Task::done(Message::PageFinished(u)),
                    BrowserEvent::TitleChanged(t)       => Task::done(Message::TitleChanged(t)),
                    BrowserEvent::Ipc(msg)              => Task::done(Message::IpcReceived(msg)),
                    BrowserEvent::DownloadStarted(u, tmp, fin) => Task::done(Message::DownloadStarted(u, tmp, fin)),
                    BrowserEvent::DownloadCompleted(u, ok) => Task::done(Message::DownloadCompleted(u, ok)),
                })
                .collect();
            // Drain progress updates from the parallel downloader.
            // Apply Progress directly to state so view() sees it this same frame
            // (going via Task::done() defers state mutation to the next cycle).
            // Keep only the latest bytes value per download id, discarding
            // intermediate chunks that accumulated between ticks.
            {
                use super::downloader::ProgressUpdate;
                // Collect the last progress value per id, and any terminal events.
                let mut latest: std::collections::HashMap<u64, (u64, Option<u64>)> =
                    std::collections::HashMap::new();
                let mut completed_ids: Vec<u64> = Vec::new();
                let mut failed_ids:    Vec<u64> = Vec::new();

                for update in super::downloader::drain_progress() {
                    match update {
                        ProgressUpdate::Progress { id, bytes, total } => {
                            // Always overwrite so only the newest value survives.
                            latest.insert(id, (bytes, total));
                        }
                        ProgressUpdate::Completed { id } => completed_ids.push(id),
                        ProgressUpdate::Failed    { id } => failed_ids.push(id),
                    }
                }

                // Mutate state in-place — view() will pick these up immediately.
                for (id, (bytes, total)) in latest {
                    if let Some(dl) = state.downloads.iter_mut().find(|d| d.id == id) {
                        let delta = bytes.saturating_sub(dl.bytes_downloaded);
                        dl.speed_bps = (delta as f64 / elapsed_secs) as u64;
                        dl.bytes_downloaded = bytes;
                        if let Some(t) = total {
                            dl.total_bytes = Some(t);
                        }
                    }
                }

                // Terminal events still route through tasks so their handlers can
                // update status, call save_stash, etc. in the normal update path.
                for id in completed_ids {
                    tasks.push(Task::done(Message::DownloadFinished(id)));
                }
                for id in failed_ids {
                    tasks.push(Task::done(Message::DownloadFailed(id)));
                }
            }

            if state.is_loading {
                if state.load_progress < 1.0 {
                    state.load_progress = (state.load_progress + LOAD_SPEED).min(1.0);
                } else {
                    state.load_alpha -= 0.045;
                    if state.load_alpha <= 0.0 {
                        state.load_alpha = 0.0;
                        state.is_loading = false;
                    }
                }
            }

            let target_w = if state.tabs_hovered { PANEL_EXPANDED_W } else { PANEL_COLLAPSED_W };
            if (state.tab_panel_w - target_w).abs() > 0.5 {
                let prev_w = state.tab_panel_w;
                state.tab_panel_w = if state.tab_panel_w < target_w {
                    (state.tab_panel_w + PANEL_SPEED).min(target_w)
                } else {
                    (state.tab_panel_w - PANEL_SPEED).max(target_w)
                };
                if (state.tab_panel_w - prev_w).abs() > 0.1 {
                    let right_w = right_panel_w(state);
                    let (x, y, w, h) = content_bounds(state.window_size, state.tab_panel_w, right_w, actions_extra_h(state));
                    webview::set_bounds(x as f64, y as f64, w as f64, h as f64);
                }
            }

            // Deferred quicklinks + theme injection.
            if state.needs_quicklinks_inject && webview::is_initialised() {
                inject_quicklinks();
                inject_theme(effective_dark(state.theme_mode));
                state.needs_quicklinks_inject = false;
            }

            // Advance the download-button ring animation while downloads are active.
            // Speed: 0.04 rad/tick @ 16 ms ≈ 2.5 rad/s → ~1 rotation every 2.5 s.
            let has_active_dl = state.downloads.iter()
                .any(|d| d.status == super::downloads::DownloadStatus::InProgress);
            if has_active_dl {
                state.download_anim_phase =
                    (state.download_anim_phase + 0.04) % (2.0 * std::f32::consts::PI);
            }

            // ── Feature 4: background tab suspension ──────────────────────
            // Check every non-active tab; after SUSPENSION_SECS of inactivity
            // mark it suspended so it will reload on next select.
            const SUSPENSION_SECS: u64 = 10 * 60; // 10 minutes
            for (i, tab) in state.tabs.iter().enumerate() {
                if i == state.active_tab || tab.suspended { continue; }
                if let Some(t) = tab.last_active_time {
                    if t.elapsed().as_secs() >= SUSPENSION_SECS {
                        tasks.push(Task::done(Message::SuspendTab(i)));
                    }
                }
            }

            // ── Feature 5: force-directed spatial layout ──────────────────
            if state.spatial_map_open {
                if state.node_positions.len() != state.tabs.len() {
                    reinit_spatial_positions(state);
                }
                let n = state.node_positions.len();
                if n > 1 {
                    let map_x0 = state.tab_panel_w + 40.0;
                    let map_w  = (state.window_size.width  - map_x0 - 40.0).max(100.0);
                    let map_h  = (state.window_size.height - 80.0).max(100.0);
                    let cx = map_x0 + map_w / 2.0;
                    let cy = 40.0 + map_h / 2.0;
                    let mut forces = vec![(0.0_f32, 0.0_f32); n];
                    // Repulsion between all pairs.
                    for i in 0..n {
                        for j in (i + 1)..n {
                            let (x1, y1) = state.node_positions[i];
                            let (x2, y2) = state.node_positions[j];
                            let dx = x1 - x2;
                            let dy = y1 - y2;
                            let d2 = dx * dx + dy * dy + 1.0;
                            let d  = d2.sqrt();
                            let k  = 4_000.0 / d2;
                            let fx = k * dx / d;
                            let fy = k * dy / d;
                            forces[i].0 += fx;
                            forces[i].1 += fy;
                            forces[j].0 -= fx;
                            forces[j].1 -= fy;
                        }
                        // Centering gravity.
                        let (x, y) = state.node_positions[i];
                        forces[i].0 += (cx - x) * 0.006;
                        forces[i].1 += (cy - y) * 0.006;
                    }
                    // Spring attraction for parent→child edges.
                    for (i, tab) in state.tabs.iter().enumerate().take(n) {
                        if let Some(p) = tab.opened_from {
                            if p < n {
                                let (x1, y1) = state.node_positions[i];
                                let (x2, y2) = state.node_positions[p];
                                let dx = x2 - x1;
                                let dy = y2 - y1;
                                let k  = 0.04;
                                forces[i].0 += k * dx;
                                forces[i].1 += k * dy;
                                forces[p].0  -= k * dx;
                                forces[p].1  -= k * dy;
                            }
                        }
                    }
                    // Apply forces (overdamped — no velocity accumulation).
                    let x_min = map_x0 + 40.0;
                    let x_max = state.window_size.width  - 40.0;
                    let y_min = 60.0_f32;
                    let y_max = state.window_size.height - 40.0;
                    for i in 0..n {
                        if state.node_positions.len() > i {
                            let (ref mut x, ref mut y) = state.node_positions[i];
                            *x = (*x + forces[i].0 * 0.016_f32).clamp(x_min, x_max);
                            *y = (*y + forces[i].1 * 0.016_f32).clamp(y_min, y_max);
                        }
                    }
                }
            }

            // ── API commands from BrowserHandle ───────────────────────────
            // Drain into a Vec first so the mutable borrow on `state.api_rx`
            // is released before we call helpers that also borrow `state`.
            let api_msgs: Vec<_> = state.api_rx
                .as_mut()
                .map(|rx| std::iter::from_fn(|| rx.try_recv().ok()).collect())
                .unwrap_or_default();

            for msg in api_msgs {
                use super::api::{ApiMessage, TabTarget};
                match msg {
                    ApiMessage::Navigate(tab_target, raw_url) => {
                        let url = resolve_url(&raw_url);
                        match tab_target {
                            TabTarget::Active => {
                                navigate_current_tab(state, url);
                            }
                            TabTarget::New => {
                                state.tabs.push(Tab::new(url.clone()));
                                state.active_tab = state.tabs.len() - 1;
                                state.address_input = url.clone();
                                state.suppress_next_push = false;
                                webview::navigate(&url);
                            }
                            TabTarget::Index(i) => {
                                let i = if i < state.tabs.len() {
                                    i
                                } else {
                                    state.tabs.push(Tab::new(url.clone()));
                                    state.tabs.len() - 1
                                };
                                state.active_tab = i;
                                state.address_input = url.clone();
                                state.suppress_next_push = false;
                                state.tabs[i].home_html = None;
                                webview::navigate(&url);
                            }
                        }
                    }
                    ApiMessage::StartDownload(url) => {
                        let (_, final_dest) = super::api::download_paths_for_url(&url);
                        let unique_final = unique_download_dest(&final_dest, &state.downloads);
                        let unique_temp = unique_final.with_file_name(format!(
                            "{}.tkz",
                            unique_final
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_else(|| "download".to_string())
                        ));
                        let id = state.next_download_id;
                        state.next_download_id += 1;
                        let filename = unique_final
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| {
                                url.split('/').last().unwrap_or("download").to_string()
                            });
                        state.downloads.push(super::downloads::DownloadEntry {
                            id,
                            url: url.clone(),
                            filename,
                            temp_dest: unique_temp.clone(),
                            final_dest: unique_final.clone(),
                            bytes_downloaded: 0,
                            total_bytes: None,
                            speed_bps: 0,
                            status: super::downloads::DownloadStatus::InProgress,
                        });
                        super::stash::save_stash(&state.downloads);
                        super::downloader::spawn_download(id, url, unique_temp, unique_final);
                    }
                    ApiMessage::SetTheme(mode) => {
                        state.theme_mode = mode;
                        inject_theme(effective_dark(state.theme_mode));
                    }
                    ApiMessage::OpenNewTab(maybe_url) => match maybe_url {
                        None => {
                            state.tabs.push(Tab::new_html(super::homepage_html_arc()));
                            state.active_tab = state.tabs.len() - 1;
                            state.address_input = String::new();
                            state.needs_quicklinks_inject = true;
                            webview::load_html(super::HOMEPAGE_HTML);
                        }
                        Some(raw_url) => {
                            let url = resolve_url(&raw_url);
                            state.tabs.push(Tab::new(url.clone()));
                            state.active_tab = state.tabs.len() - 1;
                            state.address_input = url.clone();
                            state.suppress_next_push = false;
                            webview::navigate(&url);
                        }
                    },
                }
            }

            if tasks.is_empty() { Task::none() } else { Task::batch(tasks) }
        }
    }
}

pub fn view(state: &BrowserState) -> Element<'_, Message> {
    let dark = effective_dark(state.theme_mode);
    let nav_c = if dark { Color::from_rgb(0.75, 0.75, 0.85) } else { Color::from_rgb(0.22, 0.22, 0.32) };

    let back_btn = Button::new(Text::new("←").size(18).color(nav_c))
        .on_press(Message::Back)
        .style(move |_theme, _status| nav_btn_style(dark));

    let fwd_btn = Button::new(Text::new("→").size(16).color(nav_c))
        .on_press(Message::Forward)
        .style(move |_theme, _status| nav_btn_style(dark));

    let reload_btn = Button::new(Text::new("↺").size(16).color(nav_c))
        .on_press(Message::Reload)
        .style(move |_theme, _status| nav_btn_style(dark));

    let url_input = TextInput::new("Search or enter URL", &state.address_input)
        .id(iced::widget::Id::new("addr_bar"))
        .on_input(Message::AddressChanged)
        .on_submit(Message::Navigate)
        .padding(iced::Padding::from([5, 8]))
        .size(13)
        .width(Length::FillPortion(3))
        .style(move |_theme, status| url_bar_style(matches!(status, text_input::Status::Focused { .. }), dark));

    // ── Security / TLS badge ──────────────────────────────────────────────────
    let icon_c = if dark { Color::from_rgb(0.52, 0.52, 0.62) } else { Color::from_rgb(0.35, 0.35, 0.46) };
    let sec_badge: Element<Message> = {
        let s = &state.address_input;
        if s.starts_with("https://") || s.starts_with("file://") {
            let c = if dark {
                Color::from_rgb(0.30, 0.85, 0.45)
            } else {
                Color::from_rgb(0.12, 0.62, 0.28)
            };
            Text::new("🔒").size(11).color(c).into()
        } else if s.starts_with("http://") {
            Text::new("⚠").size(11)
                .color(Color::from_rgb(0.88, 0.62, 0.10))
                .into()
        } else {
            Space::new().width(Length::Fixed(0.0)).into()
        }
    };

    // ── Zoom level chip (only shown when zoom != 100 %) ───────────────────────
    let zoom_chip: Element<Message> = if (state.zoom_level - 1.0).abs() > 0.049 {
        let pct = (state.zoom_level * 100.0).round() as i32;
        Button::new(Text::new(format!("{pct}%")).size(10).color(icon_c))
            .on_press(Message::ZoomReset)
            .padding(iced::Padding::from([2, 5]))
            .style(move |_theme, _status| button::Style {
                background: Some(iced::Background::Color(
                    if dark { Color::from_rgba(1.0, 1.0, 1.0, 0.07) }
                    else    { Color::from_rgba(0.0, 0.0, 0.0, 0.07) }
                )),
                border: iced::Border {
                    color: Color::from_rgba(0.467, 0.0, 1.0, 0.30),
                    width: 0.75,
                    radius: 4.0.into(),
                },
                shadow: iced::Shadow::default(),
                text_color: icon_c,
                snap: false,
            })
            .into()
    } else {
        Space::new().width(Length::Fixed(0.0)).into()
    };

    let theme_icon = match state.theme_mode {
        ThemeMode::Light => "☀️",
        ThemeMode::Dark  => "🌙",
        ThemeMode::Auto  => "⏰",
    };
    let theme_btn = Button::new(Text::new(theme_icon).size(12).color(icon_c))
        .on_press(Message::CycleTheme)
        .style(move |_theme, _status| nav_btn_style(dark));

    let hist_btn = Button::new(Text::new("⏳").size(13).color(icon_c))
        .on_press(Message::ToggleHistory)
        .style(move |_theme, _status| nav_btn_style(dark));

    // ── Actions menu button ───────────────────────────────────────────────────
    let actions_label_c = if state.actions_menu_open {
        if dark { Color::from_rgb(0.58, 0.30, 1.0) } else { Color::from_rgb(0.40, 0.10, 0.85) }
    } else {
        icon_c
    };
    let actions_btn = Button::new(
        Text::new("Actions ▾").size(11).color(actions_label_c),
    )
    .on_press(Message::ToggleActionsMenu)
    .style(move |_theme, _status| button::Style {
        background: if state.actions_menu_open {
            Some(iced::Background::Color(
                if dark { Color::from_rgba(0.467, 0.0, 1.0, 0.15) }
                else    { Color::from_rgba(0.467, 0.0, 1.0, 0.10) }
            ))
        } else {
            None
        },
        border: iced::Border {
            color: if state.actions_menu_open {
                Color::from_rgba(0.467, 0.0, 1.0, 0.35)
            } else {
                Color::TRANSPARENT
            },
            width: if state.actions_menu_open { 0.75 } else { 0.0 },
            radius: 4.0.into(),
        },
        shadow: iced::Shadow::default(),
        text_color: actions_label_c,
        snap: false,
    })
    .padding(iced::Padding::from([3, 7]));

    let addr_bar_bg = if dark {
        Color::from_rgb(0.09, 0.09, 0.12)
    } else {
        Color::from_rgb(0.91, 0.91, 0.94)
    };
    let active_dl_count = state.downloads.iter()
        .filter(|d| d.status == super::downloads::DownloadStatus::InProgress)
        .count();
    let done_dl_count = state.downloads.iter()
        .filter(|d| d.status == super::downloads::DownloadStatus::Completed)
        .count();
    let dl_ring = Canvas::new(DownloadRing {
        active: active_dl_count,
        done: done_dl_count,
        phase: state.download_anim_phase,
        dark,
    })
    .width(Length::Fixed(22.0))
    .height(Length::Fixed(22.0));
    let dl_btn = Button::new(dl_ring)
        .on_press(Message::ToggleDownloads)
        .padding(iced::Padding::from([2, 3]))
        .style(move |_theme, _status| button::Style {
            background: None,
            border: iced::Border::default(),
            shadow: iced::Shadow::default(),
            text_color: Color::TRANSPARENT,
            snap: false,
        });
    let vault_unlocked = state.vault.is_some();
    let vault_icon_c = if vault_unlocked {
        if dark { Color::from_rgba(0.40, 0.90, 0.55, 1.0) } else { Color::from_rgba(0.10, 0.65, 0.30, 1.0) }
    } else {
        if dark { Color::from_rgba(0.55, 0.55, 0.65, 0.80) } else { Color::from_rgba(0.38, 0.38, 0.50, 0.80) }
    };
    let vault_open_btn = Button::new(Text::new("🔐").size(13).color(vault_icon_c))
        .on_press(if state.vault_panel_open { Message::CloseVaultPanel } else { Message::OpenVaultPanel })
        .style(move |_theme, _status| nav_btn_style(dark));

    let screenshot_btn = Button::new(
        Text::new("⊡").size(16).color(nav_c),
    )
    .on_press(Message::TakeScreenshot)
    .style(move |_theme, _status| nav_btn_style(dark));

    let spatial_btn = Button::new(
        Text::new("\u{2B21}").size(14).color(nav_c),
    )
    .on_press(Message::ToggleSpatialMap)
    .style(move |_theme, _status| nav_btn_style(dark));

    let addr_bar = Container::new(
        Row::new()
            .push(back_btn)
            .push(fwd_btn)
            .push(reload_btn)
            .push(Space::new().width(Length::Fixed(4.0)))
            .push(sec_badge)
            .push(Space::new().width(Length::Fixed(2.0)))
            .push(url_input)
            .push(Space::new().width(Length::Fixed(3.0)))
            .push(zoom_chip)
            .push(Space::new().width(Length::FillPortion(1)))
            .push(screenshot_btn)
            .push(Space::new().width(Length::Fixed(2.0)))
            .push(spatial_btn)
            .push(Space::new().width(Length::Fixed(2.0)))
            .push(vault_open_btn)
            .push(Space::new().width(Length::Fixed(2.0)))
            .push(theme_btn)
            .push(Space::new().width(Length::Fixed(2.0)))
            .push(dl_btn)
            .push(Space::new().width(Length::Fixed(2.0)))
            .push(hist_btn)
            .push(Space::new().width(Length::Fixed(4.0)))
            .push(actions_btn)
            .push(Space::new().width(Length::Fixed(6.0)))
            .align_y(alignment::Vertical::Center)
            .spacing(2),
    )
    .width(Length::Fill)
    .height(Length::Fixed(ADDR_BAR_H))
    .align_y(alignment::Vertical::Center)
    .padding(iced::Padding::from([0, 6]))
    .style(move |_| container::Style {
        background: Some(iced::Background::Color(addr_bar_bg)),
        border: iced::Border { color: Color::from_rgba(1.0, 1.0, 1.0, 0.04), width: 0.0, radius: 0.0.into() },
        ..Default::default()
    });

    let tab_panel: Element<Message> = Canvas::new(VerticalTabBar {
        tabs: state.tabs.clone(),
        active: state.active_tab,
        panel_w: state.tab_panel_w,
        groups: state.tab_groups.clone(),
        dark,
        collapsed_groups: state.collapsed_groups.clone(),
    })
    .width(Length::Fixed(state.tab_panel_w))
    .height(Length::Fill)
    .into();

    let cph_bg = if dark { Color::from_rgb(0.04, 0.04, 0.06) } else { Color::from_rgb(0.95, 0.95, 0.97) };
    let content_bg = Container::new(Space::new().width(Length::Fill).height(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(cph_bg)),
            ..Default::default()
        });

    let content_stack: Element<Message> = Stack::new()
        .push(content_bg)
        .push(tab_panel)
        .width(Length::Fill)
        .height(Length::Fill)
        .into();

    let loader_canvas: Element<Message> = if state.is_loading || state.load_alpha > 0.0 {
        Canvas::new(BorderTrace { progress: state.load_progress, alpha: state.load_alpha })
            .width(Length::Fill).height(Length::Fill).into()
    } else {
        Space::new().width(Length::Fill).height(Length::Fill).into()
    };

    let main_bg = if dark { Color::from_rgb(0.06, 0.06, 0.08) } else { Color::from_rgb(0.93, 0.93, 0.96) };
    let main_layout: Element<Message> = Container::new(
        Column::new()
            .push(addr_bar)
            .push(content_stack)
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(move |_| container::Style {
        background: Some(iced::Background::Color(main_bg)),
        ..Default::default()
    })
    .into();

    let hist_layer: Element<Message> = if state.show_history {
        let panel_h = (state.window_size.height - ADDR_BAR_H).max(200.0);
        Container::new(
            Column::new()
                .push(Space::new().height(Length::Fixed(ADDR_BAR_H)))
                .push(history_panel(
                    &state.history_entries,
                    panel_h,
                    dark,
                    state.history_recording,
                    state.history_delete_amount,
                    state.history_delete_unit,
                )),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(alignment::Horizontal::Right)
        .into()
    } else {
        Space::new().width(Length::Fill).height(Length::Fill).into()
    };

    let popup_bg = if dark {
        Color::from_rgba(0.07, 0.07, 0.11, 0.97)
    } else {
        Color::from_rgba(0.96, 0.96, 0.98, 0.97)
    };
    let rename_layer: Element<Message> = if state.renaming_group.is_some() {
        Container::new(
            Column::new()
                // ── input pinned just below the address bar ───────────────
                .push(Space::new().height(Length::Fixed(CHROME_H + 6.0)))
                .push(
                    Container::new(
                        Column::new()
                            .push(
                                Text::new("Group name")
                                    .size(11)
                                    .color(if dark {
                                        Color::from_rgb(0.55, 0.55, 0.65)
                                    } else {
                                        Color::from_rgb(0.40, 0.40, 0.50)
                                    }),
                            )
                            .push(Space::new().height(Length::Fixed(4.0)))
                            .push(
                                TextInput::new("e.g. Work", &state.group_rename_text)
                                    .id(iced::widget::Id::new("group_rename"))
                                    .on_input(Message::GroupRenameChanged)
                                    .on_submit(Message::CommitGroupRename)
                                    .padding(iced::Padding::from([5, 8]))
                                    .size(13)
                                    .style(move |_theme, status| url_bar_style(
                                        matches!(status, text_input::Status::Focused { .. }), dark
                                    )),
                            )
                            .push(Space::new().height(Length::Fixed(4.0)))
                            .push(
                                Text::new("↵  confirm  · Esc  cancel")
                                    .size(10)
                                    .color(if dark {
                                        Color::from_rgb(0.38, 0.38, 0.48)
                                    } else {
                                        Color::from_rgb(0.52, 0.52, 0.60)
                                    }),
                            )
                            .spacing(0),
                    )
                    .width(Length::Fixed((state.tab_panel_w - 8.0).max(170.0)))
                    .padding(iced::Padding::from([8, 10]))
                    .style(move |_| container::Style {
                        background: Some(iced::Background::Color(popup_bg)),
                        border: iced::Border {
                            color: Color::from_rgba(0.467, 0.0, 1.0, 0.4),
                            width: 1.0,
                            radius: 8.0.into(),
                        },
                        ..Default::default()
                    }),
                )
                .push(Space::new().height(Length::Fill))
                .width(Length::Fixed(state.tab_panel_w.max(180.0)))
                .height(Length::Fill)
                .padding(iced::Padding::from([0, 4])),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    } else {
        Space::new().width(Length::Fill).height(Length::Fill).into()
    };

    // ── Downloads panel (right edge, below address bar) ──────────────────────
    let downloads_layer: Element<Message> = if state.show_downloads {
        let panel_h = (state.window_size.height - ADDR_BAR_H).max(200.0);
        Container::new(
            Column::new()
                .push(Space::new().height(Length::Fixed(ADDR_BAR_H)))
                .push(downloads_panel(
                    &state.downloads,
                    panel_h,
                    dark,
                    state.download_anim_phase,
                )),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(alignment::Horizontal::Right)
        .into()
    } else {
        Space::new().width(Length::Fill).height(Length::Fill).into()
    };

    // ── Find-in-page toolbar (bottom of window) ───────────────────────────────
    let find_bar_layer: Element<Message> = if state.find_bar_open {
        Container::new(
            Column::new()
                .push(Space::new().height(Length::Fill))
                .push(find_bar_widget(&state.find_query, dark)),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    } else {
        Space::new().width(Length::Fill).height(Length::Fill).into()
    };

    // ── URL autocomplete dropdown (below address bar) ──────────────────────────
    let autocomplete_layer: Element<Message> =
        if state.autocomplete_visible && !state.autocomplete_suggestions.is_empty() {
            Container::new(
                Column::new()
                    .push(Space::new().height(Length::Fixed(CHROME_H)))
                    .push(autocomplete_dropdown(&state.autocomplete_suggestions, dark)),
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(iced::Padding {
                left: state.tab_panel_w + INSET,
                right: INSET,
                top: 0.0,
                bottom: 0.0,
            })
            .into()
        } else {
            Space::new().width(Length::Fill).height(Length::Fill).into()
        };

    // ── Feature 5: spatial tab map overlay ──────────────────────────────────
    let spatial_layer: Element<Message> = if state.spatial_map_open {
        let map = super::spatial::SpatialTabMap {
            tabs:           &state.tabs,
            groups:         &state.tab_groups,
            node_positions: &state.node_positions,
            active:         state.active_tab,
            dark,
        };
        iced::widget::Canvas::new(map)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    } else {
        Space::new().width(Length::Fill).height(Length::Fill).into()
    };

    // ── Credential vault panel ─────────────────────────────────────────────
    let vault_layer: Element<Message> = if state.vault_panel_open {
        let panel_h = (state.window_size.height - ADDR_BAR_H).max(200.0);
        Container::new(
            Column::new()
                .push(Space::new().height(Length::Fixed(ADDR_BAR_H)))
                .push(vault_panel(
                    state.vault.as_ref(),
                    &state.vault_password_draft,
                    &state.vault_status,
                    panel_h,
                    dark,
                )),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(alignment::Horizontal::Right)
        .into()
    } else {
        Space::new().width(Length::Fill).height(Length::Fill).into()
    };

    // ── Actions dropdown overlay ──────────────────────────────────────────────
    let actions_layer: Element<Message> = if state.actions_menu_open {
        let menu_bg = if dark {
            Color::from_rgba(0.08, 0.08, 0.12, 0.97)
        } else {
            Color::from_rgba(0.97, 0.97, 0.99, 0.97)
        };
        let sep_c = if dark {
            Color::from_rgba(1.0, 1.0, 1.0, 0.07)
        } else {
            Color::from_rgba(0.0, 0.0, 0.0, 0.07)
        };
        let on_homepage = state.tabs
            .get(state.active_tab)
            .map(|t| t.url == "tkz:home" || t.home_html.is_some())
            .unwrap_or(true);

        let item_text_c = if dark {
            Color::from_rgb(0.82, 0.82, 0.90)
        } else {
            Color::from_rgb(0.18, 0.18, 0.28)
        };
        let dim_c = if dark {
            Color::from_rgba(0.55, 0.55, 0.65, 0.55)
        } else {
            Color::from_rgba(0.45, 0.45, 0.55, 0.55)
        };

        // "Add to Quick Links" — disabled on the homepage.
        let ql_item: Element<Message> = if on_homepage {
            Container::new(
                Text::new("⚡  Add to Quick Links")
                    .size(12)
                    .color(dim_c),
            )
            .width(Length::Fill)
            .padding(iced::Padding::from([7, 14]))
            .into()
        } else {
            Button::new(
                Text::new("⚡  Add to Quick Links")
                    .size(12)
                    .color(item_text_c),
            )
            .on_press(Message::AddQuickLink)
            .width(Length::Fill)
            .padding(iced::Padding::from([7, 14]))
            .style(move |_theme, status| button::Style {
                background: match status {
                    button::Status::Hovered | button::Status::Pressed => Some(
                        iced::Background::Color(
                            if dark { Color::from_rgba(0.467, 0.0, 1.0, 0.15) }
                            else    { Color::from_rgba(0.467, 0.0, 1.0, 0.10) }
                        )
                    ),
                    _ => None,
                },
                border: iced::Border::default(),
                shadow: iced::Shadow::default(),
                text_color: item_text_c,
                snap: false,
            })
            .into()
        };

        let menu_panel = Container::new(
            Column::new()
                .push(ql_item)
                .push(
                    Container::new(Space::new().width(Length::Fill).height(Length::Fixed(1.0)))
                        .width(Length::Fill)
                        .style(move |_| container::Style {
                            background: Some(iced::Background::Color(sep_c)),
                            ..Default::default()
                        }),
                )
                .spacing(0),
        )
        .width(Length::Fixed(200.0))
        .padding(iced::Padding::from([4, 0]))
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(menu_bg)),
            border: iced::Border {
                color: Color::from_rgba(0.467, 0.0, 1.0, 0.30),
                width: 1.0,
                radius: 7.0.into(),
            },
            shadow: iced::Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.35),
                offset: iced::Vector::new(0.0, 4.0),
                blur_radius: 16.0,
            },
            ..Default::default()
        });

        Container::new(
            Column::new()
                .push(Space::new().height(Length::Fixed(ADDR_BAR_H)))
                .push(menu_panel),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(alignment::Horizontal::Right)
        .padding(iced::Padding { top: 0.0, right: 6.0, bottom: 0.0, left: 0.0 })
        .into()
    } else {
        Space::new().width(Length::Fill).height(Length::Fill).into()
    };

    Stack::new()
        .push(main_layout)
        .push(loader_canvas)
        .push(hist_layer)
        .push(downloads_layer)
        .push(vault_layer)
        .push(rename_layer)
        .push(find_bar_layer)
        .push(autocomplete_layer)
        .push(spatial_layer)
        .push(actions_layer)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

pub fn subscription(state: &BrowserState) -> Subscription<Message> {
    use iced::time;

    let opened  = window::open_events().map(Message::WindowOpened);
    let resized = window::resize_events()
        .map(|(id, size)| Message::WindowResized(id, size));
    let window_subs = Subscription::batch([opened, resized]);

    let target_w = if state.tabs_hovered { PANEL_EXPANDED_W } else { PANEL_COLLAPSED_W };
    let needs_fast_tick = state.is_loading
        || state.load_alpha > 0.0
        || !webview::is_initialised()
        || (state.tab_panel_w - target_w).abs() > 0.5
        || state.downloads.iter().any(|d| d.status == super::downloads::DownloadStatus::InProgress)
        || state.download_anim_phase > 0.0;

    let tick_rate = if needs_fast_tick {
        Duration::from_millis(16)
    } else {
        Duration::from_millis(100)
    };

    Subscription::batch([
        window_subs,
        time::every(tick_rate).map(Message::Tick),
        // ── Global keyboard shortcuts ────────────────────────────────────
        iced::event::listen_with(|event, _status, _window| {
            let iced::Event::Keyboard(
                iced::keyboard::Event::KeyPressed { ref key, modifiers, .. }
            ) = event else {
                return None;
            };
            let cmd   = modifiers.command();
            let shift = modifiers.shift();
            match key {
                iced::keyboard::Key::Character(c) if cmd => match c.as_str() {
                    "t" => Some(Message::NewTab),
                    "w" => Some(Message::CloseCurrentTab),
                    "r" => Some(Message::Reload),
                    "l" => Some(Message::FocusAddressBar),
                    "[" => Some(Message::Back),
                    "]" => Some(Message::Forward),
                    "-" => Some(Message::ZoomOut),
                    "=" | "+" => Some(Message::ZoomIn),
                    "0" => Some(Message::ZoomReset),
                    "f" => Some(Message::ToggleFindBar),
                    "s" if shift => Some(Message::TakeScreenshot),
                    "m" if shift => Some(Message::ToggleSpatialMap),
                    "v" if shift => Some(Message::VaultFillPage),
                    _ => None,
                },
                iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape) => {
                    Some(Message::CloseFind)
                }
                iced::keyboard::Key::Named(iced::keyboard::key::Named::F5) => {
                    Some(Message::Reload)
                }
                _ => None,
            }
        }),
    ])
}

pub fn theme(state: &BrowserState) -> Theme {
    if effective_dark(state.theme_mode) { Theme::Dark } else { Theme::Light }
}

pub fn content_bounds(window_size: Size, tab_panel_w: f32, history_w: f32, top_extra: f32) -> (f32, f32, f32, f32) {
    let x = tab_panel_w + INSET;
    let y = CHROME_H + top_extra + INSET;
    let w = (window_size.width - tab_panel_w - history_w - 2.0 * INSET).max(0.0);
    let h = (window_size.height - CHROME_H - top_extra - 2.0 * INSET).max(0.0);
    (x, y, w, h)
}

// ── autocomplete dropdown ─────────────────────────────────────────────────────

fn autocomplete_dropdown(
    suggestions: &[history::HistoryEntry],
    dark: bool,
) -> Element<'_, Message> {
    let bg = if dark {
        Color::from_rgba(0.07, 0.07, 0.11, 0.97)
    } else {
        Color::from_rgba(0.97, 0.97, 0.99, 0.97)
    };
    let text_c = if dark { Color::from_rgb(0.88, 0.88, 0.95) } else { Color::from_rgb(0.10, 0.10, 0.18) };
    let sub_c  = if dark { Color::from_rgb(0.42, 0.42, 0.52) } else { Color::from_rgb(0.38, 0.38, 0.50) };

    let mut col = Column::new().spacing(0).width(Length::Fill);
    for entry in suggestions {
        let url     = entry.url.clone();
        let display = if entry.title.is_empty() { entry.url.clone() } else { entry.title.clone() };
        let short   = short_url_display(&entry.url);
        let item: Element<Message> = Button::new(
            Column::new()
                .push(Text::new(display).size(12).color(text_c))
                .push(Text::new(short).size(10).color(sub_c))
                .spacing(1),
        )
        .on_press(Message::AutocompleteSelected(url))
        .width(Length::Fill)
        .padding(iced::Padding::from([6, 10]))
        .style(move |_theme, status| {
            let hov = matches!(status, button::Status::Hovered);
            button::Style {
                background: if hov {
                    Some(iced::Background::Color(if dark {
                        Color::from_rgba(0.467, 0.0, 1.0, 0.14)
                    } else {
                        Color::from_rgba(0.467, 0.0, 1.0, 0.07)
                    }))
                } else {
                    None
                },
                border: iced::Border::default(),
                shadow: iced::Shadow::default(),
                text_color: text_c,
                snap: false,
            }
        })
        .into();
        col = col.push(item);
    }

    Container::new(col)
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(bg)),
            border: iced::Border {
                color: Color::from_rgba(0.467, 0.0, 1.0, if dark { 0.22 } else { 0.28 }),
                width: 1.0,
                radius: iced::border::Radius {
                    top_left: 0.0,
                    top_right: 0.0,
                    bottom_left: 6.0,
                    bottom_right: 6.0,
                },
            },
            shadow: iced::Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, if dark { 0.55 } else { 0.18 }),
                offset: iced::Vector::new(0.0, 5.0),
                blur_radius: 14.0,
            },
            ..Default::default()
        })
        .into()
}

// ── find-in-page toolbar ──────────────────────────────────────────────────────

fn find_bar_widget(query: &str, dark: bool) -> Element<'_, Message> {
    let bg = if dark {
        Color::from_rgba(0.07, 0.07, 0.11, 0.97)
    } else {
        Color::from_rgba(0.96, 0.96, 0.98, 0.97)
    };
    let lbl_c = if dark { Color::from_rgb(0.50, 0.50, 0.60) } else { Color::from_rgb(0.40, 0.40, 0.50) };
    let icon_c = if dark { Color::from_rgb(0.72, 0.72, 0.80) } else { Color::from_rgb(0.22, 0.22, 0.32) };

    let input = TextInput::new("Find in page\u{2026}", query)
        .id(iced::widget::Id::new("find_input"))
        .on_input(Message::FindQueryChanged)
        .on_submit(Message::FindNext)
        .size(13)
        .padding(iced::Padding::from([4, 8]))
        .width(Length::Fixed(240.0))
        .style(move |_theme, status| url_bar_style(
            matches!(status, text_input::Status::Focused { .. }), dark
        ));

    let prev_btn = Button::new(Text::new("↑").size(13).color(icon_c))
        .on_press(Message::FindPrev)
        .style(move |_theme, _status| nav_btn_style(dark));

    let next_btn = Button::new(Text::new("↓").size(13).color(icon_c))
        .on_press(Message::FindNext)
        .style(move |_theme, _status| nav_btn_style(dark));

    let close_btn = Button::new(Text::new("✕").size(12).color(lbl_c))
        .on_press(Message::CloseFind)
        .style(move |_theme, _status| nav_btn_style(dark));

    Container::new(
        Row::new()
            .push(Text::new("Find:").size(11).color(lbl_c))
            .push(Space::new().width(Length::Fixed(6.0)))
            .push(input)
            .push(Space::new().width(Length::Fixed(2.0)))
            .push(prev_btn)
            .push(next_btn)
            .push(Space::new().width(Length::Fill))
            .push(close_btn)
            .push(Space::new().width(Length::Fixed(6.0)))
            .align_y(alignment::Vertical::Center),
    )
    .width(Length::Fill)
    .padding(iced::Padding::from([5, 10]))
    .style(move |_| container::Style {
        background: Some(iced::Background::Color(bg)),
        border: iced::Border {
            color: Color::from_rgba(0.467, 0.0, 1.0, if dark { 0.20 } else { 0.25 }),
            width: 1.0,
            radius: 0.0.into(),
        },
        ..Default::default()
    })
    .into()
}

// ── URL helpers ───────────────────────────────────────────────────────────────

fn resolve_url(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("file://")
    {
        clean_url(trimmed)
    } else if trimmed.contains('.') && !trimmed.contains(' ') {
        clean_url(&format!("https://{trimmed}"))
    } else {
        format!(
            "https://www.google.com/search?q={}",
            urlencoding::encode(trimmed)
        )
    }
}

/// Strip common tracking parameters and redirect AMP URLs to canonical form.
///
/// Tracking params removed: utm_*, fbclid, gclid, mc_cid, mc_eid, _ga, ref,
/// igshid, twclid, msclkid, dclid, zanpid, otm_*, epik, and others.
fn clean_url(url: &str) -> String {
    // AMP redirect: amp.example.com → example.com + strip /amp suffix.
    let url = if let Some(no_scheme) = url
        .strip_prefix("https://amp.")
        .or_else(|| url.strip_prefix("http://amp."))
    {
        let base = format!("https://{no_scheme}");
        // Strip trailing /amp or /amp/ path component.
        if let Some(p) = base.strip_suffix("/amp/").or_else(|| base.strip_suffix("/amp")) {
            p.to_string()
        } else {
            base
        }
    } else {
        // Strip /amp or /amp/ suffix from the path of any URL.
        if let Some(p) = url.strip_suffix("/amp/").or_else(|| url.strip_suffix("/amp")) {
            p.to_string()
        } else {
            url.to_string()
        }
    };

    const STRIP_PARAMS: &[&str] = &[
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "utm_id", "utm_reader", "utm_referrer", "utm_name", "utm_social",
        "utm_social-type",
        "fbclid", "gclid", "dclid", "gbraid", "wbraid",
        "mc_cid", "mc_eid",
        "_ga", "_gl",
        "igshid",
        "twclid",
        "msclkid",
        "zanpid",
        "epik",
        "otm_campaign", "otm_content", "otm_medium", "otm_source", "otm_subtype",
        "ref", "source",
    ];

    // Only parse if the URL has a query string.
    let qmark = match url.find('?') {
        Some(i) => i,
        None    => return url,
    };

    let (before_query, query_and_fragment) = url.split_at(qmark);
    // query_and_fragment starts with '?'
    let (query_part, fragment) = if let Some(h) = query_and_fragment.find('#') {
        (&query_and_fragment[1..h], &query_and_fragment[h..])
    } else {
        (&query_and_fragment[1..], "")
    };

    let kept: Vec<&str> = query_part
        .split('&')
        .filter(|pair| {
            let key = pair.split('=').next().unwrap_or("");
            // Case-insensitive match for any of the stripped prefixes/names.
            let lower = key.to_lowercase();
            !STRIP_PARAMS.iter().any(|s| lower == *s)
                && !lower.starts_with("utm_")
        })
        .collect();

    if kept.is_empty() {
        format!("{before_query}{fragment}")
    } else {
        format!("{before_query}?{}{fragment}", kept.join("&"))
    }
}

// ── Feature 6 helper ──────────────────────────────────────────────────────────

/// Read `~/.config/duct-tape/userstyles/<host>.css` (if it exists) and inject
/// it into the active page.
fn inject_userstyle_for_url(url: &str) {
    // Extract hostname (skip scheme, strip port).
    let stripped = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = stripped
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim_start_matches("www.");
    if host.is_empty() {
        return;
    }
    let config = dirs_config().join("duct-tape/userstyles").join(format!("{host}.css"));
    if let Ok(css) = std::fs::read_to_string(config) {
        webview::inject_userstyle(&css);
    }
}

/// Returns the platform config directory (e.g. `~/.config` on Linux/macOS).
fn dirs_config() -> std::path::PathBuf {
    // Honour XDG_CONFIG_HOME, fall back to ~/.config.
    if let Ok(p) = std::env::var("XDG_CONFIG_HOME") {
        return std::path::PathBuf::from(p);
    }
    if let Ok(h) = std::env::var("HOME") {
        return std::path::PathBuf::from(h).join(".config");
    }
    std::path::PathBuf::from(".")
}

// ── Feature 5 helper ──────────────────────────────────────────────────────────

/// (Re)initialise `state.node_positions` with a random-ish scatter across the
/// canvas area so the force-directed layout has a good starting point.
fn reinit_spatial_positions(state: &mut BrowserState) {
    let n = state.tabs.len();
    let map_x0 = state.tab_panel_w + 40.0;
    let map_w  = (state.window_size.width  - map_x0 - 40.0).max(200.0);
    let map_h  = (state.window_size.height - 80.0).max(200.0);

    state.node_positions.resize(n, (0.0, 0.0));
    // Place nodes in a rough grid pattern as starting positions.
    let cols = ((n as f32).sqrt().ceil() as usize).max(1);
    for (i, pos) in state.node_positions.iter_mut().enumerate() {
        let col = (i % cols) as f32;
        let row = (i / cols) as f32;
        let rows = ((n as f32 / cols as f32).ceil()).max(1.0);
        // Spread evenly with some padding.
        let x = map_x0 + map_w * (col + 0.5) / cols as f32;
        let y = 60.0 + map_h * (row + 0.5) / rows;
        // Only overwrite uninitialized (zero) entries.
        if pos.0 == 0.0 && pos.1 == 0.0 {
            *pos = (x, y);
        }
    }
}

fn navigate_current_tab(state: &mut BrowserState, url: String) {
    if let Some(tab) = state.tabs.get_mut(state.active_tab) {
        tab.url = url.clone();
        // home_html is intentionally preserved — needed if user later presses Back
        // to a tkz:home entry in this tab's nav_history.
    }
    // Reset so the next PageFinished records this navigation in per-tab history.
    state.suppress_next_push = false;
    webview::navigate(&url);
}

fn create_webview_task(
    id: window::Id,
    size: Size,
    url: Option<String>,
    html: Option<String>,
) -> Task<()> {
    let (cx, cy, cw, ch) = content_bounds(size, PANEL_COLLAPSED_W, 0.0, 0.0);
    window::run(id, move |window| {
        let raw = match window.window_handle() {
            Ok(h) => h.as_raw(),
            Err(e) => { eprintln!("[browser] window_handle error: {e}"); return; }
        };
        webview::create(raw, url, html, cx as f64, cy as f64, cw as f64, ch as f64);
    })
}

fn nav_btn_style(dark: bool) -> button::Style {
    button::Style {
        background: None,
        border: iced::Border::default(),
        shadow: iced::Shadow::default(),
        text_color: if dark {
            Color::from_rgb(0.75, 0.75, 0.85)
        } else {
            Color::from_rgb(0.22, 0.22, 0.32)
        },
        snap: false,
    }
}

fn url_bar_style(focused: bool, dark: bool) -> text_input::Style {
    const UV: Color = Color { r: 0.467, g: 0.0, b: 1.0, a: 1.0 };
    let bg_rest = if dark {
        Color::from_rgba(0.0, 0.0, 0.0, 0.0)
    } else {
        Color::from_rgba(1.0, 1.0, 1.0, 0.55)
    };
    text_input::Style {
        background: iced::Background::Color(
            if focused { Color::from_rgba(0.467, 0.0, 1.0, 0.06) } else { bg_rest }
        ),
        border: iced::Border {
            color: if focused { UV } else { Color::from_rgba(0.467, 0.0, 1.0, 0.12) },
            width: if focused { 1.0 } else { 0.5 },
            radius: 6.0.into(),
        },
        icon: Color::from_rgb(0.5, 0.5, 0.58),
        placeholder: if dark { Color::from_rgb(0.35, 0.35, 0.44) } else { Color::from_rgb(0.50, 0.50, 0.58) },
        value: if dark { Color::from_rgb(0.88, 0.88, 0.95) } else { Color::from_rgb(0.10, 0.10, 0.18) },
        selection: Color { r: 0.467, g: 0.0, b: 1.0, a: 0.30 },
    }
}

// ── history panel ─────────────────────────────────────────────────────────────

fn history_panel(
    entries: &[history::HistoryEntry],
    panel_h: f32,
    dark: bool,
    recording: bool,
    delete_amount: f32,
    delete_unit: TimeUnit,
) -> Element<'_, Message> {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Compute once; passed into format_relative_time for every entry so the
    // syscall fires exactly once per panel render instead of once per entry.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let close_btn = Button::new(
        Text::new("✕").size(13).color(
            if dark { Color::from_rgb(0.65, 0.65, 0.70) } else { Color::from_rgb(0.30, 0.30, 0.36) }
        ),
    )
    .on_press(Message::ToggleHistory)
    .style(move |_theme, _status| nav_btn_style(dark));

    // ● = recording on (clickable to disable)  ○ = paused (clickable to re-enable)
    let rec_label = if recording { "● Rec" } else { "○ Off" };
    let rec_color = if recording {
        if dark { Color::from_rgb(0.30, 0.85, 0.45) } else { Color::from_rgb(0.12, 0.65, 0.30) }
    } else {
        if dark { Color::from_rgb(0.75, 0.35, 0.35) } else { Color::from_rgb(0.70, 0.20, 0.20) }
    };
    let rec_btn = Button::new(Text::new(rec_label).size(10).color(rec_color))
        .on_press(Message::ToggleHistoryRecording)
        .style(move |_theme, _status| button::Style {
            background: None,
            border: iced::Border {
                color: rec_color,
                width: 0.75,
                radius: 4.0.into(),
            },
            shadow: iced::Shadow::default(),
            text_color: rec_color,
            snap: false,
        });

    let header = Container::new(
        Row::new()
            .push(Text::new("History").size(14).color(
                if dark { Color::from_rgb(0.85, 0.85, 0.92) } else { Color::from_rgb(0.15, 0.15, 0.22) }
            ))
            .push(Space::new().width(Length::Fill))
            .push(rec_btn)
            .push(Space::new().width(Length::Fixed(6.0)))
            .push(close_btn)
            .align_y(alignment::Vertical::Center),
    )
    .width(Length::Fill)
    .padding(iced::Padding::from([10, 12]));

    let lbl_c = if dark { Color::from_rgb(0.45, 0.45, 0.52) } else { Color::from_rgb(0.38, 0.38, 0.46) };
    let del_slider = Slider::new(1.0f32..=100.0, delete_amount, Message::HistorySliderChanged)
        .step(1.0);
    let unit_picker = PickList::new(TIME_UNITS, Some(delete_unit), Message::HistoryUnitChanged)
        .text_size(10)
        .padding(iced::Padding::from([3, 5]));
    let del_by_unit = Button::new(Text::new("Delete").size(11))
        .on_press(Message::DeleteHistoryByUnit)
        .style(|_theme, _status| del_range_btn_style());
    let del_all = Button::new(Text::new("Clear all").size(11))
        .on_press(Message::DeleteAllHistory)
        .style(|_theme, _status| del_all_btn_style());

    let del_row = Container::new(
        Column::new()
            .push(
                Row::new()
                    .push(Text::new("Back:").size(10).color(lbl_c))
                    .push(Space::new().width(Length::Fixed(4.0)))
                    .push(del_slider)
                    .push(Space::new().width(Length::Fixed(4.0)))
                    .push(
                        Text::new(format!("{}", delete_amount.round() as u32))
                            .size(10).color(lbl_c)
                    )
                    .push(Space::new().width(Length::Fixed(4.0)))
                    .push(unit_picker)
                    .align_y(alignment::Vertical::Center)
                    .width(Length::Fill),
            )
            .push(Space::new().height(Length::Fixed(4.0)))
            .push(
                Row::new()
                    .push(del_by_unit)
                    .push(Space::new().width(Length::Fill))
                    .push(del_all)
                    .align_y(alignment::Vertical::Center),
            )
            .width(Length::Fill),
    )
    .width(Length::Fill)
    .padding(iced::Padding::from([6, 12]));

    let divider: Element<Message> = Container::new(
        Space::new().width(Length::Fill).height(Length::Fixed(1.0)),
    )
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(iced::Background::Color(
            if dark { Color::from_rgba(1.0, 1.0, 1.0, 0.06) } else { Color::from_rgba(0.0, 0.0, 0.0, 0.08) }
        )),
        ..Default::default()
    })
    .into();

    let mut list_col = Column::new().spacing(0).width(Length::Fill);

    if entries.is_empty() {
        list_col = list_col.push(
            Container::new(
                Text::new("No history yet")
                    .size(12)
                    .color(if dark { Color::from_rgb(0.38, 0.38, 0.45) } else { Color::from_rgb(0.50, 0.50, 0.58) }),
            )
            .width(Length::Fill)
            .padding(iced::Padding::from([24, 12]))
            .align_x(alignment::Horizontal::Center),
        );
    }

    for e in entries.iter().rev() {
        let url = e.url.clone();
        let short_url = short_url_display(&e.url);
        let display = if e.title.is_empty() {
            short_url.clone()
        } else {
            e.title.clone()
        };
        let item: Element<Message> = Button::new(
            Column::new()
                .push(
                    Text::new(display)
                        .size(12)
                        .color(if dark { Color::from_rgb(0.82, 0.82, 0.88) } else { Color::from_rgb(0.12, 0.12, 0.20) }),
                )
                .push(
                    Text::new(short_url)
                        .size(10)
                        .color(if dark { Color::from_rgb(0.42, 0.42, 0.52) } else { Color::from_rgb(0.38, 0.38, 0.50) }),
                )
                .push(
                    Text::new(format_relative_time(e.timestamp_ms, now_ms))
                        .size(9)
                        .color(if dark { Color::from_rgb(0.32, 0.32, 0.40) } else { Color::from_rgb(0.50, 0.50, 0.58) }),
                )
                .spacing(1),
        )
        .on_press(Message::NavigateHistory(url))
        .width(Length::Fill)
        .padding(iced::Padding::from([6, 12]))
        .style(move |_theme, status| {
            let hovered = matches!(status, button::Status::Hovered);
            button::Style {
                background: if hovered {
                    Some(iced::Background::Color(if dark {
                        Color::from_rgba(1.0, 1.0, 1.0, 0.05)
                    } else {
                        Color::from_rgba(0.0, 0.0, 0.0, 0.05)
                    }))
                } else { None },
                border: iced::Border::default(),
                shadow: iced::Shadow::default(),
                text_color: if dark { Color::WHITE } else { Color::from_rgb(0.10, 0.10, 0.18) },
                snap: false,
            }
        })
        .into();
        list_col = list_col.push(item);
    }

    // iced's Column distributes Fill-height children by giving each the full
    // child_limits max, which causes the Column to wrap the Scrollable into a
    // second invisible column.  Use Fixed heights instead to sidestep this.
    let list_h = (panel_h - 115.0).max(80.0);
    let list = Scrollable::new(list_col).height(Length::Fixed(list_h));

    Container::new(
        Column::new()
            .push(header)
            .push(del_row)
            .push(divider)
            .push(list)
            .width(Length::Fixed(280.0)),
    )
    .width(Length::Fixed(280.0))
    .height(Length::Fixed(panel_h))
    .style(move |_| container::Style {
        background: Some(iced::Background::Color(
            if dark { Color::from_rgba(0.07, 0.07, 0.11, 0.97) } else { Color::from_rgba(0.96, 0.96, 0.98, 0.98) }
        )),
        border: iced::Border {
            color: Color::from_rgba(0.467, 0.0, 1.0, if dark { 0.22 } else { 0.30 }),
            width: 1.0,
            radius: 0.0.into(),
        },
        shadow: iced::Shadow::default(),
        ..Default::default()
    })
    .into()
}

// ── downloads panel ────────────────────────────────────────────────────────────

fn downloads_panel(
    entries: &[super::downloads::DownloadEntry],
    panel_h: f32,
    dark: bool,
    anim_phase: f32,
) -> Element<'_, Message> {
    use super::downloads::DownloadStatus;

    let text_c = if dark { Color::from_rgb(0.85, 0.85, 0.92) } else { Color::from_rgb(0.15, 0.15, 0.22) };
    let sub_c  = if dark { Color::from_rgb(0.42, 0.42, 0.52) } else { Color::from_rgb(0.38, 0.38, 0.50) };

    let close_btn = Button::new(
        Text::new("\u{2715}").size(13).color(
            if dark { Color::from_rgb(0.65, 0.65, 0.70) } else { Color::from_rgb(0.30, 0.30, 0.36) }
        ),
    )
    .on_press(Message::ToggleDownloads)
    .style(move |_theme, _status| nav_btn_style(dark));

    let clear_btn = Button::new(Text::new("Clear done").size(10))
        .on_press(Message::ClearDoneDownloads)
        .style(move |_theme, _status| button::Style {
            background: None,
            border: iced::Border {
                color: Color::from_rgba(0.467, 0.0, 1.0, 0.25),
                width: 0.75,
                radius: 4.0.into(),
            },
            shadow: iced::Shadow::default(),
            text_color: if dark {
                Color::from_rgb(0.50, 0.50, 0.70)
            } else {
                Color::from_rgb(0.30, 0.30, 0.55)
            },
            snap: false,
        });

    let header = Container::new(
        Row::new()
            .push(Text::new("Downloads").size(14).color(text_c))
            .push(Space::new().width(Length::Fill))
            .push(clear_btn)
            .push(Space::new().width(Length::Fixed(6.0)))
            .push(close_btn)
            .align_y(alignment::Vertical::Center),
    )
    .width(Length::Fill)
    .padding(iced::Padding::from([10, 12]));

    let divider = || -> Element<Message> {
        Container::new(Space::new().width(Length::Fill).height(Length::Fixed(1.0)))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(iced::Background::Color(
                    if dark { Color::from_rgba(1.0, 1.0, 1.0, 0.06) } else { Color::from_rgba(0.0, 0.0, 0.0, 0.08) }
                )),
                ..Default::default()
            })
            .into()
    };

    let mut list_col = Column::new().spacing(0).width(Length::Fill);
    if entries.is_empty() {
        list_col = list_col.push(
            Container::new(Text::new("No downloads yet").size(12).color(sub_c))
                .width(Length::Fill)
                .padding(iced::Padding::from([24, 12]))
                .align_x(alignment::Horizontal::Center),
        );
    }

    for entry in entries.iter().rev() {
        let id = entry.id;
        let final_dest = entry.final_dest.clone();
        let bytes_str = if let Some(total) = entry.total_bytes {
            format!("{} / {}", format_bytes(entry.bytes_downloaded), format_bytes(total))
        } else {
            format_bytes(entry.bytes_downloaded)
        };
        let speed_str = if entry.speed_bps > 0
            && entry.status == DownloadStatus::InProgress
        {
            format!("  {}/s", format_bytes(entry.speed_bps))
        } else {
            String::new()
        };

        let status_row: Element<Message> = match entry.status {
            DownloadStatus::InProgress => {
                // Deterministic bar when total size is known, oscillating otherwise.
                let bar_val = match entry.total_bytes {
                    Some(total) if total > 0 =>
                        (entry.bytes_downloaded as f32 / total as f32).clamp(0.0, 1.0),
                    _ => (anim_phase.sin() * 0.5 + 0.5).clamp(0.0, 1.0),
                };
                Column::new()
                    .push(
                        Row::new()
                            .push(Text::new(format!("\u{2b07} {}{}", bytes_str, speed_str)).size(10).color(
                                if dark { Color::from_rgb(0.40, 0.70, 1.0) } else { Color::from_rgb(0.10, 0.40, 0.80) }
                            ))
                            .push(Space::new().width(Length::Fill))
                            .push(
                                Button::new(Text::new("Cancel").size(9))
                                    .on_press(Message::CancelDownload(id))
                                    .padding(iced::Padding::from([2, 5]))
                                    .style(|_theme, _status| button::Style {
                                        background: Some(iced::Background::Color(
                                            Color::from_rgba(0.8, 0.15, 0.15, 0.20)
                                        )),
                                        border: iced::Border {
                                            color: Color::from_rgba(1.0, 0.35, 0.35, 0.40),
                                            width: 1.0,
                                            radius: 4.0.into(),
                                        },
                                        shadow: iced::Shadow::default(),
                                        text_color: Color::from_rgb(0.92, 0.55, 0.55),
                                        snap: false,
                                    })
                            )
                            .align_y(alignment::Vertical::Center),
                    )
                    .push(Space::new().height(Length::Fixed(4.0)))
                    .push(
                        ProgressBar::new(0.0..=1.0, bar_val)
                            .girth(Length::Fixed(4.0))
                            .style(move |_theme| progress_bar::Style {
                                background: iced::Background::Color(
                                    if dark { Color::from_rgba(1.0, 1.0, 1.0, 0.10) } else { Color::from_rgba(0.0, 0.0, 0.0, 0.10) }
                                ),
                                bar: iced::Background::Color(Color { r: 0.467, g: 0.0, b: 1.0, a: 1.0 }),
                                border: iced::Border { radius: 2.0.into(), ..Default::default() },
                            })
                    )
                    .spacing(0)
                    .into()
            }
            DownloadStatus::Completed => {
                let _fp = final_dest.clone();
                Row::new()
                    .push(
                        Text::new(format!("\u{2713} {} \u{2014} {}", bytes_str,
                            if dark { "Done" } else { "Done" }))
                            .size(10)
                            .color(if dark { Color::from_rgb(0.30, 0.85, 0.45) } else { Color::from_rgb(0.10, 0.60, 0.25) })
                    )
                    .push(Space::new().width(Length::Fill))
                    .push(
                        Button::new(Text::new("Open").size(9))
                            .on_press(Message::OpenDownloadedFile(id))
                            .padding(iced::Padding::from([2, 5]))
                            .style(move |_theme, _status| small_action_btn_style(dark))
                    )
                    .push(Space::new().width(Length::Fixed(3.0)))
                    .push(
                        Button::new(Text::new("Reveal").size(9))
                            .on_press(Message::RevealDownload(id))
                            .padding(iced::Padding::from([2, 5]))
                            .style(move |_theme, _status| small_action_btn_style(dark))
                    )
                    .align_y(alignment::Vertical::Center)
                    .into()
            }
            DownloadStatus::Failed => {
                Text::new("\u{2717} Failed")
                    .size(10)
                    .color(if dark { Color::from_rgb(0.90, 0.40, 0.40) } else { Color::from_rgb(0.75, 0.15, 0.15) })
                    .into()
            }
            DownloadStatus::Cancelled => {
                Text::new("\u{2715} Cancelled")
                    .size(10)
                    .color(if dark { Color::from_rgb(0.60, 0.60, 0.65) } else { Color::from_rgb(0.45, 0.45, 0.50) })
                    .into()
            }
        };

        let item: Element<Message> = Container::new(
            Column::new()
                .push(Text::new(&entry.filename).size(12).color(text_c))
                .push(Text::new(short_url_display(&entry.url)).size(10).color(sub_c))
                .push(Space::new().height(Length::Fixed(3.0)))
                .push(status_row)
                .spacing(1),
        )
        .width(Length::Fill)
        .padding(iced::Padding::from([8, 12]))
        .style(move |_| container::Style {
            border: iced::Border {
                color: if dark {
                    Color::from_rgba(1.0, 1.0, 1.0, 0.04)
                } else {
                    Color::from_rgba(0.0, 0.0, 0.0, 0.05)
                },
                width: 0.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into();
        list_col = list_col.push(item);
        list_col = list_col.push(divider());
    }

    let list_h = (panel_h - 80.0).max(80.0);
    let list = Scrollable::new(list_col).height(Length::Fixed(list_h));

    Container::new(
        Column::new()
            .push(header)
            .push(divider())
            .push(list)
            .width(Length::Fixed(280.0)),
    )
    .width(Length::Fixed(280.0))
    .height(Length::Fixed(panel_h))
    .style(move |_| container::Style {
        background: Some(iced::Background::Color(
            if dark {
                Color::from_rgba(0.07, 0.07, 0.11, 0.97)
            } else {
                Color::from_rgba(0.96, 0.96, 0.98, 0.98)
            },
        )),
        border: iced::Border {
            color: Color::from_rgba(0.467, 0.0, 1.0, if dark { 0.22 } else { 0.30 }),
            width: 1.0,
            radius: 0.0.into(),
        },
        shadow: iced::Shadow::default(),
        ..Default::default()
    })
    .into()
}

// ── vault panel ───────────────────────────────────────────────────────────────

fn vault_panel<'a>(
    vault: Option<&'a super::vault::Vault>,
    password_draft: &'a str,
    status: &'a str,
    panel_h: f32,
    dark: bool,
) -> Element<'a, Message> {
    let panel_bg = if dark { Color::from_rgba(0.07, 0.07, 0.10, 0.97) } else { Color::from_rgba(0.95, 0.95, 0.97, 0.97) };
    let text_c   = if dark { Color::from_rgb(0.85, 0.85, 0.92) } else { Color::from_rgb(0.12, 0.12, 0.20) };
    let sub_c    = if dark { Color::from_rgb(0.42, 0.42, 0.52) } else { Color::from_rgb(0.38, 0.38, 0.50) };
    let accent   = if dark { Color::from_rgba(0.467, 0.0, 1.0, 0.80) } else { Color::from_rgba(0.30, 0.0, 0.85, 0.90) };

    let close_btn = Button::new(Text::new("\u{2715}").size(13).color(sub_c))
        .on_press(Message::CloseVaultPanel)
        .style(move |_t, _s| button::Style { background: None, ..Default::default() });

    let header = Row::new()
        .push(Text::new("\u{1f510}  Vault").size(13).color(text_c))
        .push(Space::new().width(Length::Fill))
        .push(close_btn)
        .align_y(alignment::Vertical::Center);

    let mut col = Column::new().spacing(8).padding(iced::Padding::from([10, 12]));
    col = col.push(header);

    if vault.is_none() {
        // ── Locked: show password input ─────────────────────────────────────
        col = col.push(
            TextInput::new("Master password\u{2026}", password_draft)
                .id(iced::widget::Id::new("vault_pw"))
                .on_input(Message::VaultPasswordChanged)
                .on_submit(Message::VaultUnlock)
                .secure(true)
                .padding(iced::Padding::from([5, 8]))
                .size(13)
                .style(move |_t, status| url_bar_style(matches!(status, text_input::Status::Focused { .. }), dark)),
        );
        col = col.push(
            Button::new(Text::new("Unlock / Create").size(12).color(Color::WHITE))
                .on_press(Message::VaultUnlock)
                .width(Length::Fill)
                .padding(iced::Padding::from([6, 10]))
                .style(move |_t, _s| button::Style {
                    background: Some(iced::Background::Color(accent)),
                    border: iced::Border { radius: 6.0.into(), ..Default::default() },
                    text_color: Color::WHITE,
                    ..Default::default()
                }),
        );
    } else {
        // ── Unlocked: prominent Fill button + credentials list ───────────────
        col = col.push(
            Button::new(
                Text::new("\u{2328}  Fill credentials on this page").size(12).color(Color::WHITE),
            )
            .on_press(Message::VaultFillPage)
            .width(Length::Fill)
            .padding(iced::Padding::from([7, 10]))
            .style(move |_t, _s| button::Style {
                background: Some(iced::Background::Color(accent)),
                border: iced::Border { radius: 6.0.into(), ..Default::default() },
                text_color: Color::WHITE,
                ..Default::default()
            }),
        );

        if let Some(v) = vault {
            let entries = v.all();
            if entries.is_empty() {
                col = col.push(Text::new("No saved credentials.").size(11).color(sub_c));
            } else {
                for entry in entries {
                    let d = entry.domain.clone();
                    let u = entry.username.clone();
                    let entry_row: Element<Message> = Row::new()
                        .push(
                            Column::new()
                                .push(Text::new(entry.domain.as_str()).size(12).color(text_c))
                                .push(Text::new(entry.username.as_str()).size(10).color(sub_c))
                                .spacing(1)
                                .width(Length::Fill),
                        )
                        .push(
                            Button::new(Text::new("del").size(10).color(sub_c))
                                .on_press(Message::VaultDelete(d, u))
                                .padding(iced::Padding::from([2, 5]))
                                .style(move |_t, _s| button::Style {
                                    background: None,
                                    border: iced::Border {
                                        color: Color::from_rgba(0.5, 0.0, 0.0, 0.5),
                                        width: 1.0,
                                        radius: 4.0.into(),
                                    },
                                    ..Default::default()
                                }),
                        )
                        .align_y(alignment::Vertical::Center)
                        .into();
                    col = col.push(entry_row);
                }
            }
        }

        col = col.push(Space::new().height(Length::Fixed(4.0)));
        col = col.push(
            Button::new(Text::new("Lock vault").size(11).color(sub_c))
                .on_press(Message::VaultLock)
                .style(move |_t, _s| button::Style { background: None, ..Default::default() }),
        );
    }

    if !status.is_empty() {
        col = col.push(Text::new(status).size(10).color(sub_c));
    }

    Container::new(
        Scrollable::new(col).height(Length::Fixed(panel_h)),
    )
    .width(Length::Fixed(280.0))
    .height(Length::Fixed(panel_h))
    .style(move |_| container::Style {
        background: Some(iced::Background::Color(panel_bg)),
        border: iced::Border {
            color: Color::from_rgba(0.467, 0.0, 1.0, if dark { 0.22 } else { 0.30 }),
            width: 1.0,
            radius: 0.0.into(),
        },
        shadow: iced::Shadow::default(),
        ..Default::default()
    })
    .into()
}

// ── helpers ────────────────────────────────────────────────────────────────────

/// Width of whichever right-side panel is currently open (0 if none).
fn right_panel_w(state: &BrowserState) -> f32 {
    if state.show_history || state.show_downloads || state.vault_panel_open { 280.0 } else { 0.0 }
}

/// Height in logical pixels reserved below the address bar for the Actions
/// dropdown.  When the dropdown is open the WebView is shifted down by this
/// amount so iced can render the dropdown without it being obscured by the
/// native OS child view.
const ACTIONS_DROPDOWN_H: f32 = 40.0;

fn actions_extra_h(state: &BrowserState) -> f32 {
    if state.actions_menu_open { ACTIONS_DROPDOWN_H } else { 0.0 }
}

/// Open `path` with the system default application.
/// If `reveal` is `true`, reveal it in the file manager instead.
fn open_path_with_system(path: &std::path::Path, reveal: bool) {
    #[cfg(target_os = "macos")]
    {
        if reveal {
            let _ = std::process::Command::new("open")
                .args(["-R"])
                .arg(path)
                .spawn();
        } else {
            let _ = std::process::Command::new("open")
                .arg(path)
                .spawn();
        }
    }
    #[cfg(target_os = "windows")]
    {
        if reveal {
            let _ = std::process::Command::new("explorer")
                .arg(format!("/select,{}", path.display()))
                .spawn();
        } else {
            let _ = std::process::Command::new("cmd")
                .args(["/c", "start", ""])
                .arg(path)
                .spawn();
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let target = if reveal {
            path.parent().unwrap_or(path)
        } else {
            path
        };
        let _ = std::process::Command::new("xdg-open").arg(target).spawn();
    }
}

/// Compute the Unix timestamp (ms) that is `amount` `unit`s before now.
fn ms_ago(amount: f32, unit: TimeUnit) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let n = amount.round() as u64;
    let delta_ms: u64 = match unit {
        TimeUnit::Seconds => n * 1_000,
        TimeUnit::Minutes => n * 60 * 1_000,
        TimeUnit::Hours   => n * 3_600 * 1_000,
        TimeUnit::Days    => n * 86_400 * 1_000,
        TimeUnit::Months  => n * 30 * 86_400 * 1_000,
        TimeUnit::Years   => n * 365 * 86_400 * 1_000,
    };
    now_ms.saturating_sub(delta_ms)
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1_024 {
        format!("{:.0} KB", bytes as f64 / 1_024.0)
    } else {
        format!("{} B", bytes)
    }
}

/// Return a path that doesn't conflict with any existing download entry or
/// on-disk file by appending `-2`, `-3`, … to the file stem when needed.
/// e.g. `video.mp4` → `video-2.mp4` → `video-3.mp4` …
fn unique_download_dest(
    base: &std::path::Path,
    downloads: &[super::downloads::DownloadEntry],
) -> std::path::PathBuf {
    let conflicts = |p: &std::path::Path| {
        downloads.iter().any(|d| d.final_dest == p || d.temp_dest == p)
            || p.exists()
    };
    if !conflicts(base) {
        return base.to_path_buf();
    }
    let stem = base
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = base
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let parent = base.parent().unwrap_or(std::path::Path::new("."));
    for n in 2u32.. {
        let candidate = parent.join(format!("{}-{}{}", stem, n, ext));
        if !conflicts(&candidate) {
            return candidate;
        }
    }
    base.to_path_buf()
}

fn small_action_btn_style(dark: bool) -> button::Style {
    button::Style {
        background: Some(iced::Background::Color(
            if dark { Color::from_rgba(1.0, 1.0, 1.0, 0.07) } else { Color::from_rgba(0.0, 0.0, 0.0, 0.07) }
        )),
        border: iced::Border {
            color: if dark { Color::from_rgba(1.0, 1.0, 1.0, 0.12) } else { Color::from_rgba(0.0, 0.0, 0.0, 0.12) },
            width: 1.0,
            radius: 4.0.into(),
        },
        shadow: iced::Shadow::default(),
        text_color: if dark { Color::from_rgb(0.72, 0.72, 0.80) } else { Color::from_rgb(0.25, 0.25, 0.35) },
        snap: false,
    }
}

fn format_relative_time(ms: u64, now_ms: u64) -> String {
    let diff_s = now_ms.saturating_sub(ms) / 1000;
    if diff_s < 60 {
        format!("{}s ago", diff_s)
    } else if diff_s < 3600 {
        format!("{}m ago", diff_s / 60)
    } else if diff_s < 86400 {
        format!("{}h ago", diff_s / 3600)
    } else {
        format!("{}d ago", diff_s / 86400)
    }
}

fn short_url_display(url: &str) -> String {
    let s = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    // Walk by char boundary — no Vec<char> allocation needed.
    match s.char_indices().nth(38) {
        Some((byte_pos, _)) => format!("{}\u{2026}", &s[..byte_pos]),
        None => s.to_string(),
    }
}

fn del_range_btn_style() -> button::Style {
    button::Style {
        background: Some(iced::Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.07))),
        border: iced::Border {
            color: Color::from_rgba(1.0, 1.0, 1.0, 0.10),
            width: 1.0,
            radius: 5.0.into(),
        },
        shadow: iced::Shadow::default(),
        text_color: Color::from_rgb(0.65, 0.65, 0.72),
        snap: false,
    }
}

fn del_all_btn_style() -> button::Style {
    button::Style {
        background: Some(iced::Background::Color(Color::from_rgba(0.8, 0.1, 0.1, 0.20))),
        border: iced::Border {
            color: Color::from_rgba(1.0, 0.3, 0.3, 0.35),
            width: 1.0,
            radius: 5.0.into(),
        },
        shadow: iced::Shadow::default(),
        text_color: Color::from_rgb(0.92, 0.55, 0.55),
        snap: false,
    }
}

// ── IPC handling ──────────────────────────────────────────────────────────────

/// Parse and act on an IPC message from `window.ipc.postMessage(json)`.
///
/// Messages are JSON objects with a `type` field:
/// ```json
/// {"type":"add_quicklink","url":"https://…","title":"Page Title"}
/// {"type":"remove_quicklink","url":"https://…"}
/// {"type":"reorder_quicklinks","order":[2,0,1]}
/// ```
fn handle_ipc(state: &BrowserState, msg: &str) {
    // Minimal hand-rolled JSON field extractor — avoids a serde dependency.
    let get = |key: &str| -> Option<String> {
        let needle = format!("\"{}\":", key);
        let start = msg.find(needle.as_str())? + needle.len();
        let rest = msg[start..].trim_start();
        if rest.starts_with('"') {
            let inner = &rest[1..];
            let end = inner.find('"')?;
            Some(inner[..end].to_string())
        } else if rest.starts_with('[') {
            // JSON array — read until the matching ']'
            let end = rest.find(']').map(|i| i + 1).unwrap_or(rest.len());
            Some(rest[..end].to_string())
        } else {
            // number or other scalar — read until delimiter
            let end = rest.find(|c: char| c == ',' || c == '}').unwrap_or(rest.len());
            Some(rest[..end].trim().to_string())
        }
    };

    let Some(kind) = get("type") else { return };

    match kind.as_str() {
        "add_quicklink" => {
            let url   = get("url").unwrap_or_default();
            let title = get("title").unwrap_or_default();
            if !url.is_empty() {
                let links = quicklinks::add(url, title);
                // If we're currently on the homepage, refresh its quicklinks.
                if state.tabs.get(state.active_tab)
                    .map(|t| t.url == "tkz:home")
                    .unwrap_or(false)
                {
                    inject_quicklinks_from(&links);
                }
            }
        }
        "remove_quicklink" => {
            let url = get("url").unwrap_or_default();
            if !url.is_empty() {
                let links = quicklinks::remove(&url);
                inject_quicklinks_from(&links);
            }
        }
        "reorder_quicklinks" => {
            // Parse a simple JSON array of integers like [2,0,1]
            if let Some(raw) = get("order") {
                // `get` returns the raw "[2,0,1]" string
                let indices: Vec<usize> = raw
                    .trim_matches(|c| c == '[' || c == ']')
                    .split(',')
                    .filter_map(|s| s.trim().parse::<usize>().ok())
                    .collect();
                let links = quicklinks::load();
                // Build reordered list from index array.
                let reordered: Vec<quicklinks::QuickLink> = indices.iter()
                    .filter_map(|&i| links.get(i).cloned())
                    .collect();
                quicklinks::save(&reordered);
                inject_quicklinks_from(&reordered);
            }
        }
        "enter_fullscreen" => {
            // Dispatched by FULLSCREEN_INIT_SCRIPT when a page requests
            // fullscreen (e.g. Netflix, YouTube full-screen button).
            // We handle it in the next update cycle via Task::done.
        }
        "exit_fullscreen" => {}
        _ => {}
    }
}

/// Returns true if the effective theme is dark (accounting for Auto + local time).
fn effective_dark(mode: ThemeMode) -> bool {
    match mode {
        ThemeMode::Dark  => true,
        ThemeMode::Light => false,
        ThemeMode::Auto  => {
            use chrono::Timelike;
            let h = chrono::Local::now().hour();
            !(7..19).contains(&h)
        }
    }
}

/// Inject the current theme into the active homepage via JS.
fn inject_theme(dark: bool) {
    let t = if dark { "dark" } else { "light" };
    webview::eval_script(&format!(
        "if(window.__tkzSetTheme)window.__tkzSetTheme({dark});\
         localStorage.setItem('tkz-theme','{t}');",
        dark = dark,
    ));
}

/// Push the given quicklinks list into the active homepage via JS eval.
fn inject_quicklinks_from(links: &[quicklinks::QuickLink]) {
    let json  = quicklinks::to_json(links);
    let js    = format!("if(window.__tkzSetLinks)window.__tkzSetLinks({json});");
    webview::eval_script(&js);
}

/// Load quicklinks from disk and inject them (used for tab-switch / init).
fn inject_quicklinks() {
    inject_quicklinks_from(&quicklinks::load());
}

/// Remove tab groups that no longer have any member tabs.
fn cleanup_empty_groups(state: &mut BrowserState) {
    state.tab_groups.retain(|g| state.tabs.iter().any(|t| t.group_id == Some(g.id)));
}
