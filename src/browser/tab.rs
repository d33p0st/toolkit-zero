//! Vertical sliding tab panel drawn with iced Canvas.
//!
//! A narrow 12 px trigger strip lives to the left of the WebView.
//! Hovering it animates `tab_panel_w` toward PANEL_EXPANDED_W (180 px),
//! revealing pill-shaped tabs with short site names.  Mouse leave collapses it.

use std::sync::Arc;

use iced::{
    Color, Point, Rectangle, Renderer, Theme,
    mouse,
    widget::canvas::{self, Action, Frame, Geometry, Path, Stroke},
    widget::text,
};

use super::app::Message;

// ── constants ────────────────────────────────────────────────────────────────────────────────

/// Width of the collapsed hover-trigger strip (nearly-invisible hairline).
pub const PANEL_COLLAPSED_W: f32 = 5.0;
/// Width of the fully expanded tab panel.
pub const PANEL_EXPANDED_W: f32 = 180.0;
/// Height of one tab pill (logical pixels).
const TAB_H: f32 = 22.0;
/// Vertical gap between tab pills.
const TAB_GAP: f32 = 3.0;
/// Top padding inside the panel before the first tab.
const TAB_TOP: f32 = 10.0;
/// Horizontal inset of pills inside the panel.
const TAB_PAD: f32 = 8.0;
/// Panel width threshold below which "collapsed" rendering is used.
const EXPAND_THRESHOLD: f32 = 40.0;
/// Bezier K for a quarter-circle approximation.
const K: f32 = 0.5523;

/// Accent colours cycled through as tab groups are created.
pub const GROUP_COLORS: &[[f32; 3]] = &[
    [0.28, 0.52, 1.00],  // blue
    [0.28, 0.80, 0.44],  // green
    [0.96, 0.65, 0.20],  // amber
    [0.73, 0.30, 0.96],  // purple
    [0.96, 0.33, 0.33],  // red
    [0.22, 0.78, 0.78],  // teal
];

// ── tab group ─────────────────────────────────────────────────────────────────────────────

/// A named, coloured collection of tabs.
#[derive(Debug, Clone, PartialEq)]
pub struct TabGroup {
    pub id: u64,
    pub name: String,
    /// Index into [`GROUP_COLORS`].
    pub color_idx: usize,
}

// ── data ────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Tab {
    pub title: String,
    /// Current display URL.  For HTML home tabs this is `"tkz:home"`.
    pub url: String,
    /// Original HTML for `Target::Html` / homepage tabs, shared via Arc so
    /// cloning Tab is O(1) regardless of HTML size.
    pub home_html: Option<Arc<str>>,
    /// Per-tab navigation stack (URL strings; `"tkz:home"` for HTML entries).
    pub nav_history: Vec<String>,
    /// Index into `nav_history` pointing at the currently visible page.
    pub nav_pos: usize,
    /// Optional group membership.
    pub group_id: Option<u64>,
}

impl Tab {
    /// Create a URL-navigated tab.
    pub fn new(url: impl Into<String>) -> Self {
        let u = url.into();
        Tab {
            title: "New Tab".to_string(),
            url: u.clone(),
            home_html: None,
            nav_history: vec![u],
            nav_pos: 0,
            group_id: None,
        }
    }

    /// Create an HTML-injected tab (stores the HTML so it can be re-injected
    /// when the user back-navigates to this tab's home entry).
    pub fn new_html(html: Arc<str>) -> Self {
        Tab {
            title: "New Tab".to_string(),
            url: "tkz:home".to_string(),
            home_html: Some(html),
            nav_history: vec!["tkz:home".to_string()],
            nav_pos: 0,
            group_id: None,
        }
    }

    /// Push `url` onto this tab's navigation stack.
    ///
    /// Any forward history beyond the current position is discarded first
    /// (mirrors how every real browser handles mid-history navigation).
    pub fn push_nav(&mut self, url: String) {
        self.nav_history.truncate(self.nav_pos + 1);
        self.nav_history.push(url);
        self.nav_pos += 1;
    }

    /// `true` if there is a page to go back to.
    pub fn can_go_back(&self) -> bool {
        self.nav_pos > 0
    }

    /// `true` if there is a page to go forward to.
    pub fn can_go_forward(&self) -> bool {
        self.nav_pos + 1 < self.nav_history.len()
    }
}

// ── canvas state ──────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct TabPanelState {
    hovered_tab: Option<usize>,
    cursor_in_panel: bool,
}

// ── canvas program ───────────────────────────────────────────────────────────────

pub struct VerticalTabBar {
    pub tabs: Vec<Tab>,
    pub active: usize,
    /// Current animated width -- drives both rendering and hit-testing.
    pub panel_w: f32,
    /// Active tab groups (for indicators and the New Group button).
    pub groups: Vec<TabGroup>,
    /// Whether the UI is currently in dark mode.
    pub dark: bool,
}

impl canvas::Program<Message> for VerticalTabBar {
    type State = TabPanelState;

    fn update(
        &self,
        state: &mut TabPanelState,
        event: &canvas::Event,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Option<Action<Message>> {
        match event {
            canvas::Event::Mouse(mouse::Event::CursorMoved { .. }) => {
                let in_panel = cursor.position_in(bounds).is_some();
                let panel_changed = in_panel != state.cursor_in_panel;
                state.cursor_in_panel = in_panel;

                let prev_tab = state.hovered_tab;
                if in_panel {
                    if let Some(pos) = cursor.position_in(bounds) {
                        state.hovered_tab =
                            tab_hit_test(&self.tabs, self.panel_w, pos);
                    }
                } else {
                    state.hovered_tab = None;
                }

                if panel_changed {
                    return Some(Action::publish(Message::TabsHovered(in_panel)));
                }
                if state.hovered_tab != prev_tab {
                    return Some(Action::request_redraw());
                }
                None
            }

            canvas::Event::Mouse(mouse::Event::CursorLeft) => {
                state.cursor_in_panel = false;
                state.hovered_tab = None;
                Some(Action::publish(Message::TabsHovered(false)))
            }

            canvas::Event::Mouse(mouse::Event::ButtonPressed(
                mouse::Button::Left,
            )) => {
                let pos = cursor.position_in(bounds)?;
                if self.panel_w >= EXPAND_THRESHOLD {
                    if let Some(idx) = close_btn_hit(&self.tabs, self.panel_w, pos) {
                        return Some(Action::publish(Message::CloseTab(idx)));
                    }
                }
                match tab_hit_test(&self.tabs, self.panel_w, pos) {
                    Some(idx) if idx < self.tabs.len() => {
                        Some(Action::publish(Message::SelectTab(idx)))
                    }
                    Some(idx) if idx == self.tabs.len() => {
                        Some(Action::publish(Message::NewTab))
                    }
                    Some(_) => Some(Action::publish(Message::CreateTabGroup)),
                    None => None,
                }
            }

            canvas::Event::Mouse(mouse::Event::ButtonPressed(
                mouse::Button::Right,
            )) => {
                // Right-click on a tab pill cycles it through available groups.
                let pos = cursor.position_in(bounds)?;
                if self.panel_w < EXPAND_THRESHOLD {
                    return None;
                }
                if let Some(idx) = tab_hit_test(&self.tabs, self.panel_w, pos) {
                    if idx < self.tabs.len() {
                        return Some(Action::publish(Message::CycleTabGroup(idx)));
                    }
                }
                None
            }

            canvas::Event::Mouse(mouse::Event::ButtonPressed(
                mouse::Button::Middle,
            )) => {
                let pos = cursor.position_in(bounds)?;
                if let Some(idx) = tab_hit_test(&self.tabs, self.panel_w, pos) {
                    if idx < self.tabs.len() {
                        return Some(Action::publish(Message::CloseTab(idx)));
                    }
                }
                None
            }

            _ => None,
        }
    }

    fn mouse_interaction(
        &self,
        state: &TabPanelState,
        _bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> mouse::Interaction {
        if state.hovered_tab.is_some() {
            mouse::Interaction::Pointer
        } else {
            mouse::Interaction::default()
        }
    }

    fn draw(
        &self,
        state: &TabPanelState,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<Geometry<Renderer>> {
        let mut frame = Frame::new(renderer, bounds.size());
        let w = self.panel_w;
        let expanded = w >= EXPAND_THRESHOLD;

        let alpha = if expanded {
            ((w - EXPAND_THRESHOLD) / (PANEL_EXPANDED_W - EXPAND_THRESHOLD))
                .clamp(0.0, 1.0)
        } else {
            0.0
        };

        if alpha > 0.0 {
            frame.fill(
                &Path::new(|b| {
                    b.rectangle(Point::ORIGIN, iced::Size::new(w, bounds.height));
                }),
                if self.dark {
                    Color::from_rgba(0.07, 0.07, 0.10, alpha * 0.96)
                } else {
                    Color::from_rgba(0.88, 0.88, 0.92, alpha * 0.97)
                },
            );
        }

        if !expanded {
            frame.stroke(
                &Path::line(
                    Point::new(w - 0.5, 0.0),
                    Point::new(w - 0.5, bounds.height),
                ),
                Stroke::default()
                    .with_color(if self.dark {
                        Color::from_rgba(1.0, 1.0, 1.0, 0.06)
                    } else {
                        Color::from_rgba(0.0, 0.0, 0.0, 0.08)
                    })
                    .with_width(0.5),
            );
            let dx = w / 2.0;
            for (i, tab) in self.tabs.iter().enumerate() {
                let dy = TAB_TOP + i as f32 * (TAB_H + TAB_GAP) + TAB_H / 2.0;
                // Use group accent colour for active grouped tabs.
                let dot_color = if i == self.active {
                    tab.group_id
                        .and_then(|gid| self.groups.iter().find(|g| g.id == gid))
                        .map(|g| {
                            let [r, gc, b] = GROUP_COLORS[g.color_idx % GROUP_COLORS.len()];
                            Color::from_rgb(r, gc, b)
                        })
                        .unwrap_or(Color::from_rgb(0.30, 0.52, 1.0))
                } else if state.hovered_tab == Some(i) {
                    if self.dark { Color::from_rgb(0.50, 0.50, 0.60) } else { Color::from_rgb(0.40, 0.40, 0.55) }
                } else {
                    if self.dark { Color::from_rgb(0.22, 0.22, 0.30) } else { Color::from_rgb(0.62, 0.62, 0.72) }
                };
                frame.fill(&Path::circle(Point::new(dx, dy), 1.5), dot_color);
            }
            return vec![frame.into_geometry()];
        }

        let pill_w = w - 2.0 * TAB_PAD;

        for (i, tab) in self.tabs.iter().enumerate() {
            let y = TAB_TOP + i as f32 * (TAB_H + TAB_GAP);
            let rect = Rectangle::new(
                Point::new(TAB_PAD, y),
                iced::Size::new(pill_w, TAB_H),
            );
            let is_active = i == self.active;
            let is_hov = state.hovered_tab == Some(i);

            frame.fill(
                &pill(rect),
                if is_active {
                    if self.dark { Color::from_rgba(0.18, 0.32, 0.72, alpha) } else { Color::from_rgba(0.25, 0.45, 0.90, alpha) }
                } else if is_hov {
                    if self.dark { Color::from_rgba(0.17, 0.17, 0.23, alpha) } else { Color::from_rgba(0.78, 0.78, 0.87, alpha) }
                } else {
                    if self.dark { Color::from_rgba(0.11, 0.11, 0.15, alpha) } else { Color::from_rgba(0.84, 0.84, 0.89, alpha * 0.7) }
                },
            );

            frame.fill_text(canvas::Text {
                content: site_name(&tab.url),
                position: Point::new(TAB_PAD + 10.0, y + TAB_H / 2.0 - 6.5),
                color: if is_active {
                    if self.dark { Color::from_rgba(1.0, 1.0, 1.0, alpha) } else { Color::from_rgba(0.08, 0.08, 0.15, alpha) }
                } else {
                    if self.dark { Color::from_rgba(0.68, 0.68, 0.75, alpha) } else { Color::from_rgba(0.28, 0.28, 0.38, alpha) }
                },
                size: iced::Pixels(12.0),
                font: iced::Font::DEFAULT,
                align_x: text::Alignment::Left,
                align_y: iced::alignment::Vertical::Top,
                line_height: text::LineHeight::default(),
                shaping: text::Shaping::Basic,
                max_width: pill_w - 26.0,
            });

            if is_active || is_hov {
                let cx = TAB_PAD + pill_w - 12.0;
                let cy = y + TAB_H / 2.0;
                frame.fill(
                    &Path::circle(Point::new(cx, cy), 7.0),
                    if self.dark { Color::from_rgba(1.0, 1.0, 1.0, 0.09 * alpha) } else { Color::from_rgba(0.0, 0.0, 0.0, 0.07 * alpha) },
                );
                frame.fill_text(canvas::Text {
                    content: "x".to_string(),
                    position: Point::new(cx - 3.5, cy - 6.5),
                    color: if self.dark { Color::from_rgba(0.80, 0.80, 0.80, alpha) } else { Color::from_rgba(0.25, 0.25, 0.35, alpha) },
                    size: iced::Pixels(13.0),
                    font: iced::Font::DEFAULT,
                    align_x: text::Alignment::Left,
                    align_y: iced::alignment::Vertical::Top,
                    line_height: text::LineHeight::default(),
                    shaping: text::Shaping::Basic,
                    max_width: 14.0,
                });
            }

            // Coloured left-edge bar for group membership.
            if let Some(gid) = tab.group_id {
                if let Some(g) = self.groups.iter().find(|g| g.id == gid) {
                    let [r, gc, b] = GROUP_COLORS[g.color_idx % GROUP_COLORS.len()];
                    frame.stroke(
                        &Path::line(
                            Point::new(TAB_PAD + 1.5, y + 3.0),
                            Point::new(TAB_PAD + 1.5, y + TAB_H - 3.0),
                        ),
                        Stroke::default()
                            .with_color(Color::from_rgba(r, gc, b, alpha * 0.9))
                            .with_width(3.0),
                    );
                }
            }
        }

        {
            let btn_y =
                TAB_TOP + self.tabs.len() as f32 * (TAB_H + TAB_GAP) + 4.0;
            let is_hov = state.hovered_tab == Some(self.tabs.len());
            frame.fill(
                &pill(Rectangle::new(
                    Point::new(TAB_PAD, btn_y),
                    iced::Size::new(pill_w, TAB_H),
                )),
                if is_hov {
                    if self.dark { Color::from_rgba(0.17, 0.17, 0.23, alpha) } else { Color::from_rgba(0.78, 0.78, 0.87, alpha) }
                } else {
                    Color::from_rgba(0.0, 0.0, 0.0, 0.0)
                },
            );
            frame.fill_text(canvas::Text {
                content: "+ New Tab".to_string(),
                position: Point::new(TAB_PAD + 10.0, btn_y + TAB_H / 2.0 - 6.5),
                color: if self.dark { Color::from_rgba(0.46, 0.46, 0.54, alpha) } else { Color::from_rgba(0.32, 0.32, 0.44, alpha) },
                size: iced::Pixels(11.5),
                font: iced::Font::DEFAULT,
                align_x: text::Alignment::Left,
                align_y: iced::alignment::Vertical::Top,
                line_height: text::LineHeight::default(),
                shaping: text::Shaping::Basic,
                max_width: pill_w - 10.0,
            });

            // ⊞ Group button beneath New Tab.
            let grp_y = btn_y + TAB_H + TAB_GAP + 4.0;
            let is_grp_hov = state.hovered_tab == Some(self.tabs.len() + 1);
            frame.fill(
                &pill(Rectangle::new(
                    Point::new(TAB_PAD, grp_y),
                    iced::Size::new(pill_w, TAB_H),
                )),
                if is_grp_hov {
                    if self.dark { Color::from_rgba(0.17, 0.17, 0.23, alpha) } else { Color::from_rgba(0.78, 0.78, 0.87, alpha) }
                } else {
                    Color::from_rgba(0.0, 0.0, 0.0, 0.0)
                },
            );
            frame.fill_text(canvas::Text {
                content: "\u{229e} Group".to_string(),
                position: Point::new(TAB_PAD + 10.0, grp_y + TAB_H / 2.0 - 6.5),
                color: if self.dark { Color::from_rgba(0.36, 0.36, 0.48, alpha) } else { Color::from_rgba(0.30, 0.30, 0.44, alpha) },
                size: iced::Pixels(11.0),
                font: iced::Font::DEFAULT,
                align_x: text::Alignment::Left,
                align_y: iced::alignment::Vertical::Top,
                line_height: text::LineHeight::default(),
                shaping: text::Shaping::Basic,
                max_width: pill_w - 10.0,
            });
        }

        frame.stroke(
            &Path::line(Point::new(w, 0.0), Point::new(w, bounds.height)),
            Stroke::default()
                .with_color(if self.dark {
                    Color::from_rgba(1.0, 1.0, 1.0, 0.07 * alpha)
                } else {
                    Color::from_rgba(0.0, 0.0, 0.0, 0.10 * alpha)
                })
                .with_width(0.5),
        );

        vec![frame.into_geometry()]
    }
}

// ── pill shape ────────────────────────────────────────────────────────────────────────────────

fn pill(rect: Rectangle) -> Path {
    Path::new(|b| {
        let x = rect.x;
        let y = rect.y;
        let w = rect.width;
        let h = rect.height;
        let r = (h / 2.0).min(w / 2.0);

        b.move_to(Point::new(x + r, y));
        b.line_to(Point::new(x + w - r, y));

        let rcx = x + w - r;
        let rcy = y + r;
        b.bezier_curve_to(
            Point::new(rcx + K * r, y),
            Point::new(x + w, rcy - K * r),
            Point::new(x + w, rcy),
        );
        b.bezier_curve_to(
            Point::new(x + w, rcy + K * r),
            Point::new(rcx + K * r, y + h),
            Point::new(rcx, y + h),
        );

        b.line_to(Point::new(x + r, y + h));

        let lcx = x + r;
        let lcy = y + r;
        b.bezier_curve_to(
            Point::new(lcx - K * r, y + h),
            Point::new(x, lcy + K * r),
            Point::new(x, lcy),
        );
        b.bezier_curve_to(
            Point::new(x, lcy - K * r),
            Point::new(lcx - K * r, y),
            Point::new(lcx, y),
        );

        b.close();
    })
}

// ── hit testing ────────────────────────────────────────────────────────────────────────────────

fn tab_hit_test(tabs: &[Tab], panel_w: f32, pos: Point) -> Option<usize> {
    let pill_w = panel_w - 2.0 * TAB_PAD;
    for i in 0..tabs.len() {
        let y = TAB_TOP + i as f32 * (TAB_H + TAB_GAP);
        if Rectangle::new(Point::new(TAB_PAD, y), iced::Size::new(pill_w, TAB_H))
            .contains(pos)
        {
            return Some(i);
        }
    }
    let btn_y = TAB_TOP + tabs.len() as f32 * (TAB_H + TAB_GAP) + 4.0;
    if Rectangle::new(
        Point::new(TAB_PAD, btn_y),
        iced::Size::new(pill_w, TAB_H),
    )
    .contains(pos)
    {
        return Some(tabs.len());
    }
    // ⊕ Group button
    let grp_y = btn_y + TAB_H + TAB_GAP + 4.0;
    if Rectangle::new(
        Point::new(TAB_PAD, grp_y),
        iced::Size::new(pill_w, TAB_H),
    )
    .contains(pos)
    {
        return Some(tabs.len() + 1);
    }
    None
}

fn close_btn_hit(tabs: &[Tab], panel_w: f32, pos: Point) -> Option<usize> {
    let pill_w = panel_w - 2.0 * TAB_PAD;
    let cx = TAB_PAD + pill_w - 12.0;
    for i in 0..tabs.len() {
        let cy = TAB_TOP + i as f32 * (TAB_H + TAB_GAP) + TAB_H / 2.0;
        let dx = pos.x - cx;
        let dy = pos.y - cy;
        if dx * dx + dy * dy <= 49.0 {
            return Some(i);
        }
    }
    None
}

// ── utilities ────────────────────────────────────────────────────────────────────────────────

/// Extract a short human-readable site name from a URL.
pub fn site_name(url: &str) -> String {
    if url.is_empty() || url == "about:blank" || url == "tkz:home" {
        return "New Tab".to_string();
    }
    if url.starts_with("file://") {
        return "Local File".to_string();
    }
    let stripped = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = stripped.split('/').next().unwrap_or(stripped);
    let host = host.trim_start_matches("www.");
    let name = if host.contains('.') {
        host.split('.').next().unwrap_or(host)
    } else {
        host
    };
    let mut chars = name.chars();
    match chars.next() {
        None => "Tab".to_string(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}
