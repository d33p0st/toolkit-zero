//! Vertical sliding tab panel drawn with iced Canvas.
//!
//! Groups are rendered as draggable labels above their member tabs.
//! Clicking a label toggles collapse.  Dragging a label reorders its group.
//! Dragging a tab pill onto a group label assigns the tab to that group.
//! Dragging a tab pill to empty space removes it from any group.

use std::collections::HashSet;
use std::sync::Arc;

use iced::{
    Color, Point, Rectangle, Renderer, Size, Theme,
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
/// Height of a group header label (slightly taller than a tab pill).
const GROUP_H: f32 = 26.0;
/// Vertical gap between tab pills.
const TAB_GAP: f32 = 3.0;
/// Extra vertical gap inserted above each group header.
const GROUP_GAP: f32 = 6.0;
/// Top padding inside the panel before the first tab.
const TAB_TOP: f32 = 10.0;
/// Horizontal inset of pills inside the panel.
const TAB_PAD: f32 = 8.0;
/// Panel width threshold below which "collapsed" rendering is used.
const EXPAND_THRESHOLD: f32 = 40.0;
/// Minimum pointer movement (px) before a press becomes a drag.
const DRAG_THRESHOLD: f32 = 5.0;
/// Group headers require a more deliberate vertical drag before reordering
/// begins, to avoid accidental reorders when the user just clicks a header.
const GROUP_DRAG_THRESHOLD: f32 = 14.0;
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
    /// Index of the tab that opened this one (via link click / context menu).
    /// Used for smart auto-grouping (Feature 10) and the spatial map (Feature 5).
    pub opened_from: Option<usize>,
    /// Whether this background tab has been suspended to reclaim resources.
    /// A suspended tab reloads its URL when re-selected.
    pub suspended: bool,
    /// Monotonic instant when this tab was last put to background.
    /// `None` while this tab is active.  Set in `SelectTab`.
    pub last_active_time: Option<std::time::Instant>,
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
            opened_from: None,
            suspended: false,
            last_active_time: None,
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
            opened_from: None,
            suspended: false,
            last_active_time: None,
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

// What kind of thing is being dragged.
#[derive(Debug, Clone, PartialEq)]
enum DragKind {
    /// A tab pill identified by its index into `tabs`.
    Tab(usize),
    /// A group header identified by its index into `groups`.
    Group(usize),
}

// Live drag state, set when the mouse button is held.
#[derive(Debug, Clone)]
struct Drag {
    kind: DragKind,
    /// Y where the press first occurred.
    press_y: f32,
    /// Most-recent cursor Y.
    cur_y: f32,
    /// Click position within the dragged item (for smooth ghost rendering).
    item_offset_y: f32,
    /// True once the pointer has moved beyond DRAG_THRESHOLD.
    active: bool,
}

impl Drag {
    fn ghost_y(&self) -> f32 { self.cur_y - self.item_offset_y }
}

// ── layout ────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum ItemKind {
    Tab { tab_idx: usize },
    GroupHeader { group_idx: usize },
    NewTabBtn,
    NewGroupBtn,
}

#[derive(Debug, Clone)]
struct LayoutItem { kind: ItemKind, y: f32, height: f32, depth: u8 }

/// Recursively emit ungrouped tabs in parent-first tree order.
///
/// Tabs whose `opened_from` index is out of range are treated as roots (depth 0).
fn emit_tab_subtree(
    items: &mut Vec<LayoutItem>,
    tabs: &[Tab],
    parent_idx: Option<usize>,
    depth: u8,
    y: &mut f32,
) {
    for (ti, tab) in tabs.iter().enumerate() {
        if tab.group_id.is_some() { continue; }
        // Normalise stale indices to None (treat as root).
        let actual_parent = tab.opened_from.filter(|&p| p < tabs.len());
        if actual_parent == parent_idx {
            items.push(LayoutItem { kind: ItemKind::Tab { tab_idx: ti }, y: *y, height: TAB_H, depth });
            *y += TAB_H + TAB_GAP;
            emit_tab_subtree(items, tabs, Some(ti), depth.saturating_add(1), y);
        }
    }
}

/// Build the ordered, y-positioned list of all panel items.
///
/// Ungrouped tabs are emitted in hierarchical (parent-before-children) order.
/// Groups are appended below, then the action buttons.
fn build_layout(tabs: &[Tab], groups: &[TabGroup], collapsed: &HashSet<u64>) -> Vec<LayoutItem> {
    let mut items: Vec<LayoutItem> = Vec::new();
    let mut y = TAB_TOP;

    // 1. Ungrouped tabs — tree order (roots then their children, depth-first)
    emit_tab_subtree(&mut items, tabs, None, 0, &mut y);

    // 2. Each group: header + (unless collapsed) member tabs
    for (gi, group) in groups.iter().enumerate() {
        y += GROUP_GAP;
        items.push(LayoutItem { kind: ItemKind::GroupHeader { group_idx: gi }, y, height: GROUP_H, depth: 0 });
        y += GROUP_H + TAB_GAP;

        if !collapsed.contains(&group.id) {
            for (ti, tab) in tabs.iter().enumerate() {
                if tab.group_id == Some(group.id) {
                    items.push(LayoutItem { kind: ItemKind::Tab { tab_idx: ti }, y, height: TAB_H, depth: 0 });
                    y += TAB_H + TAB_GAP;
                }
            }
        }
    }

    // 3. Buttons
    y += 6.0;
    items.push(LayoutItem { kind: ItemKind::NewTabBtn, y, height: TAB_H, depth: 0 });
    y += TAB_H + TAB_GAP + 4.0;
    items.push(LayoutItem { kind: ItemKind::NewGroupBtn, y, height: TAB_H, depth: 0 });

    items
}

// ── panel state ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct TabPanelState {
    hovered_idx: Option<usize>,   // index into the current layout
    cursor_in_panel: bool,
    drag: Option<Drag>,
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
    /// Groups whose member tabs are currently hidden.
    pub collapsed_groups: HashSet<u64>,
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
        let layout = build_layout(&self.tabs, &self.groups, &self.collapsed_groups);

        match event {
            // ── cursor movement ───────────────────────────────────────────────
            canvas::Event::Mouse(mouse::Event::CursorMoved { .. }) => {
                let in_panel = cursor.position_in(bounds).is_some();
                let changed = in_panel != state.cursor_in_panel;
                state.cursor_in_panel = in_panel;

                let pos = cursor.position_in(bounds).unwrap_or(Point::new(-1.0, -1.0));

                // If dragging, update cur_y and activate once past threshold.
                if let Some(drag) = state.drag.as_mut() {
                    drag.cur_y = pos.y;
                    let threshold = match drag.kind {
                        DragKind::Group(_) => GROUP_DRAG_THRESHOLD,
                        _ => DRAG_THRESHOLD,
                    };
                    if !drag.active && (pos.y - drag.press_y).abs() > threshold {
                        drag.active = true;
                    }
                    return Some(Action::request_redraw());
                }

                let prev = state.hovered_idx;
                state.hovered_idx = if in_panel {
                    layout_hit(&layout, pos)
                } else {
                    None
                };

                if changed {
                    return Some(Action::publish(Message::TabsHovered(in_panel)));
                }
                if state.hovered_idx != prev {
                    return Some(Action::request_redraw());
                }
                None
            }

            canvas::Event::Mouse(mouse::Event::CursorLeft) => {
                state.cursor_in_panel = false;
                state.hovered_idx = None;
                if state.drag.is_none() {
                    return Some(Action::publish(Message::TabsHovered(false)));
                }
                None
            }

            // ── left press ── start drag candidate ───────────────────────────
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                let pos = cursor.position_in(bounds)?;

                // In collapsed strip, a click just selects the nearest tab.
                if self.panel_w < EXPAND_THRESHOLD {
                    if let Some(item_idx) = layout_hit(&layout, pos) {
                        if let ItemKind::Tab { tab_idx } = &layout[item_idx].kind {
                            return Some(Action::publish(Message::SelectTab(*tab_idx)));
                        }
                    }
                    return None;
                }

                // Close button has highest priority.
                let pill_w = self.panel_w - 2.0 * TAB_PAD;
                let cx = TAB_PAD + pill_w - 12.0;
                for (ti, _) in self.tabs.iter().enumerate() {
                    let item_y = layout.iter().find_map(|it| {
                        if let ItemKind::Tab { tab_idx } = &it.kind {
                            if *tab_idx == ti { Some(it.y) } else { None }
                        } else { None }
                    });
                    if let Some(iy) = item_y {
                        let cy = iy + TAB_H / 2.0;
                        let dx = pos.x - cx;
                        let dy = pos.y - cy;
                        if dx * dx + dy * dy <= 49.0 {
                            return Some(Action::publish(Message::CloseTab(ti)));
                        }
                    }
                }

                // Start a drag candidate at whatever item was clicked.
                if let Some(item_idx) = layout_hit(&layout, pos) {
                    let item = &layout[item_idx];
                    match &item.kind {
                        ItemKind::Tab { tab_idx } => {
                            state.drag = Some(Drag {
                                kind: DragKind::Tab(*tab_idx),
                                press_y: pos.y,
                                cur_y: pos.y,
                                item_offset_y: pos.y - item.y,
                                active: false,
                            });
                        }
                        ItemKind::GroupHeader { group_idx } => {
                            state.drag = Some(Drag {
                                kind: DragKind::Group(*group_idx),
                                press_y: pos.y,
                                cur_y: pos.y,
                                item_offset_y: pos.y - item.y,
                                active: false,
                            });
                        }
                        ItemKind::NewTabBtn => {
                            return Some(Action::publish(Message::NewTab));
                        }
                        ItemKind::NewGroupBtn => {
                            return Some(Action::publish(Message::CreateTabGroup));
                        }
                    }
                }
                None
            }

            // ── left release ── commit drop or click ──────────────────────────
            canvas::Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)) => {
                let drag = state.drag.take()?;
                let pos = cursor.position_in(bounds)
                    .unwrap_or(Point::new(0.0, drag.cur_y));

                if !drag.active {
                    // Short click — selection / toggle.
                    return match drag.kind {
                        DragKind::Tab(ti) => Some(Action::publish(Message::SelectTab(ti))),
                        DragKind::Group(gi) => {
                            let gid = self.groups[gi].id;
                            Some(Action::publish(Message::ToggleCollapseGroup(gid)))
                        }
                    };
                }

                // Determine drop target from ghost position.
                let ghost_y = drag.ghost_y();
                let drop_item = layout_hit(&layout, Point::new(pos.x, ghost_y + 2.0));

                let msg = match drag.kind {
                    DragKind::Tab(from_ti) => {
                        match drop_item.map(|i| &layout[i].kind) {
                            Some(ItemKind::GroupHeader { group_idx }) => {
                                let gid = self.groups[*group_idx].id;
                                Message::SetTabGroup(from_ti, Some(gid))
                            }
                            Some(ItemKind::Tab { tab_idx: to_ti }) if *to_ti != from_ti => {
                                Message::ReorderTab(from_ti, *to_ti)
                            }
                            _ => Message::SetTabGroup(from_ti, None),
                        }
                    }
                    DragKind::Group(from_gi) => {
                        match drop_item.map(|i| &layout[i].kind) {
                            Some(ItemKind::GroupHeader { group_idx: to_gi }) if *to_gi != from_gi => {
                                let gid = self.groups[from_gi].id;
                                Message::MoveGroupToIndex(gid, *to_gi)
                            }
                            _ => {
                                // Dropped nowhere — emit a no-op self-move.
                                let gid = self.groups[from_gi].id;
                                Message::MoveGroupToIndex(gid, from_gi)
                            }
                        }
                    }
                };
                Some(Action::publish(msg))
            }

            // ── middle click ── close tab ─────────────────────────────────────
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Middle)) => {
                let pos = cursor.position_in(bounds)?;
                if let Some(i) = layout_hit(&layout, pos) {
                    if let ItemKind::Tab { tab_idx } = &layout[i].kind {
                        return Some(Action::publish(Message::CloseTab(*tab_idx)));
                    }
                }
                None
            }

            // ── right click ── cycle tab group ────────────────────────────────
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Right)) => {
                let pos = cursor.position_in(bounds)?;
                if self.panel_w < EXPAND_THRESHOLD { return None; }
                if let Some(i) = layout_hit(&layout, pos) {
                    if let ItemKind::Tab { tab_idx } = &layout[i].kind {
                        return Some(Action::publish(Message::CycleTabGroup(*tab_idx)));
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
        if let Some(drag) = &state.drag {
            if drag.active { return mouse::Interaction::Grabbing; }
        }
        if state.hovered_idx.is_some() {
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
        let dark = self.dark;
        let expanded = w >= EXPAND_THRESHOLD;

        let alpha = if expanded {
            ((w - EXPAND_THRESHOLD) / (PANEL_EXPANDED_W - EXPAND_THRESHOLD)).clamp(0.0, 1.0)
        } else {
            0.0
        };

        // ── Panel background ──────────────────────────────────────────────────
        if alpha > 0.0 {
            frame.fill(
                &Path::new(|b| { b.rectangle(Point::ORIGIN, Size::new(w, bounds.height)); }),
                if dark { Color::from_rgba(0.07, 0.07, 0.10, alpha * 0.96) }
                else    { Color::from_rgba(0.88, 0.88, 0.92, alpha * 0.97) },
            );
        }

        // ── Collapsed strip: dot indicators ──────────────────────────────────
        if !expanded {
            frame.stroke(
                &Path::line(Point::new(w - 0.5, 0.0), Point::new(w - 0.5, bounds.height)),
                Stroke::default()
                    .with_color(if dark { Color::from_rgba(1.0, 1.0, 1.0, 0.06) }
                                else   { Color::from_rgba(0.0, 0.0, 0.0, 0.08) })
                    .with_width(0.5),
            );
            let dx = w / 2.0;
            for (i, tab) in self.tabs.iter().enumerate() {
                let dy = TAB_TOP + i as f32 * (TAB_H + TAB_GAP) + TAB_H / 2.0;
                let dot_color = if i == self.active {
                    tab.group_id
                        .and_then(|gid| self.groups.iter().find(|g| g.id == gid))
                        .map(|g| { let [r, gc, b] = GROUP_COLORS[g.color_idx % GROUP_COLORS.len()]; Color::from_rgb(r, gc, b) })
                        .unwrap_or(Color::from_rgb(0.30, 0.52, 1.0))
                } else if state.hovered_idx == Some(i) {
                    if dark { Color::from_rgb(0.50, 0.50, 0.60) } else { Color::from_rgb(0.40, 0.40, 0.55) }
                } else {
                    if dark { Color::from_rgb(0.22, 0.22, 0.30) } else { Color::from_rgb(0.62, 0.62, 0.72) }
                };
                frame.fill(&Path::circle(Point::new(dx, dy), 1.5), dot_color);
            }
            return vec![frame.into_geometry()];
        }

        // ── Expanded: build layout and render ────────────────────────────────
        let layout = build_layout(&self.tabs, &self.groups, &self.collapsed_groups);
        let pill_w = w - 2.0 * TAB_PAD;

        let dragging_tab_idx: Option<usize> = state.drag.as_ref()
            .filter(|d| d.active)
            .and_then(|d| if let DragKind::Tab(ti) = d.kind { Some(ti) } else { None });

        let dragging_group_idx: Option<usize> = state.drag.as_ref()
            .filter(|d| d.active)
            .and_then(|d| if let DragKind::Group(gi) = d.kind { Some(gi) } else { None });

        let hidden_group_id: Option<u64> = dragging_group_idx.map(|gi| self.groups[gi].id);

        for (layout_idx, item) in layout.iter().enumerate() {
            let hov = state.hovered_idx == Some(layout_idx);

            match &item.kind {
                ItemKind::Tab { tab_idx } => {
                    let ti = *tab_idx;
                    let tab = &self.tabs[ti];
                    let is_dragged = dragging_tab_idx == Some(ti);
                    let in_dragged_group = hidden_group_id.map(|g| tab.group_id == Some(g)).unwrap_or(false);
                    if is_dragged || in_dragged_group { continue; }

                    let drop_hl = dragging_tab_idx.is_some() && hov;
                    draw_tab_pill(&mut frame, pill_w, item.y, alpha, dark,
                        ti == self.active, hov || drop_hl, tab, &self.groups, item.depth);
                }

                ItemKind::GroupHeader { group_idx } => {
                    let gi = *group_idx;
                    if dragging_group_idx == Some(gi) { continue; }

                    let drop_hl = (dragging_tab_idx.is_some() || dragging_group_idx.is_some()) && hov;
                    let collapsed = self.collapsed_groups.contains(&self.groups[gi].id);
                    draw_group_header(&mut frame, pill_w, item.y, alpha, dark,
                        &self.groups[gi], hov || drop_hl, collapsed);
                }

                ItemKind::NewTabBtn => {
                    let hov_fill = if hov {
                        if dark { Color::from_rgba(0.17, 0.17, 0.23, alpha) } else { Color::from_rgba(0.78, 0.78, 0.87, alpha) }
                    } else { Color::TRANSPARENT };
                    frame.fill(&pill(Rectangle::new(Point::new(TAB_PAD, item.y), Size::new(pill_w, TAB_H))), hov_fill);
                    frame.fill_text(btn_text("+ New Tab", TAB_PAD + 10.0, item.y, pill_w,
                        if dark { Color::from_rgba(0.46, 0.46, 0.54, alpha) } else { Color::from_rgba(0.32, 0.32, 0.44, alpha) }));
                }

                ItemKind::NewGroupBtn => {
                    let hov_fill = if hov {
                        if dark { Color::from_rgba(0.17, 0.17, 0.23, alpha) } else { Color::from_rgba(0.78, 0.78, 0.87, alpha) }
                    } else { Color::TRANSPARENT };
                    frame.fill(&pill(Rectangle::new(Point::new(TAB_PAD, item.y), Size::new(pill_w, TAB_H))), hov_fill);
                    frame.fill_text(btn_text("\u{229e} Group", TAB_PAD + 10.0, item.y, pill_w,
                        if dark { Color::from_rgba(0.36, 0.36, 0.48, alpha) } else { Color::from_rgba(0.30, 0.30, 0.44, alpha) }));
                }
            }
        }

        // ── Ghost for dragged tab ─────────────────────────────────────────────
        if let Some(drag) = &state.drag {
            if drag.active {
                match drag.kind {
                    DragKind::Tab(ti) => {
                        draw_tab_ghost(&mut frame, pill_w, drag.ghost_y(), alpha, dark,
                            &self.tabs[ti], &self.groups);
                    }
                    DragKind::Group(gi) => {
                        draw_group_ghost(&mut frame, pill_w, drag.ghost_y(), alpha, dark, &self.groups[gi]);
                        if !self.collapsed_groups.contains(&self.groups[gi].id) {
                            let mut my = drag.ghost_y() + GROUP_H + TAB_GAP;
                            for tab in &self.tabs {
                                if tab.group_id == Some(self.groups[gi].id) {
                                    draw_tab_ghost(&mut frame, pill_w, my, alpha, dark, tab, &self.groups);
                                    my += TAB_H + TAB_GAP;
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Right-edge separator ──────────────────────────────────────────────
        frame.stroke(
            &Path::line(Point::new(w, 0.0), Point::new(w, bounds.height)),
            Stroke::default()
                .with_color(if dark { Color::from_rgba(1.0, 1.0, 1.0, 0.07 * alpha) }
                            else   { Color::from_rgba(0.0, 0.0, 0.0, 0.10 * alpha) })
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

/// Return the layout-item index containing `pos`, or `None`.
fn layout_hit(layout: &[LayoutItem], pos: Point) -> Option<usize> {
    for (i, item) in layout.iter().enumerate() {
        if pos.y >= item.y && pos.y < item.y + item.height {
            return Some(i);
        }
    }
    None
}

// ── draw helpers ────────────────────────────────────────────────────────────────────────────────

fn draw_tab_pill(
    frame: &mut Frame,
    pill_w: f32,
    y: f32,
    alpha: f32,
    dark: bool,
    is_active: bool,
    hovered: bool,
    tab: &Tab,
    groups: &[TabGroup],
    depth: u8,
) {
    // Child tabs are indented by 10px per level relative to their parent.
    let indent = depth as f32 * 10.0;
    let px = TAB_PAD + indent;  // pill left edge
    let pw = pill_w - indent;   // pill width (right edge always = TAB_PAD + pill_w)

    // Suspended tabs are drawn more dimly to suggest they are sleeping.
    let eff_alpha = if tab.suspended && !is_active { alpha * 0.55 } else { alpha };

    // ── Tree connector (L-shape) for child tabs ───────────────────────────
    if depth > 0 {
        let connector_x = TAB_PAD + (depth - 1) as f32 * 10.0 + 5.0;
        let mid_y = y + TAB_H / 2.0;
        let conn_color = if dark {
            Color::from_rgba(0.35, 0.35, 0.50, eff_alpha * 0.45)
        } else {
            Color::from_rgba(0.45, 0.45, 0.60, eff_alpha * 0.45)
        };
        let stroke = Stroke::default().with_color(conn_color).with_width(1.0);
        frame.stroke(
            &Path::line(Point::new(connector_x, y - TAB_GAP * 0.5), Point::new(connector_x, mid_y)),
            stroke.clone(),
        );
        frame.stroke(
            &Path::line(Point::new(connector_x, mid_y), Point::new(px - 2.0, mid_y)),
            stroke,
        );
    }

    frame.fill(
        &pill(Rectangle::new(Point::new(px, y), Size::new(pw, TAB_H))),
        if is_active {
            if dark { Color::from_rgba(0.18, 0.32, 0.72, eff_alpha) } else { Color::from_rgba(0.25, 0.45, 0.90, eff_alpha) }
        } else if hovered {
            if dark { Color::from_rgba(0.17, 0.17, 0.23, eff_alpha) } else { Color::from_rgba(0.78, 0.78, 0.87, eff_alpha) }
        } else {
            if dark { Color::from_rgba(0.11, 0.11, 0.15, eff_alpha) } else { Color::from_rgba(0.84, 0.84, 0.89, eff_alpha * 0.7) }
        },
    );

    // Label: show "zzz" prefix for suspended tabs so the user knows at a glance.
    let label = if tab.suspended && !is_active {
        let name = site_name(&tab.url);
        format!("zz {name}")
    } else {
        site_name(&tab.url)
    };

    frame.fill_text(canvas::Text {
        content: label,
        position: Point::new(px + 10.0, y + TAB_H / 2.0 - 6.5),
        color: if is_active {
            if dark { Color::from_rgba(1.0, 1.0, 1.0, eff_alpha) } else { Color::from_rgba(0.08, 0.08, 0.15, eff_alpha) }
        } else {
            if dark { Color::from_rgba(0.68, 0.68, 0.75, eff_alpha) } else { Color::from_rgba(0.28, 0.28, 0.38, eff_alpha) }
        },
        size: iced::Pixels(12.0),
        font: iced::Font::DEFAULT,
        align_x: text::Alignment::Left,
        align_y: iced::alignment::Vertical::Top,
        line_height: text::LineHeight::default(),
        shaping: text::Shaping::Basic,
        max_width: pw - 26.0,
    });

    // Close button (shown on hover or active tab)
    // The right edge of every pill is always TAB_PAD + pill_w regardless of indent,
    // so cx is constant and the existing hit-test in update() stays correct.
    if is_active || hovered {
        let cx = TAB_PAD + pill_w - 12.0;
        let cy = y + TAB_H / 2.0;
        frame.fill(
            &Path::circle(Point::new(cx, cy), 7.0),
            if dark { Color::from_rgba(1.0, 1.0, 1.0, 0.09 * eff_alpha) } else { Color::from_rgba(0.0, 0.0, 0.0, 0.07 * eff_alpha) },
        );
        frame.fill_text(canvas::Text {
            content: "x".to_string(),
            position: Point::new(cx - 3.5, cy - 6.5),
            color: if dark { Color::from_rgba(0.80, 0.80, 0.80, eff_alpha) } else { Color::from_rgba(0.25, 0.25, 0.35, eff_alpha) },
            size: iced::Pixels(13.0),
            font: iced::Font::DEFAULT,
            align_x: text::Alignment::Left,
            align_y: iced::alignment::Vertical::Top,
            line_height: text::LineHeight::default(),
            shaping: text::Shaping::Basic,
            max_width: 14.0,
        });
    }

    // Left-edge group accent bar (aligned to pill left edge)
    if let Some(gid) = tab.group_id {
        if let Some(g) = groups.iter().find(|g| g.id == gid) {
            let [r, gc, b] = GROUP_COLORS[g.color_idx % GROUP_COLORS.len()];
            frame.stroke(
                &Path::line(Point::new(px + 1.5, y + 3.0), Point::new(px + 1.5, y + TAB_H - 3.0)),
                Stroke::default().with_color(Color::from_rgba(r, gc, b, eff_alpha * 0.9)).with_width(3.0),
            );
        }
    }
}

fn draw_tab_ghost(frame: &mut Frame, pill_w: f32, y: f32, alpha: f32, dark: bool, tab: &Tab, groups: &[TabGroup]) {
    frame.fill(
        &pill(Rectangle::new(Point::new(TAB_PAD, y), Size::new(pill_w, TAB_H))),
        if dark { Color::from_rgba(0.30, 0.50, 1.0, alpha * 0.50) } else { Color::from_rgba(0.30, 0.50, 1.0, alpha * 0.35) },
    );
    frame.fill_text(canvas::Text {
        content: site_name(&tab.url),
        position: Point::new(TAB_PAD + 10.0, y + TAB_H / 2.0 - 6.5),
        color: if dark { Color::from_rgba(1.0, 1.0, 1.0, alpha * 0.70) } else { Color::from_rgba(0.08, 0.08, 0.15, alpha * 0.70) },
        size: iced::Pixels(12.0),
        font: iced::Font::DEFAULT,
        align_x: text::Alignment::Left,
        align_y: iced::alignment::Vertical::Top,
        line_height: text::LineHeight::default(),
        shaping: text::Shaping::Basic,
        max_width: pill_w - 26.0,
    });
    if let Some(gid) = tab.group_id {
        if let Some(g) = groups.iter().find(|g| g.id == gid) {
            let [r, gc, b] = GROUP_COLORS[g.color_idx % GROUP_COLORS.len()];
            frame.stroke(
                &Path::line(Point::new(TAB_PAD + 1.5, y + 3.0), Point::new(TAB_PAD + 1.5, y + TAB_H - 3.0)),
                Stroke::default().with_color(Color::from_rgba(r, gc, b, alpha * 0.60)).with_width(3.0),
            );
        }
    }
}

fn draw_group_header(frame: &mut Frame, pill_w: f32, y: f32, alpha: f32, dark: bool, group: &TabGroup, hovered: bool, collapsed: bool) {
    let [r, gc, b] = GROUP_COLORS[group.color_idx % GROUP_COLORS.len()];
    let accent = Color::from_rgba(r, gc, b, alpha * 0.9);

    let bg = if hovered {
        if dark { Color::from_rgba(r * 0.18, gc * 0.18, b * 0.18, alpha * 0.90) }
        else    { Color::from_rgba(r * 0.80, gc * 0.80, b * 0.80, alpha * 0.30) }
    } else {
        if dark { Color::from_rgba(r * 0.12, gc * 0.12, b * 0.12, alpha * 0.80) }
        else    { Color::from_rgba(r * 0.70, gc * 0.70, b * 0.70, alpha * 0.18) }
    };
    frame.fill(&pill(Rectangle::new(Point::new(TAB_PAD, y), Size::new(pill_w, GROUP_H))), bg);
    frame.stroke(
        &Path::line(Point::new(TAB_PAD + 1.5, y + 4.0), Point::new(TAB_PAD + 1.5, y + GROUP_H - 4.0)),
        Stroke::default().with_color(accent).with_width(3.0),
    );
    let arrow = if collapsed { "▶" } else { "▼" };
    frame.fill_text(canvas::Text {
        content: format!("{} {}", arrow, &group.name),
        position: Point::new(TAB_PAD + 10.0, y + GROUP_H / 2.0 - 6.5),
        color: accent,
        size: iced::Pixels(11.5),
        font: iced::Font::DEFAULT,
        align_x: text::Alignment::Left,
        align_y: iced::alignment::Vertical::Top,
        line_height: text::LineHeight::default(),
        shaping: text::Shaping::Basic,
        max_width: pill_w - 20.0,
    });
    // Grip dots on right edge
    let gx = TAB_PAD + pill_w - 10.0;
    let gy0 = y + GROUP_H / 2.0 - 4.0;
    for di in 0..3i32 {
        frame.fill(&Path::circle(Point::new(gx, gy0 + di as f32 * 4.0), 1.3), Color::from_rgba(r, gc, b, alpha * 0.55));
    }
}

fn draw_group_ghost(frame: &mut Frame, pill_w: f32, y: f32, alpha: f32, dark: bool, group: &TabGroup) {
    let [r, gc, b] = GROUP_COLORS[group.color_idx % GROUP_COLORS.len()];
    let bg = if dark { Color::from_rgba(r * 0.25, gc * 0.25, b * 0.25, alpha * 0.70) }
             else   { Color::from_rgba(r * 0.85, gc * 0.85, b * 0.85, alpha * 0.50) };
    frame.fill(&pill(Rectangle::new(Point::new(TAB_PAD, y), Size::new(pill_w, GROUP_H))), bg);
    frame.stroke(
        &Path::line(Point::new(TAB_PAD + 1.5, y + 4.0), Point::new(TAB_PAD + 1.5, y + GROUP_H - 4.0)),
        Stroke::default().with_color(Color::from_rgba(r, gc, b, alpha * 0.75)).with_width(3.0),
    );
    frame.fill_text(canvas::Text {
        content: format!("\u{25bc} {}", &group.name),
        position: Point::new(TAB_PAD + 10.0, y + GROUP_H / 2.0 - 6.5),
        color: Color::from_rgba(r, gc, b, alpha * 0.75),
        size: iced::Pixels(11.5),
        font: iced::Font::DEFAULT,
        align_x: text::Alignment::Left,
        align_y: iced::alignment::Vertical::Top,
        line_height: text::LineHeight::default(),
        shaping: text::Shaping::Basic,
        max_width: pill_w - 12.0,
    });
    let _ = dark;
}

/// Convenience: build a canvas::Text for the button rows.
fn btn_text(label: &str, x: f32, y: f32, max_w: f32, color: Color) -> canvas::Text {
    canvas::Text {
        content: label.to_string(),
        position: Point::new(x, y + TAB_H / 2.0 - 6.5),
        color,
        size: iced::Pixels(11.5),
        font: iced::Font::DEFAULT,
        align_x: text::Alignment::Left,
        align_y: iced::alignment::Vertical::Top,
        line_height: text::LineHeight::default(),
        shaping: text::Shaping::Basic,
        max_width: max_w - 10.0,
    }
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
