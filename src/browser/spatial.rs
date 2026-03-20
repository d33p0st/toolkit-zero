//! Spatial tab map — a force-directed canvas overlay.
//!
//! Every open tab is rendered as a labelled node.  Edges connect parent tabs
//! to the tabs they spawned (`Tab::opened_from`).  Nodes in the same group
//! share a tinted background cluster.
//!
//! Interaction:
//!   - Click a node  → `Message::SpatialTabSelected(idx)` + map closes.
//!   - Drag a node   → `Message::SpatialMoveNode(idx, dx, dy)`.
//!   - Click outside → `Message::ToggleSpatialMap` (closes the overlay).

use iced::{
    Color, Point, Rectangle, Renderer, Size, Theme,
    mouse,
    widget::canvas::{self, Action, Frame, Geometry, Path, Stroke},
    widget::text,
};

use super::app::Message;
use super::tab::{Tab, TabGroup, GROUP_COLORS};

// ── node geometry ──────────────────────────────────────────────────────────────────────────

const NODE_R: f32 = 28.0;      // node circle radius
const EDGE_W: f32 = 1.5;       // edge line width
const FONT_SIZE: f32 = 11.0;

// ── canvas program ─────────────────────────────────────────────────────────────────────────

/// Local drag state held inside the canvas state machine.
#[derive(Debug, Clone, Default)]
pub struct SpatialState {
    dragging: Option<(usize, Point)>, // (tab_idx, last_cursor)
    /// Whether the last press landed on a node (vs. blank background).
    press_on_node: bool,
}

/// Immutable snapshot passed into the canvas each frame.
pub struct SpatialTabMap<'a> {
    pub tabs:           &'a [Tab],
    pub groups:         &'a [TabGroup],
    pub node_positions: &'a [(f32, f32)],   // parallel to `tabs`
    pub active:         usize,
    pub dark:           bool,
}

impl canvas::Program<Message> for SpatialTabMap<'_> {
    type State = SpatialState;

    fn update(
        &self,
        state: &mut Self::State,
        event: &canvas::Event,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Option<Action<Message>> {
        let cursor_pos = cursor.position_in(bounds)?;

        match event {
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                // Detect which node (if any) was pressed.
                for (i, pos) in self.node_positions.iter().enumerate() {
                    let dx = cursor_pos.x - pos.0;
                    let dy = cursor_pos.y - pos.1;
                    if (dx * dx + dy * dy).sqrt() <= NODE_R {
                        state.dragging = Some((i, cursor_pos));
                        state.press_on_node = true;
                        return Some(Action::request_redraw());
                    }
                }
                state.press_on_node = false;
                None
            }

            canvas::Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)) => {
                let was_dragging = state.dragging.is_some();
                let on_node = state.press_on_node;
                state.dragging = None;
                state.press_on_node = false;

                if on_node && !was_dragging {
                    // Simple click (no drag) on a node → select that tab.
                    for (i, pos) in self.node_positions.iter().enumerate() {
                        let dx = cursor_pos.x - pos.0;
                        let dy = cursor_pos.y - pos.1;
                        if (dx * dx + dy * dy).sqrt() <= NODE_R {
                            return Some(Action::publish(Message::SpatialTabSelected(i)));
                        }
                    }
                } else if !on_node {
                    // Click on blank space → close the map.
                    return Some(Action::publish(Message::ToggleSpatialMap));
                }

                Some(Action::request_redraw())
            }

            canvas::Event::Mouse(mouse::Event::CursorMoved { .. }) => {
                if let Some((idx, ref mut last)) = state.dragging {
                    let dx = cursor_pos.x - last.x;
                    let dy = cursor_pos.y - last.y;
                    if dx.abs() > 0.3 || dy.abs() > 0.3 {
                        *last = cursor_pos;
                        return Some(Action::publish(Message::SpatialMoveNode(idx, dx, dy)));
                    }
                }
                None
            }

            _ => None,
        }
    }

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Vec<Geometry> {
        let dark = self.dark;
        let mut frame = Frame::new(renderer, bounds.size());

        // ── background overlay ──
        frame.fill_rectangle(
            Point::ORIGIN,
            bounds.size(),
            Color::from_rgba(0.0, 0.0, 0.0, if dark { 0.72 } else { 0.55 }),
        );

        // ── title ──
        frame.fill_text(canvas::Text {
            content: "Tab Map  ·  click node to switch  ·  drag to rearrange  ·  click background to close".to_string(),
            position: Point::new(bounds.width / 2.0, 14.0),
            color: Color::from_rgba(1.0, 1.0, 1.0, 0.50),
            size: iced::Pixels(11.0),
            font: iced::Font::DEFAULT,
            align_x: text::Alignment::Center,
            align_y: iced::alignment::Vertical::Top,
            line_height: text::LineHeight::default(),
            shaping: text::Shaping::Basic,
            max_width: bounds.width,
        });

        let n = self.node_positions.len().min(self.tabs.len());

        // ── group cluster backgrounds ──
        for group in self.groups {
            let members: Vec<usize> = (0..n)
                .filter(|&i| self.tabs[i].group_id == Some(group.id))
                .collect();
            if members.len() < 2 {
                continue;
            }
            let [r, g, b] = GROUP_COLORS[group.color_idx % GROUP_COLORS.len()];
            let cx = members.iter().map(|&i| self.node_positions[i].0).sum::<f32>() / members.len() as f32;
            let cy = members.iter().map(|&i| self.node_positions[i].1).sum::<f32>() / members.len() as f32;
            let cluster_r = members.iter()
                .map(|&i| {
                    let dx = self.node_positions[i].0 - cx;
                    let dy = self.node_positions[i].1 - cy;
                    (dx * dx + dy * dy).sqrt()
                })
                .fold(0.0f32, f32::max) + NODE_R + 12.0;
            frame.fill(
                &Path::circle(Point::new(cx, cy), cluster_r),
                Color::from_rgba(r, g, b, 0.08),
            );
            frame.stroke(
                &Path::circle(Point::new(cx, cy), cluster_r),
                Stroke::default().with_color(Color::from_rgba(r, g, b, 0.20)).with_width(1.0),
            );
        }

        // ── edges ──
        for (i, tab) in self.tabs.iter().enumerate().take(n) {
            if let Some(parent) = tab.opened_from {
                if parent < n {
                    let (x1, y1) = self.node_positions[i];
                    let (x2, y2) = self.node_positions[parent];
                    frame.stroke(
                        &Path::line(Point::new(x1, y1), Point::new(x2, y2)),
                        Stroke::default()
                            .with_color(Color::from_rgba(0.6, 0.6, 0.8, 0.35))
                            .with_width(EDGE_W),
                    );
                }
            }
        }

        // ── nodes ──
        let cursor_pos = cursor.position_in(bounds);
        for i in 0..n {
            let (x, y) = self.node_positions[i];
            let tab = &self.tabs[i];
            let is_active = i == self.active;

            let hovered = cursor_pos.map(|p| {
                let dx = p.x - x;
                let dy = p.y - y;
                (dx * dx + dy * dy).sqrt() <= NODE_R
            }).unwrap_or(false);

            // Group color accent
            let (node_fill, node_stroke_col) = if let Some(gid) = tab.group_id {
                if let Some(g) = self.groups.iter().find(|g| g.id == gid) {
                    let [r, gc, b] = GROUP_COLORS[g.color_idx % GROUP_COLORS.len()];
                    (
                        Color::from_rgba(r, gc, b, if is_active { 0.55 } else { 0.22 }),
                        Color::from_rgba(r, gc, b, 0.85),
                    )
                } else {
                    default_node_colors(dark, is_active)
                }
            } else {
                default_node_colors(dark, is_active)
            };

            // Hover highlight
            let fill = if hovered && !is_active {
                Color { a: (node_fill.a + 0.15).min(1.0), ..node_fill }
            } else {
                node_fill
            };

            frame.fill(&Path::circle(Point::new(x, y), NODE_R), fill);
            frame.stroke(
                &Path::circle(Point::new(x, y), NODE_R),
                Stroke::default()
                    .with_color(node_stroke_col)
                    .with_width(if is_active { 2.5 } else { 1.0 }),
            );

            // Suspended dimming ring
            if tab.suspended {
                frame.stroke(
                    &Path::circle(Point::new(x, y), NODE_R - 4.0),
                    Stroke::default()
                        .with_color(Color::from_rgba(0.9, 0.9, 1.0, 0.35))
                        .with_width(1.0),
                );
            }

            // Label inside node
            let label = site_name_short(&tab.url);
            frame.fill_text(canvas::Text {
                content: label,
                position: Point::new(x, y - FONT_SIZE / 2.0 + 1.0),
                color: if is_active {
                    Color::WHITE
                } else if dark {
                    Color::from_rgba(0.82, 0.82, 0.92, 1.0)
                } else {
                    Color::from_rgba(0.12, 0.12, 0.22, 1.0)
                },
                size: iced::Pixels(FONT_SIZE),
                font: iced::Font::DEFAULT,
                align_x: text::Alignment::Center,
                align_y: iced::alignment::Vertical::Top,
                line_height: text::LineHeight::default(),
                shaping: text::Shaping::Basic,
                max_width: NODE_R * 2.0 - 4.0,
            });

            // Active indicator dot
            if is_active {
                frame.fill(
                    &Path::circle(Point::new(x, y + NODE_R - 6.0), 3.5),
                    Color::from_rgba(0.3, 0.8, 1.0, 0.9),
                );
            }
        }

        vec![frame.into_geometry()]
    }

    fn mouse_interaction(
        &self,
        state: &Self::State,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> mouse::Interaction {
        if state.dragging.is_some() {
            return mouse::Interaction::Grabbing;
        }
        if let Some(p) = cursor.position_in(bounds) {
            for pos in self.node_positions {
                let dx = p.x - pos.0;
                let dy = p.y - pos.1;
                if (dx * dx + dy * dy).sqrt() <= NODE_R {
                    return mouse::Interaction::Pointer;
                }
            }
        }
        mouse::Interaction::default()
    }
}

// ── helpers ────────────────────────────────────────────────────────────────────────────────

fn default_node_colors(dark: bool, active: bool) -> (Color, Color) {
    if active {
        (
            Color::from_rgba(0.18, 0.35, 0.75, 0.80),
            Color::from_rgba(0.45, 0.65, 1.00, 0.90),
        )
    } else if dark {
        (
            Color::from_rgba(0.15, 0.15, 0.22, 0.85),
            Color::from_rgba(0.40, 0.40, 0.55, 0.60),
        )
    } else {
        (
            Color::from_rgba(0.88, 0.88, 0.95, 0.90),
            Color::from_rgba(0.50, 0.50, 0.65, 0.70),
        )
    }
}

/// Shortened site name for node labels (≤ 8 chars).
fn site_name_short(url: &str) -> String {
    if url == "tkz:home" || url.is_empty() {
        return "home".to_string();
    }
    let stripped = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("www.");
    let host = stripped.split('/').next().unwrap_or(stripped);
    let base = host.split('.').next().unwrap_or(host);
    let s: String = base.chars().take(8).collect();
    s
}