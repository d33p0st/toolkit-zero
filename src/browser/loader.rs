//! Perimeter-tracing loading indicator.
//!
//! A 1.5 px blue line traces the full window border clockwise:
//!   top-left → down (left edge) → right (bottom) → up (right edge) → left (top)
//!
//! The line lives inside the 1.5 px inset gap around the WebView, so it is
//! always fully visible in iced's own rendering area.
//!
//! When `progress` reaches 1.0 a brief fade-out follows; the widget becomes
//! invisible again once `alpha` drops to zero.

use iced::{
    Color, Point, Rectangle, Renderer, Theme,
    mouse,
    widget::canvas::{self, Frame, Geometry, Path, Stroke},
};

/// Stroke width of the loading line (logical pixels).
const LINE_W: f32 = 1.5;

/// UV-purple / blacklight tracing colour.  Matches the address-bar focus ring.
const BLUE: Color = Color {
    r: 0.467,
    g: 0.0,
    b: 1.0,
    a: 1.0,
};

// ── canvas program ───────────────────────────────────────────────────────────

/// Loading-bar canvas program.  Driven purely by the data it holds; no
/// internal state.
pub struct BorderTrace {
    /// Progress along the perimeter from 0.0 (not started) to 1.0 (complete).
    pub progress: f32,
    /// Fade-out alpha multiplier: 1.0 = fully visible, 0.0 = hidden.
    pub alpha: f32,
}

impl<Message> canvas::Program<Message> for BorderTrace {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<Geometry<Renderer>> {
        if self.alpha <= 0.0 || self.progress <= 0.0 {
            return vec![];
        }

        let mut frame = Frame::new(renderer, bounds.size());

        let w = bounds.width;
        let h = bounds.height;

        // Perimeter segments (clockwise from top-left, staying on the 1.5 px
        // inner edge):
        //   0: left   (0,0) → (0,h)          length = h
        //   1: bottom (0,h) → (w,h)           length = w
        //   2: right  (w,h) → (w,0)           length = h
        //   3: top    (w,0) → (0,0)            length = w
        let perim = 2.0 * (w + h);
        let dist = (self.progress.clamp(0.0, 1.0) * perim).max(0.0);

        let segments: [(Point, Point, f32); 4] = [
            (Point::new(0.0, 0.0), Point::new(0.0, h), h),
            (Point::new(0.0, h),   Point::new(w, h),   w),
            (Point::new(w, h),     Point::new(w, 0.0), h),
            (Point::new(w, 0.0),   Point::new(0.0, 0.0), w),
        ];

        let color = Color {
            a: BLUE.a * self.alpha.clamp(0.0, 1.0),
            ..BLUE
        };

        let stroke = Stroke::default()
            .with_color(color)
            .with_width(LINE_W);

        let mut remaining = dist;
        for (start, end, seg_len) in &segments {
            if remaining <= 0.0 {
                break;
            }
            let t = (remaining / seg_len).min(1.0);
            let actual_end = Point::new(
                start.x + (end.x - start.x) * t,
                start.y + (end.y - start.y) * t,
            );
            let path = Path::line(*start, actual_end);
            frame.stroke(&path, stroke.clone());
            remaining -= seg_len;
        }

        vec![frame.into_geometry()]
    }
}
