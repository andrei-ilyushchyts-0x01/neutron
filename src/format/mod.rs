//! Per-event renderers (text + NDJSON).

pub mod json;
pub mod text;

pub use json::{format_event_json, format_event_json_full, format_event_json_with_stack, FdHint};
pub use text::{format_event_text, format_event_text_with_stack};
