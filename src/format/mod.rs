//! Per-event renderers (text + NDJSON).

pub mod json;
pub mod text;

pub use json::{
    format_binder_call_json, format_event_json, format_event_json_full,
    format_event_json_with_stack, format_fd_snapshot_json, format_process_exit_json, FdHint,
};
pub use text::{format_event_text, format_event_text_with_stack};
