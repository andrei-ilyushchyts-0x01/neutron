//! Shared resource bounds for host-side NDJSON capture readers.

use std::io::BufRead;

use anyhow::{bail, Context, Result};
use serde_json::Value;

pub(crate) const MAX_CAPTURE_RECORD_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_CAPTURE_RECORDS: usize = 1_000_000;
pub(crate) const MAX_CAPTURE_STRING_BYTES: usize = 64 * 1024;

pub(crate) fn valid_binder_record(kind: &str, object: &serde_json::Map<String, Value>) -> bool {
    let pid = |key| {
        object
            .get(key)
            .and_then(Value::as_u64)
            .is_some_and(|value| value > 0 && u32::try_from(value).is_ok())
    };
    let debug_id = object.get("debug_id").and_then(Value::as_i64);
    match kind {
        "binder" => {
            pid("pid")
                && debug_id.is_some()
                && object
                    .get("to_proc")
                    .and_then(Value::as_u64)
                    .is_some_and(|value| u32::try_from(value).is_ok())
        }
        "binder_call" => {
            pid("caller_pid") && pid("callee_pid") && debug_id.is_some_and(|value| value != 0)
        }
        "binder_received" => pid("pid") && debug_id.is_some(),
        _ => false,
    }
}

pub(crate) fn unusable_raw_binder_identity(
    kind: &str,
    object: &serde_json::Map<String, Value>,
) -> bool {
    match kind {
        "binder" => {
            object.get("debug_id").and_then(Value::as_i64) == Some(0)
                || object.get("to_proc").and_then(Value::as_u64) == Some(0)
        }
        "binder_received" => object.get("debug_id").and_then(Value::as_i64) == Some(0),
        _ => false,
    }
}

/// Read one newline-delimited record without ever growing `out` beyond the
/// record limit. The newline itself is consumed but not returned.
pub(crate) fn read_capture_record<R: BufRead + ?Sized>(
    reader: &mut R,
    out: &mut Vec<u8>,
    record_number: usize,
) -> Result<bool> {
    out.clear();
    loop {
        let available = reader
            .fill_buf()
            .with_context(|| format!("reading capture record {record_number}"))?;
        if available.is_empty() {
            return Ok(!out.is_empty());
        }
        if out.is_empty() && record_number > MAX_CAPTURE_RECORDS {
            bail!("capture exceeds {MAX_CAPTURE_RECORDS} records");
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        let content = newline.map_or(available, |index| &available[..index]);
        if content.len() > MAX_CAPTURE_RECORD_BYTES.saturating_sub(out.len()) {
            bail!("capture record {record_number} exceeds {MAX_CAPTURE_RECORD_BYTES} bytes");
        }
        out.extend_from_slice(content);
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(true);
        }
    }
}

/// Reject individually huge JSON strings before callers clone them into
/// long-lived aggregation structures. Returns the total string bytes in the
/// record so callers can enforce a cumulative budget where needed.
pub(crate) fn validate_capture_strings(value: &Value, record_number: usize) -> Result<usize> {
    fn visit(value: &Value, record_number: usize, total: &mut usize) -> Result<()> {
        match value {
            Value::String(text) => account(text, record_number, total)?,
            Value::Array(values) => {
                for value in values {
                    visit(value, record_number, total)?;
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    account(key, record_number, total)?;
                    visit(value, record_number, total)?;
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
        Ok(())
    }

    fn account(text: &str, record_number: usize, total: &mut usize) -> Result<()> {
        if text.len() > MAX_CAPTURE_STRING_BYTES {
            bail!(
                "capture record {record_number} contains a string exceeding {MAX_CAPTURE_STRING_BYTES} bytes"
            );
        }
        *total = total
            .checked_add(text.len())
            .context("capture string byte count overflow")?;
        Ok(())
    }

    let mut total = 0;
    visit(value, record_number, &mut total)?;
    Ok(total)
}

/// Hash exactly the bytes consumed, including line endings, without reopening input.
pub(crate) struct DigestReader<R> {
    inner: R,
    digest: sha2::Sha256,
}

impl<R: BufRead> DigestReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        use sha2::Digest;
        Self {
            inner,
            digest: sha2::Sha256::new(),
        }
    }

    pub(crate) fn sha256(&self) -> String {
        use sha2::Digest;
        format!("{:x}", self.digest.clone().finalize())
    }
}

impl<R: BufRead> std::io::Read for DigestReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let available = self.fill_buf()?;
        let size = buf.len().min(available.len());
        buf[..size].copy_from_slice(&available[..size]);
        self.consume(size);
        Ok(size)
    }
}

impl<R: BufRead> BufRead for DigestReader<R> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, size: usize) {
        use sha2::Digest;
        // consume follows a successful fill_buf, so these bytes are already buffered.
        if let Ok(bytes) = self.inner.fill_buf() {
            self.digest.update(&bytes[..size]);
        }
        self.inner.consume(size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_reader_accepts_exact_limit_and_rejects_one_more_byte() {
        let exact = vec![b'x'; MAX_CAPTURE_RECORD_BYTES];
        let mut reader = Cursor::new(exact);
        let mut record = Vec::new();
        assert!(read_capture_record(&mut reader, &mut record, 1).unwrap());
        assert_eq!(record.len(), MAX_CAPTURE_RECORD_BYTES);

        let oversized = vec![b'x'; MAX_CAPTURE_RECORD_BYTES + 1];
        let mut reader = Cursor::new(oversized);
        let error = read_capture_record(&mut reader, &mut record, 1).unwrap_err();
        assert!(error.to_string().contains("record 1 exceeds"));
        assert!(record.len() <= MAX_CAPTURE_RECORD_BYTES);
    }

    #[test]
    fn record_limit_rejects_more_input_but_allows_eof() {
        let mut record = Vec::new();
        let mut eof = Cursor::new(Vec::<u8>::new());
        assert!(!read_capture_record(&mut eof, &mut record, MAX_CAPTURE_RECORDS + 1).unwrap());

        let mut extra = Cursor::new(b"{}\n");
        let error =
            read_capture_record(&mut extra, &mut record, MAX_CAPTURE_RECORDS + 1).unwrap_err();
        assert!(error
            .to_string()
            .contains("capture exceeds 1000000 records"));
    }
}
