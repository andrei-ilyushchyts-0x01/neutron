//! Phase 1b — `--match` expression mini-language.
//!
//! Tiny recursive-descent parser for boolean predicates over the same
//! field vocabulary as the individual `--match-*` flags in
//! [`crate::matcher`]. Examples:
//!
//! ```text
//! syscall = 29 AND fd_path GLOB '/dev/lwis*'
//! ioctl.cmd = 0xc0104c64 AND arg.u32@0 IN (0x20200, 0x40200)
//! ret < 0 OR latency_us >= 5000
//! NOT comm GLOB 'audioserver*'
//! pid = 970 AND (syscall = 29 OR syscall = 222)
//! ```
//!
//! Compiler split:
//!
//! - The full AST drives the userspace evaluator on every event that
//!   survives the BPF prefilter.
//! - The BPF prefilter is built as a **safe over-approximation**: only
//!   top-level conjuncts that are single BPF-evaluable atoms are pushed
//!   into [`crate::matcher::MatchSpec`]. Anything inside an `OR`, a
//!   `NOT`, or a sub-expression with userspace-only clauses contributes
//!   no kernel-side filtering and stays purely in userspace. This is
//!   exactly the rule the plan calls "BPF prefilter accepts a strict
//!   superset of what the user predicate matches; userspace doctors the
//!   final emit decision".
//!
//! Not implemented in this phase (the existing `--match-*` flags cover
//! these without losing power):
//!
//! - Numeric range comparisons on arbitrary fields (only `ret` / `latency_us`
//!   accept `<`, `<=`, `>`, `>=`; everything else uses `=`/`!=`/`IN`).
//! - String escapes inside quoted literals (newlines / quotes inside
//!   strings need shell-level quoting today).

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Context, Result};

use crate::matcher::{
    self, ArgClause, ArgWidth, BinderClause, EventLens, IoctlDir, MatchSpec, RetClass,
};

/// Boolean expression over atomic field clauses.
#[derive(Clone, Debug)]
pub enum Expr {
    Atom(AtomicClause),
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
}

/// One field-vs-value(set) clause. Operator + values together because
/// some operators allow multi-value sets (`=`, `!=`, `IN`) while others
/// take a single scalar (`<`, `>=`).
#[derive(Clone, Debug)]
pub struct AtomicClause {
    pub field: Field,
    pub op: Op,
    pub values: Vec<Value>,
}

/// Field reference. The AST keeps it untyped so the compiler can give a
/// single error message when the field name is unknown — useful when
/// operators forget e.g. `arg.u32@0`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Field {
    Pid,
    Uid,
    Syscall,
    Comm,
    FdPath,
    IoctlCmd,
    IoctlType,
    IoctlNr,
    IoctlDir,
    Ret,
    LatencyUs,
    ProtRwx,
    ProtWx,
    /// `arg.<width>@<offset>` accessor.
    Arg {
        width: ArgWidth,
        offset: u32,
    },
    BinderToProc,
    BinderToThread,
    BinderCode,
    BinderFlags,
    BinderTargetNode,
    BinderReply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    Glob,
}

#[derive(Clone, Debug)]
pub enum Value {
    /// Decimal or hex integer.
    Int(u64),
    /// Single- or double-quoted string. Used for `GLOB` and any field
    /// that takes a string literal (today only `comm` and `fd_path`).
    Str(String),
    /// Bare identifier. Currently only `true` / `false` for `binder.reply`,
    /// or one of `r`/`w`/`rw`/`none` for `ioctl.dir`.
    Ident(String),
}

// ── Public entry points ─────────────────────────────────────────────────────

/// Parse one `--match` argument into an [`Expr`].
pub fn parse(input: &str) -> Result<Expr> {
    let tokens = lex(input)?;
    let mut p = Parser {
        toks: &tokens,
        pos: 0,
    };
    let expr = p.parse_or_expr()?;
    if p.pos != tokens.len() {
        bail!(
            "unexpected trailing tokens at position {}: {:?}",
            p.pos,
            &tokens[p.pos..]
        );
    }
    Ok(expr)
}

/// Reduce an AST to its conservative BPF-evaluable [`MatchSpec`]. Only
/// top-level conjuncts that are single BPF-evaluable atoms become BPF
/// constraints; everything else is left to the userspace evaluator.
pub fn extract_bpf_spec(expr: &Expr) -> MatchSpec {
    let mut spec = MatchSpec::default();
    for c in flatten_top_and(expr) {
        if let Expr::Atom(atom) = c {
            // Errors here mean "this atom cannot be expressed in MatchSpec
            // even though we tried" — fall back to userspace silently. The
            // userspace evaluator still applies the full AST so correctness
            // is preserved; we only lose volume reduction.
            let _ = apply_atom_to_spec(&mut spec, atom);
        }
    }
    spec
}

/// Evaluate the AST against an event view. Used as the userspace
/// post-filter when `--match` is in effect.
pub fn evaluate(expr: &Expr, ev: &dyn EventLens) -> bool {
    match expr {
        Expr::Atom(c) => eval_atom(c, ev),
        Expr::And(xs) => xs.iter().all(|x| evaluate(x, ev)),
        Expr::Or(xs) => xs.iter().any(|x| evaluate(x, ev)),
        Expr::Not(x) => !evaluate(x, ev),
    }
}

/// Audit lines describing how each clause of `expr` is evaluated. Same
/// `[bpf]` / `[user]` prefix shape as
/// [`MatchSpec::audit_lines`] so the runtime print stays consistent.
pub fn audit_lines(expr: &Expr) -> Vec<String> {
    // Top-level conjuncts that are single BPF-evaluable atoms get the
    // [bpf] prefix; everything else gets [user]. The full AST is always
    // evaluated userspace-side so we also list it at the top.
    let mut out = Vec::new();
    out.push(format!("[expr]  {}", render_expr(expr)));
    let conjuncts = flatten_top_and(expr);
    for c in conjuncts {
        match c {
            Expr::Atom(atom) => {
                let mut spec = MatchSpec::default();
                let bpf_ok =
                    apply_atom_to_spec(&mut spec, atom).is_ok() && !atom_is_userspace_only(atom);
                let prefix = if bpf_ok { "[bpf] " } else { "[user]" };
                out.push(format!("  {prefix} {}", render_atom(atom)));
            }
            other => {
                out.push(format!("  [user] {}", render_expr(other)));
            }
        }
    }
    out
}

// ── Lexer ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Int(u64),
    Str(String),
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    LParen,
    RParen,
    Comma,
    Dot,
    At,
    KwAnd,
    KwOr,
    KwNot,
    KwIn,
    KwGlob,
    KwTrue,
    KwFalse,
}

fn lex(input: &str) -> Result<Vec<Tok>> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        match c {
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            b',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            b'.' => {
                out.push(Tok::Dot);
                i += 1;
            }
            b'@' => {
                out.push(Tok::At);
                i += 1;
            }
            b'=' => {
                out.push(Tok::Eq);
                i += 1;
            }
            b'!' if i + 1 < bytes.len() && bytes[i + 1] == b'=' => {
                out.push(Tok::Ne);
                i += 2;
            }
            b'<' if i + 1 < bytes.len() && bytes[i + 1] == b'=' => {
                out.push(Tok::Le);
                i += 2;
            }
            b'<' => {
                out.push(Tok::Lt);
                i += 1;
            }
            b'>' if i + 1 < bytes.len() && bytes[i + 1] == b'=' => {
                out.push(Tok::Ge);
                i += 2;
            }
            b'>' => {
                out.push(Tok::Gt);
                i += 1;
            }
            b'\'' | b'"' => {
                let quote = c;
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes[j] != quote {
                    j += 1;
                }
                if j >= bytes.len() {
                    bail!("unterminated string starting at byte {start}");
                }
                let s = std::str::from_utf8(&bytes[start..j])
                    .with_context(|| format!("non-UTF-8 bytes in string at {start}"))?;
                out.push(Tok::Str(s.to_string()));
                i = j + 1;
            }
            b'0'..=b'9' => {
                let (val, advance) = lex_number(&bytes[i..])
                    .with_context(|| format!("number starting at byte {i}"))?;
                out.push(Tok::Int(val));
                i += advance;
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let start = i;
                let mut j = i;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                let ident = &input[start..j];
                let tok = match ident.to_ascii_uppercase().as_str() {
                    "AND" => Tok::KwAnd,
                    "OR" => Tok::KwOr,
                    "NOT" => Tok::KwNot,
                    "IN" => Tok::KwIn,
                    "GLOB" => Tok::KwGlob,
                    "TRUE" => Tok::KwTrue,
                    "FALSE" => Tok::KwFalse,
                    _ => Tok::Ident(ident.to_string()),
                };
                out.push(tok);
                i = j;
            }
            _ => bail!("unexpected character '{}' at byte {i}", c as char),
        }
    }
    Ok(out)
}

fn lex_number(bytes: &[u8]) -> Result<(u64, usize)> {
    if bytes.len() >= 2 && bytes[0] == b'0' && (bytes[1] == b'x' || bytes[1] == b'X') {
        let mut j = 2;
        while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
            j += 1;
        }
        let s = std::str::from_utf8(&bytes[2..j])?;
        let v = u64::from_str_radix(s, 16)?;
        return Ok((v, j));
    }
    let mut j = 0;
    while j < bytes.len() && bytes[j].is_ascii_digit() {
        j += 1;
    }
    let s = std::str::from_utf8(&bytes[..j])?;
    let v = s.parse::<u64>()?;
    Ok((v, j))
}

// ── Parser ───────────────────────────────────────────────────────────────────

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_or_expr(&mut self) -> Result<Expr> {
        let mut left = self.parse_and_expr()?;
        let mut acc = vec![left];
        while self.eat(&Tok::KwOr) {
            left = self.parse_and_expr()?;
            acc.push(left);
        }
        Ok(if acc.len() == 1 {
            acc.into_iter().next().unwrap()
        } else {
            Expr::Or(acc)
        })
    }

    fn parse_and_expr(&mut self) -> Result<Expr> {
        let mut left = self.parse_unary_expr()?;
        let mut acc = vec![left];
        while self.eat(&Tok::KwAnd) {
            left = self.parse_unary_expr()?;
            acc.push(left);
        }
        Ok(if acc.len() == 1 {
            acc.into_iter().next().unwrap()
        } else {
            Expr::And(acc)
        })
    }

    fn parse_unary_expr(&mut self) -> Result<Expr> {
        if self.eat(&Tok::KwNot) {
            let inner = self.parse_unary_expr()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        if self.eat(&Tok::LParen) {
            let e = self.parse_or_expr()?;
            if !self.eat(&Tok::RParen) {
                bail!("expected ')' at position {}", self.pos);
            }
            return Ok(e);
        }
        let atom = self.parse_atom()?;
        Ok(Expr::Atom(atom))
    }

    fn parse_atom(&mut self) -> Result<AtomicClause> {
        let field = self.parse_field()?;
        // Operator
        let op = match self.peek().cloned() {
            Some(Tok::Eq) => {
                self.pos += 1;
                Op::Eq
            }
            Some(Tok::Ne) => {
                self.pos += 1;
                Op::Ne
            }
            Some(Tok::Lt) => {
                self.pos += 1;
                Op::Lt
            }
            Some(Tok::Le) => {
                self.pos += 1;
                Op::Le
            }
            Some(Tok::Gt) => {
                self.pos += 1;
                Op::Gt
            }
            Some(Tok::Ge) => {
                self.pos += 1;
                Op::Ge
            }
            Some(Tok::KwIn) => {
                self.pos += 1;
                Op::In
            }
            Some(Tok::KwGlob) => {
                self.pos += 1;
                Op::Glob
            }
            other => bail!(
                "expected operator after field {field:?} at position {}, got {:?}",
                self.pos,
                other
            ),
        };
        let values = match op {
            Op::In => self.parse_value_set()?,
            Op::Eq | Op::Ne => self.parse_value_or_set()?,
            Op::Glob => vec![self.parse_value()?],
            Op::Lt | Op::Le | Op::Gt | Op::Ge => vec![self.parse_value()?],
        };
        Ok(AtomicClause { field, op, values })
    }

    fn parse_field(&mut self) -> Result<Field> {
        let head = match self.peek().cloned() {
            Some(Tok::Ident(s)) => {
                self.pos += 1;
                s
            }
            other => bail!(
                "expected field identifier at position {}, got {:?}",
                self.pos,
                other
            ),
        };
        let mut sub: Option<String> = None;
        if self.eat(&Tok::Dot) {
            sub = Some(match self.peek().cloned() {
                Some(Tok::Ident(s)) => {
                    self.pos += 1;
                    s
                }
                other => bail!(
                    "expected sub-identifier after '.' at position {}, got {:?}",
                    self.pos,
                    other
                ),
            });
        }
        let mut offset: Option<u32> = None;
        if self.eat(&Tok::At) {
            offset = Some(match self.peek().cloned() {
                Some(Tok::Int(v)) => {
                    self.pos += 1;
                    u32::try_from(v).with_context(|| format!("@offset {v} too large for u32"))?
                }
                other => bail!(
                    "expected integer offset after '@' at position {}, got {:?}",
                    self.pos,
                    other
                ),
            });
        }
        resolve_field(&head, sub.as_deref(), offset)
    }

    fn parse_value(&mut self) -> Result<Value> {
        match self.peek().cloned() {
            Some(Tok::Int(v)) => {
                self.pos += 1;
                Ok(Value::Int(v))
            }
            Some(Tok::Str(s)) => {
                self.pos += 1;
                Ok(Value::Str(s))
            }
            Some(Tok::KwTrue) => {
                self.pos += 1;
                Ok(Value::Ident("true".into()))
            }
            Some(Tok::KwFalse) => {
                self.pos += 1;
                Ok(Value::Ident("false".into()))
            }
            Some(Tok::Ident(s)) => {
                self.pos += 1;
                Ok(Value::Ident(s))
            }
            other => bail!("expected value at position {}, got {:?}", self.pos, other),
        }
    }

    fn parse_value_set(&mut self) -> Result<Vec<Value>> {
        if !self.eat(&Tok::LParen) {
            bail!("expected '(' after IN at position {}", self.pos);
        }
        let mut out = Vec::new();
        if !matches!(self.peek(), Some(Tok::RParen)) {
            out.push(self.parse_value()?);
            while self.eat(&Tok::Comma) {
                out.push(self.parse_value()?);
            }
        }
        if !self.eat(&Tok::RParen) {
            bail!("expected ')' to close IN set at position {}", self.pos);
        }
        if out.is_empty() {
            bail!("IN value set must be non-empty");
        }
        Ok(out)
    }

    fn parse_value_or_set(&mut self) -> Result<Vec<Value>> {
        // For `=` and `!=`, allow `<v>` or `<v1>,<v2>,...` as syntactic sugar.
        let mut out = vec![self.parse_value()?];
        while self.eat(&Tok::Comma) {
            out.push(self.parse_value()?);
        }
        Ok(out)
    }
}

fn resolve_field(head: &str, sub: Option<&str>, offset: Option<u32>) -> Result<Field> {
    match (head, sub) {
        ("pid", None) => Ok(Field::Pid),
        ("uid", None) => Ok(Field::Uid),
        ("syscall", None) => Ok(Field::Syscall),
        ("comm", None) => Ok(Field::Comm),
        ("fd_path", None) => Ok(Field::FdPath),
        ("ret", None) => Ok(Field::Ret),
        ("latency_us", None) => Ok(Field::LatencyUs),
        ("ioctl", Some("cmd")) => Ok(Field::IoctlCmd),
        ("ioctl", Some("type")) => Ok(Field::IoctlType),
        ("ioctl", Some("nr")) => Ok(Field::IoctlNr),
        ("ioctl", Some("dir")) => Ok(Field::IoctlDir),
        ("prot", Some("rwx")) => Ok(Field::ProtRwx),
        ("prot", Some("wx")) => Ok(Field::ProtWx),
        ("arg", Some(width_str)) => {
            let width = match width_str {
                "u8" => ArgWidth::U8,
                "u16" => ArgWidth::U16,
                "u32" => ArgWidth::U32,
                "u64" => ArgWidth::U64,
                _ => bail!("unknown arg width '{width_str}' (expected u8/u16/u32/u64)"),
            };
            let off =
                offset.ok_or_else(|| anyhow!("arg.{width_str} requires an '@offset' suffix"))?;
            let max = (124 - width.size_bytes()) as u32;
            if off > max {
                bail!("arg.{width_str}@{off}: offset out of range (max {max})");
            }
            Ok(Field::Arg { width, offset: off })
        }
        ("binder", Some("to_proc")) => Ok(Field::BinderToProc),
        ("binder", Some("to_thread")) => Ok(Field::BinderToThread),
        ("binder", Some("code")) => Ok(Field::BinderCode),
        ("binder", Some("flags")) => Ok(Field::BinderFlags),
        ("binder", Some("target_node")) => Ok(Field::BinderTargetNode),
        ("binder", Some("reply")) => Ok(Field::BinderReply),
        _ => bail!(
            "unknown field '{head}{}'",
            sub.map(|s| format!(".{s}")).unwrap_or_default()
        ),
    }
}

/// `true` if any clause inside `expr` references [`Field::FdPath`]. Used
/// to drive `STATE_EMIT_REQUIRED` even when the BPF lowering can't push
/// the fd_path clause itself (because it sits inside an `OR` or `NOT`).
pub fn mentions_fd_path(expr: &Expr) -> bool {
    match expr {
        Expr::Atom(c) => matches!(c.field, Field::FdPath),
        Expr::And(xs) | Expr::Or(xs) => xs.iter().any(mentions_fd_path),
        Expr::Not(x) => mentions_fd_path(x),
    }
}

// ── BPF spec extraction ─────────────────────────────────────────────────────

fn flatten_top_and(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::And(xs) => xs.iter().flat_map(flatten_top_and).collect(),
        other => vec![other],
    }
}

fn atom_is_userspace_only(atom: &AtomicClause) -> bool {
    match atom.field {
        Field::Comm
        | Field::FdPath
        | Field::ProtRwx
        | Field::ProtWx
        | Field::BinderToProc
        | Field::BinderToThread
        | Field::BinderCode
        | Field::BinderFlags
        | Field::BinderTargetNode
        | Field::BinderReply => true,
        Field::Arg { width, .. } => !matches!(width, ArgWidth::U32),
        _ => false,
    }
}

/// Try to fold `atom` into the BPF-evaluable [`MatchSpec`]. Returns `Ok(())`
/// when the atom translates cleanly; `Err(_)` when it doesn't fit (operator
/// mismatch, userspace-only field, multi-offset arg.u32, etc.). The latter
/// are silently downgraded to userspace-only — the AST evaluator still
/// applies the full predicate.
fn apply_atom_to_spec(spec: &mut MatchSpec, atom: &AtomicClause) -> Result<()> {
    if atom_is_userspace_only(atom) {
        bail!("userspace-only field");
    }
    if !matches!(
        atom.op,
        Op::Eq | Op::In | Op::Lt | Op::Le | Op::Gt | Op::Ge | Op::Ne
    ) {
        bail!("unsupported operator for BPF lowering: {:?}", atom.op);
    }

    let int_values: std::result::Result<Vec<u64>, _> = atom
        .values
        .iter()
        .map(|v| match v {
            Value::Int(n) => Ok(*n),
            other => Err(anyhow!("expected integer value, got {other:?}")),
        })
        .collect();
    let int_values = int_values.unwrap_or_default();

    match atom.field {
        Field::Pid => {
            if !matches!(atom.op, Op::Eq | Op::In) {
                bail!("pid only supports '=' and 'IN'");
            }
            for v in int_values {
                spec.pids.insert(v as u32);
            }
        }
        Field::Uid => {
            if !matches!(atom.op, Op::Eq | Op::In) {
                bail!("uid only supports '=' and 'IN'");
            }
            for v in int_values {
                spec.uids.insert(v as u32);
            }
        }
        Field::Syscall => {
            if !matches!(atom.op, Op::Eq | Op::In) {
                bail!("syscall only supports '=' and 'IN'");
            }
            for v in int_values {
                spec.syscalls.insert(v as i32);
            }
        }
        Field::IoctlCmd => {
            if !matches!(atom.op, Op::Eq | Op::In) {
                bail!("ioctl.cmd only supports '=' and 'IN'");
            }
            for v in int_values {
                spec.ioctl_cmds.insert(v as u32);
            }
        }
        Field::IoctlType => {
            if !matches!(atom.op, Op::Eq | Op::In) {
                bail!("ioctl.type only supports '=' and 'IN'");
            }
            for v in int_values {
                spec.ioctl_types.insert(v as u32);
            }
        }
        Field::IoctlNr => {
            if !matches!(atom.op, Op::Eq | Op::In) {
                bail!("ioctl.nr only supports '=' and 'IN'");
            }
            for v in int_values {
                spec.ioctl_nrs.insert(v as u32);
            }
        }
        Field::IoctlDir => {
            if !matches!(atom.op, Op::Eq) {
                bail!("ioctl.dir only supports '='");
            }
            let dir_str = match atom.values.first() {
                Some(Value::Ident(s)) => s.clone(),
                Some(Value::Str(s)) => s.clone(),
                other => bail!("ioctl.dir value must be ident/string, got {other:?}"),
            };
            spec.ioctl_dir = Some(IoctlDir::from_str_relaxed(&dir_str)?);
        }
        Field::Ret => {
            // Only a small set of useful comparisons map cleanly to RetClass:
            //   ret < 0    → Negative
            //   ret >= 1   → Nonzero (positive); same as `!= 0` modulo signed
            //   ret = 0    → Zero
            //   ret != 0   → Nonzero
            // anything else stays userspace-only.
            let class = match (atom.op, int_values.first().copied()) {
                (Op::Lt, Some(0)) => Some(RetClass::Negative),
                (Op::Le, Some(_)) => None,
                (Op::Eq, Some(0)) => Some(RetClass::Zero),
                (Op::Ne, Some(0)) => Some(RetClass::Nonzero),
                _ => None,
            };
            if let Some(c) = class {
                spec.ret_class = c;
            } else {
                bail!("ret comparison not lowerable to RetClass");
            }
        }
        Field::LatencyUs => {
            // Only `latency_us >= N` (and `>` mapped to `>= N+1`) maps cleanly.
            match (atom.op, int_values.first().copied()) {
                (Op::Ge, Some(n)) => spec.latency_min_us = Some(n),
                (Op::Gt, Some(n)) => spec.latency_min_us = Some(n.saturating_add(1)),
                _ => bail!("latency_us only supports '>=' / '>' for BPF lowering"),
            }
        }
        Field::Arg {
            width: ArgWidth::U32,
            offset,
        } => {
            if !matches!(atom.op, Op::Eq | Op::In) {
                bail!("arg.u32 only supports '=' and 'IN'");
            }
            let mut values = BTreeSet::new();
            for v in int_values {
                values.insert(v);
            }
            spec.arg_clauses.push(ArgClause {
                width: Some(ArgWidth::U32),
                offset,
                values,
            });
        }
        _ => bail!("field not BPF-lowerable in Phase 1"),
    }
    Ok(())
}

// ── Userspace evaluator over the AST ────────────────────────────────────────

fn eval_atom(c: &AtomicClause, ev: &dyn EventLens) -> bool {
    match &c.field {
        Field::Pid => eval_int_set(c, ev.pid() as u64),
        Field::Uid => eval_int_set(c, ev.uid() as u64),
        Field::Syscall => eval_int_set(c, ev.syscall_nr() as i64 as u64),
        Field::Comm => eval_glob(c, ev.comm()),
        Field::FdPath => match ev.fd_path() {
            Some(p) => eval_glob(c, p),
            None => false,
        },
        Field::IoctlCmd => match ev.ioctl_cmd() {
            Some(v) => eval_int_set(c, v as u64),
            None => false,
        },
        Field::IoctlType => match ev.ioctl_cmd() {
            Some(v) => eval_int_set(c, ((v >> 8) & 0xff) as u64),
            None => false,
        },
        Field::IoctlNr => match ev.ioctl_cmd() {
            Some(v) => eval_int_set(c, (v & 0xff) as u64),
            None => false,
        },
        Field::IoctlDir => match ev.ioctl_cmd() {
            Some(v) => {
                let dir = (v >> 30) & 0x3;
                let want = match c.values.first() {
                    Some(Value::Ident(s)) | Some(Value::Str(s)) => {
                        IoctlDir::from_str_relaxed(s).ok().map(|d| d.as_u32())
                    }
                    Some(Value::Int(n)) => Some(*n as u32),
                    _ => None,
                };
                matches!(c.op, Op::Eq) && want == Some(dir)
            }
            None => false,
        },
        Field::Ret => {
            // ret is meaningful only on sys_exit events. Returning true
            // for enters would short-circuit the AND/OR/NOT engine into
            // accepting every enter event — the exact `--match-ret
            // negative` bug the field test surfaced. Fail enter events
            // outright so the user gets exit-only output.
            if ev.is_enter() {
                return false;
            }
            eval_int_cmp(c, ev.ret() as u64)
        }
        Field::LatencyUs => match ev.latency_us() {
            Some(l) => eval_int_cmp(c, l),
            None => false, // enters and lost-correlation exits both fail
        },
        Field::ProtRwx => ev.rwx_marker() == Some(1),
        Field::ProtWx => ev.rwx_marker() == Some(2),
        Field::Arg { width, offset } => {
            let payload = match ev.arg_payload() {
                Some(p) => p,
                None => return false,
            };
            let off = *offset as usize;
            let size = width.size_bytes();
            if off + size > payload.len() {
                return false;
            }
            let v: u64 = match width {
                ArgWidth::U8 => payload[off] as u64,
                ArgWidth::U16 => u16::from_le_bytes([payload[off], payload[off + 1]]) as u64,
                ArgWidth::U32 => u32::from_le_bytes([
                    payload[off],
                    payload[off + 1],
                    payload[off + 2],
                    payload[off + 3],
                ]) as u64,
                ArgWidth::U64 => u64::from_le_bytes([
                    payload[off],
                    payload[off + 1],
                    payload[off + 2],
                    payload[off + 3],
                    payload[off + 4],
                    payload[off + 5],
                    payload[off + 6],
                    payload[off + 7],
                ]),
            };
            eval_int_set(c, v)
        }
        Field::BinderToProc => match ev.binder_to_proc() {
            Some(v) => eval_int_set(c, v as u64),
            None => false,
        },
        Field::BinderToThread => match ev.binder_to_thread() {
            Some(v) => eval_int_set(c, v as u64),
            None => false,
        },
        Field::BinderCode => match ev.binder_code() {
            Some(v) => eval_int_set(c, v as u64),
            None => false,
        },
        Field::BinderFlags => match ev.binder_flags() {
            Some(v) => eval_int_set(c, v as u64),
            None => false,
        },
        Field::BinderTargetNode => match ev.binder_target_node() {
            Some(v) => eval_int_set(c, v as i64 as u64),
            None => false,
        },
        Field::BinderReply => match ev.binder_reply() {
            Some(v) => match c.values.first() {
                Some(Value::Ident(s)) if s == "true" => v,
                Some(Value::Ident(s)) if s == "false" => !v,
                Some(Value::Int(n)) => (*n != 0) == v,
                _ => false,
            },
            None => false,
        },
    }
}

fn eval_int_set(c: &AtomicClause, v: u64) -> bool {
    let in_set = c
        .values
        .iter()
        .any(|x| matches!(x, Value::Int(n) if *n == v));
    match c.op {
        Op::Eq | Op::In => in_set,
        Op::Ne => !in_set,
        _ => eval_int_cmp(c, v),
    }
}

fn eval_int_cmp(c: &AtomicClause, v: u64) -> bool {
    let target = match c.values.first() {
        Some(Value::Int(n)) => *n,
        _ => return false,
    };
    // Treat unsigned rep as signed for `ret`. The cast is consistent with
    // how BPF stores ret as i64; bitwise comparison works for both.
    match c.op {
        Op::Eq => v == target,
        Op::Ne => v != target,
        Op::Lt => (v as i64) < (target as i64),
        Op::Le => (v as i64) <= (target as i64),
        Op::Gt => (v as i64) > (target as i64),
        Op::Ge => (v as i64) >= (target as i64),
        Op::In => c
            .values
            .iter()
            .any(|x| matches!(x, Value::Int(n) if *n == v)),
        Op::Glob => false,
    }
}

fn eval_glob(c: &AtomicClause, text: &str) -> bool {
    if c.op != Op::Glob && c.op != Op::Eq {
        return false;
    }
    c.values.iter().any(|v| match v {
        Value::Str(p) => matcher::glob_match(p, text),
        _ => false,
    })
}

// ── Pretty-printing ────────────────────────────────────────────────────────

fn render_expr(e: &Expr) -> String {
    match e {
        Expr::Atom(c) => render_atom(c),
        Expr::And(xs) => xs.iter().map(render_expr).collect::<Vec<_>>().join(" AND "),
        Expr::Or(xs) => format!(
            "({})",
            xs.iter().map(render_expr).collect::<Vec<_>>().join(" OR ")
        ),
        Expr::Not(x) => format!("NOT {}", render_expr(x)),
    }
}

fn render_atom(c: &AtomicClause) -> String {
    let f = render_field(&c.field);
    let op = match c.op {
        Op::Eq => "=",
        Op::Ne => "!=",
        Op::Lt => "<",
        Op::Le => "<=",
        Op::Gt => ">",
        Op::Ge => ">=",
        Op::In => "IN",
        Op::Glob => "GLOB",
    };
    let v: Vec<String> = c
        .values
        .iter()
        .map(|x| match x {
            Value::Int(n) => format!("{n:#x}"),
            Value::Str(s) => format!("'{s}'"),
            Value::Ident(s) => s.clone(),
        })
        .collect();
    let v_str = if c.op == Op::In {
        format!("({})", v.join(", "))
    } else {
        v.join(", ")
    };
    format!("{f} {op} {v_str}")
}

fn render_field(f: &Field) -> String {
    match f {
        Field::Pid => "pid".into(),
        Field::Uid => "uid".into(),
        Field::Syscall => "syscall".into(),
        Field::Comm => "comm".into(),
        Field::FdPath => "fd_path".into(),
        Field::IoctlCmd => "ioctl.cmd".into(),
        Field::IoctlType => "ioctl.type".into(),
        Field::IoctlNr => "ioctl.nr".into(),
        Field::IoctlDir => "ioctl.dir".into(),
        Field::Ret => "ret".into(),
        Field::LatencyUs => "latency_us".into(),
        Field::ProtRwx => "prot.rwx".into(),
        Field::ProtWx => "prot.wx".into(),
        Field::Arg { width, offset } => format!(
            "arg.{}@{}",
            match width {
                ArgWidth::U8 => "u8",
                ArgWidth::U16 => "u16",
                ArgWidth::U32 => "u32",
                ArgWidth::U64 => "u64",
            },
            offset
        ),
        Field::BinderToProc => "binder.to_proc".into(),
        Field::BinderToThread => "binder.to_thread".into(),
        Field::BinderCode => "binder.code".into(),
        Field::BinderFlags => "binder.flags".into(),
        Field::BinderTargetNode => "binder.target_node".into(),
        Field::BinderReply => "binder.reply".into(),
    }
}

// Convenience: borrow the `BinderClause` shape so future changes keep
// `crate::matcher::BinderClause` in sync — silences dead-code warnings if
// the struct ever gains a field.
#[allow(dead_code)]
fn _binder_clause_shape_witness(_b: &BinderClause) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub event for the AST evaluator tests. Mirrors the lens used in
    /// `matcher::tests::TestEvent` but only exposes what these tests need.
    #[derive(Default)]
    struct Ev {
        pid: u32,
        uid: u32,
        nr: i32,
        is_enter: bool,
        ret: i64,
        latency_us: Option<u64>,
        comm: String,
        fd_path: Option<String>,
        ioctl_cmd: Option<u32>,
        arg_payload: Option<Vec<u8>>,
        rwx_marker: Option<u8>,
    }

    impl EventLens for Ev {
        fn pid(&self) -> u32 {
            self.pid
        }
        fn uid(&self) -> u32 {
            self.uid
        }
        fn syscall_nr(&self) -> i32 {
            self.nr
        }
        fn is_enter(&self) -> bool {
            self.is_enter
        }
        fn ret(&self) -> i64 {
            self.ret
        }
        fn latency_us(&self) -> Option<u64> {
            self.latency_us
        }
        fn comm(&self) -> &str {
            &self.comm
        }
        fn fd_path(&self) -> Option<&str> {
            self.fd_path.as_deref()
        }
        fn ioctl_cmd(&self) -> Option<u32> {
            self.ioctl_cmd
        }
        fn arg_payload(&self) -> Option<&[u8]> {
            self.arg_payload.as_deref()
        }
        fn rwx_marker(&self) -> Option<u8> {
            self.rwx_marker
        }
        fn binder_to_proc(&self) -> Option<u32> {
            None
        }
        fn binder_to_thread(&self) -> Option<u32> {
            None
        }
        fn binder_code(&self) -> Option<u32> {
            None
        }
        fn binder_flags(&self) -> Option<u32> {
            None
        }
        fn binder_target_node(&self) -> Option<i32> {
            None
        }
        fn binder_reply(&self) -> Option<bool> {
            None
        }
    }

    fn parse_ok(s: &str) -> Expr {
        parse(s).unwrap_or_else(|e| panic!("parse {s:?}: {e:#}"))
    }

    #[test]
    fn parse_simple_eq() {
        let e = parse_ok("syscall = 29");
        match e {
            Expr::Atom(c) => {
                assert!(matches!(c.field, Field::Syscall));
                assert_eq!(c.op, Op::Eq);
                assert!(matches!(c.values[0], Value::Int(29)));
            }
            _ => panic!("expected atom"),
        }
    }

    #[test]
    fn parse_and_or_not_with_parens() {
        let e = parse_ok("pid = 970 AND (syscall = 29 OR syscall = 222)");
        if let Expr::And(xs) = e {
            assert_eq!(xs.len(), 2);
            assert!(matches!(&xs[0], Expr::Atom(c) if matches!(c.field, Field::Pid)));
            assert!(matches!(&xs[1], Expr::Or(_)));
        } else {
            panic!("expected top-level AND");
        }

        let e2 = parse_ok("NOT comm GLOB 'audio*'");
        assert!(matches!(e2, Expr::Not(_)));
    }

    #[test]
    fn parse_in_set() {
        let e = parse_ok("ioctl.cmd IN (0xc0104c64, 0xc0084c01)");
        match e {
            Expr::Atom(c) => {
                assert_eq!(c.op, Op::In);
                assert_eq!(c.values.len(), 2);
            }
            _ => panic!("expected atom"),
        }
    }

    #[test]
    fn parse_arg_accessor() {
        let e = parse_ok("arg.u32@0 = 0x20200");
        match e {
            Expr::Atom(c) => assert_eq!(
                c.field,
                Field::Arg {
                    width: ArgWidth::U32,
                    offset: 0
                }
            ),
            _ => panic!(),
        }
    }

    #[test]
    fn parse_arg_offset_out_of_range_rejected() {
        let err = parse("arg.u32@121 = 0").unwrap_err();
        assert!(format!("{err:#}").contains("out of range"));
    }

    #[test]
    fn parse_unknown_field_rejected() {
        let err = parse("garbage = 1").unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn parse_unbalanced_parens_rejected() {
        let err = parse("(pid = 1").unwrap_err();
        assert!(format!("{err:#}").contains("expected ')'"));
    }

    #[test]
    fn evaluate_simple_eq_atom() {
        let e = parse_ok("syscall = 29");
        let on = Ev {
            nr: 29,
            ..Ev::default()
        };
        let off = Ev {
            nr: 222,
            ..Ev::default()
        };
        assert!(evaluate(&e, &on));
        assert!(!evaluate(&e, &off));
    }

    #[test]
    fn evaluate_and_combines_clauses() {
        let e = parse_ok("syscall = 29 AND pid = 970");
        let ok = Ev {
            nr: 29,
            pid: 970,
            ..Ev::default()
        };
        let bad = Ev {
            nr: 29,
            pid: 1,
            ..Ev::default()
        };
        assert!(evaluate(&e, &ok));
        assert!(!evaluate(&e, &bad));
    }

    #[test]
    fn evaluate_or_picks_either_branch() {
        let e = parse_ok("syscall = 29 OR pid = 970");
        let lhs = Ev {
            nr: 29,
            pid: 1,
            ..Ev::default()
        };
        let rhs = Ev {
            nr: 222,
            pid: 970,
            ..Ev::default()
        };
        let neither = Ev {
            nr: 222,
            pid: 1,
            ..Ev::default()
        };
        assert!(evaluate(&e, &lhs));
        assert!(evaluate(&e, &rhs));
        assert!(!evaluate(&e, &neither));
    }

    #[test]
    fn evaluate_not_inverts() {
        let e = parse_ok("NOT syscall = 29");
        let nope = Ev {
            nr: 29,
            ..Ev::default()
        };
        let yep = Ev {
            nr: 222,
            ..Ev::default()
        };
        assert!(!evaluate(&e, &nope));
        assert!(evaluate(&e, &yep));
    }

    #[test]
    fn evaluate_glob_on_fd_path() {
        let e = parse_ok("fd_path GLOB '/dev/lwis*'");
        let on = Ev {
            fd_path: Some("/dev/lwis-top".into()),
            ..Ev::default()
        };
        let off = Ev {
            fd_path: Some("/dev/binder".into()),
            ..Ev::default()
        };
        assert!(evaluate(&e, &on));
        assert!(!evaluate(&e, &off));
    }

    #[test]
    fn ret_atom_drops_enter_events() {
        let e = parse("ret < 0").unwrap();
        let enter_neg = Ev {
            nr: 29,
            is_enter: true,
            ret: -22,
            ..Ev::default()
        };
        let exit_neg = Ev {
            nr: 29,
            is_enter: false,
            ret: -22,
            ..Ev::default()
        };
        // Enter events must fail even when ret would otherwise match —
        // ret is exit-only, and the previous `if is_enter() { return
        // true }` short-circuit was the source of the field-test
        // 321k-enter leak.
        assert!(!evaluate(&e, &enter_neg));
        assert!(evaluate(&e, &exit_neg));
    }

    #[test]
    fn latency_atom_drops_enter_events() {
        let e = parse("latency_us >= 5000").unwrap();
        let enter = Ev {
            nr: 29,
            is_enter: true,
            latency_us: None,
            ..Ev::default()
        };
        let exit_slow = Ev {
            nr: 29,
            is_enter: false,
            latency_us: Some(10_000),
            ..Ev::default()
        };
        assert!(!evaluate(&e, &enter));
        assert!(evaluate(&e, &exit_slow));
    }

    #[test]
    fn evaluate_arg_u32_accessor() {
        let mut payload = vec![0u8; 16];
        payload[..4].copy_from_slice(&0x20200u32.to_le_bytes());
        let e = parse_ok("arg.u32@0 = 0x20200");
        let ev = Ev {
            ioctl_cmd: Some(0xc010_4c64),
            arg_payload: Some(payload),
            ..Ev::default()
        };
        assert!(evaluate(&e, &ev));
    }

    #[test]
    fn extract_bpf_spec_pulls_top_level_atoms() {
        let e = parse_ok("syscall = 29 AND ioctl.cmd = 0xc0104c64 AND fd_path GLOB '/dev/lwis*'");
        let spec = extract_bpf_spec(&e);
        assert!(spec.syscalls.contains(&29));
        assert!(spec.ioctl_cmds.contains(&0xc010_4c64));
        // fd_path must NOT lower to BPF — userspace-only.
        assert!(spec.fd_globs.is_empty());
    }

    #[test]
    fn extract_bpf_spec_skips_inside_or() {
        let e = parse_ok("(syscall = 29 OR pid = 970)");
        let spec = extract_bpf_spec(&e);
        // Top-level is OR, not AND-of-atoms — so nothing leaks into BPF.
        assert!(spec.is_empty());
    }

    #[test]
    fn extract_bpf_spec_skips_inside_not() {
        let e = parse_ok("NOT syscall = 29");
        let spec = extract_bpf_spec(&e);
        assert!(spec.is_empty());
    }

    #[test]
    fn extract_bpf_spec_lowers_ret_lt_zero() {
        let e = parse_ok("ret < 0");
        let spec = extract_bpf_spec(&e);
        assert_eq!(spec.ret_class, RetClass::Negative);
    }

    #[test]
    fn extract_bpf_spec_lowers_latency_min() {
        let e = parse_ok("latency_us >= 5000");
        let spec = extract_bpf_spec(&e);
        assert_eq!(spec.latency_min_us, Some(5000));
    }

    #[test]
    fn audit_lines_classify_top_conjuncts() {
        let e = parse_ok("syscall = 29 AND fd_path GLOB '/dev/lwis*'");
        let lines = audit_lines(&e);
        let bpf = lines
            .iter()
            .find(|l| l.contains("[bpf]") && l.contains("syscall"))
            .expect("syscall must be flagged bpf");
        assert!(bpf.contains("[bpf]"));
        let user = lines
            .iter()
            .find(|l| l.contains("[user]") && l.contains("fd_path"))
            .expect("fd_path must be flagged user");
        assert!(user.contains("[user]"));
    }

    #[test]
    fn lex_handles_quoted_strings_with_spaces() {
        let toks = lex("comm GLOB 'cameraserver*' OR pid = 1").unwrap();
        assert!(matches!(toks[0], Tok::Ident(ref s) if s == "comm"));
        assert_eq!(toks[1], Tok::KwGlob);
        assert!(matches!(toks[2], Tok::Str(ref s) if s == "cameraserver*"));
    }

    #[test]
    fn lex_rejects_unterminated_string() {
        let err = lex("comm GLOB 'oops").unwrap_err();
        assert!(format!("{err:#}").contains("unterminated"));
    }

    #[test]
    fn parse_eq_value_set_sugar() {
        // `field = v1, v2, v3` is sugar for `field IN (v1, v2, v3)`.
        let e = parse_ok("syscall = 29, 222");
        if let Expr::Atom(c) = e {
            assert_eq!(c.values.len(), 2);
            assert_eq!(c.op, Op::Eq);
        } else {
            panic!("expected atom");
        }
    }
}
