//! A tiny no_std filter expression parser and evaluator for Linux tracepoint–like filters.
//!
//! Features:
//! - Numeric comparisons: `== != < <= > >=` (supports bit mask form: `field & 0x10 == 0x10`).
//! - String/byte comparisons: `== != ~` (`~` performs glob matching supporting `* ? [..]` and class negation `[!a]` / `[^a]`).
//! - Unquoted barewords allowed (`comm != bash`); quote when spaces or special characters are present (`"C Program"`).
//! - Logical operators with precedence: parentheses > comparison > `&&` > `||` (short‑circuit evaluation).
//! - Tri‑state runtime: missing field => `Unknown`; top‑level `Unknown` is treated as `true` (fail‑open), `Unknown` is true‑neutral for `&&` and false‑neutral for `||`.
//! - Compile‑time validation of field existence and type.
//! - Hex (`0x..`) and decimal integer literals.
//! - no_std + alloc friendly (uses `BTreeMap` in examples; can evaluate directly over a raw byte buffer via `BufContext`).
//!
//! Schema & Field Types:
//! A schema is defined via the `schema!` macro listing `(name, FieldType, offset, length)` tuples. Integer types implement `FieldClassifier` exposing a `FIELD_TYPE` constant. Bytes fields use `FieldType::Bytes`.
//!
//! Example (map based):
//! ```rust
//! extern crate alloc;
//! use alloc::collections::BTreeMap;
//! use tp_lexer::{schema, FieldType, compile_with_schema, FieldClassifier};
//!
//! let schema = schema!(
//!     "sig"  => (u32::FIELD_TYPE, 0, 4),
//!     "comm" => (FieldType::Bytes, 4, 16),
//! );
//! let compiled = compile_with_schema("sig >= 10 && comm != bash", schema).unwrap();
//! let mut ctx = BTreeMap::from([
//!     ("sig".to_string(), "12".to_string()),
//!     ("comm".to_string(), "sh".to_string()),
//! ]);
//! assert!(compiled.evaluate(&ctx));
//! ```
//!
//! Example (raw buffer):
//! ```rust
//! use tp_lexer::{schema, FieldType, compile_with_schema, BufContext, FieldClassifier};
//! // Layout: [ sig: u32 (4 bytes) | comm: 12 bytes ASCII | padding ]
//! let schema = schema!(
//!     "sig"  => (u32::FIELD_TYPE, 0, 4),
//!     "comm" => (FieldType::Bytes, 4, 12),
//! );
//! let mut buf = [0u8; 32];
//! // sig = 12
//! buf[0..4].copy_from_slice(&12u32.to_le_bytes());
//! // comm = "sh" zero padded
//! buf[4..6].copy_from_slice(b"sh");
//! let ctx = BufContext::new(&buf, &schema);
//! let compiled = compile_with_schema("sig >= 10 && comm != bash", schema).unwrap();
//! assert!(compiled.evaluate(&ctx));
//! ```
//!
//! Tri‑state rationale: treating top‑level `Unknown` as `true` prevents inadvertent data loss when a new field is not yet populated. If strict behavior is desired you can wrap your filter: `(field != value) && defined(field)` by introducing an explicit presence flag in your schema.
//!
//! Limitations / Non‑Goals:
//! - No arithmetic besides bit masking.
//! - No unary operators or regex; glob only.
//! - No implicit widening or casting between integer sizes (user is responsible for consistent layout).
//! - Evaluation is left‑associative for chains of `&&` / `||` (standard short‑circuit).
//!
//! Safety Notes:
//! - Buffer offsets and lengths are trusted; ensure schema matches actual event layout.
//! - Integer extraction uses user‑provided `ToI64` implementations; undefined behavior inside those implementations is out of scope.
//!
//! See README for a more thorough integration guide.
#![deny(missing_docs)]
#![no_std]

extern crate alloc;
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
};
use core::fmt::Debug;
mod internal;

/// A span in the input expression, used for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Zero-based start byte offset (inclusive).
    pub start: usize,
    end: usize,
}

/// An error produced while lexing or parsing a filter expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// The offending span in the original input.
    pub span: Span,
    /// A human-readable error message.
    pub message: String,
}

impl ParseError {
    fn new<S: Into<String>>(start: usize, end: usize, msg: S) -> Self {
        Self {
            span: Span { start, end },
            message: msg.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Ident(String),
    Int(i64),
    String(String),
    Bareword(String),
    AndAnd, // &&
    OrOr,   // ||
    Amp,    // &
    EqEq,   // ==
    NotEq,  // !=
    Lt,     // <
    Le,     // <=
    Gt,     // >
    Ge,     // >=
    Tilde,  // ~
    LParen, // (
    RParen, // )
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    span: Span,
}

struct Lexer<'a> {
    input: &'a str,
    bytes: &'a [u8],
    pos: usize,
    len: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            bytes: input.as_bytes(),
            pos: 0,
            len: input.len(),
        }
    }

    fn peek(&self) -> Option<u8> {
        if self.pos < self.len {
            Some(self.bytes[self.pos])
        } else {
            None
        }
    }

    fn peek2(&self) -> Option<u8> {
        if self.pos + 1 < self.len {
            Some(self.bytes[self.pos + 1])
        } else {
            None
        }
    }

    fn bump(&mut self) -> Option<u8> {
        if self.pos < self.len {
            let b = self.bytes[self.pos];
            self.pos += 1;
            Some(b)
        } else {
            None
        }
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn lex_number(&mut self, start: usize) -> Result<Token, ParseError> {
        // Support 0x... hex and decimal
        if self.peek() == Some(b'0') && matches!(self.peek2(), Some(b'x') | Some(b'X')) {
            self.bump(); // 0
            self.bump(); // x
            let from = self.pos;
            while let Some(b) = self.peek() {
                if (b as char).is_ascii_hexdigit() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if self.pos == from {
                return Err(ParseError::new(
                    start,
                    self.pos,
                    "hex literal missing digits",
                ));
            }
            let s = &self.input[from..self.pos];
            let v = i64::from_str_radix(s, 16)
                .map_err(|_| ParseError::new(start, self.pos, "hex literal overflow"))?;
            Ok(Token {
                kind: TokenKind::Int(v),
                span: Span {
                    start,
                    end: self.pos,
                },
            })
        } else {
            let from = self.pos;
            while let Some(b) = self.peek() {
                if (b as char).is_ascii_digit() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            let s = &self.input[from..self.pos];
            let v: i64 = s
                .parse()
                .map_err(|_| ParseError::new(start, self.pos, "decimal literal overflow"))?;
            Ok(Token {
                kind: TokenKind::Int(v),
                span: Span {
                    start,
                    end: self.pos,
                },
            })
        }
    }

    fn lex_ident(&mut self, start: usize) -> Token {
        let from = self.pos - 1; // already consumed first char
        while let Some(b) = self.peek() {
            if (b as char).is_ascii_alphanumeric() || b == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let s = &self.input[from..self.pos];
        Token {
            kind: TokenKind::Ident(s.to_string()),
            span: Span {
                start,
                end: self.pos,
            },
        }
    }

    fn lex_string(&mut self, start: usize, quote: u8) -> Result<Token, ParseError> {
        let mut out = String::new();
        while let Some(b) = self.bump() {
            if b == quote {
                return Ok(Token {
                    kind: TokenKind::String(out),
                    span: Span {
                        start,
                        end: self.pos,
                    },
                });
            } else if b == b'\\' {
                match self.bump() {
                    Some(b'\\') => out.push('\\'),
                    Some(b'\"') => out.push('"'),
                    Some(b'\'') => out.push('\''),
                    Some(b'n') => out.push('\n'),
                    Some(b't') => out.push('\t'),
                    Some(c) => out.push(c as char),
                    None => {
                        return Err(ParseError::new(start, self.pos, "incomplete string escape"));
                    }
                }
            } else {
                out.push(b as char);
            }
        }
        Err(ParseError::new(start, self.pos, "unterminated string"))
    }

    fn is_op_char(b: u8) -> bool {
        matches!(
            b,
            b'&' | b'|' | b'=' | b'!' | b'<' | b'>' | b'~' | b'(' | b')'
        )
    }

    fn lex_bareword(&mut self, start: usize) -> Token {
        let from = self.pos - 1; // consumed first
        // bareword continues until whitespace or operator or paren
        while let Some(b) = self.peek() {
            if b.is_ascii_whitespace() || Self::is_op_char(b) {
                break;
            }
            self.pos += 1;
        }
        let s = &self.input[from..self.pos];
        Token {
            kind: TokenKind::Bareword(s.to_string()),
            span: Span {
                start,
                end: self.pos,
            },
        }
    }

    fn next_token(&mut self) -> Result<Token, ParseError> {
        self.skip_ws();
        let start = self.pos;
        if self.pos >= self.len {
            return Ok(Token {
                kind: TokenKind::Eof,
                span: Span { start, end: start },
            });
        }
        let b = self.bump().unwrap();
        match b {
            b'(' => Ok(Token {
                kind: TokenKind::LParen,
                span: Span {
                    start,
                    end: self.pos,
                },
            }),
            b')' => Ok(Token {
                kind: TokenKind::RParen,
                span: Span {
                    start,
                    end: self.pos,
                },
            }),
            b'&' => {
                if self.peek() == Some(b'&') {
                    self.bump();
                    Ok(Token {
                        kind: TokenKind::AndAnd,
                        span: Span {
                            start,
                            end: self.pos,
                        },
                    })
                } else {
                    Ok(Token {
                        kind: TokenKind::Amp,
                        span: Span {
                            start,
                            end: self.pos,
                        },
                    })
                }
            }
            b'|' => {
                if self.peek() == Some(b'|') {
                    self.bump();
                    Ok(Token {
                        kind: TokenKind::OrOr,
                        span: Span {
                            start,
                            end: self.pos,
                        },
                    })
                } else {
                    Err(ParseError::new(
                        start,
                        self.pos,
                        "single '|' is invalid; did you mean '||'?",
                    ))
                }
            }
            b'=' => {
                if self.peek() == Some(b'=') {
                    self.bump();
                    Ok(Token {
                        kind: TokenKind::EqEq,
                        span: Span {
                            start,
                            end: self.pos,
                        },
                    })
                } else {
                    Err(ParseError::new(
                        start,
                        self.pos,
                        "single '=' is invalid; did you mean '=='?",
                    ))
                }
            }
            b'!' => {
                if self.peek() == Some(b'=') {
                    self.bump();
                    Ok(Token {
                        kind: TokenKind::NotEq,
                        span: Span {
                            start,
                            end: self.pos,
                        },
                    })
                } else {
                    Err(ParseError::new(
                        start,
                        self.pos,
                        "'!' is only supported as '!='",
                    ))
                }
            }
            b'<' => {
                if self.peek() == Some(b'=') {
                    self.bump();
                    Ok(Token {
                        kind: TokenKind::Le,
                        span: Span {
                            start,
                            end: self.pos,
                        },
                    })
                } else {
                    Ok(Token {
                        kind: TokenKind::Lt,
                        span: Span {
                            start,
                            end: self.pos,
                        },
                    })
                }
            }
            b'>' => {
                if self.peek() == Some(b'=') {
                    self.bump();
                    Ok(Token {
                        kind: TokenKind::Ge,
                        span: Span {
                            start,
                            end: self.pos,
                        },
                    })
                } else {
                    Ok(Token {
                        kind: TokenKind::Gt,
                        span: Span {
                            start,
                            end: self.pos,
                        },
                    })
                }
            }
            b'~' => Ok(Token {
                kind: TokenKind::Tilde,
                span: Span {
                    start,
                    end: self.pos,
                },
            }),
            b'"' | b'\'' => self.lex_string(start, b),
            b'0'..=b'9' => {
                // rewind pos by one because lex_number expects current pos at the first char already considered
                self.pos -= 1;
                self.lex_number(start)
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                // identifier starts with letter or '_'
                Ok(self.lex_ident(start))
            }
            other => {
                // treat as start of bareword, if it's not whitespace and not operator
                if other.is_ascii_whitespace() || Self::is_op_char(other) {
                    Err(ParseError::new(
                        start,
                        self.pos,
                        format!("unrecognized character: '{}'", other as char),
                    ))
                } else {
                    Ok(self.lex_bareword(start))
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NumOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StrOp {
    Eq,
    Ne,
    Glob,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    NumCmp {
        field: String,
        mask: Option<i64>,
        op: NumOp,
        rhs: i64,
    },
    StrCmp {
        field: String,
        op: StrOp,
        pat: String,
    },
    Group(Box<Expr>),
}

struct Parser<'a> {
    lexer: Lexer<'a>,
    lookahead: Token,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Result<Self, ParseError> {
        let mut lex = Lexer::new(input);
        let first = lex.next_token()?;
        Ok(Self {
            lexer: lex,
            lookahead: first,
        })
    }

    fn bump(&mut self) -> Result<Token, ParseError> {
        let span = self.lookahead.span;
        let cur = core::mem::replace(
            &mut self.lookahead,
            Token {
                kind: TokenKind::Eof,
                span,
            },
        );
        self.lookahead = self.lexer.next_token()?;
        Ok(cur)
    }

    fn expect(&mut self, kind: &TokenKind) -> Result<Token, ParseError> {
        if &self.lookahead.kind == kind {
            self.bump()
        } else {
            Err(ParseError::new(
                self.lookahead.span.start,
                self.lookahead.span.end,
                format!("expected {:?}, found {:?}", kind, self.lookahead.kind),
            ))
        }
    }

    fn parse(&mut self) -> Result<Expr, ParseError> {
        let expr = self.parse_or()?;
        match self.lookahead.kind {
            TokenKind::Eof => Ok(expr),
            _ => Err(ParseError::new(
                self.lookahead.span.start,
                self.lookahead.span.end,
                "extraneous input",
            )),
        }
    }

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and()?;
        while matches!(self.lookahead.kind, TokenKind::OrOr) {
            self.bump()?; // ||
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_cmp()?;
        while matches!(self.lookahead.kind, TokenKind::AndAnd) {
            self.bump()?; // &&
            let right = self.parse_cmp()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_cmp(&mut self) -> Result<Expr, ParseError> {
        match &self.lookahead.kind {
            TokenKind::LParen => {
                self.bump()?; // (
                let e = self.parse_or()?;
                self.expect(&TokenKind::RParen)?;
                Ok(Expr::Group(Box::new(e)))
            }
            TokenKind::Ident(_) => self.parse_field_cmp(),
            _ => Err(ParseError::new(
                self.lookahead.span.start,
                self.lookahead.span.end,
                "expected '(' or field name",
            )),
        }
    }

    fn parse_field_cmp(&mut self) -> Result<Expr, ParseError> {
        let name_tok = self.bump()?; // ident
        let field = match name_tok.kind {
            TokenKind::Ident(s) => s,
            _ => unreachable!(),
        };

        // Case 1: numeric with optional '& INT'
        if matches!(self.lookahead.kind, TokenKind::Amp) {
            self.bump()?; // &
            let int_tok = self.expect_int()?;
            let mask_val = match int_tok.kind {
                TokenKind::Int(v) => v,
                _ => unreachable!(),
            };
            let op_tok = self.bump()?; // numeric op
            let op = match op_tok.kind {
                TokenKind::EqEq => NumOp::Eq,
                TokenKind::NotEq => NumOp::Ne,
                TokenKind::Lt => NumOp::Lt,
                TokenKind::Le => NumOp::Le,
                TokenKind::Gt => NumOp::Gt,
                TokenKind::Ge => NumOp::Ge,
                _ => {
                    return Err(ParseError::new(
                        op_tok.span.start,
                        op_tok.span.end,
                        "numeric comparison operator required",
                    ));
                }
            };
            let int_tok = self.expect_int()?;
            let rhs = match int_tok.kind {
                TokenKind::Int(v) => v,
                _ => unreachable!(),
            };
            return Ok(Expr::NumCmp {
                field,
                mask: Some(mask_val),
                op,
                rhs,
            });
        }

        // Case 2: if next token is one of <, <=, >, >= -> numeric
        if matches!(
            self.lookahead.kind,
            TokenKind::Lt | TokenKind::Le | TokenKind::Gt | TokenKind::Ge
        ) {
            let op_tok = self.bump()?;
            let op = match op_tok.kind {
                TokenKind::Lt => NumOp::Lt,
                TokenKind::Le => NumOp::Le,
                TokenKind::Gt => NumOp::Gt,
                TokenKind::Ge => NumOp::Ge,
                _ => unreachable!(),
            };
            let int_tok = self.expect_int()?;
            let rhs = match int_tok.kind {
                TokenKind::Int(v) => v,
                _ => unreachable!(),
            };
            return Ok(Expr::NumCmp {
                field,
                mask: None,
                op,
                rhs,
            });
        }

        // Case 3: '==' / '!=' / '~' -> could be string (or numeric for ==/!=). Decide by RHS token.
        match self.lookahead.kind.clone() {
            TokenKind::Tilde => {
                self.bump()?; // ~
                let pat = self.parse_pattern_literal()?;
                Ok(Expr::StrCmp {
                    field,
                    op: StrOp::Glob,
                    pat,
                })
            }
            TokenKind::EqEq | TokenKind::NotEq => {
                let op_tok = self.bump()?;
                // if RHS is INT -> numeric; else -> string literal/pattern
                match &self.lookahead.kind {
                    TokenKind::Int(v) => {
                        let rhs = *v;
                        self.bump()?; // consume int
                        let op = match op_tok.kind {
                            TokenKind::EqEq => NumOp::Eq,
                            TokenKind::NotEq => NumOp::Ne,
                            _ => unreachable!(),
                        };
                        Ok(Expr::NumCmp {
                            field,
                            mask: None,
                            op,
                            rhs,
                        })
                    }
                    _ => {
                        let pat = self.parse_pattern_literal()?;
                        let op = match op_tok.kind {
                            TokenKind::EqEq => StrOp::Eq,
                            TokenKind::NotEq => StrOp::Ne,
                            _ => unreachable!(),
                        };
                        Ok(Expr::StrCmp { field, op, pat })
                    }
                }
            }
            _ => Err(ParseError::new(
                self.lookahead.span.start,
                self.lookahead.span.end,
                "comparison operator required",
            )),
        }
    }

    fn parse_pattern_literal(&mut self) -> Result<String, ParseError> {
        // Accept STRING, BAREWORD, or IDENT possibly followed by BAREWORD chunks (to capture bash*)
        let mut s = match self.lookahead.kind.clone() {
            TokenKind::String(st) => {
                self.bump()?;
                st
            }
            TokenKind::Bareword(st) => {
                self.bump()?;
                st
            }
            TokenKind::Ident(st) => {
                self.bump()?;
                st
            }
            _ => {
                return Err(ParseError::new(
                    self.lookahead.span.start,
                    self.lookahead.span.end,
                    "string literal required (quotes optional)",
                ));
            }
        };
        // Merge trailing bareword chunks if any
        while let TokenKind::Bareword(st) = self.lookahead.kind.clone() {
            self.bump()?;
            s.push_str(&st);
        }
        Ok(s)
    }

    fn expect_int(&mut self) -> Result<Token, ParseError> {
        match self.lookahead.kind {
            TokenKind::Int(_) => self.bump(),
            _ => Err(ParseError::new(
                self.lookahead.span.start,
                self.lookahead.span.end,
                "numeric literal required",
            )),
        }
    }
}

/// A trait to convert byte slices to i64 values.
pub trait ToI64: Send + Sync {
    /// Converts the given byte slice to an i64.
    fn to_i64(&self, bytes: &[u8], offset: usize) -> Result<i64, &'static str>;
}

fn to_bytes(buf: &[u8], offset: usize, len: usize) -> Result<&[u8], &'static str> {
    if offset + len <= buf.len() {
        Ok(&buf[offset..offset + len])
    } else {
        Err("buffer too small for field")
    }
}

/// The type of a field in the schema.
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub enum FieldType {
    Integer(&'static dyn ToI64),
    Bytes,
    Unsupported,
}

impl Debug for FieldType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FieldType::Integer(_) => write!(f, "Integer"),
            FieldType::Bytes => write!(f, "Bytes"),
            FieldType::Unsupported => write!(f, "Unsupported"),
        }
    }
}

/// A trait to classify fields at compile time.
pub trait FieldClassifier {
    /// The field type.
    const FIELD_TYPE: FieldType;
}

/// Declares the available fields and their types for compile-time validation.
///
/// Define a schema with the `schema!` macro: each entry supplies the field name,
/// its `FieldType`, and the (offset, length) describing where the data resides
/// in a raw event buffer. Integer types implement `FieldClassifier` so you can
/// write `u32::FIELD_TYPE` directly. Unknown fields referenced in an expression
/// produce a compile-time `ParseError`.
#[derive(Default, Clone, Copy)]
pub struct Schema {
    /// The list of fields and their types.
    fields: &'static [(&'static str, FieldType, usize, usize)],
}

impl Debug for Schema {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut fmt = f.debug_struct("Schema");
        for (n, t, offset, len) in self.fields.iter() {
            fmt.field(
                n,
                &format_args!("type: {:?}, offset: {}, length: {}", t, offset, len),
            );
        }
        fmt.finish()
    }
}

impl Schema {
    /// Creates a new schema from the given field list.
    pub const fn new(fields: &'static [(&'static str, FieldType, usize, usize)]) -> Self {
        Self { fields }
    }

    /// Looks up the type, offset, and length of a field by name.
    pub fn get(&self, name: &str) -> Option<(FieldType, usize, usize)> {
        for (n, t, offset, len) in self.fields.iter() {
            if *n == name {
                return Some((*t, *offset, *len));
            }
        }
        None
    }

    /// Looks up the type of a field by name.
    pub fn get_type(&self, name: &str) -> Option<FieldType> {
        self.get(name).map(|(t, _, _)| t)
    }
}

/// Helper macro to define a schema inline.
#[macro_export]
macro_rules! schema {
    ($( $name:expr => ($ftype:expr, $offset:expr, $len:expr) ),* $(,)? ) => {
        {
            let fields: &'static [(&'static str, $crate::FieldType, usize, usize)] = &[
                $(
                    ($name, $ftype, $offset, $len),
                )*
            ];
            $crate::Schema::new(fields)
        }

    };
}

/// Runtime context abstraction used during expression evaluation.
///
/// Two common implementations are provided:
/// - `BTreeMap<String,String>` (alloc based, convenient for testing)
/// - `BufContext` for zero-copy access over a raw byte buffer + schema
///
/// Custom contexts can implement this trait to bridge existing telemetry/event
/// representations without copying. Return `None` for missing fields to trigger
/// the tri-state `Unknown` logic.
pub trait Context {
    /// Returns an integer value for the given field, or `None` if missing.
    fn get_integer(&self, name: &str) -> Option<i64>;
    /// Returns a byte slice value for the given field, or `None` if missing.
    fn get_bytes(&self, name: &str) -> Option<&[u8]>;
}

impl Context for BTreeMap<String, String> {
    fn get_integer(&self, name: &str) -> Option<i64> {
        self.get(name).and_then(|s| s.parse::<i64>().ok())
    }
    fn get_bytes(&self, name: &str) -> Option<&[u8]> {
        self.get(name).map(|s| s.as_bytes())
    }
}

/// Runtime context for evaluating against a byte buffer and schema.
pub struct BufContext<'a> {
    buf: &'a [u8],
    schema: &'a Schema,
}

impl<'a> BufContext<'a> {
    /// Creates a new buffer context with the given buffer and schema.
    pub fn new(buf: &'a [u8], schema: &'a Schema) -> Self {
        Self { buf, schema }
    }
}

impl<'a> Context for BufContext<'a> {
    fn get_integer(&self, name: &str) -> Option<i64> {
        let (field_type, offset, _len) = self.schema.get(name)?;
        match field_type {
            FieldType::Integer(to_i64_fn) => to_i64_fn.to_i64(self.buf, offset).ok(),
            _ => None,
        }
    }
    fn get_bytes(&self, name: &str) -> Option<&[u8]> {
        let (field_type, offset, len) = self.schema.get(name)?;
        match field_type {
            FieldType::Bytes => {
                let bytes = to_bytes(self.buf, offset, len).ok()?;
                Some(bytes)
            }
            _ => None,
        }
    }
}

// --------------- Glob matcher ----------------
fn glob_match_bytes(p: &[u8], t: &[u8]) -> bool {
    glob_match_impl(p, 0, t, 0)
}

fn glob_match_impl(p: &[u8], pi: usize, t: &[u8], ti: usize) -> bool {
    let mut pi = pi;
    let mut ti = ti;
    while pi < p.len() {
        match p[pi] {
            b'?' => {
                if ti >= t.len() {
                    return false;
                }
                pi += 1;
                ti += 1;
            }
            b'*' => {
                // collapse consecutive *
                while pi < p.len() && p[pi] == b'*' {
                    pi += 1;
                }
                if pi == p.len() {
                    return true;
                } // trailing * matches rest
                // try to match the rest at any position
                let mut k = ti;
                while k <= t.len() {
                    if glob_match_impl(p, pi, t, k) {
                        return true;
                    }
                    if k == t.len() {
                        break;
                    }
                    k += 1;
                }
                return false;
            }
            b'[' => {
                if ti >= t.len() {
                    return false;
                }
                let (ok, new_pi) = match_class(p, pi + 1, t[ti]);
                if !ok {
                    return false;
                }
                pi = new_pi; // new_pi points after ']'
                ti += 1;
            }
            c => {
                if ti >= t.len() || t[ti] != c {
                    return false;
                }
                pi += 1;
                ti += 1;
            }
        }
    }
    ti == t.len()
}

fn match_class(p: &[u8], mut pi: usize, ch: u8) -> (bool, usize) {
    let mut matched = false;
    let negated = if pi < p.len() && (p[pi] == b'^' || p[pi] == b'!') {
        pi += 1;
        true
    } else {
        false
    };
    let _start_pi = pi;
    let mut prev: Option<u8> = None;
    while pi < p.len() && p[pi] != b']' {
        let c = p[pi];
        if c == b'-'
            && let Some(start_c) = prev
        {
            pi += 1; // consume '-'
            if pi >= p.len() {
                return (false, pi);
            }
            let end_c = p[pi];
            if ch >= start_c && ch <= end_c {
                matched = true;
            }
            prev = None;
            pi += 1;
            continue;
        }
        if ch == c {
            matched = true;
        }
        prev = Some(c);
        pi += 1;
    }
    if pi >= p.len() || p[pi] != b']' {
        // Unclosed [
        return (false, p.len());
    }
    pi += 1; // skip ']'
    let res = if negated { !matched } else { matched };
    (res, pi)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tri {
    True,
    False,
    Unknown,
}

impl Tri {
    fn and(self, other: Tri) -> Tri {
        match (self, other) {
            (Tri::False, _) | (_, Tri::False) => Tri::False,
            (Tri::Unknown, x) | (x, Tri::Unknown) => x,
            (Tri::True, Tri::True) => Tri::True,
        }
    }
    fn or(self, other: Tri) -> Tri {
        match (self, other) {
            (Tri::True, _) | (_, Tri::True) => Tri::True,
            (Tri::Unknown, x) | (x, Tri::Unknown) => x,
            (Tri::False, Tri::False) => Tri::False,
        }
    }
}

/// A compiled expression ready to be evaluated against runtime data.
#[derive(Debug, Clone)]
pub struct Compiled {
    expr: Expr,
    schema: Schema,
}

impl Compiled {
    /// Evaluates the expression against the provided context.
    ///
    /// Tri-state semantics: on `Unknown` the top-level result is treated as `true`.
    pub fn evaluate<C: Context>(&self, ctx: &C) -> bool {
        let tri = eval_expr(&self.expr, &self.schema, ctx);
        match tri {
            Tri::True => true,
            Tri::False => false,
            Tri::Unknown => true, // 顶层 Unknown 视为 true
        }
    }
}

fn eval_expr<C: Context>(e: &Expr, schema: &Schema, ctx: &C) -> Tri {
    match e {
        Expr::Group(inner) => eval_expr(inner, schema, ctx),
        Expr::Or(l, r) => {
            let lv = eval_expr(l, schema, ctx);
            if lv == Tri::True {
                return Tri::True;
            }
            let rv = eval_expr(r, schema, ctx);
            lv.or(rv)
        }
        Expr::And(l, r) => {
            let lv = eval_expr(l, schema, ctx);
            if lv == Tri::False {
                return Tri::False;
            }
            let rv = eval_expr(r, schema, ctx);
            lv.and(rv)
        }
        Expr::NumCmp {
            field,
            mask,
            op,
            rhs,
        } => {
            match schema.get_type(field) {
                Some(FieldType::Integer(_)) => match ctx.get_integer(field) {
                    None => Tri::Unknown,
                    Some(mut v) => {
                        if let Some(m) = mask {
                            v &= *m;
                        }
                        let res = match op {
                            NumOp::Eq => v == *rhs,
                            NumOp::Ne => v != *rhs,
                            NumOp::Lt => v < *rhs,
                            NumOp::Le => v <= *rhs,
                            NumOp::Gt => v > *rhs,
                            NumOp::Ge => v >= *rhs,
                        };
                        if res { Tri::True } else { Tri::False }
                    }
                },
                // Type mismatch: The expression expects an integer field, but the schema says it's a string.
                Some(FieldType::Bytes) => Tri::False,
                Some(FieldType::Unsupported) => Tri::False,
                None => unreachable!(),
            }
        }
        Expr::StrCmp { field, op, pat } => {
            match schema.get_type(field) {
                Some(FieldType::Bytes) => match ctx.get_bytes(field) {
                    None => Tri::Unknown,
                    Some(v) => {
                        let res = match op {
                            StrOp::Eq => v == pat.as_bytes(),
                            StrOp::Ne => v != pat.as_bytes(),
                            StrOp::Glob => glob_match_bytes(pat.as_bytes(), v),
                        };
                        if res { Tri::True } else { Tri::False }
                    }
                },
                // Type mismatch: The expression expects a string field, but the schema says it's an integer.
                Some(FieldType::Integer(_)) => Tri::False,
                Some(FieldType::Unsupported) => Tri::False,
                None => unreachable!(),
            }
        }
    }
}

/// Parses and validates a filter expression against the given `Schema`.
///
/// Returns a `Compiled` expression on success, or a `ParseError` if lexing,
/// parsing, or schema validation fails.
pub fn compile_with_schema(input: &str, schema: Schema) -> Result<Compiled, ParseError> {
    let mut p = Parser::new(input)?;
    let expr = p.parse()?;
    // validate identifiers against schema & type/operator compatibility
    validate(&expr, &schema)?;
    Ok(Compiled { expr, schema })
}

fn validate(expr: &Expr, schema: &Schema) -> Result<(), ParseError> {
    match expr {
        Expr::Or(l, r) | Expr::And(l, r) => {
            validate(l, schema)?;
            validate(r, schema)
        }
        Expr::Group(inner) => validate(inner, schema),
        Expr::NumCmp { field, .. } => match schema.get_type(field) {
            None => Err(ParseError::new(0, 0, format!("unknown field: {}", field))),
            Some(FieldType::Bytes) => Err(ParseError::new(
                0,
                0,
                format!("field '{}' is not numeric", field),
            )),
            Some(FieldType::Integer(_)) => Ok(()),
            Some(FieldType::Unsupported) => Err(ParseError::new(
                0,
                0,
                format!("field '{}' has unsupported type", field),
            )),
        },
        Expr::StrCmp { field, .. } => match schema.get_type(field) {
            None => Err(ParseError::new(0, 0, format!("unknown field: {}", field))),
            Some(FieldType::Integer(_)) => Err(ParseError::new(
                0,
                0,
                format!("field '{}' is not string", field),
            )),
            Some(FieldType::Bytes) => Ok(()),
            Some(FieldType::Unsupported) => Err(ParseError::new(
                0,
                0,
                format!("field '{}' has unsupported type", field),
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn schema_sig_comm_flags_user() -> Schema {
        schema! {
            "sig" => (u32::FIELD_TYPE, 0, 4),
            "comm" => (FieldType::Bytes, 4, 16),
            "flags" => (i32::FIELD_TYPE, 20, 4),
            "user" => (FieldType::Bytes, 24, 16),
        }
    }

    #[test]
    fn test_basic_parse_and_eval() {
        let schema = schema_sig_comm_flags_user();
        let compiled = compile_with_schema(
            "((sig >= 10 && sig < 15) || sig == 17) && comm != bash",
            schema,
        )
        .expect("compile");

        // matching example
        let mut ctx: BTreeMap<String, String> = BTreeMap::new();
        ctx.insert("sig".into(), "12".into());
        ctx.insert("comm".into(), "sh".into());
        assert!(compiled.evaluate(&ctx));

        // non-matching due to comm
        ctx.insert("comm".into(), "bash".into());
        assert!(!compiled.evaluate(&ctx));

        // matching by sig == 17
        ctx.insert("sig".into(), "17".into());
        ctx.insert("comm".into(), "bash5".into()); // comm != bash still true
        assert!(compiled.evaluate(&ctx));
    }

    #[test]
    fn test_hex_and_mask() {
        let schema = schema_sig_comm_flags_user();
        let compiled = compile_with_schema("flags & 0x10 == 0x10", schema).expect("compile");
        let mut ctx: BTreeMap<String, String> = BTreeMap::new();
        ctx.insert("flags".into(), format!("{}", 0x30));
        assert!(compiled.evaluate(&ctx));
        ctx.insert("flags".into(), format!("{}", 0x20));
        assert!(!compiled.evaluate(&ctx));
    }

    #[test]
    fn test_glob_match_primitives() {
        assert!(super::glob_match_bytes(b"bash*", b"bash"));
        assert!(super::glob_match_bytes(b"bash*", b"bash123"));
        assert!(super::glob_match_bytes(b"b?sh", b"bash"));
        assert!(super::glob_match_bytes(b"b[ae]sh", b"bash"));
        assert!(!super::glob_match_bytes(b"b[!a]sh", b"bash"));
        assert!(!super::glob_match_bytes(b"b[^a]sh", b"bash"));
    }

    #[test]
    fn test_string_glob_expr() {
        let schema = schema_sig_comm_flags_user();
        let compiled = compile_with_schema("comm ~ bash*", schema).expect("compile");
        let mut ctx: BTreeMap<String, String> = BTreeMap::new();
        ctx.insert("comm".into(), "bashXYZ".into());
        assert!(compiled.evaluate(&ctx));
        ctx.insert("comm".into(), "sh".into());
        assert!(!compiled.evaluate(&ctx));
    }

    #[test]
    fn test_string_equality_literal_star() {
        let schema = schema_sig_comm_flags_user();
        let compiled = compile_with_schema("comm == bash*", schema).expect("compile");
        let mut ctx: BTreeMap<String, String> = BTreeMap::new();
        ctx.insert("comm".into(), "bash*".into());
        assert!(compiled.evaluate(&ctx));
        ctx.insert("comm".into(), "bashXYZ".into());
        assert!(!compiled.evaluate(&ctx)); // equality, not glob
    }

    #[test]
    fn test_string_with_quotes_and_spaces() {
        let schema = schema_sig_comm_flags_user();
        let compiled = compile_with_schema("comm == \"C Program\"", schema).expect("compile");
        let mut ctx: BTreeMap<String, String> = BTreeMap::new();
        ctx.insert("comm".into(), "C Program".into());
        assert!(compiled.evaluate(&ctx));
    }

    #[test]
    fn test_runtime_missing_field_unknown_semantics() {
        // 'user' is in schema but not provided in ctx
        let schema = schema_sig_comm_flags_user();
        let compiled1 = compile_with_schema("user == root", schema.clone()).expect("compile");
        let compiled2 =
            compile_with_schema("user == root || sig == 17", schema.clone()).expect("compile");
        let compiled3 =
            compile_with_schema("user == root && sig == 17", schema.clone()).expect("compile");

        let mut ctx: BTreeMap<String, String> = BTreeMap::new();
        // Only sig is provided later when needed
        assert!(compiled1.evaluate(&ctx)); // Unknown at top level => true

        ctx.insert("sig".into(), "17".into());
        assert!(compiled2.evaluate(&ctx)); // Unknown || True => True
        assert!(compiled3.evaluate(&ctx)); // Unknown && True => True (true-neutral)
    }

    #[test]
    fn test_precedence_and_grouping() {
        let schema = schema_sig_comm_flags_user();
        let c1 = compile_with_schema("sig == 1 || sig == 2 && comm == bash", schema.clone())
            .expect("compile");
        let c2 = compile_with_schema("(sig == 1 || sig == 2) && comm == bash", schema.clone())
            .expect("compile");
        let mut ctx: BTreeMap<String, String> = BTreeMap::new();
        ctx.insert("sig".into(), "2".into());
        ctx.insert("comm".into(), "sh".into());
        assert!(!c1.evaluate(&ctx));
        assert!(!c2.evaluate(&ctx));
        ctx.insert("comm".into(), "bash".into());
        assert!(c2.evaluate(&ctx));
        assert!(c1.evaluate(&ctx));
    }

    #[test]
    fn test_type_mismatch_compile_error() {
        let schema = schema_sig_comm_flags_user();
        let err = compile_with_schema("sig == \"17\"", schema).unwrap_err();
        assert!(err.message.contains("not string"));
    }

    #[test]
    fn test_leading_trailing_whitespace() {
        let schema = schema_sig_comm_flags_user();
        let c = compile_with_schema("  comm   !=   bash   ", schema).expect("compile");
        let mut ctx: BTreeMap<String, String> = BTreeMap::new();
        ctx.insert("comm".into(), "zsh".into());
        assert!(c.evaluate(&ctx));
        ctx.insert("comm".into(), "bash".into());
        assert!(!c.evaluate(&ctx));
    }

    #[test]
    fn test_numeric_eq_ne() {
        let schema = schema!(
            "sig" => (u32::FIELD_TYPE, 0, 4),
        );
        let eq = compile_with_schema("sig == 10", schema.clone()).expect("compile eq");
        let ne = compile_with_schema("sig != 10", schema.clone()).expect("compile ne");
        let mut ctx = BTreeMap::new();
        ctx.insert("sig".into(), "10".into());
        assert!(eq.evaluate(&ctx));
        assert!(!ne.evaluate(&ctx));
        ctx.insert("sig".into(), "11".into());
        assert!(!eq.evaluate(&ctx));
        assert!(ne.evaluate(&ctx));
    }

    #[test]
    fn test_numeric_lt_le_gt_ge() {
        let schema = schema!(
            "v" => (u32::FIELD_TYPE, 0, 4),
        );
        let lt = compile_with_schema("v < 5", schema.clone()).unwrap();
        let le = compile_with_schema("v <= 5", schema.clone()).unwrap();
        let gt = compile_with_schema("v > 5", schema.clone()).unwrap();
        let ge = compile_with_schema("v >= 5", schema.clone()).unwrap();
        let mut ctx = BTreeMap::new();
        ctx.insert("v".into(), "5".into());
        assert!(!lt.evaluate(&ctx));
        assert!(le.evaluate(&ctx));
        assert!(!gt.evaluate(&ctx));
        assert!(ge.evaluate(&ctx));
        ctx.insert("v".into(), "4".into());
        assert!(lt.evaluate(&ctx));
        assert!(le.evaluate(&ctx));
        assert!(!gt.evaluate(&ctx));
        assert!(!ge.evaluate(&ctx));
        ctx.insert("v".into(), "6".into());
        assert!(!lt.evaluate(&ctx));
        assert!(!le.evaluate(&ctx));
        assert!(gt.evaluate(&ctx));
        assert!(ge.evaluate(&ctx));
    }

    #[test]
    fn test_numeric_mask_ne() {
        let schema = schema!(
            "flags" => (i32::FIELD_TYPE, 0, 4),
        );
        let cmp = compile_with_schema("flags & 0x10 != 0x10", schema.clone()).unwrap();
        let mut ctx = BTreeMap::new();
        ctx.insert("flags".into(), format!("{}", 0x30)); // 0x30 & 0x10 == 0x10 => expression should be false
        assert!(!cmp.evaluate(&ctx));
        ctx.insert("flags".into(), format!("{}", 0x20)); // 0x20 & 0x10 == 0x00 => != 0x10 => true
        assert!(cmp.evaluate(&ctx));
    }

    #[test]
    fn test_string_eq_ne_ops() {
        let schema = schema!(
            "comm" => (FieldType::Bytes, 0, 16),
        );
        let eq = compile_with_schema("comm == bash", schema.clone()).unwrap();
        let ne = compile_with_schema("comm != bash", schema.clone()).unwrap();
        let mut ctx = BTreeMap::new();
        ctx.insert("comm".into(), "bash".into());
        assert!(eq.evaluate(&ctx));
        assert!(!ne.evaluate(&ctx));
        ctx.insert("comm".into(), "zsh".into());
        assert!(!eq.evaluate(&ctx));
        assert!(ne.evaluate(&ctx));
    }

    #[test]
    fn test_compile_error_string_field_numeric_ops() {
        let schema = schema!(
            "comm" => (FieldType::Bytes, 0, 16),
        );
        let err = compile_with_schema("comm < 5", schema).unwrap_err();
        assert!(err.message.contains("not numeric"));
    }

    #[test]
    fn test_compile_error_numeric_field_string_glob() {
        let schema = schema!(
            "sig" => (u32::FIELD_TYPE, 0, 4),
        );
        let err = compile_with_schema("sig ~ bash*", schema).unwrap_err();
        assert!(err.message.contains("not string"));
    }
}
