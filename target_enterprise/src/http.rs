//! HTTP/1.1 — request parser + response builder. RFC 7230 §3 + 7231.
//!
//! `no_std`, no `alloc`, fixed-capacity scratch in the impl. Server-
//! side only — we parse what clients send and emit responses. Client
//! request emission + response parsing live outside this seed.
//!
//! # What's covered
//!
//! - Request line: `METHOD SP request-target SP HTTP/1.X CRLF`
//! - Header block: `Name: Value CRLF`-delimited lines, terminated by
//!   `CRLF` blank line
//! - Body framing: `Content-Length` only (no chunked transfer)
//! - Response emission: status line + Content-Type + Content-Length
//!   + body, with proper reason phrases
//! - Case-insensitive header lookup per RFC 7230 §3.2
//!
//! # What's not (yet)
//!
//! - Chunked transfer-encoding
//! - HTTP/2, HTTP/3
//! - Persistent connections (Connection: keep-alive)
//! - URL decoding / query parsing (path is raw bytes)
//! - Compression (gzip, br)
//!
//! These are explicit future tasks. The wire surface today handles
//! enough HTTP/1.1 to host a healthz endpoint or a static-file server.

#![allow(clippy::needless_range_loop)]

use proteus_contracts::{Http, HttpError, HttpMethod, HttpRequestView};

/// Minimum length of a well-formed request: `GET / HTTP/1.0\r\n\r\n`.
pub const MIN_REQUEST_LEN: usize = 18;

/// Maximum scratch we reserve for a response status line. `HTTP/1.1
/// XXX <reason>\r\n` — reason phrases are at most ~40 chars per RFC
/// 7231. 64 bytes is comfortable.
pub const MAX_STATUS_LINE_LEN: usize = 64;

/// Wire codec impl. Pure functions; no state.
pub struct HttpImpl;

impl Http for HttpImpl {
    fn parse_request(bytes: &[u8]) -> Result<HttpRequestView<'_>, HttpError> {
        if bytes.len() < MIN_REQUEST_LEN {
            return Err(HttpError::Truncated);
        }
        // Request line: METHOD SP path SP HTTP/1.X CRLF.
        let line_end = find_crlf(bytes).ok_or(HttpError::MalformedRequestLine)?;
        let line = &bytes[..line_end];

        // Method.
        let first_sp = find_byte(line, b' ').ok_or(HttpError::MalformedRequestLine)?;
        let method_bytes = &line[..first_sp];
        let method = parse_method(method_bytes)?;

        // Path.
        let rest = &line[first_sp + 1..];
        let second_sp = find_byte(rest, b' ').ok_or(HttpError::MalformedRequestLine)?;
        let path = &rest[..second_sp];
        if path.is_empty() {
            return Err(HttpError::MalformedRequestLine);
        }

        // Version: HTTP/1.X.
        let version = &rest[second_sp + 1..];
        if version.len() != 8 || &version[..7] != b"HTTP/1." {
            return Err(HttpError::UnsupportedVersion);
        }
        let version_minor = match version[7] {
            b'0' => 0u8,
            b'1' => 1u8,
            _ => return Err(HttpError::UnsupportedVersion),
        };

        // Header block: from after the request-line CRLF up to the
        // blank-line CRLF terminator.
        let after_request_line = line_end + 2;
        if bytes.len() < after_request_line {
            return Err(HttpError::Truncated);
        }
        let rest_after_rl = &bytes[after_request_line..];
        let (headers_end, body_off) =
            find_blank_line(rest_after_rl).ok_or(HttpError::HeaderBlockTooLarge)?;
        let headers_raw = &rest_after_rl[..headers_end];
        let body_start = after_request_line + body_off;
        let body = if body_start <= bytes.len() {
            &bytes[body_start..]
        } else {
            &[]
        };

        Ok(HttpRequestView {
            method,
            path,
            version_minor,
            headers_raw,
            body,
        })
    }

    fn find_header<'a>(headers_raw: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
        let mut cursor = 0usize;
        while cursor < headers_raw.len() {
            // Find end-of-line for this header.
            let rest = &headers_raw[cursor..];
            let eol = find_crlf(rest).unwrap_or(rest.len());
            let line = &rest[..eol];
            // Split at the first `:`.
            if let Some(colon) = find_byte(line, b':') {
                let hname = &line[..colon];
                if ascii_eq_ignore_case(hname, name) {
                    // Trim leading LWS (spaces + tabs) from the value.
                    let mut v_start = colon + 1;
                    while v_start < line.len()
                        && (line[v_start] == b' ' || line[v_start] == b'\t')
                    {
                        v_start += 1;
                    }
                    // Trim trailing LWS.
                    let mut v_end = line.len();
                    while v_end > v_start
                        && (line[v_end - 1] == b' ' || line[v_end - 1] == b'\t')
                    {
                        v_end -= 1;
                    }
                    return Some(&line[v_start..v_end]);
                }
            }
            if eol == rest.len() {
                break;
            }
            cursor += eol + 2; // skip CRLF
        }
        None
    }

    fn build_response(
        status: u16,
        content_type: &[u8],
        body: &[u8],
        out: &mut [u8],
    ) -> Result<usize, HttpError> {
        let reason = reason_phrase(status).ok_or(HttpError::BadStatus)?;

        // Compose status line into a small stack buffer first so we
        // know the length before copying into `out`.
        let mut sl = [0u8; MAX_STATUS_LINE_LEN];
        let prefix = b"HTTP/1.1 ";
        let mut p = 0;
        for &b in prefix {
            if p >= sl.len() {
                return Err(HttpError::OutputBufferTooSmall);
            }
            sl[p] = b;
            p += 1;
        }
        // status as 3 ASCII digits.
        let h = (status / 100) as u8;
        let t = ((status / 10) % 10) as u8;
        let o = (status % 10) as u8;
        if p + 3 >= sl.len() {
            return Err(HttpError::OutputBufferTooSmall);
        }
        sl[p] = b'0' + h;
        sl[p + 1] = b'0' + t;
        sl[p + 2] = b'0' + o;
        p += 3;
        sl[p] = b' ';
        p += 1;
        for &b in reason {
            if p >= sl.len() {
                return Err(HttpError::OutputBufferTooSmall);
            }
            sl[p] = b;
            p += 1;
        }
        if p + 2 > sl.len() {
            return Err(HttpError::OutputBufferTooSmall);
        }
        sl[p] = b'\r';
        sl[p + 1] = b'\n';
        p += 2;
        let status_line = &sl[..p];

        // Now emit: status_line + Content-Type: ct\r\n +
        // Content-Length: <body.len()>\r\n + \r\n + body.
        let mut out_pos = 0usize;
        out_pos += copy(out, out_pos, status_line)?;
        out_pos += copy(out, out_pos, b"Content-Type: ")?;
        out_pos += copy(out, out_pos, content_type)?;
        out_pos += copy(out, out_pos, b"\r\n")?;
        out_pos += copy(out, out_pos, b"Content-Length: ")?;
        out_pos += copy_decimal(out, out_pos, body.len())?;
        out_pos += copy(out, out_pos, b"\r\n\r\n")?;
        out_pos += copy(out, out_pos, body)?;
        Ok(out_pos)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_method(bytes: &[u8]) -> Result<HttpMethod, HttpError> {
    match bytes {
        b"GET" => Ok(HttpMethod::Get),
        b"HEAD" => Ok(HttpMethod::Head),
        b"POST" => Ok(HttpMethod::Post),
        b"PUT" => Ok(HttpMethod::Put),
        b"DELETE" => Ok(HttpMethod::Delete),
        b"OPTIONS" => Ok(HttpMethod::Options),
        b"PATCH" => Ok(HttpMethod::Patch),
        _ => Err(HttpError::UnknownMethod),
    }
}

fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    for i in 0..haystack.len() {
        if haystack[i] == needle {
            return Some(i);
        }
    }
    None
}

/// Find the first CRLF (`\r\n`) and return the index of the `\r`.
fn find_crlf(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 2 {
        return None;
    }
    for i in 0..bytes.len() - 1 {
        if bytes[i] == b'\r' && bytes[i + 1] == b'\n' {
            return Some(i);
        }
    }
    None
}

/// Find the blank-line separator between the header block and the body
/// and return `(headers_end, body_start)`, both as offsets into `bytes`.
///
/// Two valid shapes:
///   - `\r\n...`  — no headers; blank-line marker is the lone CRLF at
///     the very start. Returns `(0, 2)`.
///   - `H1\r\n...Hn\r\n\r\nbody...` — one or more headers, terminated
///     by `\r\n\r\n`. Returns `(i, i + 4)` where `i` is the offset of
///     the FIRST `\r` of the `\r\n\r\n` pattern. `headers_raw =
///     &bytes[..i]` then excludes the trailing CRLF of the last header
///     (which is what callers want for header parsing).
fn find_blank_line(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.len() < 2 {
        return None;
    }
    // Empty header block: blank line is the very first CRLF.
    if bytes[0] == b'\r' && bytes[1] == b'\n' {
        return Some((0, 2));
    }
    if bytes.len() < 4 {
        return None;
    }
    for i in 0..=bytes.len() - 4 {
        if bytes[i] == b'\r' && bytes[i + 1] == b'\n' && bytes[i + 2] == b'\r' && bytes[i + 3] == b'\n' {
            return Some((i, i + 4));
        }
    }
    None
}

/// ASCII case-insensitive equality. Used for header-name matching
/// (RFC 7230 §3.2 says header names are case-insensitive).
fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if to_ascii_lower(a[i]) != to_ascii_lower(b[i]) {
            return false;
        }
    }
    true
}

#[inline]
fn to_ascii_lower(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b + 32
    } else {
        b
    }
}

fn copy(out: &mut [u8], pos: usize, src: &[u8]) -> Result<usize, HttpError> {
    if pos + src.len() > out.len() {
        return Err(HttpError::OutputBufferTooSmall);
    }
    for i in 0..src.len() {
        out[pos + i] = src[i];
    }
    Ok(src.len())
}

/// Write `n` as ASCII decimal (no leading zeros, no sign) into
/// `out[pos..]`. Returns number of bytes written.
fn copy_decimal(out: &mut [u8], pos: usize, n: usize) -> Result<usize, HttpError> {
    if n == 0 {
        if pos >= out.len() {
            return Err(HttpError::OutputBufferTooSmall);
        }
        out[pos] = b'0';
        return Ok(1);
    }
    // Build digits in reverse, then copy forward.
    let mut tmp = [0u8; 20]; // 2^64 → 20 digits max
    let mut len = 0usize;
    let mut v = n;
    while v > 0 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    if pos + len > out.len() {
        return Err(HttpError::OutputBufferTooSmall);
    }
    for i in 0..len {
        out[pos + i] = tmp[len - 1 - i];
    }
    Ok(len)
}

/// Map a status code to its RFC 7231 / 9110 reason phrase. Returns
/// `None` for codes we don't recognise — those get rejected with
/// `BadStatus` so a typo doesn't ship a response with a numeric
/// reason phrase.
fn reason_phrase(status: u16) -> Option<&'static [u8]> {
    Some(match status {
        100 => b"Continue",
        101 => b"Switching Protocols",
        200 => b"OK",
        201 => b"Created",
        202 => b"Accepted",
        204 => b"No Content",
        206 => b"Partial Content",
        301 => b"Moved Permanently",
        302 => b"Found",
        304 => b"Not Modified",
        400 => b"Bad Request",
        401 => b"Unauthorized",
        403 => b"Forbidden",
        404 => b"Not Found",
        405 => b"Method Not Allowed",
        408 => b"Request Timeout",
        413 => b"Payload Too Large",
        414 => b"URI Too Long",
        429 => b"Too Many Requests",
        500 => b"Internal Server Error",
        501 => b"Not Implemented",
        502 => b"Bad Gateway",
        503 => b"Service Unavailable",
        504 => b"Gateway Timeout",
        505 => b"HTTP Version Not Supported",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_get() {
        let req = b"GET / HTTP/1.0\r\n\r\n";
        let view = HttpImpl::parse_request(req).unwrap();
        assert_eq!(view.method, HttpMethod::Get);
        assert_eq!(view.path, b"/");
        assert_eq!(view.version_minor, 0);
        assert_eq!(view.headers_raw, &[][..]);
        assert_eq!(view.body, &[][..]);
    }

    #[test]
    fn parse_get_with_headers() {
        let req = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nUser-Agent: probe\r\n\r\n";
        let view = HttpImpl::parse_request(req).unwrap();
        assert_eq!(view.method, HttpMethod::Get);
        assert_eq!(view.path, b"/healthz");
        assert_eq!(view.version_minor, 1);
        // Header block is "Host: localhost\r\nUser-Agent: probe"
        // (without the trailing CRLFCRLF terminator).
        assert!(view.headers_raw.starts_with(b"Host: localhost"));
        assert_eq!(view.body, &[][..]);
    }

    #[test]
    fn parse_post_with_body() {
        let req = b"POST /data HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let view = HttpImpl::parse_request(req).unwrap();
        assert_eq!(view.method, HttpMethod::Post);
        assert_eq!(view.path, b"/data");
        assert_eq!(view.body, b"hello");
    }

    #[test]
    fn parse_rejects_truncated() {
        assert_eq!(HttpImpl::parse_request(b"GET"), Err(HttpError::Truncated));
        assert_eq!(HttpImpl::parse_request(b""), Err(HttpError::Truncated));
    }

    #[test]
    fn parse_rejects_unknown_method() {
        let req = b"FROBNICATE / HTTP/1.1\r\n\r\n";
        assert_eq!(HttpImpl::parse_request(req), Err(HttpError::UnknownMethod));
    }

    #[test]
    fn parse_rejects_bad_version() {
        let req = b"GET / HTTP/2.0\r\n\r\n";
        assert_eq!(HttpImpl::parse_request(req), Err(HttpError::UnsupportedVersion));
    }

    #[test]
    fn parse_rejects_malformed_request_line() {
        // No spaces in the request line. Padded past MIN_REQUEST_LEN (18) so
        // we reach the request-line parser rather than bouncing off the
        // pre-flight length check.
        let req = b"GETSLASHHTTP/1.1xx\r\n\r\n";
        let err = HttpImpl::parse_request(req).unwrap_err();
        // No space → MalformedRequestLine. (We never reach parse_method
        // because find_byte(line, b' ') returns None first.)
        assert_eq!(err, HttpError::MalformedRequestLine);
    }

    #[test]
    fn parse_rejects_missing_blank_line() {
        // Request line + one header but no blank-line terminator.
        let req = b"GET / HTTP/1.1\r\nHost: localhost\r\n";
        let err = HttpImpl::parse_request(req).unwrap_err();
        assert_eq!(err, HttpError::HeaderBlockTooLarge);
    }

    #[test]
    fn find_header_case_insensitive() {
        let headers = b"Host: localhost\r\nUSER-AGENT: probe\r\nContent-Length: 0";
        assert_eq!(HttpImpl::find_header(headers, b"host"), Some(&b"localhost"[..]));
        assert_eq!(HttpImpl::find_header(headers, b"HOST"), Some(&b"localhost"[..]));
        assert_eq!(HttpImpl::find_header(headers, b"user-agent"), Some(&b"probe"[..]));
        assert_eq!(HttpImpl::find_header(headers, b"Content-Length"), Some(&b"0"[..]));
        assert_eq!(HttpImpl::find_header(headers, b"missing"), None);
    }

    #[test]
    fn find_header_trims_lws() {
        let headers = b"X-Foo:   bar baz   ";
        assert_eq!(HttpImpl::find_header(headers, b"x-foo"), Some(&b"bar baz"[..]));
    }

    #[test]
    fn build_response_200_ok_body() {
        let mut out = [0u8; 128];
        let n = HttpImpl::build_response(200, b"text/plain", b"OK", &mut out).unwrap();
        let resp = &out[..n];
        assert_eq!(
            resp,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK"
        );
    }

    #[test]
    fn build_response_404_empty_body() {
        let mut out = [0u8; 128];
        let n = HttpImpl::build_response(404, b"text/plain", b"", &mut out).unwrap();
        let resp = &out[..n];
        assert!(resp.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
        assert!(resp.contains_subseq(b"Content-Length: 0\r\n"));
    }

    #[test]
    fn build_response_500() {
        let mut out = [0u8; 128];
        let n = HttpImpl::build_response(500, b"text/plain", b"oops", &mut out).unwrap();
        let resp = &out[..n];
        assert!(resp.starts_with(b"HTTP/1.1 500 Internal Server Error\r\n"));
    }

    #[test]
    fn build_response_rejects_bad_status() {
        let mut out = [0u8; 128];
        let r = HttpImpl::build_response(999, b"text/plain", b"", &mut out);
        assert_eq!(r, Err(HttpError::BadStatus));
    }

    #[test]
    fn build_response_rejects_small_buffer() {
        let mut out = [0u8; 10];
        let r = HttpImpl::build_response(200, b"text/plain", b"OK", &mut out);
        assert_eq!(r, Err(HttpError::OutputBufferTooSmall));
    }

    #[test]
    fn build_response_status_codes_round_trip() {
        // Spot-check several status codes we'll likely emit.
        let codes = [200u16, 204, 400, 404, 405, 500, 503];
        for &c in &codes {
            let mut out = [0u8; 128];
            let n = HttpImpl::build_response(c, b"text/plain", b"", &mut out).unwrap();
            let resp = &out[..n];
            // Status line decodes to the right code.
            assert!(resp.starts_with(b"HTTP/1.1 "));
            let h = resp[9] - b'0';
            let t = resp[10] - b'0';
            let o = resp[11] - b'0';
            let parsed = (h as u16) * 100 + (t as u16) * 10 + (o as u16);
            assert_eq!(parsed, c, "round-trip failed for status {}", c);
        }
    }

    #[test]
    fn end_to_end_roundtrip() {
        // Build a response, then parse-as-request-line + headers-block
        // sanity: we can't parse a response with parse_request, but we
        // CAN parse a request whose body is the prior response — and
        // recover the response bytes byte-for-byte from `body`.
        let mut resp = [0u8; 128];
        let n = HttpImpl::build_response(200, b"application/json", b"{\"ok\":true}", &mut resp).unwrap();
        let response_bytes = &resp[..n];

        // Wrap in a synthetic request. We build the Content-Length value
        // by hand because `format!` isn't available in this no_std crate
        // even under cfg(test).
        let mut req = [0u8; 256];
        let cl = response_bytes.len();
        let mut pos = 0usize;
        for &b in b"POST /echo HTTP/1.1\r\nContent-Length: " {
            req[pos] = b;
            pos += 1;
        }
        // Render `cl` as ASCII digits (max 3 digits — response is < 256 bytes
        // by construction here, so this is plenty).
        let mut digits = [0u8; 6];
        let mut dn = 0usize;
        let mut v = cl;
        if v == 0 {
            digits[0] = b'0';
            dn = 1;
        } else {
            while v > 0 {
                digits[dn] = b'0' + (v % 10) as u8;
                v /= 10;
                dn += 1;
            }
        }
        // digits are in reverse order; copy forward.
        for i in 0..dn {
            req[pos] = digits[dn - 1 - i];
            pos += 1;
        }
        for &b in b"\r\n\r\n" {
            req[pos] = b;
            pos += 1;
        }
        for &b in response_bytes {
            req[pos] = b;
            pos += 1;
        }
        let view = HttpImpl::parse_request(&req[..pos]).unwrap();
        assert_eq!(view.method, HttpMethod::Post);
        assert_eq!(view.path, b"/echo");
        assert_eq!(view.body, response_bytes);
    }

    // Tiny `contains_subseq` extension for the assertion above.
    trait Contains {
        fn contains_subseq(&self, needle: &[u8]) -> bool;
    }
    impl Contains for &[u8] {
        fn contains_subseq(&self, needle: &[u8]) -> bool {
            if needle.is_empty() {
                return true;
            }
            if needle.len() > self.len() {
                return false;
            }
            for i in 0..=self.len() - needle.len() {
                if &self[i..i + needle.len()] == needle {
                    return true;
                }
            }
            false
        }
    }
}
